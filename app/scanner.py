from app.celery_worker import celery
from flask import Blueprint, jsonify, render_template, redirect, url_for
from app.database import db, Target, Vulnerability
from time import sleep
import time
import logging
import os
import importlib
import requests
import importlib.util
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

scanner_app = Blueprint('scanner', __name__)

logger = logging.getLogger('scanner')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('scanner.log')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def get_all_templates(vuln_templates_folder='app/vuln_templates/'):
    templates = []
    for root, dirs, files in os.walk(vuln_templates_folder):
        for file in files:
            if file.endswith('.py') and file != '__init__.py':
                module_path = os.path.relpath(os.path.join(root, file), start='app').replace(os.sep, '.')
                templates.append(module_path[:-3])
    return templates

def import_module(module_name):
    try:
        module_path = os.path.join(os.getcwd(), 'app', *module_name.split('.')) + '.py'
        if not os.path.exists(module_path):
            logger.error(f"Module file not found: {module_path}")
            return None
        
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Additional validation
        if not hasattr(module, 'SCAN_TEMPLATE'):
            logger.error(f"Module {module_name} does not have a SCAN_TEMPLATE")
            return None
        
        return module
    except ImportError as e:
        logger.error(f"Import error for module {module_name}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error importing module {module_name}: {e}")
        return None

def validate_scan_template(template_module):
    required_sections = {
        'info': ['name', 'type', 'severity', 'description'],
        'entry_point': ['entry_point_method'],
        'payloads': ['payload_type', 'payload']
    }

    if not hasattr(template_module, 'SCAN_TEMPLATE'):
        raise ValueError(f"Template {template_module} does not have a SCAN_TEMPLATE")

    template = template_module.SCAN_TEMPLATE

    # Validate info section
    if 'info' not in template:
        raise ValueError("Missing 'info' section in SCAN_TEMPLATE")
    
    info = template['info']
    for key in required_sections['info']:
        if key not in info:
            raise ValueError(f"Missing required key '{key}' in info section")

    # Validate entry_point section
    if 'entry_point' not in template:
        raise ValueError("Missing 'entry_point' section in SCAN_TEMPLATE")
    
    entry_point = template['entry_point']
    if 'entry_point_method' not in entry_point:
        raise ValueError("Missing 'entry_point_method' in entry_point section")
    
    method = entry_point['entry_point_method']
    if method not in ['header', 'parameter', 'path']:
        raise ValueError(f"Invalid entry_point_method: {method}")

    # Validate method-specific requirements
    if method == 'header' and 'headers' not in entry_point:
        raise ValueError("Missing 'headers' for header method")
    
    if method == 'parameter' and 'parameters' not in entry_point:
        raise ValueError("Missing 'parameters' for parameter method")
    
    if method == 'path' and 'paths' not in entry_point:
        raise ValueError("Missing 'paths' for path method")

    # Validate payloads section
    if 'payloads' not in template:
        raise ValueError("Missing 'payloads' section in SCAN_TEMPLATE")
    
    payloads = template['payloads']
    if 'payload_type' not in payloads or 'payload' not in payloads:
        raise ValueError("Missing 'payload_type' or 'payload' in payloads section")
    
    if payloads['payload_type'] not in ['single', 'wordlist']:
        raise ValueError(f"Invalid payload_type: {payloads['payload_type']}")

def add_vulnerability(scan_info, endpoint, target):

    if isinstance(target, int):
        target = Target.query.get(target)
    if not target:
        raise ValueError(f"Target with ID {target} not found")

    logger.warning(f"Potential Vulnerability Detected: {scan_info['name']} at {endpoint}")
    logger.warning(f"Vulnerability Details: {scan_info}")

    # Check for existing vulnerability
    existing_vuln = Vulnerability.query.filter_by(
        name=scan_info['name'], 
        endpoint=endpoint,
        scan_name=target.name
    ).first()

    if existing_vuln:
        return existing_vuln

    # Create new vulnerability
    vulnerability = Vulnerability(
        id=target.id,
        name=scan_info['name'],
        vulnerability_type=scan_info['type'],
        details=scan_info['description'],
        severity=scan_info['severity'],
        cvss_score=scan_info.get('cvss_score', 'N/A'),
        cvss_metrics=scan_info.get('cvss_metrics', 'N/A'),
        endpoint=endpoint,
        scan_name=target.name,
        full_description=scan_info.get('full_description', 'N/A'),
        remediation=scan_info.get('remediation', 'N/A'),
        cwe_code=scan_info.get('cwe_code', 'N/A'),
        cve_code=scan_info.get('cve_code', 'N/A')
    )
    
    db.session.add(vulnerability)
    db.session.commit()
    return vulnerability

def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504)
):
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def perform_scan(domain, template_module, target, total_templates, current_template_index, scan_start_time):
    validate_scan_template(template_module)

    scan_info = template_module.SCAN_TEMPLATE['info']
    payload_info = template_module.SCAN_TEMPLATE['payloads']
    entry_point = template_module.SCAN_TEMPLATE['entry_point']

    payloads = payload_info['payload']
    if payload_info['payload_type'] == 'wordlist':
        wordlist_path = os.path.join('app/vuln_templates/resources/', payloads[0])
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                payloads = [line.strip() for line in f]
                
    start_timestamp = time.strftime("%d %B %Y - %I:%M:%S %p", time .localtime(scan_start_time))
    logger.info(f"-- Running scan for {target.name} on {start_timestamp} --")
    logger.info(f"Running template: {scan_info['name']}")

    # Determine scanning method
    method = entry_point['entry_point_method']
    vulnerability_found = False

    # Scan based on entry point method
    session = requests_retry_session()
    if method == 'path':
        paths = entry_point['paths']
        logger.info(f"Scanning endpoint: {domain} with entry_point_method: {method}, payload_type: {payload_info['payload_type']}, payload: {payloads}")
        for path in paths:
            for payload in payloads:
                full_endpoint = path.format(domain=domain)
                if payload:
                    full_endpoint = f"{full_endpoint.rstrip('/')}/{payload}"
                try:
                    response = session.get(full_endpoint, timeout=10)
                    if response.status_code == 200:
                        logger.info(f"Vulnerability found: {full_endpoint} (Status Code: {response.status_code}), payload: {payload}")
                        add_vulnerability(scan_info, full_endpoint, target)
                        vulnerability_found = True
                except requests.RequestException as e:
                    logger.error(f"Error scanning {full_endpoint}: {e}")

    elif method == 'header':
        headers_list = entry_point['headers']
        logger.info(f"Scanning endpoint: {domain} with entry_point_method: {method}, payload_type: {payload_info['payload_type']}, payload: {payloads}")
        for header in headers_list:
            for payload in payloads:
                headers = {header: payload}
                try:
                    response = session.get(domain, headers=headers, timeout=10)
                    if response.status_code == 200:
                        logger.info(f"Vulnerability found with header: {header} and payload: {payload} (Status Code: {response.status_code})")
                        add_vulnerability(scan_info, domain, target)
                        vulnerability_found = True
                except requests.RequestException as e:
                    logger.error(f"Error scanning {domain} with header {header}: {e}")

    elif method == 'parameter':
        parameters_list = entry_point['parameters']
        logger.info(f"Scanning endpoint: {domain} with entry_point_method: {method}, payload_type: {payload_info['payload_type']}, payload: {payloads}")
        for payload in payloads:
            params = {param.strip('?'): payload for param in parameters_list}
            try:
                response = session.get(domain, params=params, timeout=10)
                if response.status_code == 200:
                    logger.info(f"Vulnerability found with parameters: {params} (Status Code: {response.status_code})")
                    add_vulnerability(scan_info, domain, target)
                    vulnerability_found = True
            except requests.RequestException as e:
                logger.error(f"Error scanning {domain} with parameters {params}: {e}")

    if not vulnerability_found:
        logger.info("No vulnerabilities found for this template.")

    if current_template_index == total_templates:
        elapsed_time = time.time() - scan_start_time
        logger.info(f"")
        logger.info(f"Scanning completed! Time elapsed: {elapsed_time:.2f} seconds")
        logger.info(f"Scan started at {time.strftime('%I:%M:%S %p', time.localtime(scan_start_time))} and ends at {time.strftime('%I:%M:%S %p', time.localtime(time.time()))} on {time.strftime('%d %B %Y', time.localtime(scan_start_time))}")
        logger.info(f"{current_template_index} templates are scanned successfully with vulnerabilities found.")
        logger.info(f"{total_templates - current_template_index} templates are scanned without vulnerabilities.\n")

@celery.task(name='perform_scan')
def perform_scan_task(target_id):
    from app.init import create_app
    app = create_app()
    with app.app_context():
        try:
            target = Target.query.get_or_404(target_id)
            
            scan_name = f"reports_for_{target.name}"
            
            report_dir = os.path.join('app/reports', scan_name)
            os.makedirs(report_dir, exist_ok=True)
            
            log_filename = f"log_for_{target.name}.log"
            scan_log_path = os.path.join(report_dir, log_filename)
            scan_logger = logging.getLogger(scan_name)
            scan_logger.setLevel(logging.DEBUG)

            file_handler = logging.FileHandler(scan_log_path)
            file_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            
            scan_logger.handlers.clear()
            scan_logger.addHandler(file_handler)
            
            global logger
            original_logger = logger
            logger = scan_logger

            templates = get_all_templates()
            total_templates = len(templates)
            
            scan_start_time = time.time()

            for i, template_path in enumerate(templates, start=1):
                try:
                    target.scan_progress = (i / total_templates) * 100
                    target.status = f"Scanning ({target.scan_progress:.0f}%)"
                    db.session.commit()
                    template_module = import_module(template_path)
                    if template_module:
                        perform_scan(target.domain, template_module, target, total_templates, i, scan_start_time)
                except Exception as template_error:
                    scan_logger.error(f"Error scanning with template {template_path}: {template_error}")
                    continue

            target.scan_progress = 100
            target.status = "Completed"
            db.session.commit()
            
            scan_report(report_dir, target, scan_name, scan_start_time)
            
        except Exception as e:
            logger.error(f"Scan task failed for target {target_id}: {e}")
            target.status = "Scan Error"
            target.scan_progress = 0
            db.session.commit()
        finally:
            logger = original_logger

def scan_report(report_dir, target, scan_name, scan_start_time):
    # Scan summary
    summary_filename = f"{target.name}_scan_summary.txt"
    summary_path = os.path.join(report_dir, summary_filename)
    vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()
    
    with open(summary_path, 'w') as summary_file:
        summary_file.write(f"Scan Summary for {target.name}\n")
        summary_file.write("=" * 50 + "\n")
        summary_file.write(f"Target Domain: {target.domain}\n")
        summary_file.write(f"Scan Start Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_start_time))}\n")
        summary_file.write(f"Scan End Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}\n")
        summary_file.write(f"Total Vulnerabilities Found: {len(vulnerabilities)}\n\n")
        
        summary_file.write("Vulnerability Details:\n")
        for vuln in vulnerabilities:
            summary_file.write(f"- {vuln.name} (Severity: {vuln.severity})\n")
            summary_file.write(f"  Endpoint: {vuln.endpoint}\n")
            summary_file.write(f"  Description: {vuln.details}\n\n")

@scanner_app.route('/start_scan/<int:target_id>', methods=['POST'])
def start_scan(target_id):
    perform_scan_task.delay(target_id)
    return redirect(url_for('targets.target', target_id=target_id))

@scanner_app.route('/scanner/scan_status/<int:target_id>', methods=['GET'])
def scan_status(target_id):
    target = Target.query.get_or_404(target_id)
    
    if target.status == 'Scanning' and target.scan_progress >= 100:
        target.status = 'Completed'
        db.session.commit()
    return jsonify({
        'status': target.status,
        'progress': target.scan_progress,
    })

@scanner_app.route('/results/<int:target_id>', methods=['GET'])
def view_results(target_id):
    target = Target.query.get_or_404(target_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()
    return render_template('results.html', target=target, vulnerabilities=vulnerabilities)

def severity_color(severity):
    if severity == 'Critical':
        return '#ff0000'
    elif severity == 'High':
        return '#ff4500'
    elif severity == 'Medium':
        return '#ffa500' 
    elif severity == 'Low':
        return '#32cd32' 
    else:
        return '#1e90ff' 

@scanner_app.route('/vulnerability_details/<int:vuln_id>', methods=['GET'])
def vulnerability_details(vuln_id):
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    return render_template('details.html', 
                           vulnerability=vulnerability,
                           severity_color=severity_color)