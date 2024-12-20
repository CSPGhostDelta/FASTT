import os
import importlib.util
import logging
from flask import Blueprint, jsonify, flash, render_template, redirect, url_for
from app.database import db, Target, Vulnerability, scanlog
from datetime import datetime
import time
import requests
from time import sleep

scanner_app = Blueprint('scanner', __name__)

# Set up logger
logger = logging.getLogger('scanner')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('scanner.log')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def get_all_templates(vuln_templates_folder='app/vuln_templates/'):
    templates = []
    start_time = time.time()  # Start time for loading templates

    for root, dirs, files in os.walk(vuln_templates_folder):
        for file in files:
            if file.endswith('.py') and file != '__init__.py':
                module_path = os.path.relpath(os.path.join(root, file), start='app').replace(os.sep, '.')
                templates.append(module_path[:-3])

    end_time = time.time()  # End time for loading templates
    logger.info(f"Templates loaded: {len(templates)}. Time taken: {end_time - start_time:.2f} seconds.")
    return templates

def import_module(module_name):
    module_path = os.path.join(os.getcwd(), 'app', *module_name.split('.')) + '.py'
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def validate_scan_template(template_module):
    try:
        required_info_keys = {'name', 'type', 'severity', 'description'}
        required_entry_point_keys = {'entry_point_method'}
        required_payloads_keys = {'payload_type', 'payload'}
        required_execute_keys = {'execute'}

        if not hasattr(template_module, 'SCAN_TEMPLATE'):
            raise ValueError(f"The template {template_module} does not have a SCAN_TEMPLATE.")

        scan_info = template_module.SCAN_TEMPLATE.get('info', {})
        if not isinstance(scan_info, dict):
            raise ValueError(f"The 'info' section in template {template_module} is not a valid dictionary.")
        
        if not required_info_keys.issubset(scan_info.keys()):
            missing_keys = required_info_keys - scan_info.keys()
            raise ValueError(f"The template {template_module} is missing required info keys: {missing_keys}")

        entry_point_info = template_module.SCAN_TEMPLATE.get('entry_point', {})
        if not isinstance(entry_point_info, dict):
            raise ValueError(f"The 'entry_point' section in template {template_module} is not a valid dictionary.")
        
        if not required_entry_point_keys.issubset(entry_point_info.keys()):
            missing_keys = required_entry_point_keys - entry_point_info.keys()
            raise ValueError(f"The template {template_module} is missing required entry point keys: {missing_keys}")

        payload_info = template_module.SCAN_TEMPLATE.get('payloads', {})
        if not isinstance(payload_info, dict):
            raise ValueError(f"The 'payloads' section in template {template_module} is not a valid dictionary.")
        
        if not required_payloads_keys.issubset(payload_info.keys()):
            missing_keys = required_payloads_keys - payload_info.keys()
            raise ValueError(f"The template {template_module} is missing required payloads keys: {missing_keys}")

        # Check that entry_point and payloads are not empty
        if not entry_point_info.get('paths'):
            raise ValueError(f"The 'entry_point' section in template {template_module} cannot be empty.")
        
        if not payload_info.get('payload'):
            raise ValueError(f"The 'payloads' section in template {template_module} cannot be empty.")

        execute_info = template_module.SCAN_TEMPLATE.get('execute', "")
        if not isinstance(execute_info, str):
            logger.error(f"SCAN_TEMPLATE 'execute' section: {execute_info}")
            raise ValueError(f"The 'execute' section in template {template_module} must be a string.")

    except ValueError as e:
        logger.error(f"Template validation failed: {e}")
        raise e

def template_details(scan_info, endpoint):
    return {
        'name': scan_info['name'],
        'details': scan_info['description'], 
        'severity': scan_info['severity'],
        'cvss_score': scan_info['cvss_score'],
        'cvss_metrics': scan_info['cvss_metrics'],
        'endpoint': endpoint,
        'full_description ': scan_info.get('full_description', 'N/A'),
        'remediation': scan_info.get('remediation', 'N/A'),
        'type': scan_info.get('type', 'N/A'),
        'cwe_code': scan_info.get('cwe_code', 'N/A'),
        'cve_code': scan_info.get('cve_code', 'N/A')
    }

def add_vulnerability(scan_info, endpoint, target):
    try:
        if isinstance(target, int):
            target = Target.query.get(target)
        if not target:
            raise ValueError(f"Target with ID {target} not found")

        target_name = target.name
        target_id = target.id

        vulnerability = Vulnerability(
            name=scan_info['name'],
            vulnerability_type=scan_info['type'],
            details=scan_info['description'],
            severity=scan_info['severity'],
            cvss_score=scan_info['cvss_score'],
            cvss_metrics=scan_info['cvss_metrics'],
            endpoint=endpoint,
            scan_name=target_name,
            full_description=scan_info['full_description'],
            remediation=scan_info['remediation'],
            cwe_code=scan_info['cwe_code'],
            cve_code=scan_info['cve_code'],
            id=target_id
        )
        db.session.add(vulnerability)
        db.session.commit()

        logger.info(f"Vulnerability saved: {vulnerability.name} at {vulnerability.endpoint}.")
        return vulnerability
       
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add vulnerability: {e}")
        return None

def perform_scan(domain, template_module, target):
    start_time = time.time()
    
    if not domain.endswith('/'):
        domain = f'{domain}/'

    validate_scan_template(template_module)
    results = []
    scan_info = template_module.SCAN_TEMPLATE.get('info', {})

    default_values = {
        'name': 'N/A',
        'severity': 'N/A',
        'description': 'N/A',
        'cvss_score': 'N/A',
        'full_description': 'N/A',
        'remediation': 'N/A',
        'type': 'N/A',
        'matcher': 'N/A',
        'cwe_code': 'N/A',
        'cve_code': 'N/A',
        'cvss_metrics': 'N/A',
    }

    logger.info(f"Performing scan for {scan_info['name']} on domain {domain}")

    for key, default_value in default_values.items():
        if not scan_info.get(key):
            scan_info[key] = default_value

    payload_info = template_module.SCAN_TEMPLATE.get('payloads', {})
    payload_type = payload_info.get('payload_type', None)
    payloads = payload_info.get('payload', [])

    logger.info(f"Payload type: {payload_type}, Payloads: {payloads}")

    if payload_type not in ['single', 'wordlist']:
        raise ValueError("Invalid payload type specified. Choose either 'single' or 'wordlist'.")

    entry_point = template_module.SCAN_TEMPLATE.get('entry_point', {})
    entry_point_method = entry_point.get('entry_point_method', None)
    headers = entry_point.get('headers', [])
    parameters = entry_point.get('parameters', [])
    paths = entry_point.get('paths', [])

    if entry_point_method == 'header' and headers:
        for header in headers:
            for payload in payloads:
                endpoint = f"{domain} -- Injecting header: {header} with payload: {payload}"
                logger.info(f"Scanning endpoint: {endpoint}")
                results.append(template_details(scan_info, endpoint))
                add_vulnerability(scan_info, endpoint, target)

    elif entry_point_method == 'parameter' and parameters:
        for param in parameters:
            for payload in payloads:
                endpoint = f"{domain}{param}{payload}"
                if not endpoint.startswith(domain):
                    endpoint = domain + endpoint
                logger.info(f"Scanning endpoint: {endpoint}")
                results.append(template_details(scan_info, endpoint))
                add_vulnerability(scan_info, endpoint, target)

    elif entry_point_method == 'path' and paths:
        for path in paths:
            for payload in payloads:
                endpoint = path.format(domain=domain)
                if not endpoint.startswith(domain):
                    endpoint = domain + endpoint
                endpoint = f"{endpoint}{payload}"
                logger.info(f"Scanning endpoint: {endpoint}")
                results.append(template_details(scan_info, endpoint))
                add_vulnerability(scan_info, endpoint, target)

    end_time = time.time()
    logger.info(f"Scan completed for {scan_info['name']}. Time taken: {end_time - start_time:.2f} seconds.")
    return results

def log_vulnerability(vuln):
    logger.info(
        f"Vulnerability Found: {vuln['name']} | Type: {vuln['type']} | Severity: {vuln['severity']} | "
        f"Matcher: {vuln['matcher']} | Endpoint: {vuln['endpoint']} | CWE: {vuln['cwe_code']} | CVE: {vuln['cve_code']}"
    )

@scanner_app.route('/start_scan/<int:target_id>', methods=['POST'])
def start_scan(target_id):
    target = Target.query.get_or_404(target_id)
    target.status = 'Scanning... (0%)'
    target.scan_progress = 0
    db.session.commit()

    vuln_templates_folder = 'app/vuln_templates' 
    templates = get_all_templates(vuln_templates_folder)

    try:
        total_templates = len(templates)
        for index, template in enumerate(templates):
            scan_module = import_module(template)

            # Perform the scan
            template_results = perform_scan(target.domain, scan_module, target)

            # Track execution time for each template
            start_time = datetime.now()

            for vuln in template_results:
                url = vuln['endpoint']
                try:
                    response = requests.get(url, allow_redirects=True)
                    if response.status_code == 200:
                        vulnerability = Vulnerability(
                            name=vuln['name'],
                            details=vuln['details'],
                            severity=vuln['severity'],
                            cvss_score=vuln['cvss_score'],
                            endpoint=url,
                            scan_name=target.name,
                            full_description=vuln['full_description'],
                            remediation=vuln['remediation'],
                            cwe_code=vuln.get('cwe_code'),
                            cve_code=vuln.get('cve_code'),
                            cvss_metrics=vuln.get('cvss_metrics'),
                        )
                        db.session.add(vulnerability)
                        db.session.commit()
                except requests.RequestException as e:
                    logger.error(f"Error requesting {url}: {e}")

            # Record template execution time
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            logger.info(f"Template {template} completed in {execution_time:.2f} seconds.")

            # Update progress
            progress = ((index + 1) / total_templates) * 100
            target.scan_progress = round(progress)
            target.status = f'Scanning... ({int(progress)}%)'
            db.session.commit()

            scan_log = scanlog(
                target_id=target.id,
                log_content=f"Template {template} completed with progress: {int(progress)}%"
            )
            db.session.add(scan_log)
            db.session.commit()

            # Simulate delay for demonstration purposes (remove in production)
            sleep(1)

        target.status = 'Completed'
        db.session.commit()
        flash('Scan completed successfully!', 'success')

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        flash(f'Error occurred during scan: {str(e)}', 'error')
        target.status = 'Scan Error'
        target.scan_error = str(e)
        db.session.commit()
        db.session.rollback()

    return redirect(url_for('targets.target', target_id=target.id))

# Scan progress route
@scanner_app.route('/scanner/scan_progress/<int:target_id>', methods=['GET'])
def scan_progress(target_id):
    target = Target.query.get_or_404(target_id)
    return jsonify({
        'status': target.status,
        'progress': target.scan_progress,
        'scan_error': target.scan_error
    })

@scanner_app.route('/results/<int:target_id>', methods=['GET'])
def view_results(target_id):
    target = Target.query.get_or_404(target_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()
    return render_template('results.html', target=target, vulnerabilities=vulnerabilities)

# View scan logs
@scanner_app.route('/view_logs/<int:target_id>', methods=['GET'])
def view_logs(target_id):
    target = Target.query.get_or_404(target_id)
    logs = scanlog.query.filter_by(target_id=target.id).order_by(scanlog.timestamp.desc()).all()
    return render_template('view_logs.html', target=target, logs=logs)

# Severity Colors
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

# View results
@scanner_app.route('/vulnerability_details/<int:vuln_id>', methods=['GET'])
def vulnerability_details(vuln_id):
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    return render_template('details.html', 
                           vulnerability=vulnerability,
                           severity_color=severity_color)