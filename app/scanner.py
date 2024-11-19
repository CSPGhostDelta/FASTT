from flask import Blueprint, jsonify, session, current_app
from app.database import db, Target, Vulnerability
import json
import threading
import uuid
import logging
import traceback
from datetime import datetime, timedelta
import time
import concurrent.futures

# Import templates
from app.vuln_templates.A01.bac import run as bac_scanner

logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

scanner_app = Blueprint('scanner', __name__)

class ScanSessionManager:
    def __init__(self, max_session_age=timedelta(hours=1)):
        self._sessions = {}
        self._lock = threading.Lock()
        self._max_session_age = max_session_age

    def create_session(self, target_id):
        session_id = str(uuid.uuid4())
        
        session_data = {
            'target_id': target_id,
            'progress': 0,
            'status': 'Initializing',
            'is_complete': False,
            'vulnerabilities': [],
            'created_at': datetime.now(),
            'start_time': time.time()
        }
        
        with self._lock:
            self._sessions[session_id] = session_data
        
        return session_id

    def get_session(self, session_id):
        with self._lock:
            return self._sessions.get(session_id, {})

    def update_session(self, session_id, updates):
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].update(updates)

    def check_session_timeout(self, session_id, max_duration=300):
        with self._lock:
            session = self._sessions.get(session_id, {})
            start_time = session.get('start_time', 0)
            current_time = time.time()
            
            if current_time - start_time > max_duration:
                session.update({
                    'is_complete': True,
                    'status': f'Scan Timeout: Exceeded {max_duration} seconds',
                    'progress': 100
                })
                return True
        return False
    
scan_session_manager = ScanSessionManager()

def run_vulnerability_scan(domain, timeout=30):
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(bac_scanner, domain)
            try:
                results = future.result(timeout=timeout)
                return results
            except concurrent.futures.TimeoutError:
                logger.error(f"Vulnerability scan for {domain} timed out")
                return [{
                    'endpoint': 'Scan Timeout',
                    'details': f'Scan exceeded {timeout} seconds',
                    'status': 'Error'
                }]
    except Exception as e:
        logger.error(f"Unexpected error in vulnerability scan: {e}")
        return [{
            'endpoint': 'Scan Error',
            'details': str(e),
            'status': 'Error'
        }]

def perform_scan(app, session_id):
    with app.app_context():
        local_session = db.session.session_factory()
        
        try:
            logger.debug(f"Starting scan for session {session_id}")
            session_data = scan_session_manager.get_session(session_id)
            target_id = session_data.get('target_id')
            
            if not target_id:
                logger.error(f"No target ID found for session {session_id}")
                scan_session_manager.update_session(session_id, {
                    'is_complete': True,
                    'status': 'Scan Error: No Target ID',
                    'progress': 100
                })
                return

            target = local_session.query(Target).get(target_id)
            if not target:
                logger.error(f"Target not found for ID {target_id}")
                scan_session_manager.update_session(session_id, {
                    'is_complete': True,
                    'status': 'Scan Error: Target Not Found',
                    'progress': 100
                })
                return

            scan_stages = [
                ('Initializing scan', 2),
                ('Checking network connectivity', 2),
                ('Performing initial reconnaissance', 2),
                ('Scanning for access control vulnerabilities', 30),
                ('Analyzing results', 2),
                ('Generating report', 2)
            ]

            all_scan_results = []
            vulnerabilities = []

            for stage_index, (stage, stage_timeout) in enumerate(scan_stages):
                if scan_session_manager.check_session_timeout(session_id):
                    logger.error(f"Scan session {session_id} timed out")
                    return

                progress = int((stage_index + 1) / len(scan_stages) * 100)
                scan_session_manager.update_session(session_id, {
                    'progress': progress,
                    'status': stage
                })
                
                if stage == 'Scanning for access control vulnerabilities':
                    try:
                        logger.debug(f"Running BAC scan for {target.domain}")
                        bac_results = run_vulnerability_scan(target.domain, timeout=stage_timeout)
                        all_scan_results = bac_results
                        vulnerabilities = [
                            result for result in bac_results 
                            if result.get('vulnerability_status') in ['Vulnerable', 'Potential']
                        ]
                        
                        logger.debug(f"BAC scan results: {vulnerabilities}")
                        
                        target.scan_results = json.dumps(bac_results)
                        
                        for vuln in vulnerabilities:
                            new_vulnerability = Vulnerability(
                                scan_name=target.name,
                                endpoint=vuln.get('endpoint', 'Unknown'),
                                details=vuln.get('details', 'No additional details'),
                                url=vuln.get('url', target.domain + vuln.get('endpoint', ''))
                            )
                            local_session.add(new_vulnerability)
                        
                        local_session.commit()
                        
                    except Exception as scan_error:
                        logger.error(f"BAC scan error: {scan_error}")
                        logger.error(traceback.format_exc())
                        vulnerabilities = []

                start_time = time.time()
                while time.time() - start_time < stage_timeout:
                    if scan_session_manager.check_session_timeout(session_id):
                        return
                    time.sleep(1)

            try:
                target.status = 'Completed'
                target.scanned_on = datetime.now()
                local_session.commit()
                logger.debug(f"Scan completed for target {target_id}")
            except Exception as update_error:
                logger.error(f"Error updating target status: {update_error}")
                local_session.rollback()

            scan_session_manager.update_session(session_id, {
                'progress': 100,
                'status': 'Completed',
                'is_complete': True,
                'vulnerabilities': vulnerabilities,
                'total_scan_results': all_scan_results
            })

        except Exception as error:
            logger.error(f"Scan error for session {session_id}: {error}")
            logger.error(traceback.format_exc())

            scan_session_manager.update_session(session_id, {
                'is_complete': True,
                'status': f'Scan Error: {str(error)}',
                'progress': 100,
                'vulnerabilities': vulnerabilities
            })

            try:
                target = local_session.query(Target).get(target_id)
                if target:
                    target.status = 'Scan Error'
                    local_session.commit()
            except Exception as final_error:
                logger.error(f"Final error updating target status: {final_error}")
                local_session.rollback()

        finally:
            local_session.close()

@scanner_app.route('/scan/<int:target_id>', methods=['POST'])
def start_scan(target_id):
    try:
        logger.debug(f"Received scan request for target {target_id}")

        if "username" not in session:
            logger.error("Unauthorized scan attempt: User not logged in")
            return jsonify({
                'error': 'Unauthorized',
                'status': 'Error'
            }), 401

        target = Target.query.get(target_id)
        if not target:
            logger.error(f"Target not found for ID {target_id}")
            return jsonify({
                 'error': 'Target not found',
                'status': 'Error'
            }), 404

        if target.user_id != session.get("user_id"):
            logger.error(f"Unauthorized scan attempt for target {target_id}")
            return jsonify({
                'error': 'Unauthorized to scan this target',
                'status': 'Error'
            }), 403

        target.status = 'Scanning'
        db.session.commit()

        scan_session_id = scan_session_manager.create_session(target_id)
        logger.debug(f"Created scan session {scan_session_id} for target {target_id}")

        scanning_thread = threading.Thread(
            target=perform_scan, 
            args=(current_app._get_current_object(), scan_session_id), 
            daemon=True
        )
        scanning_thread.start()

        return jsonify({
            'scan_session_id': scan_session_id,
            'target_domain': target.domain
        })

    except Exception as e:
        logger.error(f"Error initiating scan for target {target_id}: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'status': 'Error'
        }), 500

@scanner_app.route('/scan_status/<scan_session_id>')
def get_scan_status(scan_session_id):
    try:
        scan_session = scan_session_manager.get_session(scan_session_id)
        
        return jsonify({
            'is_complete': scan_session.get('is_complete', False),
            'status': scan_session.get('status', 'Unknown'),
            'progress': scan_session.get('progress', 0),
            'vulnerabilities': scan_session.get('vulnerabilities', [])
        })

    except Exception as e:
        logger.error(f"Error retrieving scan status for {scan_session_id}: {e}")
        return jsonify({
            'error': str(e),
            'status': 'Error'
        }), 500