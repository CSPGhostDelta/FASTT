from flask import Blueprint, render_template, session, redirect, url_for, abort
from app.database import db, Target, Vulnerability, get_vulnerabilities
import json
from datetime import datetime

results_app = Blueprint('results', __name__, template_folder="../templates")

@results_app.route('/homedashboard/results/<int:target_id>')
def view_results(target_id):
    if 'username' not in session:
        return redirect(url_for('app.login'))
    
    target = db.session.get(Target, target_id)
    
    if not target:
        abort(404, description="Target not found")

    vulnerabilities = []
    try:
        if target.scan_results:
            all_results = json.loads(target.scan_results)
            vulnerabilities = [
                vuln for vuln in all_results 
                if vuln.get('vulnerability_status') in ['Vulnerable', 'Potential']
            ]
    except (json.JSONDecodeError, TypeError):
        vulnerabilities = []

    db_vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()

    return render_template('results.html', 
                           target=target, 
                           vulnerabilities=vulnerabilities,
                           db_vulnerabilities=db_vulnerabilities)

@results_app.route('/homedashboard/results/download/<int:target_id>')
def download_results(target_id):
    if 'username' not in session:
        return redirect(url_for('app.login'))

    target = db.session.get(Target, target_id)
    
    if not target:
        abort(404, description="Target not found")

    results = {
        'metadata': {
            'scan_timestamp': datetime.now().isoformat(),
            'username': session.get('username', 'Unknown')
        },
        'target_info': {
            'name': target.name,
            'domain': target.domain,
            'status': target.status,
            'scanned_on': target.scanned_on.isoformat() if target.scanned_on else None
        },
        'scan_results': [],
        'database_vulnerabilities': []
    }

    try:
        if target.scan_results:
            results['scan_results'] = json.loads(target.scan_results)
    except (json.JSONDecodeError, TypeError):
        results['scan_results'] = []

    db_vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()
    results['database_vulnerabilities'] = [
        {
            'details': vuln.details,
            'endpoint': vuln.endpoint
        } for vuln in db_vulnerabilities
    ]

    # download
    import io
    from flask import send_file

    json_results = json.dumps(results, indent=2)
    
    output = io.BytesIO()
    output.write(json_results.encode('utf-8'))
    output.seek(0)

    return send_file(
        output, 
        mimetype='application/json', 
        as_attachment=True, 
        download_name=f'{target.name}_scan_results.json'
    )