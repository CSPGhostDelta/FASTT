import os
from datetime import datetime, timedelta
from flask import Blueprint, render_template, session, redirect, url_for
from app.database import Target, Vulnerability

summary_app = Blueprint("summary", __name__, template_folder="../templates", static_folder="../static")

@summary_app.route('/homedashboard/summary/')
def summary():
    if "username" not in session:
        return redirect(url_for("app.login"))

    user_id = session.get("user_id")
    
    # Get user's targets
    user_targets = Target.query.filter_by(user_id=user_id).all()
    user_target_names = [t.name for t in user_targets]

    # Basic metrics
    total_targets = len(user_targets)
    total_scans = sum(1 for t in user_targets if t.status == 'Completed')
    total_vulnerabilities = Vulnerability.query.filter(Vulnerability.scan_name.in_(user_target_names)).count()

    # Calculate Total Scan Time
    total_scan_time = timedelta()
    for report_dir in os.listdir('app/reports'):
        if not report_dir.startswith('reports_for_'):
            continue

        summary_files = [f for f in os.listdir(os.path.join('app/reports', report_dir)) 
                         if f.endswith('_scan_summary.txt')]
        
        if not summary_files:
            continue

        try:
            with open(os.path.join('app/reports', report_dir, summary_files[0]), 'r') as f:
                content = f.read()
                start_time = datetime.strptime(content.split('Scan Start Time: ')[1].split('\n')[0].strip(), "%Y-%m-%d %H:%M:%S")
                end_time = datetime.strptime(content.split('Scan End Time: ')[1].split('\n')[0].strip(), "%Y-%m-%d %H:%M:%S")
                total_scan_time += (end_time - start_time)
        except Exception as e:
            print(f"Error calculating scan time: {e}")

    # Severity and Vulnerability Type Counts
    severity_counts = {
        severity: Vulnerability.query.filter(
            Vulnerability.scan_name.in_(user_target_names),
            Vulnerability.severity == severity
        ).count() for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']
    }

    # Most Vulnerabilities Found
    vulnerability_types = {}
    vulnerabilities = Vulnerability.query.filter(Vulnerability.scan_name.in_(user_target_names)).all()
    
    for vuln in vulnerabilities:
        vulnerability_types[vuln.vulnerability_type] = vulnerability_types.get(vuln.vulnerability_type, 0) + 1

    # Sort and get top 4 vulnerability types
    most_vulnerabilities = sorted(vulnerability_types.items(), key=lambda x: x[1], reverse=True)[:4]

    # Format total scan time
    hours, remainder = divmod(total_scan_time.total_seconds(), 3600)
    minutes, seconds = divmod(remainder, 60)
    total_scan_time_str = f"{int(hours)} hours, {int(minutes)} Minutes, {int(seconds)} seconds"

    return render_template('summary.html', 
        total_targets=total_targets,
        total_scans=total_scans,
        total_vulnerabilities=total_vulnerabilities,
        total_scan_time=total_scan_time_str,
        severity_counts=severity_counts,
        most_vulnerabilities=most_vulnerabilities
    )