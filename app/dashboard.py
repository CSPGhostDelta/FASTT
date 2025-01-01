import os
from flask import Blueprint, render_template, session, redirect, url_for, jsonify
from app.database import Target, Vulnerability
from datetime import datetime

dashboard_app = Blueprint("dashboard", __name__, template_folder="../templates", static_folder="../static")

@dashboard_app.route('/homedashboard/')
def homedashboard():
    if "username" not in session:
        return redirect(url_for("app.login"))

    user_id = session.get("user_id")
    
    total_targets = Target.query.filter_by(user_id=user_id).count()
    total_scans = Target.query.filter_by(user_id=user_id, status='Completed').count()
    total_vulnerabilities = Vulnerability.query.filter(
        Vulnerability.scan_name.in_([t.name for t in Target.query.filter_by(user_id=user_id).all()])
    ).count()

    # Top 3 Targets with Most Vulnerabilities
    top_vulnerable_targets = []
    targets = Target.query.filter_by(user_id=user_id).all()
    for target in targets:
        vuln_count = Vulnerability.query.filter_by(scan_name=target.name).count()
        top_vulnerable_targets.append({
            'name': target.name,
            'vuln_count': vuln_count
        })
    
    # Sort and get top 3
    top_vulnerable_targets.sort(key=lambda x: x['vuln_count'], reverse=True)
    top_vulnerable_targets = top_vulnerable_targets[:3]

    # Recent Scans
    recent_scans = []
    for target in targets:
        # Use the most recent summary file to get scan time
        reports_dir = f'app/reports/reports_for_{target.name}'
        if os.path.exists(reports_dir):
            summary_files = [f for f in os.listdir(reports_dir) if f.endswith('_scan_summary.txt')]
            if summary_files:
                summary_file = os.path.join(reports_dir, summary_files[-1])
                try:
                    with open(summary_file, 'r') as f:
                        content = f.read()
                        start_time_str = content.split('Scan Start Time: ')[1].split('\n')[0].strip()
                        start_time = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
                        
                        # Calculate time since last scan
                        time_diff = datetime.now() - start_time
                        
                        if time_diff.days > 0:
                            last_scan = f"{time_diff.days} day{'s' if time_diff.days > 1 else ''} ago"
                        elif time_diff.seconds // 3600 > 0:
                            last_scan = f"{time_diff.seconds // 3600} hour{'s' if time_diff.seconds // 3600 > 1 else ''} ago"
                        else:
                            last_scan = f"{time_diff.seconds // 60} minute{'s' if time_diff.seconds // 60 > 1 else ''} ago"
                        
                        recent_scans.append({
                            'name': target.name,
                            'last_scan': last_scan
                        })
                except Exception as e:
                    print(f"Error processing scan time: {e}")

    # Sort recent scans by most recent
    recent_scans.sort(key=lambda x: x['last_scan'])
    recent_scans = recent_scans[:3]

    return render_template('homedashboard.html', 
        total_targets=total_targets,
        total_scans=total_scans,
        total_vulnerabilities=total_vulnerabilities,
        top_vulnerable_targets=top_vulnerable_targets,
        recent_scans=recent_scans
    )

@dashboard_app.route('/get_vulnerability_chart_data')
def get_vulnerability_chart_data():
    if "username" not in session:
        return jsonify({}), 401

    user_id = session.get("user_id")
    
    # Get user's targets
    user_targets = Target.query.filter_by(user_id=user_id).all()
    user_target_names = [t.name for t in user_targets]

    # Count vulnerabilities by severity
    severity_counts = {
        'Informational': Vulnerability.query.filter(
            Vulnerability.scan_name.in_(user_target_names),
            Vulnerability.severity == 'Informational'
        ).count(),
        'Low': Vulnerability.query.filter(
            Vulnerability.scan_name.in_(user_target_names),
            Vulnerability.severity == 'Low'
        ).count(),
        'Medium': Vulnerability.query.filter(
            Vulnerability.scan_name.in_(user_target_names),
            Vulnerability.severity == 'Medium'
        ).count(),
        'High': Vulnerability.query.filter(
            Vulnerability.scan_name.in_(user_target_names),
            Vulnerability.severity == 'High'
        ).count(),
        'Critical': Vulnerability.query.filter(
            Vulnerability.scan_name.in_(user_target_names),
            Vulnerability.severity == 'Critical'
        ).count()
    }

    return jsonify(severity_counts)