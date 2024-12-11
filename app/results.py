from flask import Blueprint, send_file
from app.database import db, Target, Vulnerability
from io import BytesIO

results_app = Blueprint('results', __name__, template_folder="../templates")

@results_app.route('/download_html/<int:target_id>', methods=['GET'])
def download_html(target_id):
    target = Target.query.get_or_404(target_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scan Results - {target.name}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 10px; text-align: left; border: 1px solid #ddd; }}
            th {{ background-color: #f4f4f4; }}
            .vuln-severity-critical {{ color: red; }}
            .vuln-severity-high {{ color: orange; }}
            .vuln-severity-medium {{ color: yellow; }}
            .vuln-severity-low {{ color: green; }}
        </style>
    </head>
    <body>
        <h1>Scan Results for Target: {target.name}</h1>
        <p><strong>Domain:</strong> {target.domain}</p>
        <p><strong>Scan Status:</strong> {target.status}</p>
        <p><strong>Scanned On:</strong> {target.added_on.strftime('%B %d, %Y, %I:%M %p')}</p>
        <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>

        <h2>Vulnerabilities Detected</h2>
        <table>
            <thead>
                <tr>
                    <th>No.</th>
                    <th>Vulnerability Name</th>
                    <th>Severity</th>
                    <th>CVSS Score</th>
                    <th>Details</th>
                    <th>Affected Endpoint</th>
                </tr>
            </thead>
            <tbody>
    """
    
    for index, vuln in enumerate(vulnerabilities):
        severity_class = f"vuln-severity-{vuln.severity.lower()}"
        html_content += f"""
                <tr class="{severity_class}">
                    <td>{index + 1}</td>
                    <td>{vuln.name}</td>
                    <td>{vuln.severity}</td>
                    <td>{vuln.cvss_score}</td>
                    <td>{vuln.details}</td>
                    <td>{vuln.endpoint}</td>
                </tr>
        """
    
    # Closing HTML tags
    html_content += """
            </tbody>
        </table>
    </body>
    </html>
    """
    
    # Convert the HTML content to a BytesIO object
    buffer = BytesIO()
    buffer.write(html_content.encode('utf-8'))
    buffer.seek(0)
    
    # Send the HTML content as a downloadable file
    return send_file(buffer, as_attachment=True, download_name=f"scan_results_{target.name}.html", mimetype="text/html")