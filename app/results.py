from flask import Blueprint, send_file, render_template
from app.database import Target, Vulnerability
from io import BytesIO
from weasyprint import HTML

results_app = Blueprint('results', __name__, template_folder="../templates")

@results_app.route('/download_pdf/<int:target_id>', methods=['GET'])
def download(target_id):
    target = Target.query.get_or_404(target_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()
    html_content = render_template('report.html', target=target, vulnerabilities=vulnerabilities, enumerate=enumerate)
    
    pdf_file = HTML(string=html_content).write_pdf()
    buffer = BytesIO(pdf_file)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f"report_{target.name}.pdf", mimetype="application/pdf")