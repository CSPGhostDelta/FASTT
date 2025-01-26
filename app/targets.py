from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from datetime import datetime
from app.database import db, Target, Vulnerability
import os
import shutil

targets_app = Blueprint("targets", __name__, template_folder="../templates", static_folder="../static")

def format_datetime(dt):
    return dt.strftime("%d %B, %Y - %I:%M %p") 

@targets_app.route('/homedashboard/scantargets/')
def target():
    if "username" not in session:
        return redirect(url_for("app.login"))

    user_id = session.get("user_id")    
    targets = Target.query.filter_by(user_id=user_id).all()

    for target in targets:
        target.added_on = format_datetime(target.added_on)

    return render_template("targets.html", targets=targets)

@targets_app.route('/homedashboard/scantargets/addtarget', methods=['GET', 'POST'])
def addtarget():
    if "username" not in session:
        return redirect(url_for("app.login"))

    if request.method == 'POST':
        scan_name = request.form['scan_name']
        target_url = request.form['target_url']
        note = request.form.get('note', '')
        user_id = session.get("user_id")

        new_target = Target(
            name=scan_name,
            domain=target_url,
            note=note,
            status='Ready', 
            added_on=datetime.now(),
            user_id=user_id
        )

        db.session.add(new_target)  
        db.session.commit() 
        flash('Target added successfully!', 'success') 
        return redirect(url_for('targets.target'))

    return render_template("addtarget.html")

@targets_app.route('/homedashboard/scantargets/delete/<int:target_id>', methods=['POST'])
def delete_target(target_id):
    if "username" not in session:
        return redirect(url_for("app.login"))

    target = Target.query.get(target_id)
    if not target:
        flash('Target not found.', 'error')
        return redirect(url_for('targets.target'))

    if target.user_id != session.get("user_id"):
        flash('You are not authorized to delete this target.', 'error')
        return redirect(url_for('targets.target'))

    try:
        target_vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()
        for vulnerability in target_vulnerabilities:
            db.session.delete(vulnerability)

        report_dir = os.path.join('app/reports', f'reports_for_{target.name}')
        if os.path.exists(report_dir):
            try:
                shutil.rmtree(report_dir)
            except Exception as dir_error:
                flash(f'Error deleting report directory: {str(dir_error)}', 'warning')

        db.session.delete(target)
        db.session.commit()

        flash(f'Target "{target.name}" has been deleted successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error occurred while deleting target: {str(e)}', 'error')

    return redirect(url_for('targets.target'))


