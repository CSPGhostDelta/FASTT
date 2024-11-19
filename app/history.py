from flask import Blueprint, render_template
from datetime import datetime
from app.database import db, Target

history_app = Blueprint("history", __name__, template_folder="../templates", static_folder="../static")

@history_app.route('/homedashboard/history/')
def history():
    targets = Target.query.order_by(Target.added_on.desc()).all()
    return render_template('history.html', targets=targets)


