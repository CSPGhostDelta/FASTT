from flask import Blueprint, render_template
from datetime import datetime
from app.database import db, Target

summary_app = Blueprint("summary", __name__, template_folder="../templates", static_folder="../static")

@summary_app.route('/homedashboard/summary/')
def summary():
    return render_template('summary.html')


