from flask import Flask
from app.database import db, dockerdb
from app.login import app as login_app
from app.dashboard import dashboard_app
from app.profile import profile_app
from app.history import history_app
from app.summary import summary_app
from app.scanner import scanner_app
from app.targets import targets_app
from app.results import results_app
from app.celery_worker import make_celery 

def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")

    app.config["SQLALCHEMY_DATABASE_URI"] = dockerdb()
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = "False"
    app.config["SECRET_KEY"] = "secretkey"

    db.init_app(app)

    # Register blueprints
    app.register_blueprint(login_app)
    app.register_blueprint(dashboard_app)
    app.register_blueprint(profile_app)
    app.register_blueprint(scanner_app)
    app.register_blueprint(history_app)
    app.register_blueprint(summary_app)
    app.register_blueprint(targets_app)
    app.register_blueprint(results_app)

    with app.app_context():
        db.create_all()

    make_celery(app)

    return app