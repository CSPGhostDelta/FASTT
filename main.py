from flask import Flask

from app.login import app as login_app
from app.targets import scantargets
from app.profile import profile_app
from app.database import db, dockerdb
from app.history import history_app
from app.summary import summary_app

app = Flask(__name__, template_folder="templates", static_folder="static")

app.config["SQLALCHEMY_DATABASE_URI"] = dockerdb()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = "False"
app.config["SECRET_KEY"] = "secretkey"
db.init_app(app)

app.register_blueprint(login_app)
app.register_blueprint(profile_app)
app.register_blueprint(scantargets)
app.register_blueprint(history_app)
app.register_blueprint(summary_app)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(
        debug=True,
        ssl_context=(
            "/home/csp-ghost-delta-purple/Documents/FASTT/certs/cert.pem", 
            "/home/csp-ghost-delta-purple/Documents/FASTT/certs/key.pem"
        ),
        host="0.0.0.0",
        port=5000
    )
