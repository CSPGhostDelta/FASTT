from flask_sqlalchemy import SQLAlchemy
import subprocess
from sqlalchemy import create_engine
from datetime import datetime

db = SQLAlchemy()

def dockerdb():
    ipaddress = subprocess.check_output(
        ["docker", "inspect", "-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "FASTTDB"]
    ).decode("utf-8").strip()
    return f"mysql+pymysql://root:fasttdb@{ipaddress}:3306/fasttdb"

engine = create_engine(dockerdb())

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    address = db.Column(db.String(255))
    targets = db.relationship("Target", back_populates="user") 

class Target(db.Model):
    __tablename__ = "targets"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='Ready')
    note = db.Column(db.Text)
    added_on = db.Column(db.DateTime)
    scan_results = db.Column(db.Text, nullable=True)
    scanned_on = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="targets")

class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    id = db.Column(db.Integer, primary_key=True)
    scan_name = db.Column(db.String(100))
    endpoint = db.Column(db.String(255))
    details = db.Column(db.Text)
    url = db.Column(db.String(500))

    def __repr__(self):
        return f'<Vulnerability {self.details}>'

def get_vulnerabilities(scan_name):
    vulnerabilities = Vulnerability.query.filter_by(scan_name=scan_name).all()
    return [{'details': vuln.details, 'endpoint': vuln.endpoint} for vuln in vulnerabilities]

def check_user():
    return User.query.count() > 0