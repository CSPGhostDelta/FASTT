from flask_sqlalchemy import SQLAlchemy
import subprocess
from datetime import datetime

db = SQLAlchemy()

def dockerdb():
    ipaddress = subprocess.check_output(
        ["docker", "inspect", "-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "FASTTDB"]
    ).decode("utf-8").strip()
    return f"mysql+pymysql://fasttdatabase:fasttdb@{ipaddress}:3306/fasttdb"

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
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="targets")

def check_user():
    return User.query.count() > 0