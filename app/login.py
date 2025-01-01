from flask import Blueprint, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from app.database import db, User, check_user
from datetime import timedelta 

app = Blueprint("app", __name__, template_folder="../templates", static_folder="../static")

app.sessiontime = timedelta(days=1) 

@app.route("/")
def home():
    return redirect(url_for("app.login")) if check_user() else redirect(url_for("app.register"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        usercheck = User.query.filter_by(username=username).first()
        if usercheck:
            flash("Username already exists. Please choose another.", "warning")
            return redirect(url_for("app.register"))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("User created successfully! Please log in.", "success")
        return redirect(url_for("app.login"))

    return render_template("register.html")

@app.route("/createnewaccount", methods=["GET", "POST"])
def createnewaccount():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        usercheck = User.query.filter_by(username=username).first()
        if usercheck:
            flash("Username already exists. Please choose another.", "warning")
            return redirect(url_for("app.createnewaccount"))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("User created successfully! Please log in.", "success")
        return redirect(url_for("app.login"))

    return render_template("createnewaccount.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        remember = request.form.get("remember")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session["username"] = username
            session["user_id"] = user.id 
            session.permanent = bool(remember)
            flash("Successfully logged in! Welcome to dashboard.", "success") 
            return redirect(url_for("dashboard.homedashboard"))
        else:
            flash("Invalid username or password", "error")
            return render_template("login.html")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("username", None) 
    session.pop("user_id", None) 
    flash("You have been successfully logged out.", "info")
    return redirect(url_for("app.login"))
