from flask import Blueprint, render_template, session, redirect, url_for, request, flash
from app.database import db, User

profile_app = Blueprint("profile", __name__, template_folder="../templates", static_folder="../static")

@profile_app.route('/homedashboard/profile/')
def profile():
    if "username" not in session:
        return redirect(url_for("app.login"))
    
    user = User.query.filter_by(username=session["username"]).first()
    return render_template("profile.html", user=user)

@profile_app.route('/homedashboard/profile/editprofile', methods=["GET", "POST"])
def editprofile():
    if "username" not in session:
        return redirect(url_for("app.login"))
    
    user = User.query.filter_by(username=session["username"]).first()
    
    if request.method == "POST":
        user.email = request.form["email"]
        user.phone = request.form["phone"]
        user.address = request.form["address"]
        db.session.commit()

        flash("Profile successfully saved!", "success")
        return redirect(url_for("profile.profile"))

    return render_template("editprofile.html", user=user)
