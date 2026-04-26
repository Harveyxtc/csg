"""
Authentication Routes
Handles login, logout, and registration pages.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from src.auth.auth_manager import AuthManager
from src.database import add_audit_entry


auth_blueprint = Blueprint(
    "auth",
    __name__,
    template_folder="../templates",
)

@auth_blueprint.route("/login", methods=["GET", "POST"])
def login():
    """Login page and authentication handler."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("login.html")

        # Delegate authentication to AuthManager        
        user = AuthManager.authenticate(username, password)
        if user:
            login_user(user)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("auth.login"))

    return render_template("login.html")


@auth_blueprint.route("/logout")
@login_required
def logout():
    """Log out the current user."""
    add_audit_entry(
        action="logout",
        performed_by=current_user.username,
        details="User logged out"
    )
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_blueprint.route("/register", methods=["GET", "POST"])
def register():
    """Registration page for new users."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")

        result = AuthManager.create_user(username, password)
        if result["success"]:
            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("auth.login"))
        else:
            flash(result["message"], "danger")

    return render_template("register.html")
