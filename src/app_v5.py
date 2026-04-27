"""
Project Proactive Defense
Main application entry point.

A cybersecurity monitoring dashboard for SMEs that combines:
- Module 1: Data Ingestion (log parsing and validation)
- Module 2: Detection Engine (rule-based threat detection)
- Module 3: Interpretation Engine (plain-English explanations)
- Module 4: Report Generator (PDF/CSV export)
- Module 5: Authentication & Scheduler (login, scheduled scans)

Technology Stack: Python, Flask, SQLite, Chart.js
"""

import sys
import os

# Ensure the project root is on the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.timezone import configure_timezone

configure_timezone()

from flask import Flask
from flask_login import LoginManager
from flask_apscheduler import APScheduler

from src.config import Config
from src.database import init_db
from src.auth.auth_manager import AuthManager
from src.routes.dashboard_routes_v4 import dashboard_blueprint
from src.routes.email_routes import email_blueprint
from src.routes.malware_routes import malware_blueprint
from src.routes.auth_routes import auth_blueprint


def create_app():
    """Application factory — creates and configures the Flask app."""
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "templates", "static"),
    )
    app.config["SECRET_KEY"] = Config.SECRET_KEY

    # Initialise directories and database
    Config.init_dirs()
    init_db()

    # ── Flask-Login Setup ──
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access the dashboard."
    login_manager.login_message_category = "info"

    @login_manager.user_loader
    def load_user(user_id):
        return AuthManager.get_user_by_id(int(user_id))

    # ── Register Blueprints ──
    app.register_blueprint(dashboard_blueprint)
    app.register_blueprint(malware_blueprint)
    app.register_blueprint(email_blueprint)
    app.register_blueprint(auth_blueprint)

    # ── Create Default Admin Account ──
    with app.app_context():
        AuthManager.create_default_admin()

    # ── Scheduler Setup (Module 5) ──
    scheduler = APScheduler()
    scheduler.init_app(app)

    @scheduler.task("interval", id="scheduled_scan", hours=24, misfire_grace_time=900)
    def scheduled_detection_scan():
        """Run automated detection scan on a schedule."""
        with app.app_context():
            from src.detection.detector import DetectionEngine
            engine = DetectionEngine()
            result = engine.run_detection()
            print(f"[Scheduled Scan] Processed {result['processed']} logs, "
                  f"detected {result['detections']} threats.")

    scheduler.start()

    return app


# ── Entry Point ──
if __name__ == "__main__":
    app = create_app()
    print("\n" + "=" * 60)
    print("  Project Proactive Defense")
    print("  Cyber Threat Monitoring Dashboard for SMEs")
    print("=" * 60)
    print("  URL:      http://127.0.0.1:5000")
    print("  Login:    admin / admin123")
    print("=" * 60 + "\n")
    
    # Run with debug enabled, but exclude data/ directory from reloader
    # to prevent Flask restart when malware scan temp files are written
    import re
    app.run(
        debug=False, # Turn false for safer access for Mobile #COMMENT CHANGE NETWORK ADAPTER TO BRIDGED FOR PHONE TO ACCESS VM/SYSTEM (http://Physical Host IP Here:5000)
        host="0.0.0.0", # Listen for all network interfaces (Mobile)
        port=5000,
        # For malware temp folder so wont refresh 
        exclude_patterns=['.*' + os.path.sep + r'data\uploads\malware_scan_temp' + os.path.sep + '.*']
    )
