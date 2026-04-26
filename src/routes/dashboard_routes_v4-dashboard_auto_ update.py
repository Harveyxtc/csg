"""
Dashboard Routes
Handles all web routes for the SIEM-like security dashboard,
including the main overview, module views, and event management.
"""

## Dont use yet likely wont work

import os

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, send_from_directory, jsonify
)
from flask_login import login_required, current_user
from src.database import (
    get_threat_events, get_dashboard_stats, update_event_status,
    get_audit_log, get_system_config, update_system_config,
    add_audit_entry
)
from src.ingestion.ingest import LogIngestor
from src.detection.detector import DetectionEngine
from src.reporting.report_generator import ReportGenerator
from src.chatbot.assistant import SecurityAssistant
from src.config import Config


dashboard_blueprint = Blueprint(
    "dashboard", __name__,
    template_folder="../templates",
    static_folder="../templates/static",
    static_url_path="/dashboard/static"
)



# ──────────────────────────────────────────────────────────────
# Main Dashboard
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/")
@login_required
def dashboard():
    """Main SIEM-like dashboard showing aggregated alerts and statistics."""
    stats = get_dashboard_stats()
    recent_events = get_threat_events(limit=20)
    return render_template("dashboard_v2.html", stats=stats, events=recent_events)


# ──────────────────────────────────────────────────────────────
# Module Views
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/malware")
@login_required
def malware_module():
    """Malware Detection module — dedicated screen with history and actions."""
    events = get_threat_events(source_module="Malware Detection", limit=50)
    return render_template("malware_v2.html", events=events)


@dashboard_blueprint.route("/email")
@login_required
def email_module():
    """Email Analysis module — dedicated screen with email threat history."""
    events = get_threat_events(source_module="Email Analysis", limit=50)
    return render_template("email_analysis.html", events=events)


@dashboard_blueprint.route("/system")
@login_required
def system_module():
    """System Monitor module — network and system-level events."""
    events = get_threat_events(source_module="System Monitor", limit=50)
    return render_template("system_monitor.html", events=events)


# ──────────────────────────────────────────────────────────────
# Event Management
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/events")
@login_required
def all_events():
    """View all threat events with filters."""
    severity = request.args.get("severity")
    module = request.args.get("module")
    status = request.args.get("status")

    events = get_threat_events(
        limit=200, severity=severity, source_module=module, status=status
    )
    return render_template(
        "events.html", events=events,
        filter_severity=severity, filter_module=module, filter_status=status
    )


@dashboard_blueprint.route("/event/<int:event_id>/status", methods=["POST"])
@login_required
def change_event_status(event_id):
    """Update the status of a threat event (Acknowledge / Resolve)."""
    new_status = request.form.get("status", "Acknowledged")
    update_event_status(event_id, new_status)
    add_audit_entry(
        action="event_status_change",
        performed_by=current_user.username,
        details=f"Event {event_id} changed to {new_status}"
    )
    flash(f"Event #{event_id} marked as {new_status}.", "success")
    return redirect(request.referrer or url_for("dashboard.all_events"))


# ──────────────────────────────────────────────────────────────
# Log Ingestion
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/ingest", methods=["GET", "POST"])
@login_required
def ingest_logs():
    result = None
    if request.method == "POST": # Triggered when the "Upload" button is clicked
        file = request.files.get("logfile") # Grabs the file from the browser
        if file and file.filename.endswith(".csv"):
            Config.init_dirs() # Ensures the 'uploads' folder exists
            filepath = os.path.join(Config.LOG_UPLOAD_DIR, file.filename)
            file.save(filepath) # Saves the CSV to your hard drive

            ingestor = LogIngestor() # Creates the "Data Translator"
            # Parses the CSV and puts the rows into the database
            result = ingestor.ingest_csv(filepath, source_label=file.filename)
            
            if result["success"]:
                # AUTO-SCAN: Immediately runs the Detection Engine after ingestion
                engine = DetectionEngine()
                scan_result = engine.run_detection()
                
                flash(
                    f"Success: Ingested {result['valid']} entries. "
                    f"Auto-scan found {scan_result['detections']} threats!", 
                    "success"
                )
                return redirect(url_for("dashboard.dashboard"))
            else:
                flash(f"Ingestion error: {result.get('error', 'Unknown error')}", "danger")
        else:
            flash("Please upload a valid CSV file.", "danger")

    return render_template("ingest.html", result=result)


# ──────────────────────────────────────────────────────────────
# Detection (Run Scan)
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/scan", methods=["POST"])
@login_required
def run_scan():
    """Manually trigger the detection engine to process new logs."""
    engine = DetectionEngine()
    result = engine.run_detection()
    flash(
        f"Scan complete: {result['processed']} logs processed, {result['detections']} threats detected.",
        "success"
    )
    return redirect(url_for("dashboard.dashboard"))


# ──────────────────────────────────────────────────────────────
# Reports
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/reports")
@login_required
def reports():
    """View report history and generate new reports."""
    generator = ReportGenerator()
    report_history = generator.get_report_history()
    return render_template("reports.html", reports=report_history)


@dashboard_blueprint.route("/reports/generate/pdf", methods=["POST"])
@login_required
def generate_pdf():
    """Generate a PDF security report."""
    report_type = request.form.get("report_type", "on_demand")
    generator = ReportGenerator()
    result = generator.generate_pdf_report(
        report_type=report_type,
        generated_by=current_user.username
    )
    if result["success"]:
        flash(f"Report generated: {result['filename']}", "success")
    else:
        flash("Failed to generate report.", "danger")
    return redirect(url_for("dashboard.reports"))


@dashboard_blueprint.route("/reports/generate/csv", methods=["POST"])
@login_required
def generate_csv():
    """Export threat events to CSV."""
    generator = ReportGenerator()
    result = generator.generate_csv_export(generated_by=current_user.username)
    if result["success"]:
        flash(f"CSV exported: {result['filename']}", "success")
    else:
        flash("Failed to export CSV.", "danger")
    return redirect(url_for("dashboard.reports"))


@dashboard_blueprint.route("/reports/download/<filename>")
@login_required
def download_report(filename):
    """Download a generated report file."""
    return send_from_directory(Config.REPORTS_DIR, filename, as_attachment=True)


# ──────────────────────────────────────────────────────────────
# Settings / Configuration
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """System configuration and module settings."""
    if request.method == "POST":
        for key in ["malware_detection_enabled", "email_analysis_enabled",
                     "scan_interval", "alert_threshold"]:
            value = request.form.get(key, "")
            if value:
                update_system_config(key, value)
        add_audit_entry(
            action="settings_updated",
            performed_by=current_user.username,
            details="System configuration updated"
        )
        flash("Settings updated successfully.", "success")
        return redirect(url_for("dashboard.settings"))

    config = get_system_config()
    return render_template("settings.html", config=config)


# ──────────────────────────────────────────────────────────────
# Audit Log
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/audit")
@login_required
def audit_log():
    """View the system audit log."""
    entries = get_audit_log(limit=100)
    return render_template("audit_log.html", entries=entries)


# ──────────────────────────────────────────────────────────────
# API Endpoints (for AJAX / dynamic updates)
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/api/stats")
@login_required
def api_stats():
    """JSON endpoint for dashboard statistics (for chart updates)."""
    return jsonify(get_dashboard_stats())


@dashboard_blueprint.route("/api/events")
@login_required
def api_events():
    """JSON endpoint for recent events (for live event feed)."""
    limit = request.args.get("limit", 20, type=int)
    severity = request.args.get("severity")         # Updated for more spec args
    module = request.args.get("module")
    status = request.args.get("status")
    events = get_threat_events(
        limit=limit,
        severity=severity,
        source_module=module,
        status=status,
    )
    return jsonify(events)

# Prev ^
#def api_events():      
#    """JSON endpoint for recent events (for live event feed)."""
#    limit = request.args.get("limit", 20, type=int)
#    events = get_threat_events(limit=limit)
#    return jsonify(events)


# ──────────────────────────────────────────────────────────────
# Rule-based chatbot + AI fallback helpers
# ──────────────────────────────────────────────────────────────
def handle_with_rules(message: str) -> str | None:
    """Return a fixed, explainable answer if a rule matches, else None."""
    msg = message.lower()

    if "what is phishing" in msg or "phishing" in msg:
        return (
            "Phishing is a scam where attackers pretend to be a trusted sender "
            "to trick you into clicking malicious links or sharing sensitive information."
        )

    if "strong password" in msg or "password" in msg:
        return (
            "A strong password is at least 12 characters long, uses a mix of letters, "
            "numbers and symbols, and is unique for each account."
        )

    if "threat summary" in msg or "summary of threats" in msg:
        stats = get_dashboard_stats()
        return (
            f"Right now there are {stats['total_events']} total events, with "
            f"{stats['high_severity']} high, {stats['medium_severity']} medium and "
            f"{stats['low_severity']} low severity alerts."
        )

    # No rule matched
    return None


def call_ai_model(message: str) -> str:
    """
    Fallback AI assistant.
    For the unit, this can be a simple placeholder or wrap a real AI API.
    """
    # Simple deterministic fallback text for now
    return (
        "I'm your AI assistant. Based on your question, here are some general "
        "cybersecurity best practices:\n\n"
        "- Be cautious of unexpected emails or links.\n"
        "- Use strong, unique passwords with a password manager.\n"
        "- Keep your systems and software up to date.\n"
        "- Review alerts on this dashboard regularly and act on high‑risk items first."
    )



# ──────────────────────────────────────────────────────────────
# AI Security Assistant Chatbot
# ──────────────────────────────────────────────────────────────
@dashboard_blueprint.route("/api/chat", methods=["POST"])
@login_required
def chat():
    """Chat endpoint — rule-based bot first, then AI model as fallback."""
    data = request.get_json()
    user_message = (data.get("message", "") if data else "").strip()

    # 1) Rule-based assistant first
    rule_answer = handle_with_rules(user_message)
    if rule_answer:
        add_audit_entry(
            action="chatbot_rule_hit",
            performed_by=current_user.username,
            details=f"Rule matched for message: {user_message[:80]}"
        )
        return jsonify({"response": rule_answer})

    # 2) AI fallback if no rule matched
    ai_answer = call_ai_model(user_message)
    add_audit_entry(
        action="chatbot_ai_fallback",
        performed_by=current_user.username,
        details=f"AI used for message: {user_message[:80]}"
    )
    return jsonify({"response": ai_answer})



