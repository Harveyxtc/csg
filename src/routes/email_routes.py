"""Email analysis API routes backed by the local email agent."""

from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from src.agent.email_agent_client import EmailAgentError, request_json


email_blueprint = Blueprint("email_api", __name__)


def _agent_request(method, path, payload=None):
    return request_json(
        method=method,
        path=path,
        payload=payload,
        username=current_user.username,
    )


def _agent_error_response(error):
    return jsonify({"success": False, "error": str(error)}), 503


@email_blueprint.route("/emailapi/status", methods=["GET"])
@login_required
def get_email_status():
    """Return status and stats from the local email analysis agent."""
    try:
        result, status = _agent_request("GET", "/email/status")
        return jsonify(result), status
    except EmailAgentError as error:
        return _agent_error_response(error)
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@email_blueprint.route("/emailapi/start", methods=["POST"])
@login_required
def start_email_analysis():
    """Enable background email analysis in the local email agent."""
    try:
        payload = request.get_json(silent=True) or {}
        result, status = _agent_request("POST", "/email/start", payload)
        return jsonify(result), status
    except EmailAgentError as error:
        return _agent_error_response(error)
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@email_blueprint.route("/emailapi/stop", methods=["POST"])
@login_required
def stop_email_analysis():
    """Disable background email analysis in the local email agent."""
    try:
        payload = request.get_json(silent=True) or {}
        result, status = _agent_request("POST", "/email/stop", payload)
        return jsonify(result), status
    except EmailAgentError as error:
        return _agent_error_response(error)
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@email_blueprint.route("/emailapi/run-once", methods=["POST"])
@login_required
def run_email_analysis_once():
    """Manually trigger one email analysis cycle in the local email agent."""
    try:
        payload = request.get_json(silent=True) or {}
        result, status = _agent_request("POST", "/email/run-once", payload)
        return jsonify(result), status
    except EmailAgentError as error:
        return _agent_error_response(error)
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@email_blueprint.route("/emailapi/configure-manual", methods=["POST"])
@login_required
def configure_email_manual_connection():
    """Update manual Mailpit/SMTP connection settings in the local email agent."""
    try:
        payload = request.get_json(silent=True) or {}
        result, status = _agent_request("POST", "/email/configure-manual", payload)
        return jsonify(result), status
    except EmailAgentError as error:
        return _agent_error_response(error)
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@email_blueprint.route("/emailapi/events/<int:event_id>/acknowledge", methods=["POST"])
@login_required
def acknowledge_email_event(event_id):
    """Acknowledge an email analysis event from the email module modal."""
    try:
        payload = request.get_json(silent=True) or {}
        result, status = _agent_request("POST", f"/email/events/{event_id}/acknowledge", payload)
        return jsonify(result), status
    except EmailAgentError as error:
        return _agent_error_response(error)
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@email_blueprint.route("/emailapi/events/<int:event_id>/delete-and-block", methods=["POST"])
@login_required
def delete_and_block_email_event(event_id):
    """Delete the suspicious email in Mailpit, block sender, and resolve event."""
    try:
        payload = request.get_json(silent=True) or {}
        result, status = _agent_request("POST", f"/email/events/{event_id}/delete-and-block", payload)
        return jsonify(result), status
    except EmailAgentError as error:
        return _agent_error_response(error)
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@email_blueprint.route("/emailapi/events/<int:event_id>/block-sender", methods=["POST"])
@login_required
def block_sender_for_email_event(event_id):
    """Block sender, delete suspicious email in Mailpit, and resolve event."""
    try:
        payload = request.get_json(silent=True) or {}
        result, status = _agent_request("POST", f"/email/events/{event_id}/block-sender", payload)
        return jsonify(result), status
    except EmailAgentError as error:
        return _agent_error_response(error)
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@email_blueprint.route("/emailapi/events/<int:event_id>/mark-safe", methods=["POST"])
@login_required
def mark_email_event_safe(event_id):
    """Mark suspicious email as safe and resolve the event."""
    try:
        payload = request.get_json(silent=True) or {}
        result, status = _agent_request("POST", f"/email/events/{event_id}/mark-safe", payload)
        return jsonify(result), status
    except EmailAgentError as error:
        return _agent_error_response(error)
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500
