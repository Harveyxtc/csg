"""Local email analysis agent process."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from src.database import (  # noqa: E402
    add_audit_entry,
    add_threat_event,
    get_threat_event,
    get_system_config,
    init_db,
    update_event_status,
    update_system_config,
)
from src.email.analyse_emails import (  # noqa: E402
    HIGH_RISK_TAG,
    LOW_RISK_TAG,
    MARKED_SAFE_TAG,
    SUSPICIOUS_TAG,
    add_blocked_sender,
    configure_runtime_connections,
    delete_message,
    find_message_id_for_event,
    get_runtime_connection_settings,
    get_recipients,
    process_messages_once,
    tag_message,
)
from src.interpretation.interpreter import InterpretationEngine  # noqa: E402
from src.timezone import configure_timezone, perth_now  # noqa: E402


configure_timezone()

AGENT_VERSION = "1.0"
DEFAULT_HOST = os.environ.get("EMAIL_AGENT_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("EMAIL_AGENT_PORT", "8766"))
DEFAULT_POLL_SECONDS = max(1, int(os.environ.get("EMAIL_ANALYSIS_POLL_SECONDS", "2")))

STATE_LOCK = threading.RLock()
RUN_LOCK = threading.Lock()
WORKER_THREAD: threading.Thread | None = None
INTERPRETER = InterpretationEngine()

AGENT_STATE: dict[str, Any] = {
    "enabled": True,
    "poll_seconds": DEFAULT_POLL_SECONDS,
    "last_scan_at": None,
    "last_error": None,
    "last_cycle": {
        "checked": 0,
        "processed": 0,
        "suspicious": 0,
        "phishing": 0,
        "low_risk": 0,
        "links_detected": 0,
        "events_created": 0,
        "errors": [],
    },
    "stats": {
        "emails_analysed": 0,
        "suspicious_emails": 0,
        "phishing_emails": 0,
        "low_risk_emails": 0,
        "links_detected": 0,
        "events_created": 0,
        "last_email_subject": "-",
        "last_email_sender": "-",
        "last_email_category": "-",
    },
    "connections": {
        "mailpit_host": "mail.heml.cc",
        "mailpit_port": 80,
        "smtp_host": "mail.heml.cc",
        "smtp_port": 1025,
    },
    "recent_results": [],
}


def _agent_log(message: str) -> None:
    print(f"[EmailAgent] {message}", flush=True)


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    content_length = int(handler.headers.get("Content-Length", "0") or 0)
    if content_length <= 0:
        return {}
    raw_body = handler.rfile.read(content_length)
    if not raw_body:
        return {}
    return json.loads(raw_body.decode("utf-8"))


def _is_enabled_from_config(default: bool = True) -> bool:
    try:
        config = get_system_config()
        value = str(config.get("email_analysis_enabled", "true")).strip().lower()
        return value in {"1", "true", "yes", "on"}
    except Exception:
        return default


def _bootstrap_state() -> None:
    with STATE_LOCK:
        AGENT_STATE["enabled"] = _is_enabled_from_config(default=True)
        AGENT_STATE["poll_seconds"] = max(1, int(AGENT_STATE.get("poll_seconds", DEFAULT_POLL_SECONDS)))
        AGENT_STATE["connections"] = get_runtime_connection_settings()


def _apply_manual_connection_settings(payload: dict[str, Any]) -> dict[str, Any]:
    settings = configure_runtime_connections(
        mailpit_host=payload.get("mailpit_host"),
        mailpit_port=payload.get("mailpit_port"),
        smtp_host=payload.get("smtp_host"),
        smtp_port=payload.get("smtp_port"),
    )
    with STATE_LOCK:
        AGENT_STATE["connections"] = settings
    return settings


def _create_email_event(payload: dict[str, Any]) -> dict[str, Any]:
    analysis = payload.get("analysis") or {}
    category = str(analysis.get("category", "")).strip()
    event_type = str(payload.get("event_type", "")).strip()

    if category == LOW_RISK_TAG or not event_type:
        return {"success": False, "reason": "non_suspicious"}

    severity = "High" if category == HIGH_RISK_TAG else "Medium"
    message_id = str(payload.get("message_id", "")).strip()
    full_msg = payload.get("full") or {}
    summary_msg = payload.get("summary") or {}

    subject = str(full_msg.get("Subject") or summary_msg.get("Subject") or "(no subject)").strip()
    sender = str(analysis.get("sender") or "unknown-sender").strip()
    _, recipient_addresses = get_recipients(summary_msg)
    user_affected = ", ".join(recipient_addresses[:3]) if recipient_addresses else sender

    reasons = [str(reason).strip() for reason in analysis.get("reasons", []) if str(reason).strip()]
    reasons_text = ", ".join(reasons[:6]) if reasons else "No specific reason captured"
    details = (
        f"message_id={message_id}; "
        f"sender={sender}; "
        f"subject={subject}; "
        f"category={category}; "
        f"score={analysis.get('final_score')}; "
        f"reasons={reasons_text}"
    )

    timestamp = perth_now().strftime("%Y-%m-%d %H:%M:%S")
    rule = {
        "name": event_type,
        "severity": severity,
    }
    interpretation = INTERPRETER.interpret(
        rule,
        {
            "timestamp": timestamp,
            "event_type": "email_received",
            "user": user_affected,
            "ip_address": "mailpit-local",
            "details": details,
        },
    )

    add_threat_event(
        timestamp=timestamp,
        event_type=event_type,
        source_module="Email Analysis",
        severity=severity,
        user_affected=user_affected,
        ip_address="mailpit-local",
        details=details,
        explanation=interpretation["explanation"],
        recommendation=interpretation["recommendation"],
    )
    return {"success": True, "event_type": event_type}


def _merge_cycle_into_state(cycle: dict[str, Any]) -> None:
    now_iso = perth_now().isoformat()
    results = list(cycle.get("results") or [])

    with STATE_LOCK:
        stats = AGENT_STATE["stats"]
        stats["emails_analysed"] = int(stats.get("emails_analysed", 0)) + int(cycle.get("processed", 0) or 0)
        stats["suspicious_emails"] = int(stats.get("suspicious_emails", 0)) + int(cycle.get("suspicious", 0) or 0)
        stats["phishing_emails"] = int(stats.get("phishing_emails", 0)) + int(cycle.get("phishing", 0) or 0)
        stats["low_risk_emails"] = int(stats.get("low_risk_emails", 0)) + int(cycle.get("low_risk", 0) or 0)
        stats["links_detected"] = int(stats.get("links_detected", 0)) + int(cycle.get("links_detected", 0) or 0)
        stats["events_created"] = int(stats.get("events_created", 0)) + int(cycle.get("events_created", 0) or 0)

        if results:
            latest = results[-1]
            stats["last_email_subject"] = latest.get("subject") or "-"
            stats["last_email_sender"] = latest.get("sender") or "-"
            stats["last_email_category"] = latest.get("category") or "-"

            recent = AGENT_STATE.get("recent_results", [])
            recent.extend(results)
            AGENT_STATE["recent_results"] = recent[-200:]

        AGENT_STATE["last_scan_at"] = now_iso
        AGENT_STATE["last_cycle"] = {
            "checked": int(cycle.get("checked", 0) or 0),
            "processed": int(cycle.get("processed", 0) or 0),
            "suspicious": int(cycle.get("suspicious", 0) or 0),
            "phishing": int(cycle.get("phishing", 0) or 0),
            "low_risk": int(cycle.get("low_risk", 0) or 0),
            "links_detected": int(cycle.get("links_detected", 0) or 0),
            "events_created": int(cycle.get("events_created", 0) or 0),
            "errors": list(cycle.get("errors") or []),
        }
        AGENT_STATE["last_error"] = (cycle.get("errors") or [None])[-1]


def _run_cycle(trigger: str, username: str = "agent") -> dict[str, Any]:
    with RUN_LOCK:
        cycle = process_messages_once(event_callback=_create_email_event, logger=_agent_log)
    _merge_cycle_into_state(cycle)

    if int(cycle.get("processed", 0) or 0) > 0:
        add_audit_entry(
            action="email_analysis_cycle",
            performed_by=username,
            details=(
                f"Email analysis cycle ({trigger}): "
                f"processed={cycle.get('processed', 0)}, "
                f"suspicious={cycle.get('suspicious', 0)}, "
                f"phishing={cycle.get('phishing', 0)}, "
                f"events_created={cycle.get('events_created', 0)}"
            ),
        )
    return cycle


def _worker_loop() -> None:
    while True:
        with STATE_LOCK:
            enabled = bool(AGENT_STATE.get("enabled", True))
            poll_seconds = max(1, int(AGENT_STATE.get("poll_seconds", DEFAULT_POLL_SECONDS)))

        if enabled:
            try:
                _run_cycle(trigger="background")
            except Exception as error:
                with STATE_LOCK:
                    AGENT_STATE["last_error"] = str(error)
                _agent_log(f"Cycle error: {error}")

        time.sleep(poll_seconds)


def _ensure_worker_started() -> None:
    global WORKER_THREAD
    if WORKER_THREAD and WORKER_THREAD.is_alive():
        return

    WORKER_THREAD = threading.Thread(target=_worker_loop, name="email-analysis-worker", daemon=True)
    WORKER_THREAD.start()


def _status_payload() -> dict[str, Any]:
    with STATE_LOCK:
        return {
            "success": True,
            "enabled": bool(AGENT_STATE.get("enabled", True)),
            "poll_seconds": int(AGENT_STATE.get("poll_seconds", DEFAULT_POLL_SECONDS)),
            "last_scan_at": AGENT_STATE.get("last_scan_at"),
            "last_error": AGENT_STATE.get("last_error"),
            "last_cycle": dict(AGENT_STATE.get("last_cycle") or {}),
            "stats": dict(AGENT_STATE.get("stats") or {}),
            "connections": dict(AGENT_STATE.get("connections") or {}),
            "recent_results": list(AGENT_STATE.get("recent_results") or [])[-50:],
        }


def _extract_event_detail(details: str, key: str) -> str:
    pattern = rf"(?:^|;\s*){re.escape(key)}=([^;]+)"
    match = re.search(pattern, str(details or ""), flags=re.IGNORECASE)
    if not match:
        return ""
    return str(match.group(1) or "").strip()


def _load_email_event(event_id: int) -> dict[str, Any]:
    event = get_threat_event(event_id)
    if not event or event.get("source_module") != "Email Analysis":
        raise ValueError("Email event not found")
    return event


def _event_message_context(event: dict[str, Any]) -> dict[str, str]:
    details = str(event.get("details") or "")
    return {
        "message_id": _extract_event_detail(details, "message_id"),
        "sender": _extract_event_detail(details, "sender"),
        "subject": _extract_event_detail(details, "subject"),
        "category": _extract_event_detail(details, "category"),
    }


def _resolve_event_mailpit_message_id(event: dict[str, Any]) -> str:
    context = _event_message_context(event)
    return find_message_id_for_event(
        message_id=context["message_id"],
        sender=context["sender"],
        subject=context["subject"],
        category=context["category"],
    )


def _acknowledge_email_event(event_id: int, username: str) -> dict[str, Any]:
    event = _load_email_event(event_id)
    update_event_status(event_id, "Acknowledged")
    add_audit_entry(
        action="email_event_acknowledged",
        performed_by=username,
        details=f"Acknowledged email event {event_id}",
    )
    return {"success": True, "status": "Acknowledged", "event_id": event_id}


def _delete_and_block_email_event(event_id: int, username: str, action_name: str) -> dict[str, Any]:
    event = _load_email_event(event_id)
    context = _event_message_context(event)
    sender = context["sender"]
    mailpit_message_id = _resolve_event_mailpit_message_id(event)
    if not mailpit_message_id:
        raise ValueError("Unable to locate the email in Mailpit for this event")

    delete_message(mailpit_message_id)
    add_blocked_sender(
        sender,
        blocked_by=username,
        reason=f"{action_name} from event {event_id}",
    )
    update_event_status(event_id, "Resolved")
    add_audit_entry(
        action=action_name,
        performed_by=username,
        details=(
            f"Resolved email event {event_id}; deleted message {mailpit_message_id}; "
            f"blocked sender {sender or 'unknown'}"
        ),
    )
    return {
        "success": True,
        "status": "Resolved",
        "event_id": event_id,
        "message_id": mailpit_message_id,
        "sender": sender,
    }


def _mark_email_event_safe(event_id: int, username: str) -> dict[str, Any]:
    event = _load_email_event(event_id)
    severity = str(event.get("severity") or "").strip().lower()
    if severity != "medium":
        raise ValueError("Mark as Safe is available only for Medium severity email events")

    mailpit_message_id = _resolve_event_mailpit_message_id(event)
    if not mailpit_message_id:
        raise ValueError("Unable to locate the email in Mailpit for this event")

    tag_message(mailpit_message_id, MARKED_SAFE_TAG)
    update_event_status(event_id, "Resolved")
    add_audit_entry(
        action="email_event_marked_safe",
        performed_by=username,
        details=f"Resolved event {event_id}; tagged message {mailpit_message_id} as {MARKED_SAFE_TAG}",
    )
    return {
        "success": True,
        "status": "Resolved",
        "event_id": event_id,
        "message_id": mailpit_message_id,
        "tag": MARKED_SAFE_TAG,
    }


class EmailAgentHandler(BaseHTTPRequestHandler):
    server_version = "EmailAgent/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[EmailAgent] {self.address_string()} - {format % args}", flush=True)

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            if path in {"/health", "/"}:
                _json_response(self, 200, {"success": True, "agent": "email", "version": AGENT_VERSION})
                return

            if path == "/email/status":
                _json_response(self, 200, _status_payload())
                return

            _json_response(self, 404, {"success": False, "error": "Unknown endpoint"})
        except Exception as error:
            _json_response(self, 500, {"success": False, "error": str(error)})

    def do_POST(self) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            data = _read_json(self)
            username = self.headers.get("X-PPD-Username") or data.get("username") or "agent"

            if path == "/email/start":
                with STATE_LOCK:
                    AGENT_STATE["enabled"] = True
                update_system_config("email_analysis_enabled", "true")
                add_audit_entry(
                    action="email_analysis_enabled",
                    performed_by=username,
                    details="Email analysis scanning enabled from email module",
                )
                _json_response(self, 200, _status_payload())
                return

            if path == "/email/stop":
                with STATE_LOCK:
                    AGENT_STATE["enabled"] = False
                update_system_config("email_analysis_enabled", "false")
                add_audit_entry(
                    action="email_analysis_disabled",
                    performed_by=username,
                    details="Email analysis scanning disabled from email module",
                )
                _json_response(self, 200, _status_payload())
                return

            if path == "/email/run-once":
                cycle = _run_cycle(trigger="manual", username=username)
                payload = _status_payload()
                payload["cycle"] = cycle
                _json_response(self, 200, payload)
                return

            if path == "/email/configure-manual":
                settings = _apply_manual_connection_settings(data)
                add_audit_entry(
                    action="email_manual_connection_updated",
                    performed_by=username,
                    details=(
                        "Updated email manual connection settings: "
                        f"mailpit={settings['mailpit_host']}:{settings['mailpit_port']}, "
                        f"smtp={settings['smtp_host']}:{settings['smtp_port']}"
                    ),
                )
                payload = _status_payload()
                _json_response(self, 200, payload)
                return

            if path.startswith("/email/events/"):
                parts = [part for part in path.split("/") if part]
                if len(parts) == 4 and parts[0] == "email" and parts[1] == "events":
                    try:
                        event_id = int(parts[2])
                    except ValueError:
                        _json_response(self, 400, {"success": False, "error": "Invalid event id"})
                        return

                    action = parts[3]
                    if action == "acknowledge":
                        payload = _acknowledge_email_event(event_id, username=username)
                        _json_response(self, 200, payload)
                        return
                    if action == "delete-and-block":
                        payload = _delete_and_block_email_event(
                            event_id,
                            username=username,
                            action_name="email_event_delete_and_block",
                        )
                        _json_response(self, 200, payload)
                        return
                    if action == "block-sender":
                        payload = _delete_and_block_email_event(
                            event_id,
                            username=username,
                            action_name="email_event_block_sender",
                        )
                        _json_response(self, 200, payload)
                        return
                    if action == "mark-safe":
                        payload = _mark_email_event_safe(event_id, username=username)
                        _json_response(self, 200, payload)
                        return

            _json_response(self, 404, {"success": False, "error": "Unknown endpoint"})
        except ValueError as error:
            _json_response(self, 400, {"success": False, "error": str(error)})
        except Exception as error:
            _json_response(self, 500, {"success": False, "error": str(error)})


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    init_db()
    _bootstrap_state()
    _ensure_worker_started()
    server = ThreadingHTTPServer((host, port), EmailAgentHandler)
    print(f"[EmailAgent] listening on http://{host}:{port}", flush=True)
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local email analysis agent")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    run_server(args.host, args.port)


if __name__ == "__main__":
    main()
