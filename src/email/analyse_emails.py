import html
import json
import os
import re
import smtplib
import threading
import time
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from urllib.parse import urlparse

import requests


MAILPIT_API = os.environ.get("MAILPIT_API", "http://mail.heml.cc/api/v1/messages")
MAILPIT_TAGS_API = os.environ.get("MAILPIT_TAGS_API", "http://mail.heml.cc/api/v1/tags")
MAILPIT_MSG = os.environ.get("MAILPIT_MSG", "http://mail.heml.cc/api/v1/message")
SMTP_HOST = os.environ.get("SMTP_HOST", "mail.heml.cc")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "1025"))
POLL_SECONDS = 1
ANALYSED_TAG = "Analysed"
SUSPICIOUS_TAG = "Suspicious"
LOW_RISK_TAG = "Low-Risk"
HIGH_RISK_TAG = "High-Risk"
MARKED_SAFE_TAG = "Marked Safe"

# Local state files
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT_DIR = os.path.abspath(os.path.join(MODULE_DIR, "..", ".."))
STATE_DIR = os.path.abspath(os.environ.get("EMAIL_STATE_DIR", MODULE_DIR))
os.makedirs(STATE_DIR, exist_ok=True)

ANALYSIS_DB_FILE = os.path.join(STATE_DIR, "emails.json")
SENDER_DB_FILE = os.path.join(STATE_DIR, "sender_db.json")
SUSPICIOUS_SENDERS_DB_FILE = os.path.join(STATE_DIR, "suspicious_senders_db.json")
BLOCKED_SENDERS_DB_FILE = os.path.join(STATE_DIR, "blocked_senders_db.json")

# Keep legacy behavior by default (delete + resend for suspicious messages).
# Set EMAIL_REPLACE_SUSPICIOUS=false to keep suspicious messages in place.
REPLACE_SUSPICIOUS_EMAILS = os.environ.get("EMAIL_REPLACE_SUSPICIOUS", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# Optional allowlists for demo tuning
TRUSTED_SENDERS = {
    "hr@yourcompany.com",
    "it@yourcompany.com",
    "no-reply@yourcompany.com",
}
TRUSTED_DOMAINS = {
    "yourcompany.com",
    "microsoft.com",
    "adobe.com",
    "google.com",
}

# Organization and manual contact trust (Mailpit has no native contacts)
ORG_DOMAIN = "johnsmithlegal.au"
MANUAL_CONTACTS = [
    ("Sarah Parker", "sarah.parker@johnsmithlegal.au"),
    ("Michael Chen", "michael.chen@johnsmithlegal.au"),
    ("Emily Wright", "emily.wright@johnsmithlegal.au"),
    ("David Morris", "david.morris@johnsmithlegal.au"),
    ("Reception", "reception@johnsmithlegal.au"),
]
MANUAL_CONTACT_EMAILS = {email.strip().lower() for _, email in MANUAL_CONTACTS}

PHISHING_KEYWORDS = (
    "urgent",
    "immediately",
    "verify",
    "suspended",
    "reset password",
    "action required",
    "click here",
    "wire transfer",
    "gift card",
    "invoice",
    "login",
    "confirm account",
)

SUSPICIOUS_ATTACHMENT_EXTS = (
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".zip",
)


def _default_logger(message):
    print(message)


def _smtp_host_without_port(host_value):
    """
    Accept values like 'localhost:8025' but return only host for smtplib.
    SMTP port is controlled by SMTP_PORT.
    """
    host_value = str(host_value or "").strip()
    if not host_value:
        return "localhost"
    if host_value.startswith("["):
        return host_value
    if ":" in host_value:
        return host_value.split(":", 1)[0].strip() or "localhost"
    return host_value


_CONNECTION_LOCK = threading.RLock()


def _safe_port(value, fallback):
    try:
        port = int(value)
        if 1 <= port <= 65535:
            return port
    except (TypeError, ValueError):
        pass
    return int(fallback)


def _clean_host(value, fallback="localhost"):
    raw = str(value or "").strip()
    if not raw:
        return fallback

    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.hostname:
            return parsed.hostname
        raw = parsed.netloc or raw

    if "/" in raw:
        raw = raw.split("/", 1)[0]

    if raw.startswith("["):
        return raw

    if ":" in raw:
        raw = raw.split(":", 1)[0]

    raw = raw.strip()
    return raw or fallback


def get_runtime_connection_settings():
    with _CONNECTION_LOCK:
        parsed = urlparse(MAILPIT_API)
        mailpit_host = parsed.hostname or _clean_host(MAILPIT_API, "localhost")
        mailpit_port = parsed.port or 8025
        smtp_host = _smtp_host_without_port(SMTP_HOST)
        smtp_port = int(SMTP_PORT)

    return {
        "mailpit_host": mailpit_host,
        "mailpit_port": int(mailpit_port),
        "smtp_host": smtp_host,
        "smtp_port": int(smtp_port),
    }


def configure_runtime_connections(mailpit_host, mailpit_port, smtp_host, smtp_port):
    global MAILPIT_API, MAILPIT_TAGS_API, MAILPIT_MSG, SMTP_HOST, SMTP_PORT

    current = get_runtime_connection_settings()
    final_mailpit_host = _clean_host(mailpit_host, current["mailpit_host"])
    final_mailpit_port = _safe_port(mailpit_port, current["mailpit_port"])
    final_smtp_host = _clean_host(smtp_host, current["smtp_host"])
    final_smtp_port = _safe_port(smtp_port, current["smtp_port"])

    base_url = f"http://{final_mailpit_host}:{final_mailpit_port}"
    with _CONNECTION_LOCK:
        MAILPIT_API = f"{base_url}/api/v1/messages"
        MAILPIT_TAGS_API = f"{base_url}/api/v1/tags"
        MAILPIT_MSG = f"{base_url}/api/v1/message"
        SMTP_HOST = final_smtp_host
        SMTP_PORT = int(final_smtp_port)

    return get_runtime_connection_settings()


def load_json(path, default):
    candidate_paths = [path]
    base_name = os.path.basename(path)
    legacy_project_path = os.path.join(PROJECT_ROOT_DIR, base_name)
    if legacy_project_path not in candidate_paths:
        candidate_paths.append(legacy_project_path)

    for candidate in candidate_paths:
        if not os.path.exists(candidate):
            continue
        with open(candidate, "r", encoding="utf-8") as handle:
            try:
                payload = json.load(handle)
            except json.JSONDecodeError:
                return default

        # Migrate legacy root-level state files to src/email automatically.
        if candidate != path:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as destination:
                    json.dump(payload, destination, indent=2)
            except OSError:
                pass
        return payload
    return default


def save_json(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


store = load_json(ANALYSIS_DB_FILE, {})
sender_db = load_json(SENDER_DB_FILE, {})
suspicious_senders = load_json(SUSPICIOUS_SENDERS_DB_FILE, {})
blocked_senders = load_json(BLOCKED_SENDERS_DB_FILE, {})


def save_store():
    save_json(ANALYSIS_DB_FILE, store)


def save_sender_db():
    save_json(SENDER_DB_FILE, sender_db)


def save_suspicious_senders():
    save_json(SUSPICIOUS_SENDERS_DB_FILE, suspicious_senders)


def save_blocked_senders():
    save_json(BLOCKED_SENDERS_DB_FILE, blocked_senders)


def fetch_messages():
    response = requests.get(MAILPIT_API, timeout=10)
    response.raise_for_status()
    return response.json().get("messages", [])


def fetch_full(msg_id):
    response = requests.get(f"{MAILPIT_MSG}/{msg_id}", timeout=10)
    response.raise_for_status()
    return response.json()


def delete_message(msg_id):
    response = requests.delete(MAILPIT_API, json={"IDs": [msg_id]}, timeout=10)
    response.raise_for_status()


def tag_message(msg_id, tag):
    response = requests.put(MAILPIT_TAGS_API, json={"IDs": [msg_id], "Tags": [tag]}, timeout=10)
    response.raise_for_status()


def set_unread(msg_id):
    response = requests.put(MAILPIT_API, json={"IDs": [msg_id], "Read": False}, timeout=10)
    response.raise_for_status()


def has_analysed_tag(message_obj):
    tags = message_obj.get("Tags") or []
    return any(str(tag).strip().lower() == ANALYSED_TAG.lower() for tag in tags)


def normalize_email(address):
    return (address or "").strip().lower()


def add_blocked_sender(sender, blocked_by="system", reason=""):
    sender_email = normalize_email(sender)
    if not sender_email:
        return False

    blocked_senders[sender_email] = {
        "sender": sender_email,
        "blocked_at": int(time.time()),
        "blocked_by": str(blocked_by or "system"),
        "reason": str(reason or "").strip(),
    }
    save_blocked_senders()
    return True


def get_domain(email_address):
    if "@" not in email_address:
        return ""
    return email_address.rsplit("@", 1)[1].lower().strip()


def format_contact(contact):
    if not isinstance(contact, dict):
        return ""
    name = (contact.get("Name") or "").strip()
    address = normalize_email(contact.get("Address"))
    return formataddr((name, address)) if address else ""


def get_sender(message_obj):
    sender_obj = message_obj.get("From")
    if isinstance(sender_obj, dict):
        header = format_contact(sender_obj)
        email_address = normalize_email(sender_obj.get("Address"))
        if header and email_address:
            return header, email_address
    return "", ""


def _header_values(message_obj, header_name):
    values = []
    target = str(header_name or "").strip().lower()
    if not target or not isinstance(message_obj, dict):
        return values

    header_maps = []
    headers = message_obj.get("Headers")
    if isinstance(headers, dict):
        header_maps.append(headers)

    mime = message_obj.get("MIME")
    if isinstance(mime, dict):
        mime_headers = mime.get("Headers")
        if isinstance(mime_headers, dict):
            header_maps.append(mime_headers)

    for header_map in header_maps:
        for name, raw_value in header_map.items():
            if str(name or "").strip().lower() != target:
                continue
            if isinstance(raw_value, list):
                values.extend(str(item or "").strip() for item in raw_value if str(item or "").strip())
            elif str(raw_value or "").strip():
                values.append(str(raw_value).strip())

    return values


def _extract_sender_email(message_obj):
    if not isinstance(message_obj, dict):
        return ""

    _, sender = get_sender(message_obj)
    if sender:
        return sender

    from_field = message_obj.get("From")
    if isinstance(from_field, str):
        _, parsed_email = parseaddr(from_field)
        return normalize_email(parsed_email)

    for header_value in _header_values(message_obj, "From"):
        _, parsed_email = parseaddr(header_value)
        parsed_email = normalize_email(parsed_email)
        if parsed_email:
            return parsed_email

    return ""


def _extract_subject(message_obj):
    if not isinstance(message_obj, dict):
        return ""

    subject = str(message_obj.get("Subject") or "").strip()
    if subject:
        return subject

    for header_value in _header_values(message_obj, "Subject"):
        if str(header_value or "").strip():
            return str(header_value).strip()

    return ""


def _normalize_subject(value):
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def _subject_candidates(subject, category):
    candidates = set()
    base_subject = str(subject or "").strip()
    if not base_subject:
        return candidates

    candidates.add(_normalize_subject(base_subject))
    if category:
        candidates.add(_normalize_subject(f"[{str(category).upper()}] {base_subject}"))
    return {value for value in candidates if value}


def _message_has_original_id(message_obj, original_id):
    wanted = str(original_id or "").strip()
    if not wanted:
        return False
    for value in _header_values(message_obj, "X-Original-Mailpit-ID"):
        if value.strip() == wanted:
            return True
    return False


def find_message_id_for_event(message_id=None, sender=None, subject=None, category=None):
    """
    Resolve the active Mailpit message ID for an event.
    Handles the replace flow where the original message is deleted and resent.
    """
    original_id = str(message_id or "").strip()
    target_sender = normalize_email(sender)
    subject_set = _subject_candidates(subject, category)

    try:
        messages = fetch_messages()
    except requests.RequestException:
        return ""

    if original_id:
        for message in messages:
            candidate_id = str(message.get("ID") or "").strip()
            if candidate_id == original_id:
                return candidate_id
            if _message_has_original_id(message, original_id) and candidate_id:
                return candidate_id

    for message in messages:
        candidate_id = str(message.get("ID") or "").strip()
        if not candidate_id:
            continue

        if target_sender:
            sender_email = _extract_sender_email(message)
            if sender_email and sender_email != target_sender:
                continue

        if subject_set:
            message_subject = _normalize_subject(_extract_subject(message))
            if message_subject and message_subject not in subject_set:
                continue

        if target_sender or subject_set:
            return candidate_id

    if original_id:
        for message in messages:
            candidate_id = str(message.get("ID") or "").strip()
            if not candidate_id:
                continue
            try:
                full = fetch_full(candidate_id)
            except requests.RequestException:
                continue
            if candidate_id == original_id or _message_has_original_id(full, original_id):
                return candidate_id

    return ""


def get_recipients(message_obj):
    headers, emails = [], []
    for contact in (message_obj.get("To") or []):
        if not isinstance(contact, dict):
            continue
        address = normalize_email(contact.get("Address"))
        if address:
            emails.append(address)
            headers.append(format_contact(contact))
    return (", ".join(headers), emails) if emails else ("", [])


def update_sender_history(sender):
    if not sender:
        return

    now = int(time.time())

    if sender not in sender_db:
        sender_db[sender] = {
            "email": sender,
            "email_count": 1,
            "first_seen": now,
            "last_seen": now,
            "suspicious_count": 0,
        }
    else:
        sender_db[sender]["email_count"] = sender_db[sender].get("email_count", 0) + 1
        sender_db[sender]["last_seen"] = now

    save_sender_db()


def score_sender(sender):
    trust = 0
    risk = 0
    reasons = []

    if not sender:
        risk += 4
        reasons.append("Missing sender address")
        return trust, risk, reasons

    sender_data = sender_db.get(sender)
    sender_domain = get_domain(sender)

    if sender_domain == ORG_DOMAIN:
        risk = max(0, risk - 2)
        reasons.append("Internal domain sender")

    if sender in MANUAL_CONTACT_EMAILS:
        trust += 4
        reasons.append("Manual contact allowlist")

    if sender in TRUSTED_SENDERS:
        trust += 4
        reasons.append("Trusted sender allowlist")
    elif sender_domain in TRUSTED_DOMAINS:
        trust += 2
        reasons.append("Trusted sender domain")

    if not sender_data:
        risk += 3
        reasons.append("Unknown sender")
    else:
        email_count = sender_data.get("email_count", 0)
        if email_count < 3:
            risk += 1
            reasons.append("Low sender history")
        elif email_count > 5:
            trust += 2
            reasons.append("Strong sender history")
        elif email_count > 3:
            trust += 1
            reasons.append("Some sender history")

    if sender in suspicious_senders:
        risk += 1
        reasons.append("Previously flagged sender")

    if sender in blocked_senders:
        risk += 6
        reasons.append("Sender is blocked")

    return trust, risk, reasons


def score_content(full_msg):
    risk = 0
    reasons = []

    subject = (full_msg.get("Subject") or "").strip()
    text_body = (full_msg.get("Text") or "").strip()
    html_body = (full_msg.get("HTML") or "").strip()
    combined = f"{subject}\n{text_body}\n{html_body}".lower()

    keyword_hits = [word for word in PHISHING_KEYWORDS if word in combined]
    if keyword_hits:
        keyword_risk = min(len(keyword_hits), 4)
        risk += keyword_risk
        reasons.append(f"Phishing language: {', '.join(keyword_hits[:4])}")

    links = re.findall(r"https?://[^\s\"')>]+", combined)
    if len(links) >= 3:
        risk += 2
        reasons.append("Multiple links in message")
    elif len(links) >= 1:
        risk += 1
        reasons.append("Contains URL")

    if ".invalid" in combined:
        risk += 2
        reasons.append("Demo/fake domain detected")

    lookalike_brands = ("micr0soft", "paypa1", "goog1e", "ad0be", "out1ook")
    for token in lookalike_brands:
        if token in combined:
            risk += 2
            reasons.append(f"Lookalike brand token: {token}")

    for attachment in (full_msg.get("Attachments") or []):
        file_name = str(attachment.get("FileName", "")).lower().strip()
        if not file_name:
            continue
        if file_name.endswith(SUSPICIOUS_ATTACHMENT_EXTS):
            risk += 3
            reasons.append(f"Suspicious attachment type: {file_name}")

    return risk, reasons


def get_category(final_score):
    if final_score >= 6:
        return HIGH_RISK_TAG
    if final_score >= 3:
        return SUSPICIOUS_TAG
    return LOW_RISK_TAG


def analyse_email(msg_summary, full_msg):
    sender_header, sender_email = get_sender(msg_summary)
    update_sender_history(sender_email)

    trust_score, sender_risk, sender_reasons = score_sender(sender_email)
    content_risk, content_reasons = score_content(full_msg)
    total_risk = sender_risk + content_risk
    final_score = total_risk - trust_score
    category = get_category(final_score)

    return {
        "suspicious": category != LOW_RISK_TAG,
        "category": category,
        "final_score": final_score,
        "trust_score": trust_score,
        "risk_score": total_risk,
        "sender": sender_email,
        "sender_header": sender_header,
        "reasons": sender_reasons + content_reasons,
    }


def extract_urls_from_message(full_msg):
    subject = (full_msg.get("Subject") or "").strip()
    text_body = (full_msg.get("Text") or "").strip()
    html_body = (full_msg.get("HTML") or "").strip()
    combined = f"{subject}\n{text_body}\n{html_body}"

    raw_urls = re.findall(r"https?://[^\s\"')>]+", combined, flags=re.IGNORECASE)
    unique_urls = []
    seen = set()
    for url in raw_urls:
        cleaned = url.rstrip(".,;:!?")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_urls.append(cleaned)
    return unique_urls


def build_warned_email(msg_summary, full_msg, analysis):
    sender, from_email = get_sender(msg_summary)
    recipients, to_addresses = get_recipients(msg_summary)

    if not from_email:
        raise ValueError("Cannot resend: sender address missing")
    if not to_addresses:
        raise ValueError("Cannot resend: recipient address missing")

    subject = full_msg.get("Subject") or msg_summary.get("Subject") or "(no subject)"
    text_body = full_msg.get("Text") or ""
    html_body = full_msg.get("HTML") or ""
    detected_urls = extract_urls_from_message(full_msg)[:8]

    warning_html = (
        '<div style="background:#fff3cd;border:2px solid #e65100;padding:16px;'
        'margin:0 0 24px 0;font-family:sans-serif;border-radius:4px;">'
        '<strong style="display:block;color:#b45309;font-size:16px;margin-bottom:10px;">'
        "&#9888;&#65039; WARNING: Suspicious Email Detected."
        "</strong>"
        '<p style="margin:8px 0 0;color:#92400e;font-size:14px;">'
        "This email has been flagged as potentially suspicious or malicious. "
        "Do not click any links, open attachments, or provide personal information."
        "</p></div>"
    )
    link_warning_html = ""
    link_warning_text = ""
    if detected_urls:
        links_html = "".join(
            f'<li style="margin:6px 0;"><a href="{html.escape(url)}">{html.escape(url)}</a></li>'
            for url in detected_urls
        )
        link_warning_html = (
            '<div style="background:#fef2f2;border:1px solid #f87171;padding:14px;'
            'margin:0 0 24px 0;font-family:sans-serif;border-radius:4px;">'
            '<strong style="display:block;color:#991b1b;font-size:14px;margin-bottom:8px;">'
            "Link caution: verify destination before clicking."
            "</strong>"
            '<ul style="margin:0 0 0 18px;padding:0;color:#7f1d1d;font-size:13px;">'
            f"{links_html}</ul></div>"
        )
        link_warning_text = (
            "Link caution: verify destination before clicking.\n"
            + "\n".join(f"- {url}" for url in detected_urls)
            + "\n\n"
        )
    warning_text = (
        "WARNING: This email has been flagged as potentially suspicious or malicious.\n\n"
        "Do not click any links, open attachments, or provide personal information.\n"
        f"Risk category: {analysis.get('category')} (score={analysis.get('final_score')})\n"
        + "-" * 60
        + "\n\n"
    )

    out = EmailMessage()
    out["Subject"] = f"[{analysis.get('category').upper()}] {subject}"
    out["From"] = sender
    out["To"] = recipients
    out["X-Tags"] = f"{ANALYSED_TAG},{analysis.get('category')}"
    out["X-Original-Mailpit-ID"] = str(full_msg.get("ID", ""))

    out.set_content(warning_text + link_warning_text + (text_body or "(No plain text body available.)"))

    if html_body:
        warning_blocks = warning_html + link_warning_html
        warned_html = html_body.replace("<body>", f"<body>{warning_blocks}", 1)
        if warned_html == html_body:
            warned_html = warning_blocks + html_body
        out.add_alternative(warned_html, subtype="html")

    return out, from_email, to_addresses


def _event_type_for_category(category):
    if category == HIGH_RISK_TAG:
        return "Phishing Email Detected"
    if category == SUSPICIOUS_TAG:
        return "Suspicious Email Detected"
    return None


def process_messages_once(event_callback=None, logger=None):
    """
    Process one poll cycle.

    Args:
        event_callback: optional callback for suspicious/high-risk messages.
            Signature:
            fn(payload_dict) -> bool | dict
        logger: optional logger function that takes one string argument.
    """
    log = logger or _default_logger
    cycle = {
        "checked": 0,
        "processed": 0,
        "suspicious": 0,
        "phishing": 0,
        "low_risk": 0,
        "links_detected": 0,
        "events_created": 0,
        "errors": [],
        "results": [],
    }

    try:
        messages = fetch_messages()
    except requests.RequestException as error:
        cycle["errors"].append(f"Mailpit fetch error: {error}")
        return cycle

    for msg in messages:
        cycle["checked"] += 1
        msg_id = str(msg.get("ID", "")).strip()
        if not msg_id:
            continue

        if msg_id in store or has_analysed_tag(msg):
            continue

        log(f"\nNEW EMAIL: {msg_id}")

        try:
            full = fetch_full(msg_id)
        except requests.RequestException as error:
            cycle["errors"].append(f"Fetch failed for {msg_id}: {error}")
            log(f"  Fetch failed: {error}")
            continue

        if has_analysed_tag(full):
            log("  Already tagged - skipping")
            store[msg_id] = {"skipped": ANALYSED_TAG}
            save_store()
            continue

        analysis = analyse_email(msg, full)
        suspicious = analysis["suspicious"]
        category = analysis.get("category")
        event_type = _event_type_for_category(category)
        detected_urls = extract_urls_from_message(full)
        links_detected = len(detected_urls)
        processed_at = int(time.time())

        log(
            "  Analysis: "
            f"{analysis['category']} "
            f"(final={analysis['final_score']} trust={analysis['trust_score']} risk={analysis['risk_score']})"
        )
        for reason in analysis["reasons"]:
            log(f"    - {reason}")

        store[msg_id] = {
            "processed_at": processed_at,
            "subject": full.get("Subject"),
            "from": str(full.get("From")),
            "text": full.get("Text"),
            "html": full.get("HTML"),
            "analysis": analysis,
            "event_recorded": False,
            "event_type": event_type,
        }
        save_store()

        cycle["processed"] += 1
        cycle_result = {
            "message_id": msg_id,
            "subject": full.get("Subject"),
            "sender": analysis.get("sender"),
            "category": category,
            "score": analysis.get("final_score"),
            "links_detected": links_detected,
            "event_type": event_type,
            "event_recorded": False,
            "processed_at": processed_at,
            "reasons": list(analysis.get("reasons", [])),
        }

        cycle["links_detected"] += links_detected

        if suspicious:
            cycle["suspicious"] += 1
            if category == HIGH_RISK_TAG:
                cycle["phishing"] += 1
        else:
            cycle["low_risk"] += 1

        if suspicious and event_callback and event_type:
            try:
                callback_result = event_callback(
                    {
                        "message_id": msg_id,
                        "summary": msg,
                        "full": full,
                        "analysis": analysis,
                        "event_type": event_type,
                        "processed_at": processed_at,
                    }
                )
                created = False
                if isinstance(callback_result, dict):
                    created = bool(callback_result.get("success"))
                else:
                    created = bool(callback_result)

                if created:
                    cycle["events_created"] += 1
                    cycle_result["event_recorded"] = True
                    store[msg_id]["event_recorded"] = True
                    save_store()
            except Exception as error:
                cycle["errors"].append(f"Event callback failed for {msg_id}: {error}")
                log(f"  Event callback failed: {error}")

        if suspicious:
            sender_email = analysis.get("sender")
            if sender_email:
                suspicious_senders[sender_email] = {
                    "last_flagged": int(time.time()),
                    "category": category,
                    "score": analysis["final_score"],
                }
                if sender_email in sender_db:
                    sender_db[sender_email]["suspicious_count"] = sender_db[sender_email].get("suspicious_count", 0) + 1
                    save_sender_db()
                save_suspicious_senders()

            if REPLACE_SUSPICIOUS_EMAILS:
                try:
                    warned_msg, from_email, to_addresses = build_warned_email(msg, full, analysis)
                except ValueError as error:
                    cycle["errors"].append(f"Cannot build warned email for {msg_id}: {error}")
                    log(f"  Cannot build warned email: {error}")
                    cycle["results"].append(cycle_result)
                    continue

                try:
                    with smtplib.SMTP(_smtp_host_without_port(SMTP_HOST), SMTP_PORT) as server:
                        server.send_message(warned_msg, from_addr=from_email, to_addrs=to_addresses)
                    log("  Resent with warning banner")
                except Exception as error:
                    cycle["errors"].append(f"Resend failed for {msg_id}: {error}")
                    log(f"  Resend failed: {error}")
                    cycle["results"].append(cycle_result)
                    continue

                # Delete only after resend succeeds; avoids losing messages when SMTP fails.
                try:
                    delete_message(msg_id)
                    log("  Deleted original")
                except requests.RequestException as error:
                    cycle["errors"].append(f"Delete failed for {msg_id}: {error}")
                    log(f"  Delete failed: {error}")
            else:
                try:
                    tag_message(msg_id, ANALYSED_TAG)
                    tag_message(msg_id, category)
                    log(f"  Tagged suspicious email: {ANALYSED_TAG}, {category}")
                except requests.RequestException as error:
                    cycle["errors"].append(f"Tagging failed for {msg_id}: {error}")
                    log(f"  Tagging failed: {error}")

                try:
                    set_unread(msg_id)
                    log("  Preserved unread")
                except requests.RequestException as error:
                    cycle["errors"].append(f"Unread reset failed for {msg_id}: {error}")
                    log(f"  Unread reset failed: {error}")
        else:
            try:
                tag_message(msg_id, ANALYSED_TAG)
                tag_message(msg_id, LOW_RISK_TAG)
                log(f"  Tagged: {ANALYSED_TAG}, {LOW_RISK_TAG}")
            except requests.RequestException as error:
                cycle["errors"].append(f"Tagging failed for {msg_id}: {error}")
                log(f"  Tagging failed: {error}")

            try:
                set_unread(msg_id)
                log("  Preserved unread")
            except requests.RequestException as error:
                cycle["errors"].append(f"Unread reset failed for {msg_id}: {error}")
                log(f"  Unread reset failed: {error}")

        cycle["results"].append(cycle_result)

    return cycle


def run_forever(event_callback=None, poll_seconds=POLL_SECONDS, logger=None, stop_event=None):
    while True:
        process_messages_once(event_callback=event_callback, logger=logger)
        if stop_event is not None:
            if stop_event.wait(poll_seconds):
                return
        else:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    run_forever()
