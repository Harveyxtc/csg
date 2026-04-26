"""
Module 2: Detection Engine
Rule-based threat detection system that analyses ingested logs.
Assigns risk levels (Low, Medium, High) based on configurable detection rules.
Rules are data-driven and can be extended without major code changes.
"""

from datetime import datetime, timedelta
from src.database import get_db_connection, add_threat_event, add_audit_entry
from src.ingestion.ingest import LogIngestor
from src.interpretation.interpreter import InterpretationEngine


# ──────────────────────────────────────────────────────────────
# Detection Rules (data-driven – add new rules here to extend)
# ──────────────────────────────────────────────────────────────
DETECTION_RULES = [
    {
        "id": "RULE-001",
        "name": "Brute Force Login Attempt",
        "description": "Multiple failed login attempts from the same IP address",
        "event_type": "login_failed",
        "severity": "High",
        "condition": "count_based",
        "threshold": 3,
        "window_minutes": 10,
        "group_by": "ip_address",
    },
    {
        "id": "RULE-002",
        "name": "Phishing Email Detected",
        "description": "Email received from a suspicious or known malicious domain",
        "event_type": "email_received",
        "severity": "Medium",
        "condition": "keyword_match",
        "keywords": [
            "phishing", "suspicious", "malicious", ".ru", ".cn",
            "urgent", "verify your account", "click here immediately",
        ],
        "match_field": "details",
    },
    {
        "id": "RULE-003",
        "name": "Suspicious File Modification",
        "description": "Unusual file rename or modification activity detected",
        "event_type": "file_change",
        "severity": "Medium",
        "condition": "keyword_match",
        "keywords": [
            "rename", "encrypt", "ransomware", "batch rename",
            "multiple file", "mass modification",
        ],
        "match_field": "details",
    },
    {
        "id": "RULE-004",
        "name": "Malware Detected on System",
        "description": "A known malware signature was identified in a scanned file",
        "event_type": "malware_detected",
        "severity": "High",
        "condition": "keyword_match",
        "keywords": ["signature="],
        "match_field": "details",
        "fallback": True,
    },
    {
        "id": "RULE-011",
        "name": "Coin Miner Malware Signature Detected",
        "description": "Coin miner malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "Medium",
        "condition": "keyword_match",
        "keywords": ["Win.CoinMiner.xYZ"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-012",
        "name": "Ransomware Malware Signature Detected",
        "description": "Ransomware malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "High",
        "condition": "keyword_match",
        "keywords": ["Win.Ransomware.aQ1"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-013",
        "name": "Trojan Malware Signature Detected",
        "description": "Trojan malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "High",
        "condition": "keyword_match",
        "keywords": ["Win.Trojan.z9K"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-014",
        "name": "Stealer Malware Signature Detected",
        "description": "Credential stealer malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "High",
        "condition": "keyword_match",
        "keywords": ["Win.Stealer.pL2"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-015",
        "name": "Backdoor Malware Signature Detected",
        "description": "Backdoor malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "High",
        "condition": "keyword_match",
        "keywords": ["Win.Backdoor.mX7"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-016",
        "name": "Keylogger Malware Signature Detected",
        "description": "Keylogger malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "High",
        "condition": "keyword_match",
        "keywords": ["Win.Keylogger.tR4"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-017",
        "name": "Adware Malware Signature Detected",
        "description": "Adware malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "Medium",
        "condition": "keyword_match",
        "keywords": ["Win.Adware.bN8"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-018",
        "name": "Spammer Malware Signature Detected",
        "description": "Spammer malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "Medium",
        "condition": "keyword_match",
        "keywords": ["Win.Spammer.kJ3"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-019",
        "name": "Worm Malware Signature Detected",
        "description": "Worm malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "High",
        "condition": "keyword_match",
        "keywords": ["Win.Worm.vC6"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-020",
        "name": "Rootkit Malware Signature Detected",
        "description": "Rootkit malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "High",
        "condition": "keyword_match",
        "keywords": ["Win.Rootkit.dF5"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-021",
        "name": "Botnet Malware Signature Detected",
        "description": "Botnet malware signature matched in a scanned file",
        "event_type": "malware_detected",
        "severity": "High",
        "condition": "keyword_match",
        "keywords": ["Win.Botnet.sH9"],
        "match_field": "details",
        "signature_specific": True,
    },
    {
        "id": "RULE-005",
        "name": "Privilege Escalation Attempt",
        "description": "A user attempted to escalate their privileges without authorisation",
        "event_type": "privilege_escalation",
        "severity": "High",
        "condition": "always",
    },
    {
        "id": "RULE-006",
        "name": "Suspicious Download",
        "description": "A potentially dangerous file was downloaded from the internet",
        "event_type": "suspicious_download",
        "severity": "Medium",
        "condition": "keyword_match",
        "keywords": [".exe", ".bat", ".ps1", ".vbs", ".scr", "macro"],
        "match_field": "details",
    },
    {
        "id": "RULE-007",
        "name": "Unauthorized Access Attempt",
        "description": "Access to a restricted resource was attempted without proper credentials",
        "event_type": "unauthorized_access",
        "severity": "High",
        "condition": "always",
    },
    {
        "id": "RULE-008",
        "name": "Network Port Scan Detected",
        "description": "Scanning activity detected from an external IP address",
        "event_type": "network_scan",
        "severity": "Low",
        "condition": "always",
    },
    {
        "id": "RULE-009",
        "name": "Configuration Change",
        "description": "A system configuration was modified",
        "event_type": "config_change",
        "severity": "Low",
        "condition": "always",
    },
    {
        "id": "RULE-010",
        "name": "Phishing Attempt via Email Link",
        "description": "An email containing a link to a known phishing site was received",
        "event_type": "phishing_attempt",
        "severity": "High",
        "condition": "always",
    },
]


class DetectionEngine:
    """
    Processes unprocessed ingested logs through detection rules
    and generates threat events with risk levels.
    """

    def __init__(self):
        self.ingestor = LogIngestor()
        self.interpreter = InterpretationEngine()
        self.detections = []

    def run_detection(self):
        """
        Main detection loop:
        1. Fetch unprocessed logs
        2. Apply each rule
        3. Generate threat events with explanations
        4. Mark logs as processed
        """
        unprocessed = self.ingestor.get_unprocessed_logs()
        if not unprocessed:
            return {"processed": 0, "detections": 0, "message": "No new logs to process."}

        self.detections = []
        processed_ids = []

        for log in unprocessed:
            processed_ids.append(log["id"])
            matched_rules = self._evaluate_rules(log, unprocessed)

            for rule in matched_rules:
                # Generate plain-English explanation and recommendation
                interpretation = self.interpreter.interpret(rule, log)

                add_threat_event(
                    timestamp=log["timestamp"],
                    event_type=rule["name"],
                    source_module=self._get_source_module(rule),
                    severity=rule["severity"],
                    user_affected=log.get("user", "Unknown"),
                    ip_address=log.get("ip_address", "N/A"),
                    details=log.get("details", ""),
                    explanation=interpretation["explanation"],
                    recommendation=interpretation["recommendation"],
                )
                self.detections.append({
                    "rule": rule["name"],
                    "severity": rule["severity"],
                    "log_timestamp": log["timestamp"],
                    "user": log.get("user", "Unknown"),
                })

        # Mark all processed
        self.ingestor.mark_as_processed(processed_ids)

        add_audit_entry(
            action="detection_scan",
            performed_by="system",
            details=f"Processed {len(processed_ids)} logs, generated {len(self.detections)} alerts"
        )

        return {
            "processed": len(processed_ids),
            "detections": len(self.detections),
            "alerts": self.detections,
        }

    def _evaluate_rules(self, log, all_logs):
        """Evaluate all detection rules against a single log entry."""
        matched = []

        for rule in DETECTION_RULES:
            if rule["event_type"] != log["event_type"]:
                continue

            condition = rule["condition"]

            if condition == "always":
                matched.append(rule)

            elif condition == "keyword_match":
                field_value = log.get(rule.get("match_field", "details"), "").lower()
                if any(kw.lower() in field_value for kw in rule["keywords"]):
                    matched.append(rule)

            elif condition == "count_based":
                count = self._count_in_window(
                    all_logs, log,
                    event_type=rule["event_type"],
                    group_field=rule["group_by"],
                    window_minutes=rule["window_minutes"],
                )
                if count >= rule["threshold"]:
                    matched.append(rule)

        # If a malware signature-specific rule matched, suppress the generic fallback
        # so each malware log creates a single, most relevant event.
        if log.get("event_type") == "malware_detected":
            has_signature_specific = any(r.get("signature_specific") for r in matched)
            if has_signature_specific:
                matched = [r for r in matched if not r.get("fallback")]
            elif not any(r.get("fallback") for r in matched):
                matched.extend(
                    r for r in DETECTION_RULES
                    if r["event_type"] == "malware_detected" and r.get("fallback")
                )

        return matched

    def _count_in_window(self, all_logs, current_log, event_type, group_field, window_minutes):
        """Count events of the same type and group within a time window."""
        try:
            try:
                current_time = datetime.strptime(current_log["timestamp"], "%Y-%m-%d %H:%M")
            except ValueError:
                current_time = datetime.strptime(current_log["timestamp"], "%Y-%m-%d %H:%M:%S")
        except (ValueError, KeyError):
            return 0

        window_start = current_time - timedelta(minutes=window_minutes)
        group_value = current_log.get(group_field, "")
        count = 0

        for log in all_logs:
            if log["event_type"] != event_type:
                continue
            if log.get(group_field, "") != group_value:
                continue
            try:
                try:
                    log_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M")
                except ValueError:
                    log_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
                if window_start <= log_time <= current_time:
                    count += 1
            except (ValueError, KeyError):
                continue

        return count

    def _get_source_module(self, rule):
        """Map a rule to its source module for dashboard display."""
        email_types = ["email_received", "phishing_attempt", "email_sent"]
        malware_types = ["malware_detected", "file_change", "suspicious_download", "file_access"]

        if rule["event_type"] in email_types:
            return "Email Analysis"
        elif rule["event_type"] in malware_types:
            return "Malware Detection"
        else:
            return "System Monitor"

    def get_rules(self):
        """Return all detection rules for display or configuration."""
        return DETECTION_RULES
