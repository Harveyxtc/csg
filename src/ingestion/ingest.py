"""
Module 1: Data Ingestion
Accepts local logs, simulated events, and email-derived metadata.
Validates structure and rejects malformed entries.
"""

import csv
import os
from datetime import datetime
from src.database import get_db_connection, add_audit_entry


# Required columns for a valid log entry
REQUIRED_FIELDS = ["timestamp", "event_type", "user", "ip_address", "details"]


class LogIngestor:
    """Handles ingestion of log files into the system database."""

    def __init__(self):
        self.valid_count = 0
        self.rejected_count = 0
        self.errors = []

    def validate_entry(self, row):
        """
        Validate a single log entry.
        Returns (is_valid, error_message).
        """
        # Check all required fields are present and non-empty
        for field in REQUIRED_FIELDS:
            if field not in row or not row[field].strip():
                return False, f"Missing or empty field: {field}"

        # Validate timestamp format
        try:
            datetime.strptime(row["timestamp"].strip(), "%Y-%m-%d %H:%M")
        except ValueError:
            try:
                datetime.strptime(row["timestamp"].strip(), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return False, f"Invalid timestamp format: {row['timestamp']}"

        # Validate event_type is a recognized type
        valid_types = [
            "login_failed", "login_success", "email_received", "email_sent",
            "file_change", "file_access", "malware_detected", "network_scan",
            "privilege_escalation", "config_change", "brute_force",
            "phishing_attempt", "suspicious_download", "unauthorized_access"
        ]
        if row["event_type"].strip() not in valid_types:
            return False, f"Unrecognized event type: {row['event_type']}"

        return True, ""

    def ingest_csv(self, filepath, source_label=None):
        """
        Ingest a CSV log file into the database.
        Returns a summary dict with counts and errors.
        """
        if not os.path.exists(filepath):
            return {
                "success": False,
                "error": f"File not found: {filepath}",
                "valid": 0,
                "rejected": 0
            }

        source = source_label or os.path.basename(filepath)
        self.valid_count = 0
        self.rejected_count = 0
        self.errors = []

        conn = get_db_connection()

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)

                # Verify CSV has required headers
                if reader.fieldnames is None:
                    return {
                        "success": False,
                        "error": "CSV file is empty or has no headers",
                        "valid": 0,
                        "rejected": 0
                    }

                missing_headers = [
                    h for h in REQUIRED_FIELDS if h not in reader.fieldnames
                ]
                if missing_headers:
                    return {
                        "success": False,
                        "error": f"Missing required columns: {', '.join(missing_headers)}",
                        "valid": 0,
                        "rejected": 0
                    }

                for i, row in enumerate(reader, start=2):  # start=2 (header is row 1)
                    is_valid, error_msg = self.validate_entry(row)

                    if is_valid:
                        conn.execute(
                            """INSERT INTO ingested_logs
                               (timestamp, event_type, user, ip_address, details, source_file)
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (
                                row["timestamp"].strip(),
                                row["event_type"].strip(),
                                row["user"].strip(),
                                row["ip_address"].strip(),
                                row["details"].strip(),
                                source,
                            )
                        )
                        self.valid_count += 1
                    else:
                        self.rejected_count += 1
                        self.errors.append(f"Row {i}: {error_msg}")

            conn.commit()

            # Log the ingestion in the audit trail
            add_audit_entry(
                action="log_ingestion",
                performed_by="system",
                details=f"Ingested {source}: {self.valid_count} valid, {self.rejected_count} rejected"
            )

        except Exception as e:
            conn.rollback()
            return {
                "success": False,
                "error": str(e),
                "valid": self.valid_count,
                "rejected": self.rejected_count
            }
        finally:
            conn.close()

        return {
            "success": True,
            "valid": self.valid_count,
            "rejected": self.rejected_count,
            "errors": self.errors,
            "source": source
        }

    def ingest_single_event(self, timestamp, event_type, user, ip_address, details,
                            source="manual_entry"):
        """Ingest a single event directly (e.g., from simulated events or API)."""
        row = {
            "timestamp": timestamp,
            "event_type": event_type,
            "user": user,
            "ip_address": ip_address,
            "details": details,
        }

        is_valid, error_msg = self.validate_entry(row)
        if not is_valid:
            return {"success": False, "error": error_msg}

        conn = get_db_connection()
        conn.execute(
            """INSERT INTO ingested_logs
               (timestamp, event_type, user, ip_address, details, source_file)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (timestamp, event_type, user, ip_address, details, source)
        )
        conn.commit()
        conn.close()

        return {"success": True}

    def get_unprocessed_logs(self):
        """Retrieve all logs that have not yet been processed by the detection engine."""
        conn = get_db_connection()
        logs = conn.execute(
            "SELECT * FROM ingested_logs WHERE processed = 0 ORDER BY timestamp"
        ).fetchall()
        conn.close()
        return [dict(log) for log in logs]

    def mark_as_processed(self, log_ids):
        """Mark a list of log IDs as processed."""
        if not log_ids:
            return
        conn = get_db_connection()
        placeholders = ",".join("?" * len(log_ids))
        conn.execute(
            f"UPDATE ingested_logs SET processed = 1 WHERE id IN ({placeholders})",
            log_ids
        )
        conn.commit()
        conn.close()
