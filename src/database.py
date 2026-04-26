"""
Database models and initialization for Project Proactive Defense.
Uses SQLite for local storage of threat events, configurations, and logs.
"""

import sqlite3
import os
from datetime import datetime
from src.config import Config


def get_db_connection():
    """Create and return a database connection."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table for authentication
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Threat events table (central store for all detections)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_module TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High')),
            user_affected TEXT,
            ip_address TEXT,
            details TEXT,
            explanation TEXT,
            recommendation TEXT,
            status TEXT DEFAULT 'Open' CHECK(status IN ('Open', 'Acknowledged', 'Resolved')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Ingested logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ingested_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            user TEXT,
            ip_address TEXT,
            details TEXT,
            source_file TEXT,
            ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed INTEGER DEFAULT 0
        )
    """)

    # Audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            performed_by TEXT,
            details TEXT
        )
    """)

    # System configuration table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Reports table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            generated_by TEXT,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            parameters TEXT
        )
    """)

    # Insert default configuration if not exists
    defaults = {
        "malware_detection_enabled": "true",
        "email_analysis_enabled": "true",
        "scan_interval": "daily",
        "alert_threshold": "Medium",
    }
    for key, value in defaults.items():
        cursor.execute(
            "INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)",
            (key, value)
        )

    conn.commit()
    conn.close()


def add_threat_event(timestamp, event_type, source_module, severity,
                     user_affected, ip_address, details, explanation,
                     recommendation):
    """Insert a new threat event into the database."""
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO threat_events
           (timestamp, event_type, source_module, severity, user_affected,
            ip_address, details, explanation, recommendation)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, event_type, source_module, severity, user_affected,
         ip_address, details, explanation, recommendation)
    )
    conn.commit()
    conn.close()


def get_threat_events(limit=100, severity=None, source_module=None, status=None):
    """Retrieve threat events with optional filters."""
    conn = get_db_connection()
    query = "SELECT * FROM threat_events WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if source_module:
        query += " AND source_module = ?"
        params.append(source_module)
    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    events = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(e) for e in events]


def get_threat_event(event_id):
    """Retrieve a single threat event by id."""
    conn = get_db_connection()
    event = conn.execute(
        "SELECT * FROM threat_events WHERE id = ?",
        (event_id,)
    ).fetchone()
    conn.close()
    return dict(event) if event else None


def update_event_status(event_id, new_status):
    """Update the status of a threat event."""
    conn = get_db_connection()
    conn.execute(
        "UPDATE threat_events SET status = ? WHERE id = ?",
        (new_status, event_id)
    )
    conn.commit()
    conn.close()


def add_audit_entry(action, performed_by, details=""):
    """Add an entry to the audit log."""
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO audit_log (action, performed_by, details) VALUES (?, ?, ?)",
        (action, performed_by, details)
    )
    conn.commit()
    conn.close()


def get_audit_log(limit=50):
    """Retrieve recent audit log entries."""
    conn = get_db_connection()
    entries = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(e) for e in entries]


def get_system_config():
    """Retrieve all system configuration as a dictionary."""
    conn = get_db_connection()
    rows = conn.execute("SELECT key, value FROM system_config").fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}


def update_system_config(key, value):
    """Update a system configuration value."""
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO system_config (key, value, updated_at)
           VALUES (?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP""",
        (key, value, value)
    )
    conn.commit()
    conn.close()


def get_dashboard_stats():
    """Get summary statistics for the dashboard."""
    conn = get_db_connection()

    total = conn.execute("SELECT COUNT(*) as c FROM threat_events").fetchone()["c"]
    high = conn.execute(
        "SELECT COUNT(*) as c FROM threat_events WHERE severity = 'High'"
    ).fetchone()["c"]
    medium = conn.execute(
        "SELECT COUNT(*) as c FROM threat_events WHERE severity = 'Medium'"
    ).fetchone()["c"]
    low = conn.execute(
        "SELECT COUNT(*) as c FROM threat_events WHERE severity = 'Low'"
    ).fetchone()["c"]
    open_events = conn.execute(
        "SELECT COUNT(*) as c FROM threat_events WHERE status = 'Open'"
    ).fetchone()["c"]
    acknowledged = conn.execute(
        "SELECT COUNT(*) as c FROM threat_events WHERE status = 'Acknowledged'"
    ).fetchone()["c"]
    resolved = conn.execute(
        "SELECT COUNT(*) as c FROM threat_events WHERE status = 'Resolved'"
    ).fetchone()["c"]

    # Events by source module
    by_module = conn.execute(
        """SELECT source_module, COUNT(*) as count
           FROM threat_events GROUP BY source_module"""
    ).fetchall()

    # Events by day (last 7 days)
    by_day = conn.execute(
        """SELECT DATE(timestamp) as day, COUNT(*) as count
           FROM threat_events
           GROUP BY DATE(timestamp)
           ORDER BY day DESC LIMIT 7"""
    ).fetchall()

    # Severity breakdown per module (for stacked bar chart)
    severity_by_module = conn.execute(
        """SELECT source_module, severity, COUNT(*) as count
           FROM threat_events
           GROUP BY source_module, severity
           ORDER BY source_module"""
    ).fetchall()

    # Top threat types (for horizontal bar chart)
    top_threats = conn.execute(
        """SELECT event_type, COUNT(*) as count
           FROM threat_events
           GROUP BY event_type
           ORDER BY count DESC LIMIT 10"""
    ).fetchall()

    # Events by hour of day (for activity heatmap bar)
    events_by_hour = conn.execute(
        """SELECT CAST(SUBSTR(timestamp, 12, 2) AS INTEGER) as hour, COUNT(*) as count
           FROM threat_events
           WHERE timestamp LIKE '%-%-% %:%'
           GROUP BY hour
           ORDER BY hour"""
    ).fetchall()

    # Severity trend by day (for stacked area chart)
    severity_by_day = conn.execute(
        """SELECT DATE(timestamp) as day, severity, COUNT(*) as count
           FROM threat_events
           GROUP BY DATE(timestamp), severity
           ORDER BY day DESC LIMIT 21"""
    ).fetchall()

    conn.close()

    return {
        "total_events": total,
        "high_severity": high,
        "medium_severity": medium,
        "low_severity": low,
        "open_events": open_events,
        "acknowledged_events": acknowledged,
        "resolved_events": resolved,
        "events_by_module": [dict(r) for r in by_module],
        "events_by_day": [dict(r) for r in by_day],
        "severity_by_module": [dict(r) for r in severity_by_module],
        "top_threats": [dict(r) for r in top_threats],
        "events_by_hour": [dict(r) for r in events_by_hour],
        "severity_by_day": [dict(r) for r in severity_by_day],
    }
