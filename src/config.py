"""
Configuration settings for Project Proactive Defense.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "proactive-defense-secret-key-change-in-production")
    DATABASE_PATH = os.path.join(PROJECT_DIR, "data", "proactive_defense.db")
    REPORTS_DIR = os.path.join(PROJECT_DIR, "reports")
    SAMPLE_LOGS_DIR = os.path.join(PROJECT_DIR, "data", "sample_logs")
    LOG_UPLOAD_DIR = os.path.join(PROJECT_DIR, "data", "uploads")

    # Scheduler settings
    SCHEDULER_API_ENABLED = False
    SCAN_INTERVAL_HOURS = 24  # Default daily scan

    # Session settings
    SESSION_PROTECTION = "strong"

    # Ensure directories exist
    @staticmethod
    def init_dirs():
        for d in [Config.REPORTS_DIR, Config.SAMPLE_LOGS_DIR, Config.LOG_UPLOAD_DIR]:
            os.makedirs(d, exist_ok=True)
