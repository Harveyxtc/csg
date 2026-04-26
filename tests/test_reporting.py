"""
Tests for Module 4: Report Generator
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database import init_db, add_threat_event
from src.config import Config
from src.reporting.report_generator import ReportGenerator


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Use a temporary database for each test."""
    Config.DATABASE_PATH = str(tmp_path / "test.db")
    Config.REPORTS_DIR = str(tmp_path / "reports")
    Config.init_dirs()
    init_db()
    yield


def _add_sample_events():
    """Add sample threat events for testing."""
    add_threat_event(
        timestamp="2026-03-10 10:01",
        event_type="Brute Force Login Attempt",
        source_module="System Monitor",
        severity="High",
        user_affected="admin",
        ip_address="192.168.1.10",
        details="Multiple failed login attempts",
        explanation="Someone tried to log in multiple times with incorrect passwords.",
        recommendation="Change the password immediately."
    )
    add_threat_event(
        timestamp="2026-03-10 10:05",
        event_type="Phishing Email Detected",
        source_module="Email Analysis",
        severity="Medium",
        user_affected="user1",
        ip_address="suspicious.ru",
        details="Suspicious email received",
        explanation="An email was received from a suspicious domain.",
        recommendation="Do not click any links in this email."
    )


class TestReportGenerator:
    """Test suite for the ReportGenerator class."""

    def test_generate_pdf_report(self):
        """Test PDF report generation."""
        _add_sample_events()
        generator = ReportGenerator()
        result = generator.generate_pdf_report(report_type="on_demand", generated_by="test")

        assert result["success"] is True
        assert result["filename"].endswith(".pdf")
        assert os.path.exists(result["filepath"])

    def test_generate_weekly_pdf(self):
        """Test weekly PDF report generation."""
        _add_sample_events()
        generator = ReportGenerator()
        result = generator.generate_pdf_report(report_type="weekly", generated_by="test")

        assert result["success"] is True
        assert "weekly" in result["filename"]

    def test_generate_csv_export(self):
        """Test CSV export generation."""
        _add_sample_events()
        generator = ReportGenerator()
        result = generator.generate_csv_export(generated_by="test")

        assert result["success"] is True
        assert result["filename"].endswith(".csv")
        assert os.path.exists(result["filepath"])

    def test_empty_report(self):
        """Test report generation with no events."""
        generator = ReportGenerator()
        result = generator.generate_pdf_report(report_type="on_demand", generated_by="test")
        assert result["success"] is True

    def test_report_history(self):
        """Test that reports are recorded in history."""
        _add_sample_events()
        generator = ReportGenerator()
        generator.generate_pdf_report(generated_by="test")
        generator.generate_csv_export(generated_by="test")

        history = generator.get_report_history()
        assert len(history) == 2
