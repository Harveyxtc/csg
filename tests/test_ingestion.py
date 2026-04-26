"""
Tests for Module 1: Data Ingestion
"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database import init_db, get_db_connection
from src.config import Config
from src.ingestion.ingest import LogIngestor


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Use a temporary database for each test."""
    Config.DATABASE_PATH = str(tmp_path / "test.db")
    Config.REPORTS_DIR = str(tmp_path / "reports")
    Config.init_dirs()
    init_db()
    yield


class TestLogIngestor:
    """Test suite for the LogIngestor class."""

    def test_ingest_valid_csv(self, tmp_path):
        """Test ingestion of a valid CSV file."""
        csv_content = (
            "timestamp,event_type,user,ip_address,details\n"
            "2026-03-10 10:01,login_failed,admin,192.168.1.10,Invalid password\n"
            "2026-03-10 10:05,email_received,user1,suspicious-domain.ru,Possible phishing email\n"
        )
        csv_path = tmp_path / "valid.csv"
        csv_path.write_text(csv_content)

        ingestor = LogIngestor()
        result = ingestor.ingest_csv(str(csv_path))

        assert result["success"] is True
        assert result["valid"] == 2
        assert result["rejected"] == 0

    def test_reject_malformed_entries(self, tmp_path):
        """Test that malformed entries are rejected."""
        csv_content = (
            "timestamp,event_type,user,ip_address,details\n"
            "2026-03-10 10:01,login_failed,admin,192.168.1.10,Invalid password\n"
            "bad-timestamp,login_failed,admin,192.168.1.10,Invalid password\n"
            "2026-03-10 10:01,unknown_type,admin,192.168.1.10,Test\n"
        )
        csv_path = tmp_path / "malformed.csv"
        csv_path.write_text(csv_content)

        ingestor = LogIngestor()
        result = ingestor.ingest_csv(str(csv_path))

        assert result["success"] is True
        assert result["valid"] == 1
        assert result["rejected"] == 2

    def test_reject_missing_columns(self, tmp_path):
        """Test that CSV with missing columns is rejected."""
        csv_content = "timestamp,event_type\n2026-03-10 10:01,login_failed\n"
        csv_path = tmp_path / "missing_cols.csv"
        csv_path.write_text(csv_content)

        ingestor = LogIngestor()
        result = ingestor.ingest_csv(str(csv_path))

        assert result["success"] is False
        assert "Missing required columns" in result["error"]

    def test_file_not_found(self):
        """Test ingestion of a non-existent file."""
        ingestor = LogIngestor()
        result = ingestor.ingest_csv("/nonexistent/path.csv")

        assert result["success"] is False
        assert "not found" in result["error"]

    def test_ingest_single_event(self):
        """Test single event ingestion."""
        ingestor = LogIngestor()
        result = ingestor.ingest_single_event(
            timestamp="2026-03-10 10:01",
            event_type="login_failed",
            user="admin",
            ip_address="192.168.1.10",
            details="Invalid password"
        )
        assert result["success"] is True

    def test_get_unprocessed_logs(self, tmp_path):
        """Test retrieving unprocessed logs."""
        csv_content = (
            "timestamp,event_type,user,ip_address,details\n"
            "2026-03-10 10:01,login_failed,admin,192.168.1.10,Invalid password\n"
        )
        csv_path = tmp_path / "test.csv"
        csv_path.write_text(csv_content)

        ingestor = LogIngestor()
        ingestor.ingest_csv(str(csv_path))
        unprocessed = ingestor.get_unprocessed_logs()

        assert len(unprocessed) == 1
        assert unprocessed[0]["event_type"] == "login_failed"

    def test_mark_as_processed(self, tmp_path):
        """Test marking logs as processed."""
        csv_content = (
            "timestamp,event_type,user,ip_address,details\n"
            "2026-03-10 10:01,login_failed,admin,192.168.1.10,Invalid password\n"
        )
        csv_path = tmp_path / "test.csv"
        csv_path.write_text(csv_content)

        ingestor = LogIngestor()
        ingestor.ingest_csv(str(csv_path))
        unprocessed = ingestor.get_unprocessed_logs()
        ingestor.mark_as_processed([unprocessed[0]["id"]])

        remaining = ingestor.get_unprocessed_logs()
        assert len(remaining) == 0
