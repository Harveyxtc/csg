"""
Tests for Module 2: Detection Engine
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database import init_db, get_threat_events
from src.config import Config
from src.ingestion.ingest import LogIngestor
from src.detection.detector import DetectionEngine


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Use a temporary database for each test."""
    Config.DATABASE_PATH = str(tmp_path / "test.db")
    Config.REPORTS_DIR = str(tmp_path / "reports")
    Config.init_dirs()
    init_db()
    yield


class TestDetectionEngine:
    """Test suite for the DetectionEngine class."""

    def _ingest_and_detect(self, tmp_path, csv_content):
        """Helper to ingest CSV and run detection."""
        csv_path = tmp_path / "test.csv"
        csv_path.write_text(csv_content)
        ingestor = LogIngestor()
        ingestor.ingest_csv(str(csv_path))
        engine = DetectionEngine()
        return engine.run_detection()

    def test_brute_force_detection(self, tmp_path):
        """Test that multiple failed logins trigger brute force rule."""
        csv = (
            "timestamp,event_type,user,ip_address,details\n"
            "2026-03-10 10:01,login_failed,admin,192.168.1.10,Invalid password\n"
            "2026-03-10 10:02,login_failed,admin,192.168.1.10,Invalid password\n"
            "2026-03-10 10:03,login_failed,admin,192.168.1.10,Invalid password\n"
        )
        result = self._ingest_and_detect(tmp_path, csv)
        assert result["detections"] >= 1

        events = get_threat_events()
        assert any("Brute Force" in e["event_type"] for e in events)

    def test_phishing_detection(self, tmp_path):
        """Test that suspicious emails trigger phishing rule."""
        csv = (
            "timestamp,event_type,user,ip_address,details\n"
            "2026-03-10 10:05,email_received,user1,suspicious-domain.ru,Possible phishing email\n"
        )
        result = self._ingest_and_detect(tmp_path, csv)
        assert result["detections"] >= 1

        events = get_threat_events()
        assert any("Phishing" in e["event_type"] for e in events)

    def test_malware_detection(self, tmp_path):
        """Test that malware events are always detected."""
        csv = (
            "timestamp,event_type,user,ip_address,details\n"
            "2026-03-10 10:10,malware_detected,user2,local,Trojan detected\n"
        )
        result = self._ingest_and_detect(tmp_path, csv)
        assert result["detections"] >= 1

        events = get_threat_events()
        assert any("Malware" in e["event_type"] for e in events)
        assert events[0]["severity"] == "High"

    def test_file_change_detection(self, tmp_path):
        """Test that suspicious file changes are detected."""
        csv = (
            "timestamp,event_type,user,ip_address,details\n"
            "2026-03-10 10:10,file_change,system,local,Multiple file rename activity\n"
        )
        result = self._ingest_and_detect(tmp_path, csv)
        assert result["detections"] >= 1

    def test_no_logs_to_process(self):
        """Test detection with no unprocessed logs."""
        engine = DetectionEngine()
        result = engine.run_detection()
        assert result["processed"] == 0
        assert result["detections"] == 0

    def test_events_have_explanations(self, tmp_path):
        """Test that detected events include plain-English explanations."""
        csv = (
            "timestamp,event_type,user,ip_address,details\n"
            "2026-03-10 10:10,malware_detected,user2,local,Trojan detected\n"
        )
        self._ingest_and_detect(tmp_path, csv)
        events = get_threat_events()

        assert len(events) > 0
        assert events[0]["explanation"] is not None
        assert len(events[0]["explanation"]) > 20
        assert events[0]["recommendation"] is not None
        assert len(events[0]["recommendation"]) > 20

    def test_get_rules(self):
        """Test that detection rules can be retrieved."""
        engine = DetectionEngine()
        rules = engine.get_rules()
        assert len(rules) >= 10
        assert all("id" in r and "name" in r and "severity" in r for r in rules)
