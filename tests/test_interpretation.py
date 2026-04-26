"""
Tests for Module 3: Interpretation Engine
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.interpretation.interpreter import InterpretationEngine


class TestInterpretationEngine:
    """Test suite for the InterpretationEngine class."""

    def setup_method(self):
        self.engine = InterpretationEngine()

    def test_brute_force_interpretation(self):
        """Test plain-English explanation for brute force attempts."""
        rule = {"id": "RULE-001", "name": "Brute Force Login Attempt", "severity": "High"}
        log = {"ip_address": "192.168.1.10", "user": "admin",
               "timestamp": "2026-03-10 10:01", "event_type": "login_failed",
               "details": "Invalid password"}

        result = self.engine.interpret(rule, log)

        assert "password" in result["explanation"].lower()
        assert result["recommendation"] is not None
        assert "192.168.1.10" in result["recommendation"]

    def test_phishing_interpretation(self):
        """Test plain-English explanation for phishing emails."""
        rule = {"id": "RULE-002", "name": "Phishing Email Detected", "severity": "Medium"}
        log = {"ip_address": "suspicious.ru", "user": "user1",
               "timestamp": "2026-03-10 10:05", "event_type": "email_received",
               "details": "Possible phishing email"}

        result = self.engine.interpret(rule, log)

        assert "phishing" in result["explanation"].lower()
        assert "click" in result["recommendation"].lower()

    def test_malware_interpretation(self):
        """Test plain-English explanation for malware detection."""
        rule = {"id": "RULE-004", "name": "Malware Detected on System", "severity": "High"}
        log = {"ip_address": "local", "user": "user2",
               "timestamp": "2026-03-10 10:10", "event_type": "malware_detected",
               "details": "Trojan detected"}

        result = self.engine.interpret(rule, log)

        assert "malware" in result["explanation"].lower() or "malicious" in result["explanation"].lower()
        assert "scan" in result["recommendation"].lower()

    def test_unknown_rule_uses_default(self):
        """Test that unknown rules get a default explanation."""
        rule = {"id": "UNKNOWN", "name": "Some New Rule", "severity": "Low"}
        log = {"ip_address": "1.2.3.4", "user": "test",
               "timestamp": "2026-03-10 10:00", "event_type": "test",
               "details": "Test event"}

        result = self.engine.interpret(rule, log)

        assert result["explanation"] is not None
        assert len(result["explanation"]) > 10

    def test_severity_summary(self):
        """Test severity level summaries."""
        high = self.engine.get_severity_summary("High")
        medium = self.engine.get_severity_summary("Medium")
        low = self.engine.get_severity_summary("Low")

        assert "immediate" in high.lower()
        assert "investigate" in medium.lower() or "moderate" in medium.lower()
        assert "low" in low.lower() or "awareness" in low.lower()

    def test_placeholder_replacement(self):
        """Test that placeholders in templates are replaced with actual data."""
        rule = {"id": "RULE-001", "name": "Brute Force Login Attempt", "severity": "High"}
        log = {"ip_address": "10.0.0.99", "user": "testuser",
               "timestamp": "2026-03-10 10:01", "event_type": "login_failed",
               "details": "Failed attempt"}

        result = self.engine.interpret(rule, log)

        assert "10.0.0.99" in result["recommendation"]
