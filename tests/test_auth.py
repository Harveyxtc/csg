"""
Tests for Module 5: Authentication
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database import init_db
from src.config import Config
from src.auth.auth_manager import AuthManager


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Use a temporary database for each test."""
    Config.DATABASE_PATH = str(tmp_path / "test.db")
    Config.REPORTS_DIR = str(tmp_path / "reports")
    Config.init_dirs()
    init_db()
    yield


class TestAuthManager:
    """Test suite for the AuthManager class."""

    def test_create_user(self):
        """Test user creation with hashed password."""
        result = AuthManager.create_user("testuser", "password123")
        assert result["success"] is True

    def test_create_duplicate_user(self):
        """Test that duplicate usernames are rejected."""
        AuthManager.create_user("testuser", "password123")
        result = AuthManager.create_user("testuser", "different123")
        assert result["success"] is False
        assert "already exists" in result["message"]

    def test_authenticate_valid(self):
        """Test successful authentication."""
        AuthManager.create_user("testuser", "password123")
        user = AuthManager.authenticate("testuser", "password123")
        assert user is not None
        assert user.username == "testuser"

    def test_authenticate_invalid_password(self):
        """Test authentication with wrong password."""
        AuthManager.create_user("testuser", "password123")
        user = AuthManager.authenticate("testuser", "wrongpassword")
        assert user is None

    def test_authenticate_nonexistent_user(self):
        """Test authentication with non-existent username."""
        user = AuthManager.authenticate("nouser", "password123")
        assert user is None

    def test_get_user_by_id(self):
        """Test retrieving user by ID."""
        AuthManager.create_user("testuser", "password123")
        user = AuthManager.get_user_by_id(1)
        assert user is not None
        assert user.username == "testuser"

    def test_password_is_hashed(self):
        """Test that passwords are stored as hashes, not plaintext."""
        from src.database import get_db_connection
        AuthManager.create_user("testuser", "password123")
        conn = get_db_connection()
        row = conn.execute("SELECT password_hash FROM users WHERE username = 'testuser'").fetchone()
        conn.close()
        assert row["password_hash"] != "password123"
        assert "pbkdf2" in row["password_hash"]

    def test_create_default_admin(self):
        """Test default admin creation."""
        result = AuthManager.create_default_admin()
        assert result["success"] is True
        user = AuthManager.authenticate("admin", "admin123")
        assert user is not None
