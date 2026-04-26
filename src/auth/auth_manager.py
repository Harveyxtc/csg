"""
Module 5: Authentication and Scheduler
Handles user authentication with secure password hashing,
login/logout, and scheduled scan management.
"""

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from src.database import get_db_connection, add_audit_entry
from src.auth.models import User


class User(UserMixin):
    """Flask-Login compatible user model."""
    def __init__(self, id, username, role="admin"):
        self.id = id
        self.username = username
        self.role = role


class AuthManager:
    """Manages user authentication and account operations."""
    @staticmethod
    def create_user(username: str, password: str, role: str = "admin"):
        """Create a new user with securely hashed password."""
        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        conn = get_db_connection()

        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )
            conn.commit()
            add_audit_entry(
                action="user_created",
                performed_by="system",
                details=f"Created user: {username} with role: {role}"
            )
            return {"success": True, "message": f"User '{username}' created successfully."}
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                return {"success": False, "message": f"Username '{username}' already exists."}
            return {"success": False, "message": str(e)}
        finally:
            conn.close()

    @staticmethod
    def authenticate(username: str, password: str):
        """Verify username and password. Returns User on success, None on failure."""
        conn = get_db_connection()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,),
        ).fetchone()
        conn.close()
        
        if row and check_password_hash(row["password_hash"], password):
            add_audit_entry(
                action="login_success",
                performed_by=username,
                details="User logged in successfully"
            )
            return User(id=row["id"], username=row["username"], role=row["role"])

        add_audit_entry(
            action="login_failed",
            performed_by=username or "unknown",
            details=f"Failed login attempt for user: {username}"
        )
        return None

    @staticmethod
    def get_user_by_id(user_id):
        """Retrieve a user by ID (for Flask-Login session loading)."""
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        if row:
            return User(id=row["id"], username=row["username"], role=row["role"])
        return None

    @staticmethod
    def create_default_admin():
        """Create a default admin account if no users exist."""
        conn = get_db_connection()
        count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        conn.close()

        if count == 0:
            return AuthManager.create_user("admin", "admin123", role="admin")
        return {"success": False, "message": "Users already exist."}
