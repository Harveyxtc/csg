"""
Module 5: Authentication and Scheduler
Handles user authentication with secure password hashing,
login/logout, and scheduled scan management.
"""

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from src.database import get_db_connection, add_audit_entry

class User(UserMixin):
    """Flask-Login compatible user model."""
    def __init__(self, id, username, role="analyst"):
        self.id = id
        self.username = username
        self.role = role

class AuthManager:
    """Manages user authentication and account operations."""

    @staticmethod
    def _ensure_role_column():
        """Ensures the 'role' column exists in the users table to prevent 500 errors."""
        conn = get_db_connection()
        try:
            # Check if role column exists
            cursor = conn.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'role' not in columns:
                print("[!] Database Outdated: Adding 'role' column...")
                conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'analyst'")
                conn.commit()
        except Exception as e:
            print(f"[-] Database Fix Failed: {e}")
        finally:
            conn.close()

    @staticmethod
    def create_user(username: str, password: str, role: str = "analyst", creator: str = "system"):
        """Create a new user with securely hashed password and assigned role."""
        AuthManager._ensure_role_column() # Fixes potential 500 errors
        
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
                performed_by=creator,
                details=f"Created user: {username} with role: {role}"
            )
            return {"success": True, "message": f"User '{username}' created successfully as {role}."}
        
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                return {"success": False, "message": f"Username '{username}' already exists."}
            return {"success": False, "message": str(e)}
        finally:
            conn.close()

    @staticmethod
    def authenticate(username: str, password: str):
        """Verify username and password. Returns User object or None."""
        AuthManager._ensure_role_column()
        
        conn = get_db_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,),
            ).fetchone()
            
            if row and check_password_hash(row["password_hash"], password):
                add_audit_entry(
                    action="login_success",
                    performed_by=username,
                    details=f"User logged in successfully with role: {row['role']}"
                )
                return User(id=row["id"], username=row["username"], role=row["role"])
        finally:
            conn.close()

        add_audit_entry(
            action="login_failed",
            performed_by=username or "unknown",
            details=f"Failed login attempt for user: {username}"
        )
        return None

    @staticmethod
    def get_user_by_id(user_id):
        """Retrieve a user by ID for Flask-Login session loading."""
        conn = get_db_connection()
        try:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row:
                # Default to analyst if role is somehow missing in the row
                role = row["role"] if "role" in row.keys() else "analyst"
                return User(id=row["id"], username=row["username"], role=role)
        finally:
            conn.close()
        return None

    @staticmethod
    def create_default_admin():
        """Initializes default accounts if the database is empty."""
        AuthManager._ensure_role_column()
        
        conn = get_db_connection()
        count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        conn.close()

        if count == 0:
            # Create Admin with default password
            AuthManager.create_user("admin", "admin123", role="admin", creator="system")
            # Create Analyst with password 'user123' as requested
            return AuthManager.create_user("analyst1", "anal123", role="analyst", creator="system")
        
        return {"success": False, "message": "Users already exist."}