"""Local dashboard authentication helpers.

This is intentionally simple SQLite-backed auth for a local Streamlit app.
It validates basic input, hashes passwords with bcrypt, and returns plain dicts
so dashboard.py can display user-friendly errors without importing web classes.
"""

import sqlite3
import bcrypt
import uuid
from datetime import datetime, timezone

try:
    from .paths import db_path
except ImportError:
    from paths import db_path


def register_user(username: str, email: str, password: str) -> dict:
    """Register a new user and return a success/error result dict."""
    username = username.strip()
    email = email.strip().lower()

    # Keep validation close to storage so every caller gets the same rules.
    if not username or not email or not password:
        return {"success": False, "error": "All fields are required."}
    if len(password) < 8:
        return {"success": False, "error": "Password must be at least 8 characters."}
    if "@" not in email or "." not in email.split("@")[-1]:
        return {"success": False, "error": "Enter a valid email address."}

    # bcrypt.gensalt() gives every user a unique salt embedded in the hash.
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        with sqlite3.connect(db_path()) as conn:
            conn.execute(
                "INSERT INTO users (user_id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, username, email, password_hash, created_at),
            )
        return {"success": True, "user_id": user_id, "username": username, "email": email}
    except sqlite3.IntegrityError as exc:
        # SQLite reports which UNIQUE constraint failed; translate that into a
        # form-level message the dashboard can show directly.
        msg = str(exc).lower()
        if "email" in msg:
            return {"success": False, "error": "An account with this email already exists."}
        if "username" in msg:
            return {"success": False, "error": "This username is already taken."}
        return {"success": False, "error": "Registration failed. Please try again."}
    except Exception as exc:
        return {"success": False, "error": f"Database error: {exc}"}


def login_user(email: str, password: str) -> dict:
    """Authenticate a user and return a dashboard-ready result dict."""
    email = email.strip().lower()

    if not email or not password:
        return {"success": False, "error": "Email and password are required."}

    try:
        with sqlite3.connect(db_path()) as conn:
            cursor = conn.execute(
                "SELECT user_id, username, email, password_hash FROM users WHERE email = ?",
                (email,),
            )
            row = cursor.fetchone()
    except Exception as exc:
        return {"success": False, "error": f"Database error: {exc}"}

    if not row:
        return {"success": False, "error": "Invalid email or password."}

    user_id, username, email_db, password_hash = row

    # checkpw handles the salt and timing-safe comparison internally.
    if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
        return {"success": False, "error": "Invalid email or password."}

    return {
        "success": True,
        "user": {"user_id": user_id, "username": username, "email": email_db},
    }


def get_user_by_id(user_id: str) -> dict | None:
    """Fetch the public user fields by id, or None if absent/unavailable."""
    try:
        with sqlite3.connect(db_path()) as conn:
            cursor = conn.execute(
                "SELECT user_id, username, email, created_at FROM users WHERE user_id = ?",
                (user_id,),
            )
            row = cursor.fetchone()
        if row:
            return {"user_id": row[0], "username": row[1], "email": row[2], "created_at": row[3]}
    except Exception:
        pass
    return None
