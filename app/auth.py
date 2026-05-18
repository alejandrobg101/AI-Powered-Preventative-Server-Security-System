import sqlite3
import bcrypt
import uuid
from datetime import datetime, timezone

DB_PATH = "threat_memory.db"


def register_user(username: str, email: str, password: str) -> dict:
    """Register a new user. Returns dict with 'success' key."""
    username = username.strip()
    email = email.strip().lower()

    if not username or not email or not password:
        return {"success": False, "error": "All fields are required."}
    if len(password) < 8:
        return {"success": False, "error": "Password must be at least 8 characters."}
    if "@" not in email or "." not in email.split("@")[-1]:
        return {"success": False, "error": "Enter a valid email address."}

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (user_id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, username, email, password_hash, created_at),
            )
        return {"success": True, "user_id": user_id, "username": username, "email": email}
    except sqlite3.IntegrityError as exc:
        msg = str(exc).lower()
        if "email" in msg:
            return {"success": False, "error": "An account with this email already exists."}
        if "username" in msg:
            return {"success": False, "error": "This username is already taken."}
        return {"success": False, "error": "Registration failed. Please try again."}
    except Exception as exc:
        return {"success": False, "error": f"Database error: {exc}"}


def login_user(email: str, password: str) -> dict:
    """Authenticate a user. Returns dict with 'success' key."""
    email = email.strip().lower()

    if not email or not password:
        return {"success": False, "error": "Email and password are required."}

    try:
        with sqlite3.connect(DB_PATH) as conn:
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

    if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
        return {"success": False, "error": "Invalid email or password."}

    return {
        "success": True,
        "user": {"user_id": user_id, "username": username, "email": email_db},
    }


def get_user_by_id(user_id: str) -> dict | None:
    """Fetch user record by user_id."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
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
