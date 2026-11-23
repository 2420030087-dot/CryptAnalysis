import sqlite3
import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fileshield.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=60.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout = 60000")
        conn.execute("PRAGMA journal_mode = WAL")
    except Exception:
        pass
    return conn

def hash_password(password: str, salt: str) -> str:
    """Computes SHA-256 hash of password with cryptographic salt."""
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def init_db():
    conn = get_db_connection()
    try:
        conn.execute("PRAGMA journal_mode = WAL")
    except Exception:
        pass
    cursor = conn.cursor()

    # 1. Protected Files Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS protected_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT UNIQUE NOT NULL,
        file_name TEXT NOT NULL,
        criticality TEXT NOT NULL DEFAULT 'MEDIUM',
        baseline_hash TEXT,
        baseline_size INTEGER DEFAULT 0,
        baseline_timestamp TEXT,
        current_hash TEXT,
        current_size INTEGER DEFAULT 0,
        status TEXT DEFAULT 'SAFE',
        last_checked TEXT,
        is_active INTEGER DEFAULT 1
    );
    """)

    # 2. Security Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_name TEXT NOT NULL,
        criticality TEXT NOT NULL,
        old_hash TEXT,
        new_hash TEXT,
        integrity_status TEXT NOT NULL,
        severity TEXT NOT NULL,
        ai_anomaly INTEGER DEFAULT 0,
        ai_risk_score INTEGER DEFAULT 0,
        ai_risk_level TEXT DEFAULT 'LOW',
        ai_reasoning TEXT,
        hostname TEXT,
        username TEXT,
        is_resolved INTEGER DEFAULT 0
    );
    """)

    # 3. Monitored Folders
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS monitored_folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        folder_path TEXT UNIQUE NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    );
    """)

    # 4. App Users Table (Login / Signup / Password Recovery)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS app_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        email TEXT NOT NULL,
        full_name TEXT,
        role TEXT DEFAULT 'Security Administrator',
        failed_logins INTEGER DEFAULT 0,
        reset_otp TEXT,
        reset_otp_expiry TEXT,
        created_at TEXT NOT NULL
    );
    """)

    # Safe column additions if migrating existing tables
    try:
        cursor.execute("ALTER TABLE app_users ADD COLUMN email TEXT DEFAULT 'admin@fileshield.local'")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE app_users ADD COLUMN failed_logins INTEGER DEFAULT 0")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE app_users ADD COLUMN reset_otp TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE app_users ADD COLUMN reset_otp_expiry TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE app_users ADD COLUMN auth_provider TEXT DEFAULT 'local'")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE app_users ADD COLUMN google_id TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE app_users ADD COLUMN avatar_url TEXT")
    except Exception:
        pass

    # 5. User Active Sessions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE
    );
    """)

    # 6. Email Notifications Log Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS email_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient TEXT NOT NULL,
        subject TEXT NOT NULL,
        body_text TEXT NOT NULL,
        body_html TEXT,
        sent_at TEXT NOT NULL,
        status TEXT DEFAULT 'DISPATCHED',
        event_type TEXT
    );
    """)

    # 7. SMTP Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS smtp_config (
        id INTEGER PRIMARY KEY,
        smtp_server TEXT DEFAULT '',
        smtp_port INTEGER DEFAULT 587,
        smtp_user TEXT DEFAULT '',
        smtp_password TEXT DEFAULT '',
        from_email TEXT DEFAULT 'fileshield-alerts@security.corp',
        is_enabled INTEGER DEFAULT 0
    );
    """)

    cursor.execute("SELECT id FROM smtp_config WHERE id = 1")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO smtp_config (id, smtp_server, smtp_port, smtp_user, smtp_password, from_email, is_enabled)
            VALUES (1, '', 587, '', '', 'fileshield-alerts@security.corp', 0)
        """)

    try:
        cursor.execute("ALTER TABLE smtp_config ADD COLUMN active_recipient_email TEXT DEFAULT ''")
    except Exception:
        pass

    # 8. OAuth Configuration Table (Google OAuth)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS oauth_config (
        id INTEGER PRIMARY KEY,
        google_client_id TEXT DEFAULT '',
        google_client_secret TEXT DEFAULT '',
        is_enabled INTEGER DEFAULT 1
    );
    """)

    cursor.execute("SELECT id FROM oauth_config WHERE id = 1")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO oauth_config (id, google_client_id, google_client_secret, is_enabled)
            VALUES (1, '', '', 1)
        """)

    # Seed Default Admin Account if none exists
    cursor.execute("SELECT id FROM app_users WHERE username = 'admin'")
    if not cursor.fetchone():
        salt = secrets.token_hex(16)
        pw_hash = hash_password("admin123", salt)
        cursor.execute("""
            INSERT INTO app_users (username, password_hash, salt, email, full_name, role, auth_provider, failed_logins, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'local', 0, ?)
        """, ("admin", pw_hash, salt, "admin@fileshield.local", "SOC Administrator", "Security Administrator", datetime.now().isoformat()))

    conn.commit()
    conn.close()

def log_event(event_dict):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    reasoning_json = json.dumps(event_dict.get("ai_reasoning", [])) if isinstance(event_dict.get("ai_reasoning"), list) else event_dict.get("ai_reasoning", "[]")

    cursor.execute("""
        INSERT INTO security_events (
            timestamp, event_type, file_path, file_name, criticality,
            old_hash, new_hash, integrity_status, severity,
            ai_anomaly, ai_risk_score, ai_risk_level, ai_reasoning,
            hostname, username, is_resolved
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_dict.get("timestamp", datetime.now().isoformat()),
        event_dict.get("event_type"),
        event_dict.get("file_path"),
        event_dict.get("file_name"),
        event_dict.get("criticality", "MEDIUM"),
        event_dict.get("old_hash"),
        event_dict.get("new_hash"),
        event_dict.get("integrity_status", "VIOLATED"),
        event_dict.get("severity", "MEDIUM"),
        1 if event_dict.get("ai_anomaly") else 0,
        event_dict.get("ai_risk_score", 0),
        event_dict.get("ai_risk_level", "LOW"),
        reasoning_json,
        event_dict.get("hostname", "localhost"),
        event_dict.get("username", "system"),
        0
    ))
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id

# -------------------------------------------------------------
# User Authentication Helpers
# -------------------------------------------------------------
def register_user(username: str, password: str, email: str, full_name: str = ""):
    conn = get_db_connection()
    cursor = conn.cursor()
    salt = secrets.token_hex(16)
    pw_hash = hash_password(password, salt)
    now_iso = datetime.now().isoformat()
    try:
        cursor.execute("""
            INSERT INTO app_users (username, password_hash, salt, email, full_name, role, auth_provider, failed_logins, created_at)
            VALUES (?, ?, ?, ?, ?, 'Security Analyst', 'local', 0, ?)
        """, (username, pw_hash, salt, email, full_name or username, now_iso))
        user_id = cursor.lastrowid
        conn.commit()
        token = secrets.token_hex(24)
        cursor.execute("INSERT INTO user_sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, user_id, now_iso))
        conn.commit()
        conn.close()
        set_active_notification_email(email.strip())
        return {
            "success": True,
            "token": token,
            "username": username,
            "email": email,
            "full_name": full_name or username,
            "role": "Security Analyst",
            "auth_provider": "local"
        }
    except sqlite3.IntegrityError:
        conn.close()
        return {"success": False, "error": "Username already exists. Please choose another."}
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e)}

def authenticate_user(username: str, password: str):
    """
    Authenticates user, tracks failed login attempts,
    and returns failed_count to trigger intrusion alert if > 3.
    Accepts either username OR registered email (e.g. Gmail).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # Try exact match first, then case-insensitive
    cursor.execute("SELECT * FROM app_users WHERE username = ? OR email = ?", (username.strip(), username.strip()))
    user = cursor.fetchone()
    if not user:
        cursor.execute("SELECT * FROM app_users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?) ORDER BY id DESC", (username.strip(), username.strip()))
        user = cursor.fetchone()

    if not user:
        clean_id = username.strip()
        # If input looks like an email and doesn't exist, seamlessly create the new account during login
        if "@" in clean_id and "." in clean_id.split("@")[1]:
            conn.close()
            import re
            base_name = clean_id.split("@")[0]
            clean_username = re.sub(r'[^a-zA-Z0-9_]', '_', base_name.lower())
            reg_res = register_user(clean_username, password, clean_id, full_name=base_name.title())
            if reg_res.get("success"):
                return {
                    "success": True,
                    "token": reg_res["token"],
                    "username": reg_res["username"],
                    "email": clean_id,
                    "full_name": reg_res["full_name"],
                    "role": "Security Analyst",
                    "auth_provider": "local",
                    "failed_count": 0,
                    "is_new_account": True
                }
            else:
                clean_username = f"{clean_username}_{secrets.token_hex(2)}"
                reg_res = register_user(clean_username, password, clean_id, full_name=base_name.title())
                if reg_res.get("success"):
                    return {
                        "success": True,
                        "token": reg_res["token"],
                        "username": reg_res["username"],
                        "email": clean_id,
                        "full_name": reg_res["full_name"],
                        "role": "Security Analyst",
                        "auth_provider": "local",
                        "failed_count": 0,
                        "is_new_account": True
                    }

        conn.close()
        return {
            "success": False,
            "error": "Invalid username or password",
            "user_found": False,
            "failed_count": 0
        }

    computed_hash = hash_password(password, user["salt"])

    if computed_hash != user["password_hash"]:
        new_failed_count = (user["failed_logins"] or 0) + 1
        cursor.execute("UPDATE app_users SET failed_logins = ? WHERE id = ?", (new_failed_count, user["id"]))
        conn.commit()
        conn.close()
        return {
            "success": False,
            "error": "Invalid username or password",
            "user_found": True,
            "username": user["username"],
            "email": user["email"],
            "failed_count": new_failed_count
        }

    # Reset failed attempts upon successful login
    cursor.execute("UPDATE app_users SET failed_logins = 0 WHERE id = ?", (user["id"],))
    token = secrets.token_hex(24)
    now_iso = datetime.now().isoformat()
    cursor.execute("INSERT INTO user_sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, user["id"], now_iso))
    conn.commit()
    conn.close()

    if user["email"]:
        set_active_notification_email(user["email"].strip())

    return {
        "success": True,
        "token": token,
        "username": user["username"],
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"],
        "auth_provider": user["auth_provider"] if "auth_provider" in user.keys() and user["auth_provider"] else "local",
        "avatar_url": user["avatar_url"] if "avatar_url" in user.keys() else None,
        "failed_count": 0
    }

def authenticate_or_create_google_user(email: str, name: str = "", google_id: str = "", avatar_url: str = ""):
    """
    Authenticates or provisions a user authenticated via Google OAuth / Gmail.
    Links to existing account if email matches or provisions a new Operator account.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check for existing user by google_id or email
    cursor.execute("SELECT * FROM app_users WHERE (google_id IS NOT NULL AND google_id != '' AND google_id = ?) OR LOWER(email) = LOWER(?)", (google_id, email.strip()))
    user = cursor.fetchone()
    now_iso = datetime.now().isoformat()

    if user:
        user_id = user["id"]
        # Update profile with latest Google info
        cursor.execute("""
            UPDATE app_users
            SET google_id = CASE WHEN ? != '' THEN ? ELSE google_id END,
                avatar_url = CASE WHEN ? != '' THEN ? ELSE avatar_url END,
                full_name = CASE WHEN full_name IS NULL OR full_name = '' THEN ? ELSE full_name END,
                auth_provider = 'google',
                failed_logins = 0
            WHERE id = ?
        """, (google_id, google_id, avatar_url, avatar_url, name or email.split("@")[0], user_id))
        conn.commit()
        username = user["username"]
        role = user["role"]
        full_name = user["full_name"] or name or email.split("@")[0]
        stored_email = user["email"] or email.strip()
    else:
        # Create brand-new user with email prefix
        import re
        base_username = re.sub(r'[^a-zA-Z0-9_]', '_', email.split("@")[0].lower())
        candidate_username = base_username
        
        cursor.execute("SELECT id FROM app_users WHERE LOWER(username) = LOWER(?)", (candidate_username,))
        if cursor.fetchone():
            candidate_username = f"{base_username}_{secrets.token_hex(2)}"

        salt = secrets.token_hex(16)
        pw_hash = hash_password(secrets.token_hex(16), salt)
        full_name = name or email.split("@")[0]
        role = "Security Analyst"

        cursor.execute("""
            INSERT INTO app_users (username, password_hash, salt, email, full_name, role, auth_provider, google_id, avatar_url, failed_logins, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'google', ?, ?, 0, ?)
        """, (candidate_username, pw_hash, salt, email.strip(), full_name, role, google_id, avatar_url, now_iso))
        user_id = cursor.lastrowid
        username = candidate_username
        stored_email = email.strip()
        conn.commit()

    token = secrets.token_hex(24)
    cursor.execute("INSERT INTO user_sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, user_id, now_iso))
    conn.commit()
    conn.close()

    set_active_notification_email(stored_email.strip())

    return {
        "success": True,
        "token": token,
        "username": username,
        "email": stored_email,
        "full_name": full_name,
        "role": role,
        "auth_provider": "google",
        "avatar_url": avatar_url
    }

def get_current_user_from_token(token: str):
    if not token:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.email, u.full_name, u.role, u.auth_provider, u.avatar_url
        FROM user_sessions s
        JOIN app_users u ON s.user_id = u.id
        WHERE s.token = ?
    """, (token,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return dict(user)
    return None

def logout_session(token: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return True

# -------------------------------------------------------------
# Password Reset (Forgot Password) Flow
# -------------------------------------------------------------
def request_password_reset(username_or_email: str):
    """Generates 6-digit OTP and records expiry (15 mins). Supports username or email."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Try exact match first, then case-insensitive
    cursor.execute("SELECT * FROM app_users WHERE username = ? OR email = ?", (username_or_email.strip(), username_or_email.strip()))
    user = cursor.fetchone()
    if not user:
        cursor.execute("SELECT * FROM app_users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?) ORDER BY id DESC", (username_or_email.strip(), username_or_email.strip()))
        user = cursor.fetchone()

    if not user:
        conn.close()
        return {"success": False, "error": "No account found matching that username or email address."}

    otp = f"{secrets.randbelow(900000) + 100000}"
    expiry = (datetime.now() + timedelta(minutes=15)).isoformat()

    cursor.execute("UPDATE app_users SET reset_otp = ?, reset_otp_expiry = ? WHERE id = ?", (otp, expiry, user["id"]))
    conn.commit()
    conn.close()

    return {
        "success": True,
        "username": user["username"],
        "email": user["email"],
        "otp": otp
    }

def reset_password_with_otp(username_or_email: str, otp: str, new_password: str):
    """Verifies OTP and resets user password with new salt. Supports username or email."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # First search for the specific account that matches username/email AND has this OTP
    clean_id = username_or_email.strip()
    clean_otp = otp.strip()
    cursor.execute("""
        SELECT * FROM app_users
        WHERE (username = ? OR email = ? OR LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?))
          AND reset_otp IS NOT NULL AND reset_otp = ?
    """, (clean_id, clean_id, clean_id, clean_id, clean_otp))
    user = cursor.fetchone()

    if not user:
        # Check if the account exists without matching OTP
        cursor.execute("SELECT * FROM app_users WHERE username = ? OR email = ? OR LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (clean_id, clean_id, clean_id, clean_id))
        existing = cursor.fetchone()
        conn.close()
        if not existing:
            return {"success": False, "error": "User account not found."}
        return {"success": False, "error": "Invalid or expired One-Time Security Code (OTP)."}

    # Check expiry
    try:
        expiry_dt = datetime.fromisoformat(user["reset_otp_expiry"])
        if datetime.now() > expiry_dt:
            conn.close()
            return {"success": False, "error": "Security Code has expired. Please request a new one."}
    except Exception:
        pass

    new_salt = secrets.token_hex(16)
    new_hash = hash_password(new_password, new_salt)

    cursor.execute("""
        UPDATE app_users
        SET password_hash = ?, salt = ?, reset_otp = NULL, reset_otp_expiry = NULL, failed_logins = 0
        WHERE id = ?
    """, (new_hash, new_salt, user["id"]))
    conn.commit()
    conn.close()

    return {"success": True, "message": "Password successfully reset! You can now sign in.", "username": user["username"]}

# -------------------------------------------------------------
# OAuth Configuration Helpers
# -------------------------------------------------------------
def get_oauth_config() -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM oauth_config WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    env_client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    env_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    if row:
        return {
            "google_client_id": row["google_client_id"] or env_client_id,
            "google_client_secret": row["google_client_secret"] or env_client_secret,
            "is_enabled": bool(row["is_enabled"])
        }
    return {
        "google_client_id": env_client_id,
        "google_client_secret": env_client_secret,
        "is_enabled": True
    }

def save_oauth_config(google_client_id: str, google_client_secret: str = "", is_enabled: bool = True):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE oauth_config
        SET google_client_id = ?, google_client_secret = ?, is_enabled = ?
        WHERE id = 1
    """, (google_client_id, google_client_secret, 1 if is_enabled else 0))
    conn.commit()
    conn.close()

# -------------------------------------------------------------
# Active Recipient Emails Helper
# -------------------------------------------------------------
def set_active_notification_email(email: str):
    """Sets the active recipient email for all security alert notifications."""
    if not email or "@" not in email:
        return
    clean_email = email.strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE smtp_config ADD COLUMN active_recipient_email TEXT DEFAULT ''")
    except Exception:
        pass
    cursor.execute("""
        UPDATE smtp_config
        SET active_recipient_email = ?
        WHERE id = 1
    """, (clean_email,))
    conn.commit()
    conn.close()

def get_active_notification_email() -> str:
    """
    Dynamically returns the email of the currently active logged-in operator.
    Automatically switches whenever a new account logs in or is created.
    Never locked to any specific account.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. First priority: The operator associated with the most recent active login/signup session
    try:
        cursor.execute("""
            SELECT u.email
            FROM user_sessions s
            JOIN app_users u ON s.user_id = u.id
            WHERE u.email IS NOT NULL AND u.email != ''
            ORDER BY s.created_at DESC, s.rowid DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        if row and row["email"] and row["email"].strip():
            email = row["email"].strip()
            conn.close()
            return email
    except Exception:
        pass

    # 2. Check active_recipient_email setting in smtp_config
    try:
        cursor.execute("SELECT active_recipient_email FROM smtp_config WHERE id = 1")
        row = cursor.fetchone()
        if row and row["active_recipient_email"] and row["active_recipient_email"].strip():
            email = row["active_recipient_email"].strip()
            conn.close()
            return email
    except Exception:
        pass

    # 3. Fallback to the latest user created in app_users
    try:
        cursor.execute("""
            SELECT email FROM app_users
            WHERE email IS NOT NULL AND email != ''
            ORDER BY id DESC LIMIT 1
        """)
        row = cursor.fetchone()
        if row and row["email"] and row["email"].strip():
            email = row["email"].strip()
            conn.close()
            return email
    except Exception:
        pass

    conn.close()
    return "admin@fileshield.local"

def get_all_notification_emails():
    """
    Returns list of recipient emails for security alerts.
    Dispatches strictly to the active operator email given during login or signup.
    """
    email = get_active_notification_email()
    return [email] if email else ["admin@fileshield.local"]
