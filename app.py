import os
import json
import sqlite3
import asyncio
import socket
import shutil
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header, Query, Request, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .database import (
    get_db_connection, init_db, DB_PATH,
    register_user, authenticate_user, authenticate_or_create_google_user,
    get_current_user_from_token, logout_session,
    request_password_reset, reset_password_with_otp,
    get_oauth_config, save_oauth_config,
    set_active_notification_email, get_active_notification_email,
    log_event
)
from .integrity import compute_sha256, verify_file_integrity, get_file_metadata
from .rules_engine import SeverityRulesEngine
from .agent import FileShieldAgent
from .simulator import AttackSimulator
from .diff_engine import (
    save_baseline_snapshot, restore_from_snapshot, compute_diff, delete_snapshot, get_snapshot_path
)
from .email_service import (
    send_file_tamper_alert, send_file_change_notification, send_brute_force_alert, send_password_reset_otp,
    get_recent_email_logs, get_smtp_settings, save_smtp_settings, dispatch_email
)
from .ai_engine import ai_engine

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTECTED_DIR = os.path.join(BASE_DIR, "protected_files")
TEMPLATE_DIR = os.path.join(BASE_DIR, "protected_files_template")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Initialize database & default accounts
init_db()

app = FastAPI(title="FileShield Cybersecurity Platform", version="2.5.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Simulator instance
simulator = AttackSimulator(PROTECTED_DIR, TEMPLATE_DIR)

# WebSocket Connection Manager for real-time live push
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# Background Event Loop Holder
event_loop = None

def agent_broadcast_callback(event_data: dict):
    if event_loop and event_loop.is_running():
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({"type": "SECURITY_EVENT", "data": event_data}),
            event_loop
        )

# Initialize Agent
agent = FileShieldAgent(broadcast_callback=agent_broadcast_callback)

@app.on_event("startup")
async def startup_event():
    global event_loop
    event_loop = asyncio.get_running_loop()
    
    # Gracefully handle Windows Proactor pipe connection reset errors
    def proactor_exception_handler(loop, context):
        exc = context.get("exception")
        msg = context.get("message", "")
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
            return
        if "ConnectionResetError" in msg or "10054" in str(exc) or "10054" in msg:
            return
        loop.default_exception_handler(context)

    event_loop.set_exception_handler(proactor_exception_handler)

    # Initialize baseline and snapshots for default files
    seed_default_protected_files()

    # Collect all directories to monitor:
    # 1. Default protected_files folder
    # 2. Monitored folders saved in database
    # 3. Parent directories of all active protected files in database
    paths_to_monitor = set()
    norm_prot = os.path.normpath(os.path.abspath(PROTECTED_DIR))
    if os.path.exists(norm_prot):
        paths_to_monitor.add(norm_prot)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # From monitored_folders table
        cursor.execute("SELECT folder_path FROM monitored_folders WHERE is_active = 1")
        for r in cursor.fetchall():
            fp = os.path.normpath(os.path.abspath(r[0]))
            if os.path.exists(fp) and os.path.isdir(fp):
                paths_to_monitor.add(fp)

        # From protected_files table (parent dirs of active assets)
        cursor.execute("SELECT file_path FROM protected_files WHERE is_active = 1")
        for r in cursor.fetchall():
            fp = r[0]
            if fp:
                pdir = os.path.normpath(os.path.abspath(os.path.dirname(fp)))
                if os.path.exists(pdir) and os.path.isdir(pdir):
                    paths_to_monitor.add(pdir)
                    cursor.execute("INSERT OR IGNORE INTO monitored_folders (folder_path, is_active, created_at) VALUES (?, 1, ?)", (pdir, datetime.now().isoformat()))

        # Auto-index any existing files in all monitored folders that are not yet in protected_files
        for mdir in paths_to_monitor:
            if os.path.exists(mdir) and os.path.isdir(mdir):
                for fname in os.listdir(mdir):
                    fpath = os.path.normpath(os.path.join(mdir, fname))
                    if os.path.isfile(fpath) and not fname.startswith("~") and not fname.startswith(".") and not fname.endswith(".tmp") and not fname.endswith(".swp"):
                        cursor.execute("SELECT id FROM protected_files WHERE LOWER(file_path) = LOWER(?)", (fpath,))
                        if not cursor.fetchone():
                            h = compute_sha256(fpath)
                            m = get_file_metadata(fpath)
                            now_iso = datetime.now().isoformat()
                            cursor.execute("""
                                INSERT INTO protected_files (
                                    file_path, file_name, criticality, baseline_hash,
                                    baseline_size, baseline_timestamp, current_hash,
                                    current_size, status, last_checked
                                ) VALUES (?, ?, 'MEDIUM', ?, ?, ?, ?, ?, 'SAFE', ?)
                            """, (fpath, fname, h, m["size"], now_iso, h, m["size"], now_iso))
                            fid = cursor.lastrowid
                            save_baseline_snapshot(fid, fpath)

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Startup] Error querying monitored paths: {e}")

    # Start file monitoring agent across all discovered paths
    agent.start(list(paths_to_monitor))

@app.on_event("shutdown")
def shutdown_event():
    agent.stop()

def seed_default_protected_files():
    """Seeds default sample files, creates SHA-256 baselines, and stores pristine snapshots."""
    os.makedirs(PROTECTED_DIR, exist_ok=True)
    if os.path.exists(TEMPLATE_DIR):
        for item in os.listdir(TEMPLATE_DIR):
            src = os.path.join(TEMPLATE_DIR, item)
            dst = os.path.join(PROTECTED_DIR, item)
            if not os.path.exists(dst) and os.path.isfile(src):
                try:
                    shutil.copy2(src, dst)
                except Exception as e:
                    print(f"[Seed] Error copying {item}: {e}")

    conn = get_db_connection()
    cursor = conn.cursor()

    default_criticalities = {
        "database.sql": "CRITICAL",
        "users.json": "HIGH",
        "config.txt": "HIGH",
        "confidential.txt": "MEDIUM"
    }

    if os.path.exists(PROTECTED_DIR):
        for fname in os.listdir(PROTECTED_DIR):
            fpath = os.path.normpath(os.path.join(PROTECTED_DIR, fname))
            if os.path.isfile(fpath):
                cursor.execute("SELECT id, baseline_hash, current_hash FROM protected_files WHERE LOWER(file_path) = LOWER(?)", (fpath,))
                row = cursor.fetchone()
                if not row:
                    sha256_hash = compute_sha256(fpath)
                    meta = get_file_metadata(fpath)
                    crit = default_criticalities.get(fname, "MEDIUM")
                    now_iso = datetime.now().isoformat()
                    cursor.execute("""
                        INSERT INTO protected_files (
                            file_path, file_name, criticality, baseline_hash,
                            baseline_size, baseline_timestamp, current_hash,
                            current_size, status, last_checked
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SAFE', ?)
                    """, (fpath, fname, crit, sha256_hash, meta["size"], now_iso, sha256_hash, meta["size"], now_iso))
                    file_id = cursor.lastrowid
                    save_baseline_snapshot(file_id, fpath)
                else:
                    file_id = row["id"]
                    snap_path = get_snapshot_path(file_id)
                    # Only create snapshot if missing; never overwrite with tampered file
                    if not os.path.exists(snap_path):
                        template_file = os.path.join(TEMPLATE_DIR, fname)
                        if os.path.exists(template_file):
                            save_baseline_snapshot(file_id, template_file)
                        else:
                            curr_h = compute_sha256(fpath)
                            if curr_h and row["baseline_hash"] and curr_h.upper() == row["baseline_hash"].upper():
                                save_baseline_snapshot(file_id, fpath)
    conn.commit()
    conn.close()

# -------------------------------------------------------------
# Authentication Endpoints
# -------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str

class SignupRequest(BaseModel):
    username: str
    password: str
    email: str
    full_name: Optional[str] = None

class ForgotPasswordRequest(BaseModel):
    username_or_email: str

class ResetPasswordRequest(BaseModel):
    username: str
    otp: str
    new_password: str

@app.post("/api/auth/login")
def api_login(payload: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    res = authenticate_user(payload.username.strip(), payload.password)
    
    if not res["success"]:
        failed_count = res.get("failed_count", 0)
        # Check if wrong password entered for more than 3 times
        if failed_count > 3:
            # 1. Send Intrusion Alert Email
            target_email = res.get("email")
            send_brute_force_alert(
                username=payload.username.strip(),
                failed_count=failed_count,
                ip_addr=client_ip,
                to_email=target_email
            )

            # 2. Log High-Severity Intrusion Event to SOC Feed
            intrusion_event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "FAILED_LOGIN_BURST",
                "file_path": "/api/auth/login",
                "file_name": f"Account: {payload.username}",
                "criticality": "HIGH",
                "old_hash": "N/A",
                "new_hash": "N/A",
                "integrity_status": "SECURITY_ALERT",
                "severity": "HIGH",
                "ai_anomaly": 1,
                "ai_risk_score": 88,
                "ai_risk_level": "HIGH",
                "ai_reasoning": [
                    f"Brute-Force Alert: {failed_count} consecutive failed login attempts detected",
                    f"Threshold of >3 failed authentications exceeded for user '{payload.username}'",
                    f"Source connection originating from {client_ip}"
                ],
                "hostname": socket.gethostname(),
                "username": payload.username
            }
            log_event(intrusion_event)
            agent_broadcast_callback(intrusion_event)

            raise HTTPException(
                status_code=401,
                detail=f"Security Alert: Wrong password entered {failed_count} times! An intrusion alert has been dispatched to the registered administrator email."
            )

        raise HTTPException(
            status_code=401,
            detail=f"Invalid username or password. (Attempt {failed_count}/3 before security escalation)"
        )
    if res.get("email"):
        set_active_notification_email(res["email"])
    return res

@app.post("/api/auth/signup")
def api_signup(payload: SignupRequest):
    if len(payload.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(payload.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    if not payload.email or "@" not in payload.email:
        raise HTTPException(status_code=400, detail="A valid email address is required for security alerts")

    res = register_user(payload.username.strip(), payload.password, payload.email.strip(), payload.full_name or payload.username)
    if not res["success"]:
        raise HTTPException(status_code=400, detail=res["error"])
    set_active_notification_email(payload.email.strip())
    return res

@app.post("/api/auth/forgot-password")
def api_forgot_password(payload: ForgotPasswordRequest):
    """Initiates password reset by generating 6-digit OTP and dispatching email."""
    res = request_password_reset(payload.username_or_email.strip())
    if not res["success"]:
        raise HTTPException(status_code=404, detail=res["error"])

    # Dispatch OTP Email
    send_password_reset_otp(res["username"], res["email"], res["otp"])

    return {
        "success": True,
        "message": f"Security One-Time Code (OTP) has been dispatched to {res['email']}",
        "username": res["username"],
        "email": res["email"],
        "otp_demo_preview": res["otp"]  # Provided for convenience in professor live demos!
    }

@app.post("/api/auth/reset-password")
def api_reset_password(payload: ResetPasswordRequest):
    """Verifies OTP and resets password."""
    if len(payload.new_password) < 4:
        raise HTTPException(status_code=400, detail="New password must be at least 4 characters")

    res = reset_password_with_otp(payload.username.strip(), payload.otp.strip(), payload.new_password)
    if not res["success"]:
        raise HTTPException(status_code=400, detail=res["error"])
    return res

@app.get("/api/auth/me")
def api_auth_me(authorization: Optional[str] = Header(None)):
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1].strip()

    user = get_current_user_from_token(token)
    if not user:
        return {"authenticated": False, "user": None}
    if user.get("email"):
        set_active_notification_email(user["email"])
    return {"authenticated": True, "user": user}

@app.post("/api/auth/logout")
def api_logout(authorization: Optional[str] = Header(None)):
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1].strip()
    if token:
        logout_session(token)
    return {"success": True}

class GoogleAuthRequest(BaseModel):
    credential: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    google_id: Optional[str] = None
    avatar: Optional[str] = None

class OAuthConfigRequest(BaseModel):
    google_client_id: str
    google_client_secret: Optional[str] = ""

@app.post("/api/auth/google")
async def api_google_auth(payload: GoogleAuthRequest):
    email = payload.email
    name = payload.name
    google_id = payload.google_id
    avatar = payload.avatar

    # Verify ID token if provided from Google Identity Services (GIS)
    if payload.credential:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={payload.credential}")
                if res.status_code == 200:
                    g_data = res.json()
                    email = g_data.get("email") or email
                    name = g_data.get("name") or g_data.get("given_name") or name
                    google_id = g_data.get("sub") or google_id
                    avatar = g_data.get("picture") or avatar
                else:
                    import base64
                    parts = payload.credential.split(".")
                    if len(parts) >= 2:
                        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                        decoded = json.loads(base64.urlsafe_b64decode(padded))
                        email = decoded.get("email", email)
                        name = decoded.get("name", name)
                        google_id = decoded.get("sub", google_id)
                        avatar = decoded.get("picture", avatar)
        except Exception as e:
            print(f"[GoogleAuth] Token verification note: {e}")
            if not email:
                import base64
                try:
                    parts = payload.credential.split(".")
                    if len(parts) >= 2:
                        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                        decoded = json.loads(base64.urlsafe_b64decode(padded))
                        email = decoded.get("email")
                        name = decoded.get("name")
                        google_id = decoded.get("sub")
                        avatar = decoded.get("picture")
                except Exception:
                    pass

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="A valid Gmail address is required to authenticate with Google.")

    res = authenticate_or_create_google_user(email.strip(), name=name or "", google_id=google_id or "", avatar_url=avatar or "")
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Google authentication failed."))

    # Log Google Sign-In Event to Security Events Stream
    google_event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": "GOOGLE_AUTH_SUCCESS",
        "file_path": "/api/auth/google",
        "file_name": f"Account: {res['username']}",
        "criticality": "LOW",
        "old_hash": "N/A",
        "new_hash": "N/A",
        "integrity_status": "AUTHENTICATED",
        "severity": "INFORMATIONAL",
        "ai_anomaly": 0,
        "ai_risk_score": 0,
        "ai_risk_level": "LOW",
        "ai_reasoning": [f"Operator logged in via Google OAuth with Gmail: {email}"],
        "hostname": socket.gethostname(),
        "username": res["username"]
    }
    log_event(google_event)
    agent_broadcast_callback(google_event)

    return res

@app.get("/api/auth/oauth-config")
def api_get_oauth_config():
    return get_oauth_config()

@app.post("/api/auth/oauth-config")
def api_save_oauth_config(payload: OAuthConfigRequest):
    save_oauth_config(payload.google_client_id.strip(), payload.google_client_secret.strip() if payload.google_client_secret else "")
    return {"success": True, "message": "Google OAuth configuration saved."}

# -------------------------------------------------------------
# Email Outbox & SMTP Settings Endpoints
# -------------------------------------------------------------

@app.get("/api/emails")
def get_email_outbox():
    """Returns list of dispatched security emails."""
    return get_recent_email_logs(limit=25)

@app.get("/api/smtp")
def get_smtp_settings_api():
    return get_smtp_settings()

class SmtpConfigRequest(BaseModel):
    smtp_server: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    from_email: str
    active_recipient_email: Optional[str] = ""
    is_enabled: bool

@app.post("/api/smtp")
def save_smtp_settings_api(payload: SmtpConfigRequest):
    save_smtp_settings(
        payload.smtp_server.strip(),
        payload.smtp_port,
        payload.smtp_user.strip(),
        payload.smtp_password,
        payload.from_email.strip(),
        payload.is_enabled,
        active_recipient_email=(payload.active_recipient_email or "").strip()
    )
    return {"success": True, "message": "SMTP configuration saved."}

class RecipientUpdateRequest(BaseModel):
    email: str

@app.get("/api/recipient")
def api_get_active_recipient():
    return {"active_recipient": get_active_notification_email()}

@app.post("/api/recipient")
def api_set_active_recipient(payload: RecipientUpdateRequest):
    if not payload.email or "@" not in payload.email:
        raise HTTPException(status_code=400, detail="A valid email address is required.")
    set_active_notification_email(payload.email.strip())
    return {"success": True, "active_recipient": payload.email.strip()}

class SmtpTestRequest(BaseModel):
    to_email: str

@app.post("/api/smtp/test")
def test_smtp_api(payload: SmtpTestRequest):
    if not payload.to_email or "@" not in payload.to_email:
        raise HTTPException(status_code=400, detail="Valid recipient email required.")
    
    settings = get_smtp_settings()
    if not settings.get("is_enabled") or not settings.get("smtp_server"):
        raise HTTPException(
            status_code=400,
            detail="Live SMTP is currently disabled. Open 'Mail Outbox' -> 'SMTP Configuration', fill in your SMTP host, port, email, and password, then check 'Enable Real Live SMTP Dispatch' and click 'Save Settings'."
        )

    subject = "🛡️ [FileShield Test] Security Alert Email Pipeline Operational"
    body_text = f"Test email from FileShield SOC Security System at {datetime.now().isoformat()}.\nAll cryptographic monitoring channels are operational."
    body_html = f"<div style='padding:20px;background:#142038;color:#fff;'><h2>🛡️ FileShield Alert Pipeline Test</h2><p>Your email notification pipeline is operational!</p></div>"
    
    res = dispatch_email(payload.to_email.strip(), subject, body_text, body_html, event_type="TEST_EMAIL")
    if res.get("error"):
        raise HTTPException(
            status_code=500,
            detail=f"SMTP Delivery Failed: {res.get('error')}. For Gmail, make sure you use a 16-character Google App Password (not your normal Gmail password)."
        )
    return {"success": True, "message": f"Live security alert email successfully delivered to {payload.to_email}!"}

# -------------------------------------------------------------
# System Status & Telemetry
# -------------------------------------------------------------

@app.get("/api/status")
def get_system_status():
    return {
        "status": "ONLINE",
        "agent_running": agent.is_running,
        "monitored_paths": list(agent.monitored_paths),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/stats")
def get_system_stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM protected_files WHERE is_active = 1")
    total_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM protected_files WHERE is_active = 1 AND status = 'SAFE'")
    safe_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM protected_files WHERE is_active = 1 AND status = 'VIOLATED'")
    violated_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM protected_files WHERE is_active = 1 AND status = 'DELETED'")
    deleted_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_events WHERE ai_anomaly = 1")
    ai_anomalies = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_events WHERE severity = 'CRITICAL'")
    critical_alerts = cursor.fetchone()[0]

    conn.close()

    return {
        "protected_files": total_files,
        "safe_files": safe_files,
        "modified_files": violated_files,
        "deleted_files": deleted_files,
        "security_events": total_events,
        "ai_anomalies": ai_anomalies,
        "critical_alerts": critical_alerts
    }

@app.get("/api/files")
def get_protected_files():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM protected_files WHERE is_active = 1 ORDER BY criticality DESC, file_name ASC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

# -------------------------------------------------------------
# What Changed / Diff Engine
# -------------------------------------------------------------

@app.get("/api/files/{file_id}/diff")
def get_file_diff(file_id: int):
    """Returns exact unified differences between baseline snapshot and current file."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM protected_files WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="File record not found")

    file_path = row["file_path"]
    diff_data = compute_diff(file_id, file_path)
    diff_data["file_name"] = row["file_name"]
    diff_data["file_path"] = row["file_path"]
    diff_data["baseline_hash"] = row["baseline_hash"]
    diff_data["current_hash"] = row["current_hash"]
    diff_data["file_status"] = row["status"]
    if diff_data.get("status") not in ["DELETED", "BINARY", "NO_SNAPSHOT", "ERROR"]:
        diff_data["status"] = row["status"]
    return diff_data

# -------------------------------------------------------------
# Restore Changed File
# -------------------------------------------------------------

@app.post("/api/files/{file_id}/restore")
def restore_file(file_id: int):
    """Restores the changed or deleted file from trusted baseline snapshot."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM protected_files WHERE id = ?", (file_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="File record not found")

    file_path = row["file_path"]
    file_name = row["file_name"]
    criticality = row["criticality"]

    # 1. Restore bytes on disk from snapshot
    restore_res = restore_from_snapshot(file_id, file_path)
    if not restore_res["success"]:
        conn.close()
        raise HTTPException(status_code=400, detail=restore_res["message"])

    # 2. Re-verify SHA-256
    new_hash = compute_sha256(file_path)
    meta = get_file_metadata(file_path)
    now_iso = datetime.now().isoformat()

    cursor.execute("""
        UPDATE protected_files
        SET current_hash = ?, current_size = ?, status = 'SAFE', last_checked = ?
        WHERE id = ?
    """, (new_hash, meta["size"], now_iso, file_id))
    conn.commit()
    conn.close()

    # 3. Log security resolution event
    res_event = {
        "timestamp": now_iso,
        "event_type": "RESTORE",
        "file_path": file_path,
        "file_name": file_name,
        "criticality": criticality,
        "old_hash": row["current_hash"],
        "new_hash": new_hash,
        "integrity_status": "SAFE",
        "severity": "INFORMATIONAL",
        "ai_anomaly": 0,
        "ai_risk_score": 0,
        "ai_risk_level": "LOW",
        "ai_reasoning": [f"File {file_name} restored to baseline cryptographic snapshot by administrator."],
        "hostname": socket.gethostname(),
        "username": "admin"
    }
    log_event(res_event)

    agent_broadcast_callback(res_event)

    return {
        "success": True,
        "message": f"{file_name} has been successfully restored to its trusted baseline state.",
        "current_hash": new_hash,
        "status": "SAFE"
    }

# -------------------------------------------------------------
# Remove Files Option (From Database and Optionally from Disk)
# -------------------------------------------------------------

@app.delete("/api/files/{file_id}")
def remove_protected_file(file_id: int, delete_disk: bool = Query(False)):
    """
    Stops monitoring the file and removes it from FileShield.
    If delete_disk is True, also physically deletes the file from disk.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM protected_files WHERE id = ?", (file_id,))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="File record not found")

        file_path = row["file_path"]
        file_name = row["file_name"]

        # 1. Remove from database
        cursor.execute("DELETE FROM protected_files WHERE id = ?", (file_id,))
        conn.commit()
    finally:
        conn.close()

    # 2. Delete local snapshot
    delete_snapshot(file_id)

    # 3. If requested, delete physical file from disk
    disk_deleted = False
    if delete_disk:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                disk_deleted = True
            except Exception as e:
                print(f"[Remove] Could not delete physical file: {e}")

    # Broadcast removal
    agent_broadcast_callback({
        "timestamp": datetime.now().isoformat(),
        "event_type": "UNTRACK",
        "file_name": file_name,
        "file_path": file_path,
        "criticality": "LOW",
        "integrity_status": "REMOVED",
        "severity": "INFORMATIONAL",
        "ai_anomaly": 0,
        "ai_risk_score": 0,
        "ai_risk_level": "LOW",
        "ai_reasoning": ["Resource untracked and removed from FileShield database."]
    })

    return {
        "success": True,
        "file_id": file_id,
        "file_name": file_name,
        "disk_deleted": disk_deleted,
        "message": f"Successfully removed '{file_name}' from database" + (" and deleted from disk." if disk_deleted else ".")
    }

# -------------------------------------------------------------
# Folder Management & Bulk Path Removal
# -------------------------------------------------------------

@app.get("/api/folders")
def get_monitored_folders():
    """Returns list of all monitored folder paths with active file counts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM monitored_folders ORDER BY id DESC")
    folders = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT id, file_path FROM protected_files WHERE is_active = 1")
    all_files = [dict(r) for r in cursor.fetchall()]
    conn.close()

    result = []
    for f in folders:
        norm_dir = os.path.normpath(f["folder_path"]).lower()
        count = sum(1 for file in all_files if os.path.normpath(file["file_path"]).lower().startswith(norm_dir))
        result.append({
            "id": f["id"],
            "folder_path": f["folder_path"],
            "folder_name": os.path.basename(f["folder_path"]) or f["folder_path"],
            "file_count": count,
            "created_at": f["created_at"],
            "is_default": norm_dir == os.path.normpath(PROTECTED_DIR).lower()
        })
    return result

class RemoveFolderRequest(BaseModel):
    folder_path: str
    delete_disk: Optional[bool] = False

@app.post("/api/folders/remove")
def remove_folder_path(payload: RemoveFolderRequest):
    """
    Removes an entire folder path and all of its monitored files from the database and snapshot store.
    If delete_disk is True, also physically deletes the files from disk.
    Stops monitoring the path in the watchdog agent.
    """
    raw_path = payload.folder_path.strip().strip('"\'')
    if not raw_path:
        raise HTTPException(status_code=400, detail="Folder path is required.")

    norm_dir = os.path.normpath(os.path.abspath(raw_path))
    is_core_dir = (norm_dir.lower() == os.path.normpath(PROTECTED_DIR).lower())

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Find all files in protected_files belonging to this folder path
    cursor.execute("SELECT id, file_path, file_name FROM protected_files")
    all_files = cursor.fetchall()

    matching_ids = []
    matching_files = []
    for f in all_files:
        fpath = os.path.normpath(f["file_path"])
        if fpath.lower().startswith(norm_dir.lower()):
            matching_ids.append(f["id"])
            matching_files.append((f["id"], fpath, f["file_name"]))

    # 2. Delete matching files from database
    if matching_ids:
        placeholders = ",".join("?" * len(matching_ids))
        cursor.execute(f"DELETE FROM protected_files WHERE id IN ({placeholders})", matching_ids)

    # 3. Delete from monitored_folders table
    cursor.execute("DELETE FROM monitored_folders WHERE LOWER(folder_path) = LOWER(?)", (norm_dir,))
    conn.commit()
    conn.close()

    # 4. Delete snapshots and optionally disk files
    deleted_disk_count = 0
    for fid, fpath, fname in matching_files:
        delete_snapshot(fid)
        if payload.delete_disk and os.path.exists(fpath):
            try:
                os.remove(fpath)
                deleted_disk_count += 1
            except Exception as e:
                print(f"[RemoveFolder] Disk file remove error: {e}")

    # 5. Remove watch from watchdog agent
    agent.remove_watch(norm_dir)

    # 6. Broadcast untrack event
    agent_broadcast_callback({
        "timestamp": datetime.now().isoformat(),
        "event_type": "FOLDER_REMOVED",
        "file_name": os.path.basename(norm_dir),
        "file_path": norm_dir,
        "criticality": "LOW",
        "integrity_status": "REMOVED",
        "severity": "INFORMATIONAL",
        "ai_anomaly": 0,
        "ai_risk_score": 0,
        "ai_risk_level": "LOW",
        "ai_reasoning": [f"Removed path '{norm_dir}' and {len(matching_files)} file(s) from FileShield."]
    })

    # If the user removed the default protected_files directory, re-seed defaults cleanly
    if is_core_dir:
        seed_default_protected_files()

    return {
        "success": True,
        "folder_path": norm_dir,
        "removed_files_count": len(matching_files),
        "deleted_disk_count": deleted_disk_count,
        "message": f"Successfully removed path '{os.path.basename(norm_dir)}' and {len(matching_files)} file(s) from FileShield."
    }

# -------------------------------------------------------------
# Criticality & Baselining
# -------------------------------------------------------------

class CriticalityUpdate(BaseModel):
    criticality: str

@app.put("/api/files/{file_id}/criticality")
def update_criticality(file_id: int, payload: CriticalityUpdate):
    if payload.criticality not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        raise HTTPException(status_code=400, detail="Invalid criticality level")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE protected_files SET criticality = ? WHERE id = ?", (payload.criticality, file_id))
    conn.commit()
    conn.close()
    return {"success": True, "criticality": payload.criticality}

@app.post("/api/files/{file_id}/baseline")
def rebaseline_file(file_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM protected_files WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="File record not found")

    file_path = row["file_path"]
    if not os.path.exists(file_path):
        conn.close()
        raise HTTPException(status_code=400, detail="File is currently missing or deleted. Cannot baseline.")

    new_hash = compute_sha256(file_path)
    meta = get_file_metadata(file_path)
    now_iso = datetime.now().isoformat()

    cursor.execute("""
        UPDATE protected_files
        SET baseline_hash = ?, baseline_size = ?, baseline_timestamp = ?,
            current_hash = ?, current_size = ?, status = 'SAFE', last_checked = ?
        WHERE id = ?
    """, (new_hash, meta["size"], now_iso, new_hash, meta["size"], now_iso, file_id))
    conn.commit()
    conn.close()

    # Save new baseline snapshot
    save_baseline_snapshot(file_id, file_path)

    return {"success": True, "baseline_hash": new_hash, "status": "SAFE"}

@app.post("/api/files/baseline-all")
def rebaseline_all_files():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM protected_files WHERE is_active = 1")
    rows = cursor.fetchall()
    now_iso = datetime.now().isoformat()

    count = 0
    for row in rows:
        fpath = row["file_path"]
        if os.path.exists(fpath):
            chash = compute_sha256(fpath)
            meta = get_file_metadata(fpath)
            cursor.execute("""
                UPDATE protected_files
                SET baseline_hash = ?, baseline_size = ?, baseline_timestamp = ?,
                    current_hash = ?, current_size = ?, status = 'SAFE', last_checked = ?
                WHERE id = ?
            """, (chash, meta["size"], now_iso, chash, meta["size"], now_iso, row["id"]))
            save_baseline_snapshot(row["id"], fpath)
            count += 1

    conn.commit()
    conn.close()
    return {"success": True, "rebaselined_count": count}

@app.post("/api/files/verify-all")
def verify_all_files():
    conn = get_db_connection()
    cursor = conn.cursor()
    updated = []
    events_to_dispatch = []
    try:
        cursor.execute("SELECT * FROM protected_files WHERE is_active = 1")
        rows = cursor.fetchall()
        now_iso = datetime.now().isoformat()

        for row in rows:
            fpath = row["file_path"]
            status, current_hash, is_violation = verify_file_integrity(fpath, row["baseline_hash"])
            meta = get_file_metadata(fpath)
            cursor.execute("""
                UPDATE protected_files
                SET current_hash = ?, current_size = ?, status = ?, last_checked = ?
                WHERE id = ?
            """, (current_hash, meta["size"], status, now_iso, row["id"]))
            updated.append({"id": row["id"], "file_name": row["file_name"], "status": status})

            # If a violation or deletion is detected on a file that previously had a different status, prepare alert
            if (is_violation or status in ["VIOLATED", "DELETED"]) and row["status"] != status:
                event_type = "DELETE" if status == "DELETED" else "MODIFY"
                sev = SeverityRulesEngine.evaluate(
                    event_type=event_type,
                    criticality=row["criticality"],
                    integrity_status=status,
                    file_name=row["file_name"]
                )
                ai_res = ai_engine.analyze({
                    "file_name": row["file_name"],
                    "criticality": row["criticality"],
                    "event_type": event_type,
                    "integrity_status": status,
                    "timestamp": now_iso
                })
                evt = {
                    "timestamp": now_iso,
                    "event_type": event_type,
                    "file_path": fpath,
                    "file_name": row["file_name"],
                    "criticality": row["criticality"],
                    "old_hash": row["baseline_hash"] or row["current_hash"],
                    "new_hash": current_hash,
                    "integrity_status": status,
                    "severity": sev,
                    "ai_anomaly": 1 if ai_res["is_anomaly"] else 0,
                    "ai_risk_score": ai_res["risk_score"],
                    "ai_risk_level": ai_res["risk_level"],
                    "ai_reasoning": ai_res["reasons"],
                    "hostname": socket.gethostname(),
                    "username": "IntegrityScanner"
                }
                events_to_dispatch.append((row["file_name"], evt))
        conn.commit()
    finally:
        conn.close()

    # Dispatch events and notifications safely after DB connection is closed
    for fname, evt in events_to_dispatch:
        log_event(evt)
        agent_broadcast_callback(evt)
        try:
            from .email_service import send_file_change_notification
            send_file_change_notification(fname, evt)
        except Exception as e:
            print(f"[VerifyAll] Email dispatch note: {e}")

    return {"success": True, "results": updated}

class AddFileRequest(BaseModel):
    file_path: str
    criticality: Optional[str] = "MEDIUM"
    create_if_missing: Optional[bool] = False

@app.post("/api/files/add")
def add_protected_file(payload: AddFileRequest):
    raw_path = payload.file_path.strip().strip('"\'')
    if not raw_path:
        raise HTTPException(status_code=400, detail="Please provide a valid file or folder path.")

    # 1. Resolve path (support relative paths & protected_files shortcut)
    candidate_path = os.path.normpath(os.path.abspath(raw_path))
    if not os.path.exists(candidate_path):
        alt_path = os.path.normpath(os.path.join(PROTECTED_DIR, raw_path))
        if os.path.exists(alt_path):
            candidate_path = alt_path

    # If missing and auto-create enabled, create the file
    if not os.path.exists(candidate_path):
        if payload.create_if_missing:
            try:
                parent_dir = os.path.dirname(candidate_path)
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)
                with open(candidate_path, "w", encoding="utf-8") as f:
                    f.write(f"# FileShield Protected Resource: {os.path.basename(candidate_path)}\n# Registered: {datetime.now().isoformat()}\n")
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Failed to create file on disk: {e}")
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Target path does not exist on disk: '{raw_path}'. Check path or check 'Create new file if missing'."
            )

    norm_path = candidate_path
    conn = get_db_connection()
    cursor = conn.cursor()

    if os.path.isdir(norm_path):
        agent.add_watch(norm_path)
        ignored_dirs = {'snapshots', '.git', '__pycache__', 'node_modules', '.vscode', 'venv', '.env', '.agents', 'dist', 'build', '__macosx'}
        added_files = 0
        for root, dirs, files in os.walk(norm_path):
            dirs[:] = [d for d in dirs if d.lower() not in ignored_dirs and not d.startswith('.')]
            for file in files:
                if file.startswith('.') or file.startswith('~') or file.endswith('.tmp') or file.endswith('.snap'):
                    continue
                full_f = os.path.normpath(os.path.join(root, file))
                cursor.execute("SELECT id FROM protected_files WHERE LOWER(file_path) = LOWER(?)", (full_f,))
                row = cursor.fetchone()
                h = compute_sha256(full_f)
                m = get_file_metadata(full_f)
                now_iso = datetime.now().isoformat()
                if not row:
                    cursor.execute("""
                        INSERT INTO protected_files (file_path, file_name, criticality, baseline_hash, baseline_size, baseline_timestamp, current_hash, current_size, status, last_checked)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SAFE', ?)
                    """, (full_f, file, payload.criticality, h, m["size"], now_iso, h, m["size"], now_iso))
                    fid = cursor.lastrowid
                    save_baseline_snapshot(fid, full_f)
                    added_files += 1
                else:
                    fid = row["id"]
                    cursor.execute("""
                        UPDATE protected_files
                        SET baseline_hash = ?, baseline_size = ?, baseline_timestamp = ?, current_hash = ?, current_size = ?, status = 'SAFE', last_checked = ?
                        WHERE id = ?
                    """, (h, m["size"], now_iso, h, m["size"], now_iso, fid))
                    save_baseline_snapshot(fid, full_f)
                    added_files += 1
        conn.commit()
        conn.close()
        return {"success": True, "message": f"Monitored folder processed. Indexed/updated {added_files} file(s)."}
    else:
        file_name = os.path.basename(norm_path)
        parent_dir = os.path.dirname(norm_path)
        if parent_dir:
            agent.add_watch(parent_dir)

        h = compute_sha256(norm_path)
        m = get_file_metadata(norm_path)
        now_iso = datetime.now().isoformat()

        cursor.execute("SELECT id FROM protected_files WHERE LOWER(file_path) = LOWER(?)", (norm_path,))
        existing = cursor.fetchone()

        if existing:
            fid = existing["id"]
            cursor.execute("""
                UPDATE protected_files
                SET criticality = ?, baseline_hash = ?, baseline_size = ?, baseline_timestamp = ?, current_hash = ?, current_size = ?, status = 'SAFE', last_checked = ?
                WHERE id = ?
            """, (payload.criticality, h, m["size"], now_iso, h, m["size"], now_iso, fid))
            save_baseline_snapshot(fid, norm_path)
            conn.commit()
            conn.close()
            return {"success": True, "file_name": file_name, "baseline_hash": h, "message": f"Target '{file_name}' already registered. Trusted baseline updated."}
        else:
            try:
                cursor.execute("""
                    INSERT INTO protected_files (file_path, file_name, criticality, baseline_hash, baseline_size, baseline_timestamp, current_hash, current_size, status, last_checked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SAFE', ?)
                """, (norm_path, file_name, payload.criticality, h, m["size"], now_iso, h, m["size"], now_iso))
                fid = cursor.lastrowid
                save_baseline_snapshot(fid, norm_path)
                conn.commit()
            except sqlite3.IntegrityError:
                # Concurrently indexed by watchdog thread, update baseline smoothly
                cursor.execute("""
                    UPDATE protected_files
                    SET criticality = ?, baseline_hash = ?, baseline_size = ?, baseline_timestamp = ?, current_hash = ?, current_size = ?, status = 'SAFE', last_checked = ?
                    WHERE LOWER(file_path) = LOWER(?)
                """, (payload.criticality, h, m["size"], now_iso, h, m["size"], now_iso, norm_path))
                cursor.execute("SELECT id FROM protected_files WHERE LOWER(file_path) = LOWER(?)", (norm_path,))
                r = cursor.fetchone()
                if r:
                    save_baseline_snapshot(r["id"], norm_path)
                conn.commit()
            except Exception as e:
                conn.close()
                raise HTTPException(status_code=400, detail=f"Database registration error: {e}")

        # Broadcast TARGET_ADDED event
        add_event = {
            "timestamp": now_iso,
            "event_type": "TARGET_ADDED",
            "file_path": norm_path,
            "file_name": file_name,
            "criticality": payload.criticality,
            "old_hash": "N/A",
            "new_hash": h,
            "integrity_status": "SAFE",
            "severity": "INFORMATIONAL",
            "ai_anomaly": 0,
            "ai_risk_score": 0,
            "ai_risk_level": "LOW",
            "ai_reasoning": [f"Operator registered new protected target resource: {file_name}"],
            "hostname": socket.gethostname(),
            "username": "Operator"
        }
        log_event(add_event)
        agent_broadcast_callback(add_event)

        conn.close()
        return {"success": True, "file_name": file_name, "baseline_hash": h, "message": f"Target '{file_name}' protected and baselined."}

@app.post("/api/files/upload")
async def upload_protected_files(
    files: List[UploadFile] = File(...),
    criticality: Optional[str] = Form("HIGH"),
    destination_folder: Optional[str] = Form(None)
):
    """
    Accepts one or more files uploaded via Drag & Drop or file picker,
    saves them to destination_folder (or PROTECTED_DIR by default),
    computes SHA-256 hash, creates snapshot, registers in DB, and emits event.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files selected.")

    # Determine destination directory
    dest_dir = destination_folder.strip() if (destination_folder and destination_folder.strip()) else PROTECTED_DIR
    dest_dir = os.path.normpath(os.path.abspath(dest_dir))
    os.makedirs(dest_dir, exist_ok=True)

    # Ensure watchdog is actively monitoring the directory
    agent.add_watch(dest_dir)

    results = []
    events_to_log = []

    conn = get_db_connection()
    cursor = conn.cursor()

    for upload_file in files:
        raw_name = upload_file.filename
        if not raw_name:
            continue
        # Strip potential client directory path prefix to get basename
        file_name = os.path.basename(raw_name.replace("\\", "/"))
        if not file_name or file_name.startswith('.'):
            continue

        target_file_path = os.path.normpath(os.path.join(dest_dir, file_name))

        # Write uploaded contents
        content = await upload_file.read()
        with open(target_file_path, "wb") as f:
            f.write(content)

        # Compute hash and size
        h = compute_sha256(target_file_path)
        m = get_file_metadata(target_file_path)
        now_iso = datetime.now().isoformat()

        cursor.execute("SELECT id FROM protected_files WHERE LOWER(file_path) = LOWER(?)", (target_file_path,))
        existing = cursor.fetchone()

        if existing:
            fid = existing["id"]
            cursor.execute("""
                UPDATE protected_files
                SET criticality = ?, baseline_hash = ?, baseline_size = ?, baseline_timestamp = ?,
                    current_hash = ?, current_size = ?, status = 'SAFE', is_active = 1, last_checked = ?
                WHERE id = ?
            """, (criticality, h, m["size"], now_iso, h, m["size"], now_iso, fid))
        else:
            cursor.execute("""
                INSERT INTO protected_files (file_path, file_name, criticality, baseline_hash, baseline_size, baseline_timestamp, current_hash, current_size, status, is_active, last_checked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SAFE', 1, ?)
            """, (target_file_path, file_name, criticality, h, m["size"], now_iso, h, m["size"], now_iso))
            fid = cursor.lastrowid

        # Save snapshot
        save_baseline_snapshot(fid, target_file_path)

        events_to_log.append({
            "timestamp": now_iso,
            "event_type": "TARGET_ADDED",
            "file_path": target_file_path,
            "file_name": file_name,
            "criticality": criticality,
            "old_hash": "N/A",
            "new_hash": h,
            "integrity_status": "SAFE",
            "severity": "INFORMATIONAL",
            "ai_anomaly": 0,
            "ai_risk_score": 0,
            "ai_risk_level": "LOW",
            "ai_reasoning": [f"Operator uploaded file '{file_name}', calculated initial SHA-256 baseline and saved snapshot."],
            "hostname": socket.gethostname(),
            "username": "Operator"
        })

        results.append({
            "id": fid,
            "file_name": file_name,
            "file_path": target_file_path,
            "hash": h,
            "size": m["size"]
        })

    # Commit DB transaction first to release lock
    conn.commit()
    conn.close()

    # Log and broadcast events after DB commit
    for ev in events_to_log:
        try:
            log_event(ev)
        except Exception as e:
            print(f"[Upload] Event log notice: {e}")
        try:
            agent_broadcast_callback(ev)
        except Exception:
            pass

    return {
        "success": True,
        "count": len(results),
        "files": results,
        "message": f"Successfully secured and baselined {len(results)} file(s)."
    }

# -------------------------------------------------------------
# Events & Alerts
# -------------------------------------------------------------

@app.get("/api/events")
def get_security_events(limit: int = 50, severity: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if severity:
        sev_up = severity.upper()
        if sev_up == "AI_ANOMALY":
            cursor.execute("SELECT * FROM security_events WHERE ai_anomaly = 1 ORDER BY id DESC LIMIT ?", (limit,))
        elif sev_up in ["HIGH", "HIGH_ABOVE"]:
            cursor.execute("SELECT * FROM security_events WHERE severity IN ('CRITICAL', 'HIGH') ORDER BY id DESC LIMIT ?", (limit,))
        elif sev_up != "ALL":
            cursor.execute("SELECT * FROM security_events WHERE severity = ? ORDER BY id DESC LIMIT ?", (sev_up, limit))
        else:
            cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))
    else:
        cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))

    rows = []
    for r in cursor.fetchall():
        item = dict(r)
        try:
            item["ai_reasoning"] = json.loads(item["ai_reasoning"])
        except Exception:
            item["ai_reasoning"] = []
        rows.append(item)

    conn.close()
    return rows

@app.get("/api/events/{event_id}")
def get_event_detail(event_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    data = dict(row)
    try:
        data["ai_reasoning"] = json.loads(data["ai_reasoning"])
    except Exception:
        data["ai_reasoning"] = []
    return data

@app.post("/api/events/clear")
def clear_events():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM security_events")
    conn.commit()
    conn.close()
    ai_engine.reset()
    return {"success": True, "message": "Security events history cleared."}

# -------------------------------------------------------------
# Attack Simulation Endpoints
# -------------------------------------------------------------

@app.post("/api/simulate/database-tamper")
def run_db_tamper_sim():
    res = simulator.simulate_database_tamper()
    verify_all_files()
    return res

@app.post("/api/simulate/ransomware-burst")
def run_ransomware_sim():
    res = simulator.simulate_ransomware_burst()
    verify_all_files()
    return res

@app.post("/api/simulate/file-deletion")
def run_deletion_sim():
    res = simulator.simulate_file_deletion()
    verify_all_files()
    return res

@app.post("/api/simulate/normal-maintenance")
def run_maintenance_sim():
    res = simulator.simulate_normal_maintenance()
    verify_all_files()
    return res

@app.post("/api/simulate/restore-all")
def run_restore_sim():
    res = simulator.restore_all_test_files()
    seed_default_protected_files()
    verify_all_files()
    rebaseline_all_files()
    return res

# -------------------------------------------------------------
# WebSocket for Live Push
# -------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

# Mount frontend static files
if os.path.exists(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
