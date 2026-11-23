import os
import smtplib
import socket
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Optional, Dict, Any

from .database import get_db_connection, get_all_notification_emails, get_active_notification_email, set_active_notification_email

def get_smtp_settings() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM smtp_config WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    env_server = os.environ.get("SMTP_SERVER", "")
    env_port = int(os.environ.get("SMTP_PORT", 587))
    env_user = os.environ.get("SMTP_USER", "")
    env_pass = os.environ.get("SMTP_PASSWORD", "")
    env_from = os.environ.get("FROM_EMAIL", "")

    active_recipient = get_active_notification_email()

    if row:
        cfg = dict(row)
        return {
            "smtp_server": cfg.get("smtp_server") or env_server,
            "smtp_port": cfg.get("smtp_port") or env_port,
            "smtp_user": cfg.get("smtp_user") or env_user,
            "smtp_password": cfg.get("smtp_password") or env_pass,
            "from_email": cfg.get("from_email") or env_from or "fileshield-alerts@security.corp",
            "active_recipient_email": cfg.get("active_recipient_email") or active_recipient,
            "is_enabled": cfg.get("is_enabled") if cfg.get("is_enabled") else (1 if (env_server and env_user) else 0)
        }
    return {
        "smtp_server": env_server,
        "smtp_port": env_port,
        "smtp_user": env_user,
        "smtp_password": env_pass,
        "from_email": env_from or "fileshield-alerts@security.corp",
        "active_recipient_email": active_recipient,
        "is_enabled": 1 if (env_server and env_user) else 0
    }

def save_smtp_settings(server: str, port: int, user: str, password: str, from_email: str, is_enabled: bool, active_recipient_email: str = ""):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE smtp_config ADD COLUMN active_recipient_email TEXT DEFAULT ''")
    except Exception:
        pass
    if active_recipient_email:
        cursor.execute("""
            UPDATE smtp_config
            SET smtp_server = ?, smtp_port = ?, smtp_user = ?, smtp_password = ?, from_email = ?, is_enabled = ?, active_recipient_email = ?
            WHERE id = 1
        """, (server, port, user, password, from_email, 1 if is_enabled else 0, active_recipient_email.strip()))
    else:
        cursor.execute("""
            UPDATE smtp_config
            SET smtp_server = ?, smtp_port = ?, smtp_user = ?, smtp_password = ?, from_email = ?, is_enabled = ?
            WHERE id = 1
        """, (server, port, user, password, from_email, 1 if is_enabled else 0))
    conn.commit()
    conn.close()

def log_email_to_db(recipient: str, subject: str, body_text: str, body_html: str, event_type: str, status: str = "DISPATCHED"):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO email_notifications (recipient, subject, body_text, body_html, sent_at, status, event_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (recipient, subject, body_text, body_html, now_iso, status, event_type))
    conn.commit()
    conn.close()

def is_real_deliverable_email(email: str) -> bool:
    """Checks if an email is a real external deliverable domain (not a dummy .local or internal placeholder)."""
    if not email or "@" not in email:
        return False
    domain = email.split("@")[1].strip().lower()
    dummy_suffixes = (
        ".local", ".corp", ".internal", ".test", ".invalid", ".example", ".sample"
    )
    if domain.endswith(dummy_suffixes) or domain == "localhost":
        return False
    dummy_domains = {
        "university.edu", "example.com", "example.org", "example.net",
        "demo.com", "placeholder.org", "test.com", "security.corp"
    }
    if domain in dummy_domains:
        return False
    return "." in domain

def dispatch_email(recipient: str, subject: str, body_text: str, body_html: str, event_type: str) -> Dict[str, Any]:
    """
    Sends email via real SMTP if enabled, and always records to local SOC Outbox.
    Guarantees no crash if SMTP server is unavailable.
    """
    settings = get_smtp_settings()
    is_smtp_enabled = bool(settings.get("is_enabled")) and bool(settings.get("smtp_server"))

    delivery_status = "SENT_VIA_SMTP" if is_smtp_enabled else "DISPATCHED (SOC Outbox)"
    error_msg = None

    if is_smtp_enabled:
        if not is_real_deliverable_email(recipient):
            # For local test placeholders like admin@fileshield.local, log locally and skip remote SMTP
            delivery_status = "DISPATCHED (Local Outbox)"
        else:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                from_addr = settings.get("from_email") or settings.get("smtp_user") or "fileshield-alerts@security.corp"
                msg["From"] = from_addr
                msg["To"] = recipient

                part1 = MIMEText(body_text, "plain", "utf-8")
                part2 = MIMEText(body_html, "html", "utf-8")
                msg.attach(part1)
                msg.attach(part2)

                server_host = settings.get("smtp_server")
                server_port = int(settings.get("smtp_port") or 587)

                if server_port == 465:
                    server = smtplib.SMTP_SSL(server_host, server_port, timeout=10)
                    server.ehlo()
                else:
                    server = smtplib.SMTP(server_host, server_port, timeout=10)
                    server.ehlo()
                    try:
                        server.starttls()
                        server.ehlo()
                    except Exception as te:
                        print(f"[EmailService] STARTTLS note: {te}")

                if settings.get("smtp_user") and settings.get("smtp_password"):
                    server.login(settings.get("smtp_user"), settings.get("smtp_password"))

                server.sendmail(from_addr, [recipient], msg.as_string())
                server.quit()
                delivery_status = "DELIVERED (SMTP)"
                print(f"[EmailService] Real SMTP email delivered to: {recipient}")
            except Exception as e:
                error_msg = str(e)
                print(f"[EmailService] SMTP delivery failed to {recipient} ({e}), saved to SOC Outbox.")
                delivery_status = f"SMTP_FAIL ({str(e)[:45]})"

    # Record into email logs
    log_email_to_db(recipient, subject, body_text, body_html, event_type, status=delivery_status)
    return {
        "success": error_msg is None,
        "delivery_status": delivery_status,
        "error": error_msg
    }

def dispatch_batch_emails(recipients: List[str], subject: str, body_text: str, body_html: str, event_type: str):
    """
    Sends email to multiple recipients asynchronously in a background worker thread.
    Uses a single authenticated SMTP session to avoid reconnect delays and socket exhaustion.
    """
    def _worker():
        settings = get_smtp_settings()
        is_smtp_enabled = bool(settings.get("is_enabled")) and bool(settings.get("smtp_server"))
        server_host = settings.get("smtp_server")
        server_port = int(settings.get("smtp_port") or 587)
        smtp_user = settings.get("smtp_user")
        smtp_pass = settings.get("smtp_password")
        from_addr = settings.get("from_email") or smtp_user or "fileshield-alerts@security.corp"

        smtp_server = None
        if is_smtp_enabled:
            try:
                if server_port == 465:
                    smtp_server = smtplib.SMTP_SSL(server_host, server_port, timeout=12)
                    smtp_server.ehlo()
                else:
                    smtp_server = smtplib.SMTP(server_host, server_port, timeout=12)
                    smtp_server.ehlo()
                    try:
                        smtp_server.starttls()
                        smtp_server.ehlo()
                    except Exception as te:
                        print(f"[EmailService] STARTTLS note: {te}")

                if smtp_user and smtp_pass:
                    smtp_server.login(smtp_user, smtp_pass)
            except Exception as conn_err:
                print(f"[EmailService] SMTP session connection error: {conn_err}")
                smtp_server = None

        for recipient in recipients:
            delivery_status = "SENT_VIA_SMTP" if is_smtp_enabled else "DISPATCHED (SOC Outbox)"
            if is_smtp_enabled:
                if not is_real_deliverable_email(recipient):
                    delivery_status = "DISPATCHED (Local Outbox)"
                elif smtp_server:
                    try:
                        msg = MIMEMultipart("alternative")
                        msg["Subject"] = subject
                        msg["From"] = from_addr
                        msg["To"] = recipient
                        msg.attach(MIMEText(body_text, "plain", "utf-8"))
                        msg.attach(MIMEText(body_html, "html", "utf-8"))
                        smtp_server.sendmail(from_addr, [recipient], msg.as_string())
                        delivery_status = "DELIVERED (SMTP)"
                        print(f"[EmailService] Real SMTP email delivered to: {recipient}")
                    except Exception as send_err:
                        delivery_status = f"SMTP_FAIL ({str(send_err)[:45]})"
                        print(f"[EmailService] Send failure to {recipient}: {send_err}")
                else:
                    delivery_status = "SMTP_FAIL (Connection Error)"

            log_email_to_db(recipient, subject, body_text, body_html, event_type, status=delivery_status)

        if smtp_server:
            try:
                smtp_server.quit()
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()

# -------------------------------------------------------------
# Specific Email Triggers
# -------------------------------------------------------------

def send_file_change_notification(file_name: str, event_data: Dict[str, Any]):
    """Sends notification to all registered admin & user emails whenever a change is detected in any protected file."""
    recipients = get_all_notification_emails()
    event_type = event_data.get("event_type", "MODIFY")
    severity = event_data.get("severity", "CRITICAL")
    risk_score = event_data.get("ai_risk_score", 85)
    risk_level = event_data.get("ai_risk_level", "HIGH")
    old_hash = event_data.get("old_hash") or "N/A"
    new_hash = event_data.get("new_hash") or "(Deleted)"
    integrity = event_data.get("integrity_status", "VIOLATED")
    hostname = event_data.get("hostname", socket.gethostname())
    user = event_data.get("username", "system")
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    reasons = event_data.get("ai_reasoning", [])
    if isinstance(reasons, str):
        try:
            import json
            reasons = json.loads(reasons)
        except Exception:
            reasons = [reasons]
    reasons_html = "".join([f"<li>{r}</li>" for r in reasons]) if reasons else "<li>File change event captured by real-time watchdog kernel observer.</li>"

    # Customize title, subject, badge, and color depending on the change type
    if integrity == "VIOLATED":
        subject = f"🚨 [FileShield Alert] Cryptographic Tamper Detected: {file_name} [Risk: {risk_score}/100]"
        header_title = f"🚨 INTEGRITY VIOLATION DETECTED"
        header_subtitle = "Unauthorized SHA-256 Digital Fingerprint Mismatch"
        header_gradient = "linear-gradient(135deg, #b91c1c, #dc2626)"
        badge_color = "#ef4444"
    elif event_type == "DELETE":
        subject = f"🚨 [FileShield Alert] File Deletion Detected: {file_name}"
        header_title = f"🚨 PROTECTED FILE DELETED"
        header_subtitle = "Monitored Asset Was Unexpectedly Removed From Disk"
        header_gradient = "linear-gradient(135deg, #991b1b, #7f1d1d)"
        badge_color = "#dc2626"
    elif event_type == "CREATE":
        subject = f"ℹ️ [FileShield Alert] New Protected File Created: {file_name}"
        header_title = f"ℹ️ NEW FILE CREATED"
        header_subtitle = "New Asset Added to Monitored Directory & Fingerprinted"
        header_gradient = "linear-gradient(135deg, #0369a1, #0284c7)"
        badge_color = "#0284c7"
    elif event_type == "RENAME":
        subject = f"ℹ️ [FileShield Alert] File Renamed: {file_name}"
        header_title = f"ℹ️ FILE RENAMED"
        header_subtitle = "Path Reassignment Captured on Monitored Volume"
        header_gradient = "linear-gradient(135deg, #4338ca, #6366f1)"
        badge_color = "#6366f1"
    else:
        subject = f"⚠️ [FileShield Alert] File Modification Detected: {file_name}"
        header_title = f"⚠️ FILE MODIFICATION DETECTED"
        header_subtitle = "Change Detected on Monitored File Asset"
        header_gradient = "linear-gradient(135deg, #d97706, #b45309)"
        badge_color = "#f59e0b"

    body_text = f"""
===============================================================
FILESHIELD CYBER DEFENSE: {header_title}
===============================================================
Target Asset:       {file_name}
Event Type:         {event_type}
Integrity Status:   {integrity}
Severity Level:     {severity}
AI Risk Score:      {risk_score}/100 ({risk_level})
Host Device:        {hostname}
Operating User:     {user}
Detection Time:     {time_str}

Trusted Baseline SHA-256: {old_hash}
Current Hash on Disk:     {new_hash}

AI Behavioral Indicators:
{chr(10).join([' - ' + str(r) for r in reasons])}

RECOMMENDED ACTION:
Inspect the visual diff on the FileShield Dashboard (http://127.0.0.1:8000)
or click 'Restore to Baseline' to revert the file to trusted state.
===============================================================
"""

    body_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0b1120; color: #f1f5f9; padding: 20px; margin: 0; }}
        .card {{ background-color: #142038; border: 1px solid #334155; border-radius: 12px; max-width: 620px; margin: 0 auto; overflow: hidden; box-shadow: 0 12px 35px rgba(0,0,0,0.6); }}
        .header {{ background: {header_gradient}; padding: 20px 24px; color: white; }}
        .header h2 {{ margin: 0 0 4px 0; font-size: 19px; letter-spacing: 0.5px; }}
        .body {{ padding: 24px; }}
        .badge {{ background: {badge_color}; color: white; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 12px; letter-spacing: 0.5px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 18px 0; background: rgba(0,0,0,0.3); padding: 14px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.06); }}
        .label {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }}
        .val {{ font-size: 13px; font-weight: 600; color: #fff; margin-top: 3px; word-break: break-all; }}
        .hash-box {{ background: #060912; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 11px; margin-top: 14px; word-break: break-all; border-left: 4px solid {badge_color}; line-height: 1.5; }}
        .btn {{ display: inline-block; background: #2563eb; color: white; padding: 11px 22px; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 13px; margin-top: 20px; box-shadow: 0 4px 14px rgba(37,99,235,0.4); }}
        .reasons {{ margin: 10px 0; padding-left: 20px; font-size: 13px; color: #cbd5e1; line-height: 1.6; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <h2>{header_title}</h2>
          <span style="font-size: 12px; opacity: 0.95;">{header_subtitle}</span>
        </div>
        <div class="body">
          <p style="font-size: 14px; line-height: 1.5; color: #e2e8f0; margin-top: 0;">
            A real-time file change event was intercepted on a protected system file.
          </p>
          <div class="grid">
            <div><span class="label">Target Asset</span><div class="val font-mono">{file_name}</div></div>
            <div><span class="label">Event Type</span><div class="val">{event_type}</div></div>
            <div><span class="label">AI Risk Score</span><div class="val" style="color:#f43f5e;">{risk_score}/100 [{risk_level}]</div></div>
            <div><span class="label">Integrity Status</span><div class="val"><span class="badge">{integrity}</span></div></div>
            <div><span class="label">Host Machine</span><div class="val">{hostname}</div></div>
            <div><span class="label">Operating User</span><div class="val">{user}</div></div>
          </div>

          <span class="label">AI Anomaly Analysis:</span>
          <ul class="reasons">
            {reasons_html}
          </ul>

          <div class="hash-box">
            <strong style="color:#10b981;">TRUSTED BASELINE:</strong> {old_hash}<br><br>
            <strong style="color:#f43f5e;">CURRENT STATUS:</strong> {new_hash}
          </div>

          <a href="http://127.0.0.1:8000" class="btn">Open SOC Dashboard &amp; View Diff</a>
        </div>
      </div>
    </body>
    </html>
    """

    dispatch_batch_emails(recipients, subject, body_text, body_html, event_type="FILE_CHANGE_ALERT")

# Keep alias for backwards compatibility
send_file_tamper_alert = send_file_change_notification

def send_brute_force_alert(username: str, failed_count: int, ip_addr: str = "127.0.0.1", to_email: Optional[str] = None):
    """Sends immediate high-priority warning when wrong password entered > 3 times."""
    admin_emails = get_all_notification_emails()
    recipients = list(set(([to_email] if to_email else []) + admin_emails))
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    subject = f"🚨 [FileShield Security] Brute-Force Alert: {failed_count} Failed Logins on Account '{username}'"

    body_text = f"""
===============================================================
FILESHIELD INTRUSION DETECTION: MULTIPLE FAILED LOGINS
===============================================================
Target Account:       {username}
Consecutive Failures: {failed_count} (Threshold: > 3 attempts)
Source Address:       {ip_addr}
Alert Timestamp:      {time_str}

SECURITY THREAT ASSESSMENT:
A potential credential-stuffing or brute-force dictionary attack was detected
attempting to access the FileShield SOC Console.

RECOMMENDED ACTIONS:
1. Verify if this was an authorized analyst attempting to log in.
2. If unauthorized, check host network connections.
3. Use 'Forgot Password' to securely reset the account password if compromised.
===============================================================
"""

    body_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0b1120; color: #f1f5f9; padding: 20px; }}
        .card {{ background-color: #142038; border: 1px solid #f59e0b; border-radius: 10px; max-width: 600px; margin: 0 auto; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #d97706, #b45309); padding: 18px 24px; color: white; }}
        .body {{ padding: 22px 24px; }}
        .alert-box {{ background: rgba(245, 158, 11, 0.12); border: 1px solid #f59e0b; border-radius: 6px; padding: 14px; margin: 16px 0; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <h2 style="margin:0;">🚨 BRUTE-FORCE INTRUSION ALERT</h2>
          <span style="font-size:12px;">Failed Authentication Threshold Exceeded</span>
        </div>
        <div class="body">
          <p>More than <strong>3 consecutive failed password attempts</strong> were detected on operator account <strong>{username}</strong>.</p>
          <div class="alert-box">
            <strong>Target Account:</strong> {username}<br>
            <strong>Failed Password Attempts:</strong> {failed_count}<br>
            <strong>Source Address:</strong> {ip_addr}<br>
            <strong>Detection Timestamp:</strong> {time_str}
          </div>
          <p style="font-size: 13px; color: #cbd5e1;">If this was not you, your account may be under an automated guessing attack. Access the FileShield gateway to reset credentials.</p>
          <a href="http://127.0.0.1:8000" style="display:inline-block; background:#2563eb; color:white; padding:8px 16px; border-radius:5px; text-decoration:none; font-weight:bold;">Launch Security Console</a>
        </div>
      </div>
    </body>
    </html>
    """

    dispatch_batch_emails(recipients, subject, body_text, body_html, event_type="BRUTE_FORCE_ALERT")

def send_password_reset_otp(username: str, to_email: str, otp: str):
    """Sends OTP verification code for the Forgot Password flow."""
    subject = f"🔐 [FileShield] Password Reset Authorization Code: {otp}"

    body_text = f"""
===============================================================
FILESHIELD OPERATOR PASSWORD RESET
===============================================================
Hello {username},

A request was submitted to reset your FileShield SOC Console password.

Your One-Time Security Authorization Code (OTP) is:
  >>> {otp} <<<

This code is valid for 15 minutes.
If you did not request this password reset, please review system activity immediately.
===============================================================
"""

    body_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0b1120; color: #f1f5f9; padding: 20px; }}
        .card {{ background-color: #142038; border: 1px solid #3b82f6; border-radius: 10px; max-width: 520px; margin: 0 auto; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #1d4ed8, #2563eb); padding: 18px 24px; color: white; }}
        .body {{ padding: 22px 24px; }}
        .otp-box {{ background: #060912; border: 2px dashed #38bdf8; border-radius: 8px; padding: 18px; text-align: center; margin: 20px 0; }}
        .otp-code {{ font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; font-family: monospace; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <h2 style="margin:0;">🔐 FileShield Password Reset</h2>
          <span style="font-size:12px;">Security Authorization Code</span>
        </div>
        <div class="body">
          <p>Hello <strong>{username}</strong>,</p>
          <p>We received a request to reset your console password. Enter the One-Time Security Code below to authorize the update:</p>
          <div class="otp-box">
            <div style="font-size:11px; color:#94a3b8; text-transform:uppercase; margin-bottom:4px;">One-Time Security Code (OTP)</div>
            <div class="otp-code">{otp}</div>
            <div style="font-size:11px; color:#64748b; margin-top:4px;">Valid for 15 minutes</div>
          </div>
          <p style="font-size: 12px; color: #94a3b8;">If you did not request this reset, someone may be attempting to access your account.</p>
        </div>
      </div>
    </body>
    </html>
    """

    dispatch_email(to_email, subject, body_text, body_html, event_type="PASSWORD_RESET_OTP")

def get_recent_email_logs(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM email_notifications ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows
