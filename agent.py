import os
import time
import socket
import getpass
import sqlite3
from datetime import datetime
from typing import Optional, Callable, Dict, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileDeletedEvent, FileCreatedEvent, FileMovedEvent

from .database import get_db_connection, log_event
from .integrity import compute_sha256, verify_file_integrity, get_file_metadata
from .rules_engine import SeverityRulesEngine
from .ai_engine import ai_engine
from .diff_engine import save_baseline_snapshot

class FileShieldEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that intercepts filesystem changes,
    verifies SHA-256 against baseline, applies rules, invokes AI,
    and logs security events to database.
    """

    def __init__(self, broadcast_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        super().__init__()
        self.broadcast_callback = broadcast_callback
        self.last_event_times = {} # Debounce map {file_path: timestamp}
        self.debounce_seconds = 0.4

    def _should_debounce(self, file_path: str) -> bool:
        now = time.time()
        last_time = self.last_event_times.get(file_path, 0)
        if (now - last_time) < self.debounce_seconds:
            return True
        self.last_event_times[file_path] = now
        return False

    def process_file_event(self, event_type: str, file_path: str, old_path: Optional[str] = None):
        norm_path = os.path.normpath(os.path.abspath(file_path))
        file_name = os.path.basename(norm_path)

        # Detect Windows atomic file replacement (e.g. Word/Notepad ~WRD...tmp -> docx)
        if old_path:
            old_name = os.path.basename(old_path)
            if old_name.startswith("~") or old_name.endswith(".tmp") or old_name.endswith(".swp"):
                event_type = "MODIFY"

        # Ignore directories, temporary editor files, or hidden files
        if os.path.isdir(norm_path) or file_name.startswith("~") or file_name.startswith(".") or file_name.endswith(".tmp") or file_name.endswith(".swp"):
            return

        # Ignore internal FileShield snapshots, database files, and dev artifacts
        lower_path = norm_path.lower()
        if any(ign in lower_path for ign in ['snapshots', 'fileshield.db', '.git', '__pycache__', 'node_modules', '.vscode', 'venv']):
            return

        if self._should_debounce(norm_path) and event_type != "DELETE":
            return

        # Short pause on Windows to allow editor write lock to fully commit
        if event_type != "DELETE":
            time.sleep(0.12)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if file is monitored in DB (case-insensitive for Windows)
        cursor.execute("SELECT * FROM protected_files WHERE LOWER(file_path) = LOWER(?)", (norm_path,))
        row = cursor.fetchone()

        if not row:
            # Check by basename in protected_files directory if full path differs
            cursor.execute("SELECT * FROM protected_files WHERE LOWER(file_name) = LOWER(?)", (file_name,))
            row = cursor.fetchone()

        # If file was deleted but is not a monitored file, ignore
        if not row and event_type == "DELETE":
            conn.close()
            return

        criticality = "MEDIUM"
        baseline_hash = None
        old_hash = None
        now_iso = datetime.now().isoformat()

        if row:
            criticality = row["criticality"]
            baseline_hash = row["baseline_hash"]
            old_hash = row["baseline_hash"] or row["current_hash"]

            if event_type == "DELETE":
                status = "DELETED"
                new_hash = None
                integrity_status = "DELETED"
                meta_size = 0
            else:
                new_hash = compute_sha256(norm_path)
                if new_hash is None:
                    time.sleep(0.15)
                    new_hash = compute_sha256(norm_path)
                if new_hash is None:
                    conn.close()
                    return

                # Prevent redundant touch events if neither current nor baseline hash changed
                curr_recorded = (row["current_hash"] or "").upper()
                base_recorded = (row["baseline_hash"] or "").upper()
                if new_hash.upper() == curr_recorded and new_hash.upper() == base_recorded and row["status"] == "SAFE":
                    conn.close()
                    return

                status, new_hash, is_violation = verify_file_integrity(norm_path, baseline_hash)
                integrity_status = "VIOLATED" if is_violation else "SAFE"
                meta = get_file_metadata(norm_path)
                meta_size = meta["size"]
        else:
            # New file added manually to a monitored directory
            criticality = "CRITICAL" if ("database" in file_name.lower() or "sql" in file_name.lower() or "auth" in file_name.lower()) else ("HIGH" if ("user" in file_name.lower() or "config" in file_name.lower()) else "MEDIUM")
            new_hash = compute_sha256(norm_path)
            if new_hash is None:
                time.sleep(0.15)
                new_hash = compute_sha256(norm_path)
            if new_hash is None:
                conn.close()
                return

            meta = get_file_metadata(norm_path)
            meta_size = meta["size"]
            status = "SAFE"
            integrity_status = "SAFE"
            baseline_hash = new_hash
            old_hash = "N/A"
            event_type = "CREATE"

        # Step 5: Rule-based severity
        severity = SeverityRulesEngine.evaluate(
            event_type=event_type,
            criticality=criticality,
            integrity_status=integrity_status,
            file_name=file_name
        )

        # Step 6: AI Behavior Analysis
        event_meta = {
            "file_name": file_name,
            "criticality": criticality,
            "event_type": event_type,
            "integrity_status": integrity_status,
            "timestamp": now_iso
        }
        ai_result = ai_engine.analyze(event_meta)

        # Host & User Metadata
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "DESKTOP-SYSTEM"

        try:
            username = getpass.getuser()
        except Exception:
            username = "admin"

        # Update or Insert into protected_files table safely
        try:
            if row:
                cursor.execute("""
                    UPDATE protected_files
                    SET current_hash = ?, current_size = ?, status = ?, last_checked = ?
                    WHERE id = ?
                """, (new_hash, meta_size, status, now_iso, row["id"]))
            else:
                try:
                    cursor.execute("""
                        INSERT INTO protected_files (file_path, file_name, criticality, baseline_hash, baseline_size, baseline_timestamp, current_hash, current_size, status, last_checked)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SAFE', ?)
                    """, (norm_path, file_name, criticality, new_hash, meta_size, now_iso, new_hash, meta_size, now_iso))
                    new_id = cursor.lastrowid
                    save_baseline_snapshot(new_id, norm_path)
                except sqlite3.IntegrityError:
                    cursor.execute("""
                        UPDATE protected_files
                        SET current_hash = ?, current_size = ?, status = ?, last_checked = ?
                        WHERE LOWER(file_path) = LOWER(?)
                    """, (new_hash, meta_size, status, now_iso, norm_path))
            conn.commit()
        except Exception as db_err:
            print(f"[Agent] DB update error: {db_err}")
        finally:
            conn.close()

        # Log event to security_events
        event_dict = {
            "timestamp": now_iso,
            "event_type": event_type,
            "file_path": norm_path,
            "file_name": file_name,
            "criticality": criticality,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "integrity_status": integrity_status,
            "severity": severity,
            "ai_anomaly": 1 if ai_result["is_anomaly"] else 0,
            "ai_risk_score": ai_result["risk_score"],
            "ai_risk_level": ai_result["risk_level"],
            "ai_reasoning": ai_result["reasons"],
            "hostname": hostname,
            "username": username
        }

        event_id = log_event(event_dict)
        event_dict["id"] = event_id

        # Email Notification Trigger on ANY file change or tamper violation
        if event_type in ["MODIFY", "DELETE", "CREATE", "RENAME"] or integrity_status in ["VIOLATED", "DELETED"]:
            try:
                from .email_service import send_file_change_notification
                send_file_change_notification(file_name, event_dict)
            except Exception as e:
                print(f"[Agent] Email dispatch notice: {e}")

        # Real-time WebSocket or Callback broadcast
        if self.broadcast_callback:
            try:
                self.broadcast_callback(event_dict)
            except Exception as e:
                print(f"[Agent] Broadcast error: {e}")

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file_event("MODIFY", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.process_file_event("DELETE", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.process_file_event("CREATE", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_file_event("RENAME", event.dest_path, old_path=event.src_path)


class FileShieldAgent:
    """
    Manages the watchdog observer thread for monitored folders.
    Automatically persists monitored folders and supports recursive subfolder watching.
    """

    def __init__(self, broadcast_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.broadcast_callback = broadcast_callback
        self.observer = None
        self.monitored_paths = set()
        self.is_running = False

    def start(self, initial_paths: list[str]):
        if self.is_running:
            return

        self.observer = Observer()
        handler = FileShieldEventHandler(broadcast_callback=self.broadcast_callback)

        for path in initial_paths:
            norm_path = os.path.normpath(os.path.abspath(path))
            if os.path.exists(norm_path) and os.path.isdir(norm_path):
                self.observer.schedule(handler, norm_path, recursive=True)
                self.monitored_paths.add(norm_path)
                print(f"[FileShield Agent] Monitoring directory (recursive): {norm_path}")
                try:
                    conn = get_db_connection()
                    c = conn.cursor()
                    c.execute("INSERT OR IGNORE INTO monitored_folders (folder_path, is_active, created_at) VALUES (?, 1, ?)", (norm_path, datetime.now().isoformat()))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

        self.observer.daemon = True
        self.observer.start()
        self.is_running = True
        print(f"[FileShield Agent] Active and listening for file events across {len(self.monitored_paths)} directory tree(s).")

    def stop(self):
        if self.observer and self.is_running:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            print("[FileShield Agent] Monitoring stopped.")

    def add_watch(self, directory: str):
        norm_path = os.path.normpath(os.path.abspath(directory))
        if os.path.isfile(norm_path):
            norm_path = os.path.dirname(norm_path)

        if not os.path.exists(norm_path) or not os.path.isdir(norm_path):
            return

        # Persist folder path to database so it is remembered permanently on restart
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO monitored_folders (folder_path, is_active, created_at) VALUES (?, 1, ?)", (norm_path, datetime.now().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[FileShield Agent] Folder persistence error: {e}")

        if norm_path not in self.monitored_paths:
            if self.observer and self.is_running:
                handler = FileShieldEventHandler(broadcast_callback=self.broadcast_callback)
                self.observer.schedule(handler, norm_path, recursive=True)
            self.monitored_paths.add(norm_path)
            print(f"[FileShield Agent] Added recursive watch on: {norm_path}")

    def remove_watch(self, directory: str):
        norm_path = os.path.normpath(os.path.abspath(directory))
        matching_paths = [p for p in list(self.monitored_paths) if os.path.normpath(p).lower() == norm_path.lower() or os.path.normpath(p).lower().startswith(norm_path.lower())]
        for p in matching_paths:
            self.monitored_paths.discard(p)

        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("DELETE FROM monitored_folders WHERE LOWER(folder_path) = LOWER(?)", (norm_path,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[FileShield Agent] Folder unwatch DB error: {e}")

        if self.is_running and self.observer:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            self.start(list(self.monitored_paths))
        print(f"[FileShield Agent] Removed watch on: {norm_path}")
