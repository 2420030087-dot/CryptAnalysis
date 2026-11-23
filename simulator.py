import os
import shutil
import time
from pathlib import Path
from typing import Dict, Any

class AttackSimulator:
    """
    Simulates real-world attack scenarios and maintenance events
    directly on disk in protected_files/ so that the live agent detects genuine OS events.
    """

    def __init__(self, protected_dir: str, template_dir: str):
        self.protected_dir = os.path.normpath(os.path.abspath(protected_dir))
        self.template_dir = os.path.normpath(os.path.abspath(template_dir))

    def simulate_database_tamper(self) -> Dict[str, Any]:
        """Tamper database.sql with unauthorized privilege escalation injection."""
        db_file = os.path.join(self.protected_dir, "database.sql")
        if not os.path.exists(db_file):
            return {"success": False, "message": "database.sql not found."}

        malicious_payload = f"\n-- [TAMPERED_INJECTION] {time.strftime('%Y-%m-%d %H:%M:%S')}\n" \
                            f"UPDATE system_users SET role = 'superuser', mfa_enabled = 0 WHERE username = 'audit_service';\n" \
                            f"INSERT INTO financial_ledger VALUES ('EXPLOIT-007', 'CORP-TREASURY-01', 'OFFSHORE-SHADOW-ACC', 999999.00, 'audit_service', 'ROUTED');\n"

        with open(db_file, "a", encoding="utf-8") as f:
            f.write(malicious_payload)

        return {
            "success": True,
            "scenario": "Database Tamper",
            "file": "database.sql",
            "description": "Unauthorized SQL injection inserted into financial ledger and users table."
        }

    def simulate_ransomware_burst(self) -> Dict[str, Any]:
        """
        Simulates rapid multi-target modification and deletion in quick succession (<1s).
        This triggers the AI Behavioral Anomaly detector.
        """
        db_file = os.path.join(self.protected_dir, "database.sql")
        users_file = os.path.join(self.protected_dir, "users.json")
        config_file = os.path.join(self.protected_dir, "config.txt")

        # 1. Corrupt database.sql
        if os.path.exists(db_file):
            with open(db_file, "a", encoding="utf-8") as f:
                f.write(f"\n/* LOCKED BY SHADOW_CRYPT_V2 @ {time.time()} */\n")

        time.sleep(0.1)

        # 2. Corrupt users.json
        if os.path.exists(users_file):
            with open(users_file, "a", encoding="utf-8") as f:
                f.write(f"\n/* ENCRYPTED PAYLOAD HEADER */\n")

        time.sleep(0.1)

        # 3. Delete config.txt
        if os.path.exists(config_file):
            os.remove(config_file)

        return {
            "success": True,
            "scenario": "Ransomware Burst Attack",
            "description": "Rapid succession tampering across database.sql, users.json, and deletion of config.txt within 0.3s."
        }

    def simulate_file_deletion(self) -> Dict[str, Any]:
        """Deletes confidential.txt to test unauthorized file deletion."""
        target = os.path.join(self.protected_dir, "confidential.txt")
        if os.path.exists(target):
            os.remove(target)
            return {
                "success": True,
                "scenario": "Unauthorized File Deletion",
                "file": "confidential.txt",
                "description": "Confidential corporate roadmap was unexpectedly deleted."
            }
        else:
            # If already deleted, delete users.json
            alt = os.path.join(self.protected_dir, "users.json")
            if os.path.exists(alt):
                os.remove(alt)
                return {"success": True, "scenario": "Unauthorized File Deletion", "file": "users.json"}
            return {"success": False, "message": "Target files already deleted."}

    def simulate_normal_maintenance(self) -> Dict[str, Any]:
        """Performs routine, authorized-like minor update on config.txt."""
        cfg_file = os.path.join(self.protected_dir, "config.txt")
        # Ensure it exists
        if not os.path.exists(cfg_file):
            template_cfg = os.path.join(self.template_dir, "config.txt")
            if os.path.exists(template_cfg):
                shutil.copy2(template_cfg, cfg_file)

        with open(cfg_file, "a", encoding="utf-8") as f:
            f.write(f"\n# Routine maintenance heartbeat check: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        return {
            "success": True,
            "scenario": "Routine Config Update",
            "file": "config.txt",
            "description": "Routine config timestamp heartbeat updated."
        }

    def restore_all_test_files(self) -> Dict[str, Any]:
        """Restores protected_files/ from protected_files_template/."""
        if not os.path.exists(self.template_dir):
            return {"success": False, "message": "Template directory does not exist."}

        for item in os.listdir(self.template_dir):
            src = os.path.join(self.template_dir, item)
            dst = os.path.join(self.protected_dir, item)
            if os.path.isfile(src):
                shutil.copy2(src, dst)

        return {
            "success": True,
            "message": "All protected test files have been restored to initial pristine state."
        }
