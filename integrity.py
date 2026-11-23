import hashlib
import os
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

def compute_sha256(filepath: str, retries: int = 15, retry_delay: float = 0.08) -> Optional[str]:
    """Compute the SHA-256 hexadecimal hash of a file safely with retries for transient file locks."""
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return None
    
    for attempt in range(retries):
        try:
            hasher = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest().upper()
        except (PermissionError, OSError) as e:
            if attempt < retries - 1:
                time.sleep(retry_delay)
            else:
                print(f"[Integrity] Error reading {filepath}: {e}")
                return None
        except Exception as e:
            print(f"[Integrity] Error reading {filepath}: {e}")
            return None
    return None

def get_file_metadata(filepath: str) -> Dict[str, Any]:
    """Return size, existence, and modified timestamp."""
    exists = os.path.exists(filepath) and os.path.isfile(filepath)
    if not exists:
        return {
            "exists": False,
            "size": 0,
            "modified_time": None
        }
    stat = os.stat(filepath)
    return {
        "exists": True,
        "size": stat.st_size,
        "modified_time": stat.st_mtime
    }

def verify_file_integrity(filepath: str, baseline_hash: Optional[str]) -> Tuple[str, Optional[str], bool]:
    """
    Returns (status, current_hash, is_violation).
    Status values: 'SAFE', 'VIOLATED', 'DELETED', 'NEW_UNBASELINE'
    """
    if not os.path.exists(filepath):
        return "DELETED", None, True

    current_hash = compute_sha256(filepath)
    if current_hash is None:
        return "READ_ERROR", None, True

    if not baseline_hash:
        return "NEW_UNBASELINE", current_hash, False

    if current_hash.upper() == baseline_hash.upper():
        return "SAFE", current_hash, False
    else:
        return "VIOLATED", current_hash, True
