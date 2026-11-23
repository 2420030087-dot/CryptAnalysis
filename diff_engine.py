import os
import shutil
import difflib
import stat
from pathlib import Path
from typing import Dict, Any, List, Optional

SNAPSHOTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "snapshots")

def ensure_snapshots_dir():
    os.makedirs(SNAPSHOTS_DIR, exist_ok=True)

def get_snapshot_path(file_id: int) -> str:
    return os.path.join(SNAPSHOTS_DIR, f"{file_id}.snap")

def save_baseline_snapshot(file_id: int, file_path: str) -> bool:
    """Saves a byte-exact pristine copy of the file for diffing and restoration."""
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return False
    ensure_snapshots_dir()
    snap_path = get_snapshot_path(file_id)

    # Clear attributes and unlink existing snapshot if present
    if os.path.exists(snap_path):
        try:
            import stat
            os.chmod(snap_path, stat.S_IWRITE | stat.S_IREAD)
            os.remove(snap_path)
        except Exception:
            try:
                os.system(f'attrib -r -s -h "{snap_path}" >nul 2>&1')
                os.remove(snap_path)
            except Exception:
                pass

    try:
        shutil.copy2(file_path, snap_path)
        return True
    except Exception as e:
        # Fallback to direct byte streaming if shutil.copy2 encounters attribute or metadata issues
        try:
            with open(file_path, "rb") as src, open(snap_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            return True
        except Exception as e2:
            print(f"[DiffEngine] Failed to save snapshot for file {file_id}: {e} / {e2}")
            return False

def restore_from_snapshot(file_id: int, file_path: str) -> Dict[str, Any]:
    """Restores the original file on disk from its trusted baseline snapshot."""
    snap_path = get_snapshot_path(file_id)
    if not os.path.exists(snap_path):
        return {"success": False, "message": "Baseline snapshot not found on disk."}

    try:
        parent_dir = os.path.dirname(file_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        if os.path.exists(file_path):
            try:
                import stat
                os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass

        try:
            shutil.copy2(snap_path, file_path)
        except Exception:
            with open(snap_path, "rb") as src, open(file_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

        return {"success": True, "message": f"Successfully restored {os.path.basename(file_path)} from trusted snapshot."}
    except Exception as e:
        return {"success": False, "message": f"Restoration failed: {str(e)}"}

def delete_snapshot(file_id: int):
    """Removes snapshot when a file is permanently removed."""
    snap_path = get_snapshot_path(file_id)
    if os.path.exists(snap_path):
        try:
            import stat
            os.chmod(snap_path, stat.S_IWRITE | stat.S_IREAD)
            os.remove(snap_path)
        except Exception:
            try:
                os.system(f'attrib -r -s -h "{snap_path}" >nul 2>&1')
                os.remove(snap_path)
            except Exception:
                pass

def is_text_file(filepath: str) -> bool:
    """Heuristic check to determine if file is text or binary."""
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            if b'\x00' in chunk:
                return False
        return True
    except Exception:
        return False

def compute_diff(file_id: int, current_file_path: str) -> Dict[str, Any]:
    """
    Computes precise visual diff showing:
    - What file was changed
    - EXACTLY what lines were added, modified, or removed
    """
    snap_path = get_snapshot_path(file_id)

    if not os.path.exists(snap_path):
        return {
            "status": "NO_SNAPSHOT",
            "has_diff": False,
            "message": "No baseline snapshot found. Please re-baseline to enable diffing.",
            "diff_lines": [],
            "summary": "Baseline snapshot missing."
        }

    if not os.path.exists(current_file_path):
        return {
            "status": "DELETED",
            "has_diff": True,
            "message": "The file was completely deleted from disk.",
            "diff_lines": [],
            "summary": "File is missing on filesystem."
        }

    # Binary check
    if not is_text_file(snap_path) or not is_text_file(current_file_path):
        old_size = os.path.getsize(snap_path)
        new_size = os.path.getsize(current_file_path)
        return {
            "status": "BINARY",
            "has_diff": True,
            "message": f"Binary content modified. Size changed from {old_size} bytes to {new_size} bytes.",
            "diff_lines": [],
            "summary": f"Binary file mismatch ({old_size}B → {new_size}B)"
        }

    # Text Diff
    try:
        with open(snap_path, 'r', encoding='utf-8', errors='replace') as f1:
            baseline_lines = f1.readlines()
        with open(current_file_path, 'r', encoding='utf-8', errors='replace') as f2:
            current_lines = f2.readlines()

        matcher = difflib.SequenceMatcher(None, baseline_lines, current_lines)
        diff_lines = []
        added_count = 0
        removed_count = 0

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                # Show context lines around changes (or collapsed if too long)
                for line_idx in range(i1, i2):
                    diff_lines.append({
                        "type": "context",
                        "text": baseline_lines[line_idx].rstrip('\r\n'),
                        "line_old": line_idx + 1,
                        "line_new": j1 + (line_idx - i1) + 1
                    })
            elif tag == 'replace':
                for line_idx in range(i1, i2):
                    removed_count += 1
                    diff_lines.append({
                        "type": "removed",
                        "text": baseline_lines[line_idx].rstrip('\r\n'),
                        "line_old": line_idx + 1,
                        "line_new": None
                    })
                for line_idx in range(j1, j2):
                    added_count += 1
                    diff_lines.append({
                        "type": "added",
                        "text": current_lines[line_idx].rstrip('\r\n'),
                        "line_old": None,
                        "line_new": line_idx + 1
                    })
            elif tag == 'delete':
                for line_idx in range(i1, i2):
                    removed_count += 1
                    diff_lines.append({
                        "type": "removed",
                        "text": baseline_lines[line_idx].rstrip('\r\n'),
                        "line_old": line_idx + 1,
                        "line_new": None
                    })
            elif tag == 'insert':
                for line_idx in range(j1, j2):
                    added_count += 1
                    diff_lines.append({
                        "type": "added",
                        "text": current_lines[line_idx].rstrip('\r\n'),
                        "line_old": None,
                        "line_new": line_idx + 1
                    })

        has_diff = (added_count > 0 or removed_count > 0)
        summary = f"+{added_count} line(s) injected, -{removed_count} line(s) deleted" if has_diff else "No content modifications detected (Identical to baseline)."

        return {
            "status": "SUCCESS",
            "has_diff": has_diff,
            "added_count": added_count,
            "removed_count": removed_count,
            "summary": summary,
            "diff_lines": diff_lines
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "has_diff": True,
            "message": f"Diff calculation error: {str(e)}",
            "diff_lines": [],
            "summary": "Failed to parse text diff."
        }
