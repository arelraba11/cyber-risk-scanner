import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Ensure log folder exists
LOG_DIR = Path("data")
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "scan_logs.json"


def save_scan_log(scan_result: dict):
    """
    Append a scan result to the log file (data/scan_logs.json).
    Creates the directory and file if they don't exist.
    Handles JSON corruption safely.
    """
    # Add timestamp for internal tracking
    scan_result["logged_at"] = datetime.now().isoformat(timespec="seconds")

    # --- Read existing logs safely ---
    logs = []
    if LOG_FILE.exists():
        try:
            with LOG_FILE.open("r", encoding="utf-8") as f:
                logs = json.load(f)
                if not isinstance(logs, list):
                    logs = []
        except (json.JSONDecodeError, OSError):
            logs = []

    # --- Append and save back ---
    logs.append(scan_result)

    try:
        with LOG_FILE.open("w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[Logger] Failed to write log: {e}")


def get_scan_logs(limit: int = 10, domain: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Read and optionally filter stored scan logs.
    Args:
        limit: max number of records to return (default 10, newest first)
        domain: optional domain name filter (substring match)
    Returns:
        List of scan dicts (sorted by timestamp, newest first)
    """
    if not LOG_FILE.exists():
        return []

    try:
        with LOG_FILE.open("r", encoding="utf-8") as f:
            logs = json.load(f)
    except json.JSONDecodeError:
        return []

    # Filter by domain if requested
    if domain:
        logs = [log for log in logs if domain.lower() in log.get("url", "").lower()]

    # Sort by timestamp (newest first)
    logs.sort(key=lambda x: x.get("scan_timestamp", ""), reverse=True)

    # Limit the number of results
    return logs[:limit]