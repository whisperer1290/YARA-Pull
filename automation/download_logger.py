"""
Sample Download Date Logger

Appends to a CSV log file for manual verification that downloaded samples
have first_seen within the configured past_months_filter (e.g. 3 months).
"""

import csv
from datetime import datetime
from pathlib import Path

from .config import get_config


def _get_log_path() -> Path:
    """Path to the sample download dates log CSV."""
    config = get_config()
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    return config.reports_dir / "sample_download_dates.csv"


def _ensure_header(path: Path) -> None:
    """Ensure CSV has header if file is new."""
    if not path.exists():
        with open(path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'log_timestamp', 'rule_name', 'sha256_hash', 'first_seen',
                'action', 'past_months_filter'
            ])


def log_sample_download(
    rule_name: str,
    sha256: str,
    first_seen: str,
    action: str,
    past_months_filter: int,
) -> None:
    """
    Log a sample's first_seen date for manual verification of the time filter.
    
    Args:
        rule_name: YARA rule that matched the sample
        sha256: Sample SHA256 hash
        first_seen: first_seen date from API (e.g. "2022-04-15 08:24:20 UTC")
        action: "downloaded" | "already_existed" | "download_failed"
        past_months_filter: Configured months filter (for reference)
    """
    path = _get_log_path()
    _ensure_header(path)
    
    try:
        with open(path, 'a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                rule_name,
                sha256,
                first_seen or '',
                action,
                past_months_filter,
            ])
    except (IOError, OSError):
        pass
