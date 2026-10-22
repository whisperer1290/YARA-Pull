"""
Malware Family Statistics Tracker

Maintains a CSV file tracking:
- malware_family: Name of the malware family
- samples_detected_downloaded: Count of samples detected and downloaded for this family
- rules_detected_count: Count of unique YARA rules that detected samples for this family
"""

import csv
import json
import re
from pathlib import Path
from typing import Dict, Set

from .config import get_config


def _extract_family_from_rule(rule_name: str) -> str:
    """
    Extract malware family name from YARA rule name.
    Examples: MALWARE_Win_Neshta -> Neshta, win_danabot -> Danabot
    """
    config = get_config()
    target_families = config.target_families
    
    # Try to match against target families (case-insensitive)
    rule_lower = rule_name.lower()
    for family in target_families:
        if family.lower() in rule_lower:
            return family
    
    # Extract from common patterns: MALWARE_Win_X, MALW_X, win_x, etc.
    parts = re.split(r'[_\-]', rule_name)
    for part in reversed(parts):
        if part and len(part) > 2 and part.lower() not in ('win', 'malware', 'malw', 'auto'):
            return part[0].upper() + part[1:].lower() if len(part) > 1 else part.upper()
    
    return rule_name


def _get_csv_path() -> Path:
    """Get path to the malware family stats CSV file."""
    config = get_config()
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    return config.reports_dir / "malware_family_stats.csv"


def _get_rules_json_path() -> Path:
    """Get path to JSON file storing which rules detected each family."""
    config = get_config()
    return config.reports_dir / "malware_family_rules.json"


def _load_stats() -> Dict[str, dict]:
    """Load existing stats from CSV and rules from JSON."""
    csv_path = _get_csv_path()
    json_path = _get_rules_json_path()
    stats = {}
    
    # Load rules_seen from JSON (tracks unique rules per family)
    rules_data: Dict[str, list] = {}
    if json_path.exists():
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            rules_data = {}
    
    if csv_path.exists():
        try:
            with open(csv_path, 'r', encoding='utf-8', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    family = row.get('malware_family', '').strip()
                    if family:
                        rules_seen = set(rules_data.get(family, []))
                        csv_rules_count = int(row.get('rules_detected_count', 0) or 0)
                        stats[family] = {
                            'samples_detected_downloaded': int(row.get('samples_detected_downloaded', 0) or 0),
                            'rules_detected_count': max(csv_rules_count, len(rules_seen)),
                            'rules_seen': rules_seen
                        }
        except (csv.Error, ValueError, IOError):
            stats = {}
    
    return stats


def _save_stats(stats: dict) -> None:
    """Save stats to CSV and rules to JSON."""
    csv_path = _get_csv_path()
    json_path = _get_rules_json_path()
    
    with open(csv_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['malware_family', 'samples_detected_downloaded', 'rules_detected_count'])
        writer.writeheader()
        for family in sorted(stats.keys()):
            writer.writerow({
                'malware_family': family,
                'samples_detected_downloaded': stats[family]['samples_detected_downloaded'],
                'rules_detected_count': stats[family]['rules_detected_count']
            })
    
    rules_data = {f: list(stats[f]['rules_seen']) for f in stats}
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(rules_data, f, indent=2)


def record_detection(rule_name: str, samples_count: int) -> None:
    """
    Record a detection: a rule detected and we downloaded samples_count samples.
    Increments samples_detected_downloaded for the family and adds the rule to rules_detected_count.
    
    Args:
        rule_name: YARA rule that detected the samples
        samples_count: Number of samples detected and downloaded
    """
    if samples_count <= 0:
        return
    
    family = _extract_family_from_rule(rule_name)
    stats = _load_stats()
    
    if family not in stats:
        stats[family] = {
            'samples_detected_downloaded': 0,
            'rules_detected_count': 0,
            'rules_seen': set()
        }
    
    stats[family]['samples_detected_downloaded'] += samples_count
    rules_seen = stats[family].get('rules_seen', set())
    is_new_rule = rule_name not in rules_seen
    rules_seen.add(rule_name)
    stats[family]['rules_seen'] = rules_seen
    if is_new_rule:
        stats[family]['rules_detected_count'] += 1
    
    _save_stats(stats)


def get_stats_path() -> Path:
    """Return path to the stats CSV file (for display)."""
    return _get_csv_path()
