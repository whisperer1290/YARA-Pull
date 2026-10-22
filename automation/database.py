"""
Database Layer

SQLite database for tracking:
- Downloaded samples
- YARA scan results
- Validation history
- Rule statistics
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console

from .config import get_config

console = Console()


class Database:
    """SQLite database for YARA automation tracking."""
    
    SCHEMA = """
    -- Samples table: tracks all downloaded malware samples
    CREATE TABLE IF NOT EXISTS samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256_hash TEXT UNIQUE NOT NULL,
        md5_hash TEXT,
        sha1_hash TEXT,
        file_size INTEGER,
        file_name TEXT,
        source TEXT,  -- 'yaraify', 'malwarebazaar', 'manual'
        expected_family TEXT,
        download_date TEXT,
        file_path TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Scan results table: tracks YARA scan results
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sample_id INTEGER,
        scan_date TEXT,
        matched_rules TEXT,  -- JSON array of rule names
        matched_families TEXT,  -- JSON array of families
        scan_time_ms INTEGER,
        error TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sample_id) REFERENCES samples(id)
    );
    
    -- Validation results table
    CREATE TABLE IF NOT EXISTS validation_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sample_id INTEGER,
        validation_date TEXT,
        expected_family TEXT,
        detected_families TEXT,  -- JSON array
        status TEXT,  -- 'valid', 'mismatch', 'no_match', 'error'
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sample_id) REFERENCES samples(id)
    );
    
    -- Rule statistics table
    CREATE TABLE IF NOT EXISTS rule_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT UNIQUE NOT NULL,
        total_matches INTEGER DEFAULT 0,
        fp_count INTEGER DEFAULT 0,
        last_match_date TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Rule sources table: tracks YARA rule sources
    CREATE TABLE IF NOT EXISTS rule_sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_name TEXT UNIQUE NOT NULL,
        source_url TEXT,
        last_update TEXT,
        rule_count INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Aggregated rules table: tracks all YARA rules that have been aggregated
    CREATE TABLE IF NOT EXISTS aggregated_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT UNIQUE NOT NULL,
        content_hash TEXT NOT NULL,  -- MD5 hash of rule content for deduplication
        source TEXT,  -- Where the rule came from
        added_date TEXT,
        searched INTEGER DEFAULT 0,  -- 0 = not searched, 1 = searched on YARAify
        last_searched_date TEXT,
        samples_found INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_samples_hash ON samples(sha256_hash);
    CREATE INDEX IF NOT EXISTS idx_samples_family ON samples(expected_family);
    CREATE INDEX IF NOT EXISTS idx_samples_source ON samples(source);
    CREATE INDEX IF NOT EXISTS idx_scan_results_sample ON scan_results(sample_id);
    CREATE INDEX IF NOT EXISTS idx_validation_sample ON validation_results(sample_id);
    CREATE INDEX IF NOT EXISTS idx_rule_stats_name ON rule_stats(rule_name);
    CREATE INDEX IF NOT EXISTS idx_aggregated_rules_name ON aggregated_rules(rule_name);
    CREATE INDEX IF NOT EXISTS idx_aggregated_rules_hash ON aggregated_rules(content_hash);
    CREATE INDEX IF NOT EXISTS idx_aggregated_rules_searched ON aggregated_rules(searched);
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.config = get_config()
        self.db_path = db_path or self.config.database_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript(self.SCHEMA)
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    # ----- Sample Operations -----
    
    def add_sample(self, sha256_hash: str, source: str,
                   expected_family: Optional[str] = None,
                   md5_hash: Optional[str] = None,
                   sha1_hash: Optional[str] = None,
                   file_size: Optional[int] = None,
                   file_name: Optional[str] = None,
                   file_path: Optional[str] = None) -> int:
        """
        Add a sample to the database.
        
        Returns:
            Sample ID
        """
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO samples 
                (sha256_hash, md5_hash, sha1_hash, file_size, file_name, 
                 source, expected_family, download_date, file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (sha256_hash, md5_hash, sha1_hash, file_size, file_name,
                  source, expected_family, datetime.now().isoformat(), file_path))
            conn.commit()
            return cursor.lastrowid
    
    def get_sample(self, sha256_hash: str) -> Optional[Dict[str, Any]]:
        """Get sample by hash."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM samples WHERE sha256_hash = ?",
                (sha256_hash,)
            ).fetchone()
            
            if row:
                return dict(row)
            return None
    
    def get_samples_by_family(self, family: str) -> List[Dict[str, Any]]:
        """Get all samples for a family."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM samples WHERE expected_family = ?",
                (family,)
            ).fetchall()
            return [dict(row) for row in rows]
    
    def get_samples_by_source(self, source: str) -> List[Dict[str, Any]]:
        """Get all samples from a source."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM samples WHERE source = ?",
                (source,)
            ).fetchall()
            return [dict(row) for row in rows]
    
    def sample_exists(self, sha256_hash: str) -> bool:
        """Check if sample exists in database."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM samples WHERE sha256_hash = ?",
                (sha256_hash,)
            ).fetchone()
            return row is not None
    
    # ----- Scan Results Operations -----
    
    def add_scan_result(self, sha256_hash: str, 
                        matched_rules: List[str],
                        matched_families: List[str],
                        scan_time_ms: int = 0,
                        error: Optional[str] = None) -> int:
        """Add a scan result for a sample."""
        # Get or create sample
        sample = self.get_sample(sha256_hash)
        if not sample:
            sample_id = self.add_sample(sha256_hash, source="scan")
        else:
            sample_id = sample['id']
        
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scan_results 
                (sample_id, scan_date, matched_rules, matched_families, scan_time_ms, error)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (sample_id, datetime.now().isoformat(),
                  json.dumps(matched_rules), json.dumps(matched_families),
                  scan_time_ms, error))
            conn.commit()
            
            # Update rule stats
            for rule in matched_rules:
                self._update_rule_stats(rule, conn)
            
            return cursor.lastrowid
    
    def get_scan_results(self, sha256_hash: str) -> List[Dict[str, Any]]:
        """Get all scan results for a sample."""
        sample = self.get_sample(sha256_hash)
        if not sample:
            return []
        
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_results WHERE sample_id = ? ORDER BY scan_date DESC",
                (sample['id'],)
            ).fetchall()
            
            results = []
            for row in rows:
                result = dict(row)
                result['matched_rules'] = json.loads(result['matched_rules'])
                result['matched_families'] = json.loads(result['matched_families'])
                results.append(result)
            
            return results
    
    # ----- Validation Results Operations -----
    
    def add_validation_result(self, sha256_hash: str,
                              expected_family: str,
                              detected_families: List[str],
                              status: str) -> int:
        """Add a validation result."""
        sample = self.get_sample(sha256_hash)
        if not sample:
            sample_id = self.add_sample(sha256_hash, source="validation",
                                        expected_family=expected_family)
        else:
            sample_id = sample['id']
        
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO validation_results 
                (sample_id, validation_date, expected_family, detected_families, status)
                VALUES (?, ?, ?, ?, ?)
            """, (sample_id, datetime.now().isoformat(),
                  expected_family, json.dumps(detected_families), status))
            conn.commit()
            return cursor.lastrowid
    
    def get_validation_stats(self) -> Dict[str, int]:
        """Get validation statistics."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT status, COUNT(*) as count 
                FROM validation_results 
                GROUP BY status
            """).fetchall()
            
            return {row['status']: row['count'] for row in rows}
    
    # ----- Rule Statistics Operations -----
    
    def _update_rule_stats(self, rule_name: str, conn: sqlite3.Connection):
        """Update rule statistics."""
        conn.execute("""
            INSERT INTO rule_stats (rule_name, total_matches, last_match_date, updated_at)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(rule_name) DO UPDATE SET
                total_matches = total_matches + 1,
                last_match_date = excluded.last_match_date,
                updated_at = excluded.updated_at
        """, (rule_name, datetime.now().isoformat(), datetime.now().isoformat()))
    
    def update_rule_fp_count(self, rule_name: str, fp_count: int):
        """Update false positive count for a rule."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO rule_stats (rule_name, fp_count, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(rule_name) DO UPDATE SET
                    fp_count = excluded.fp_count,
                    updated_at = excluded.updated_at
            """, (rule_name, fp_count, datetime.now().isoformat()))
            conn.commit()
    
    def get_rule_stats(self, rule_name: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a rule."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM rule_stats WHERE rule_name = ?",
                (rule_name,)
            ).fetchone()
            
            if row:
                return dict(row)
            return None
    
    def get_top_rules(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get top rules by match count."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM rule_stats 
                ORDER BY total_matches DESC 
                LIMIT ?
            """, (limit,)).fetchall()
            
            return [dict(row) for row in rows]
    
    def get_high_fp_rules(self, min_fp_count: int = 1) -> List[Dict[str, Any]]:
        """Get rules with high false positive counts."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM rule_stats 
                WHERE fp_count >= ?
                ORDER BY fp_count DESC
            """, (min_fp_count,)).fetchall()
            
            return [dict(row) for row in rows]
    
    # ----- Rule Sources Operations -----
    
    def update_rule_source(self, source_name: str, source_url: str,
                           rule_count: int):
        """Update rule source information."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO rule_sources (source_name, source_url, last_update, rule_count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source_name) DO UPDATE SET
                    source_url = excluded.source_url,
                    last_update = excluded.last_update,
                    rule_count = excluded.rule_count
            """, (source_name, source_url, datetime.now().isoformat(), rule_count))
            conn.commit()
    
    def get_rule_sources(self) -> List[Dict[str, Any]]:
        """Get all rule sources."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM rule_sources").fetchall()
            return [dict(row) for row in rows]
    
    # ----- Aggregated Rules Operations -----
    
    def add_aggregated_rule(self, rule_name: str, content_hash: str, 
                            source: str = "unknown") -> bool:
        """
        Add a rule to the aggregated rules tracking table.
        
        Returns:
            True if rule was added (new), False if it already existed
        """
        with self._get_connection() as conn:
            try:
                conn.execute("""
                    INSERT INTO aggregated_rules (rule_name, content_hash, source, added_date)
                    VALUES (?, ?, ?, ?)
                """, (rule_name, content_hash, source, datetime.now().isoformat()))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                # Rule already exists
                return False
    
    def rule_exists_by_hash(self, content_hash: str) -> bool:
        """Check if a rule with this content hash already exists."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM aggregated_rules WHERE content_hash = ?",
                (content_hash,)
            ).fetchone()
            return row is not None
    
    def rule_exists_by_name(self, rule_name: str) -> bool:
        """Check if a rule with this name already exists."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM aggregated_rules WHERE rule_name = ?",
                (rule_name,)
            ).fetchone()
            return row is not None
    
    def get_all_rule_hashes(self) -> set:
        """Get all content hashes of aggregated rules."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT content_hash FROM aggregated_rules").fetchall()
            return {row['content_hash'] for row in rows}
    
    def get_all_rule_names(self) -> set:
        """Get all names of aggregated rules."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT rule_name FROM aggregated_rules").fetchall()
            return {row['rule_name'] for row in rows}
    
    def get_unsearched_rules(self, limit: Optional[int] = None) -> List[str]:
        """
        Get rule names that haven't been searched on YARAify yet.
        
        Args:
            limit: Maximum number of rules to return (None = all)
            
        Returns:
            List of rule names that haven't been searched
        """
        with self._get_connection() as conn:
            query = "SELECT rule_name FROM aggregated_rules WHERE searched = 0"
            if limit:
                query += f" LIMIT {limit}"
            rows = conn.execute(query).fetchall()
            return [row['rule_name'] for row in rows]
    
    def get_unsearched_count(self) -> int:
        """Get count of rules that haven't been searched yet."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as count FROM aggregated_rules WHERE searched = 0"
            ).fetchone()
            return row['count']
    
    def get_searched_count(self) -> int:
        """Get count of rules that have been searched."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as count FROM aggregated_rules WHERE searched = 1"
            ).fetchone()
            return row['count']
    
    def mark_rule_searched(self, rule_name: str, samples_found: int = 0):
        """Mark a rule as having been searched on YARAify."""
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE aggregated_rules 
                SET searched = 1, 
                    last_searched_date = ?,
                    samples_found = ?
                WHERE rule_name = ?
            """, (datetime.now().isoformat(), samples_found, rule_name))
            conn.commit()
    
    def mark_rules_searched(self, rule_names: List[str], samples_found_map: Optional[Dict[str, int]] = None):
        """Mark multiple rules as searched."""
        with self._get_connection() as conn:
            for rule_name in rule_names:
                samples = samples_found_map.get(rule_name, 0) if samples_found_map else 0
                conn.execute("""
                    UPDATE aggregated_rules 
                    SET searched = 1, 
                        last_searched_date = ?,
                        samples_found = ?
                    WHERE rule_name = ?
                """, (datetime.now().isoformat(), samples, rule_name))
            conn.commit()
    
    def reset_all_searched_status(self):
        """Reset all rules to unsearched status (for starting a new cycle)."""
        with self._get_connection() as conn:
            conn.execute("UPDATE aggregated_rules SET searched = 0")
            conn.commit()
            console.print("[yellow]Reset all rules to unsearched status[/yellow]")
    
    def get_rule_search_stats(self) -> Dict[str, Any]:
        """Get statistics about rule searching."""
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) as count FROM aggregated_rules").fetchone()['count']
            searched = conn.execute("SELECT COUNT(*) as count FROM aggregated_rules WHERE searched = 1").fetchone()['count']
            unsearched = total - searched
            
            return {
                'total_rules': total,
                'searched': searched,
                'unsearched': unsearched,
                'progress_percent': (searched / total * 100) if total > 0 else 0
            }
    
    # ----- Statistics Operations -----
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall database statistics."""
        with self._get_connection() as conn:
            stats = {}
            
            # Sample counts
            row = conn.execute("SELECT COUNT(*) as count FROM samples").fetchone()
            stats['total_samples'] = row['count']
            
            # Samples by source
            rows = conn.execute("""
                SELECT source, COUNT(*) as count 
                FROM samples 
                GROUP BY source
            """).fetchall()
            stats['samples_by_source'] = {row['source']: row['count'] for row in rows}
            
            # Samples by family
            rows = conn.execute("""
                SELECT expected_family, COUNT(*) as count 
                FROM samples 
                WHERE expected_family IS NOT NULL
                GROUP BY expected_family
                ORDER BY count DESC
                LIMIT 10
            """).fetchall()
            stats['top_families'] = {row['expected_family']: row['count'] for row in rows}
            
            # Scan counts
            row = conn.execute("SELECT COUNT(*) as count FROM scan_results").fetchone()
            stats['total_scans'] = row['count']
            
            # Validation stats
            stats['validation'] = self.get_validation_stats()
            
            # Rule stats
            row = conn.execute("SELECT COUNT(*) as count FROM rule_stats").fetchone()
            stats['tracked_rules'] = row['count']
            
            return stats
    
    def print_statistics(self):
        """Print database statistics to console."""
        stats = self.get_statistics()
        
        console.print("\n[bold]Database Statistics[/bold]")
        console.print(f"Total samples: {stats['total_samples']}")
        console.print(f"Total scans: {stats['total_scans']}")
        console.print(f"Tracked rules: {stats['tracked_rules']}")
        
        if stats['samples_by_source']:
            console.print("\n[cyan]Samples by Source:[/cyan]")
            for source, count in stats['samples_by_source'].items():
                console.print(f"  {source}: {count}")
        
        if stats['top_families']:
            console.print("\n[cyan]Top Families:[/cyan]")
            for family, count in stats['top_families'].items():
                console.print(f"  {family}: {count}")
        
        if stats['validation']:
            console.print("\n[cyan]Validation Results:[/cyan]")
            for status, count in stats['validation'].items():
                console.print(f"  {status}: {count}")


def get_database() -> Database:
    """Get the global database instance."""
    return Database()


if __name__ == "__main__":
    # Test the database
    db = Database()
    
    # Add test sample
    db.add_sample(
        sha256_hash="test123",
        source="test",
        expected_family="TestMalware",
        file_name="test.exe"
    )
    
    # Add scan result
    db.add_scan_result(
        sha256_hash="test123",
        matched_rules=["TestRule1", "TestRule2"],
        matched_families=["TestMalware"],
        scan_time_ms=100
    )
    
    # Print stats
    db.print_statistics()
