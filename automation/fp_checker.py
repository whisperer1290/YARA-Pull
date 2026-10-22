"""
YARA Rule False Positive Checker

Tests YARA rules against known clean/legitimate files to identify
rules that produce false positives (match non-malware).

Supports both directories and .zip files in goodware_paths.
Zip files are extracted to a temp dir, scanned, then the temp dir is deleted.
The original zip is kept for future runs.
"""

import json
import shutil
import tempfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from .config import get_config
from .scanner import YARAScanner, ScanResult

console = Console()


@dataclass
class RuleFPStats:
    """False positive statistics for a single rule."""
    rule_name: str
    fp_count: int = 0
    matched_files: List[str] = field(default_factory=list)
    
    @property
    def is_problematic(self) -> bool:
        """Check if rule has concerning FP rate."""
        return self.fp_count > 0
    
    def to_dict(self) -> dict:
        return {
            "rule_name": self.rule_name,
            "fp_count": self.fp_count,
            "matched_files": self.matched_files[:10]  # Limit to 10 examples
        }


@dataclass
class FPCheckReport:
    """False positive check report."""
    timestamp: datetime
    total_files_scanned: int = 0
    total_rules_tested: int = 0
    problematic_rules: int = 0
    fp_threshold: float = 0.01
    rule_stats: Dict[str, RuleFPStats] = field(default_factory=dict)
    scanned_directories: List[str] = field(default_factory=list)
    
    def get_problematic_rules(self, threshold: Optional[float] = None) -> List[RuleFPStats]:
        """Get rules with FP rate above threshold."""
        threshold = threshold or self.fp_threshold
        max_fps = int(self.total_files_scanned * threshold)
        
        return [
            stats for stats in self.rule_stats.values()
            if stats.fp_count > max_fps
        ]
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_files_scanned": self.total_files_scanned,
            "total_rules_tested": self.total_rules_tested,
            "problematic_rules": self.problematic_rules,
            "fp_threshold": self.fp_threshold,
            "scanned_directories": self.scanned_directories,
            "rule_stats": {k: v.to_dict() for k, v in self.rule_stats.items()
                         if v.fp_count > 0}
        }
    
    def save_report(self, output_path: Path):
        """Save report to JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2)


class FalsePositiveChecker:
    """Tests YARA rules against known clean files."""
    
    def __init__(self, scanner: Optional[YARAScanner] = None):
        """
        Initialize the checker.
        
        Args:
            scanner: YARAScanner to use for scanning
        """
        self.config = get_config()
        self.scanner = scanner or YARAScanner()
        
        # FP checker config
        fp_config = self.config.fp_checker_config
        self.fp_threshold = fp_config.get('fp_threshold', 0.01)
        self.max_files_per_dir = fp_config.get('max_files_per_dir', 1000)
        self.extensions = fp_config.get('extensions', ['.exe', '.dll', '.sys'])
    
    def _resolve_goodware_paths(self, paths: List[str]) -> Tuple[List[Path], List[Path]]:
        """
        Resolve goodware paths. If a path is a .zip file, extract to temp dir.
        Returns (dirs to scan, temp dirs to cleanup after FP check).
        """
        dirs_to_scan: List[Path] = []
        temp_dirs: List[Path] = []
        
        for path_str in paths:
            path = Path(path_str).expanduser().resolve()
            if not path.exists():
                console.print(f"[yellow]Path not found: {path}[/yellow]")
                continue
            if path.suffix.lower() == '.zip' and path.is_file():
                try:
                    temp_dir = Path(tempfile.mkdtemp(prefix='fp_check_'))
                    with zipfile.ZipFile(path, 'r') as zf:
                        zf.extractall(temp_dir)
                    dirs_to_scan.append(temp_dir)
                    temp_dirs.append(temp_dir)
                    console.print(f"[cyan]Extracted zip for scanning: {path.name} -> {temp_dir}[/cyan]")
                except (zipfile.BadZipFile, OSError) as e:
                    console.print(f"[red]Failed to extract {path}: {e}[/red]")
            elif path.is_dir():
                dirs_to_scan.append(path)
            else:
                console.print(f"[yellow]Skipping (not dir or zip): {path}[/yellow]")
        
        return dirs_to_scan, temp_dirs
    
    def collect_goodware_files(self, directories: Optional[List[str]] = None,
                                max_files: Optional[int] = None) -> Tuple[List[Path], List[Path]]:
        """
        Collect known clean files from specified directories or zip files.
        Zip files are extracted to temp, scanned, then temp is deleted by caller.
        
        Args:
            directories: Directories or .zip paths (uses config default if None)
            max_files: Maximum total files to collect
            
        Returns:
            Tuple of (list of file paths, list of temp dirs to cleanup)
        """
        paths = directories or self.config.goodware_paths
        dirs_to_scan, temp_dirs = self._resolve_goodware_paths(paths)
        max_files = max_files or (self.max_files_per_dir * len(paths))
        
        files: List[Path] = []
        
        for dir_path in dirs_to_scan:
            console.print(f"[cyan]Collecting files from: {dir_path}[/cyan]")
            
            count = 0
            for ext in self.extensions:
                for filepath in dir_path.rglob(f"*{ext}"):
                    if filepath.is_file() and count < self.max_files_per_dir:
                        files.append(filepath)
                        count += 1
                
                if count >= self.max_files_per_dir:
                    break
            
            console.print(f"  Found {count} files")
            
            if len(files) >= max_files:
                break
        
        console.print(f"[green]Total goodware files: {len(files)}[/green]")
        return files[:max_files], temp_dirs
    
    def check_rules(self, goodware_dirs: Optional[List[str]] = None,
                    max_files: Optional[int] = None,
                    threshold: Optional[float] = None) -> FPCheckReport:
        """
        Check YARA rules for false positives against goodware.
        
        Args:
            goodware_dirs: Directories containing known clean files
            max_files: Maximum files to scan
            threshold: FP rate threshold for flagging rules
            
        Returns:
            FPCheckReport
        """
        threshold = threshold or self.fp_threshold
        
        report = FPCheckReport(
            timestamp=datetime.now(),
            fp_threshold=threshold,
            scanned_directories=goodware_dirs or self.config.goodware_paths
        )
        
        # Collect goodware files (may extract zips to temp dirs)
        console.print("\n[bold blue]Collecting Goodware Files[/bold blue]\n")
        files, temp_dirs = self.collect_goodware_files(goodware_dirs, max_files)
        
        try:
            if not files:
                console.print("[red]No files to scan[/red]")
                return report
            
            report.total_files_scanned = len(files)
            
            # Scan all files
            console.print(f"\n[bold blue]Scanning {len(files)} Files for False Positives[/bold blue]\n")
            
            with Progress() as progress:
                task = progress.add_task("Scanning goodware...", total=len(files))
                
                for filepath in files:
                    result = self.scanner.scan_file(filepath)
                    
                    if result.is_malicious:
                        # Record FPs for each matched rule
                        for match in result.matches:
                            rule_name = match.rule_name
                            
                            if rule_name not in report.rule_stats:
                                report.rule_stats[rule_name] = RuleFPStats(rule_name=rule_name)
                            
                            report.rule_stats[rule_name].fp_count += 1
                            report.rule_stats[rule_name].matched_files.append(str(filepath.name))
                    
                    progress.advance(task)
        finally:
            # Cleanup temp dirs from zip extraction (keep original zip files)
            for temp_dir in temp_dirs:
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    console.print(f"[dim]Cleaned up temp: {temp_dir}[/dim]")
                except OSError:
                    pass
        
        # Calculate stats
        # Note: yara.Rules object doesn't support len(), so we can't count rules directly
        # We track the number of unique rules that matched something instead
        report.total_rules_tested = len(report.rule_stats)  # Rules that had at least one match
        problematic = report.get_problematic_rules(threshold)
        report.problematic_rules = len(problematic)
        
        return report
    
    def print_report(self, report: FPCheckReport, verbose: bool = False):
        """Print FP check report to console."""
        console.print(f"\n[bold]False Positive Check Report[/bold]")
        console.print(f"Timestamp: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        console.print(f"Files scanned: {report.total_files_scanned}")
        console.print(f"FP threshold: {report.fp_threshold * 100:.1f}%")
        
        # Summary
        rules_with_fp = len([s for s in report.rule_stats.values() if s.fp_count > 0])
        console.print(f"\n[cyan]Rules with any FP: {rules_with_fp}[/cyan]")
        console.print(f"[red]Problematic rules (above threshold): {report.problematic_rules}[/red]")
        
        # Problematic rules table
        problematic = report.get_problematic_rules()
        
        if problematic:
            console.print(f"\n[bold red]Problematic Rules (FP rate > {report.fp_threshold*100:.1f}%):[/bold red]\n")
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("Rule Name", style="red")
            table.add_column("FP Count")
            table.add_column("FP Rate")
            table.add_column("Example Files")
            
            # Sort by FP count
            problematic.sort(key=lambda x: x.fp_count, reverse=True)
            
            for stats in problematic[:20]:  # Top 20
                fp_rate = stats.fp_count / report.total_files_scanned * 100
                examples = ", ".join(stats.matched_files[:3])
                if len(stats.matched_files) > 3:
                    examples += f" (+{len(stats.matched_files)-3} more)"
                
                table.add_row(
                    stats.rule_name[:50],
                    str(stats.fp_count),
                    f"{fp_rate:.2f}%",
                    examples[:50]
                )
            
            console.print(table)
        
        # All rules with FPs
        if verbose and rules_with_fp > 0:
            console.print(f"\n[bold yellow]All Rules with False Positives:[/bold yellow]\n")
            
            all_fp_rules = sorted(
                [s for s in report.rule_stats.values() if s.fp_count > 0],
                key=lambda x: x.fp_count,
                reverse=True
            )
            
            for stats in all_fp_rules:
                fp_rate = stats.fp_count / report.total_files_scanned * 100
                console.print(f"  {stats.rule_name}: {stats.fp_count} FPs ({fp_rate:.2f}%)")
    
    def generate_exclude_list(self, report: FPCheckReport, 
                              output_path: Optional[Path] = None) -> List[str]:
        """
        Generate a list of rules to exclude due to high FP rate.
        
        Args:
            report: FP check report
            output_path: Optional path to save the list
            
        Returns:
            List of rule names to exclude
        """
        problematic = report.get_problematic_rules()
        exclude_list = [stats.rule_name for stats in problematic]
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# YARA Rules to Exclude (High False Positive Rate)\n")
                f.write(f"# Generated: {report.timestamp.isoformat()}\n")
                f.write(f"# Threshold: {report.fp_threshold * 100:.1f}%\n")
                f.write(f"# Files scanned: {report.total_files_scanned}\n\n")
                
                for rule in exclude_list:
                    stats = report.rule_stats[rule]
                    fp_rate = stats.fp_count / report.total_files_scanned * 100
                    f.write(f"{rule}  # FP rate: {fp_rate:.2f}%\n")
            
            console.print(f"[green]Exclude list saved to: {output_path}[/green]")
        
        return exclude_list


def check_false_positives(goodware_dirs: Optional[List[str]] = None,
                          threshold: float = 0.01,
                          max_files: int = 1000) -> FPCheckReport:
    """
    Convenience function to check for false positives.
    
    Args:
        goodware_dirs: Directories with known clean files
        threshold: FP rate threshold
        max_files: Maximum files to scan
        
    Returns:
        FPCheckReport
    """
    checker = FalsePositiveChecker()
    report = checker.check_rules(
        goodware_dirs=goodware_dirs,
        threshold=threshold,
        max_files=max_files
    )
    
    checker.print_report(report)
    
    # Save report
    config = get_config()
    report_path = config.reports_dir / f"fp_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report.save_report(report_path)
    console.print(f"\n[green]Report saved to: {report_path}[/green]")
    
    # Generate exclude list if there are problematic rules
    if report.problematic_rules > 0:
        exclude_path = config.rules_dir / "exclude_rules.txt"
        checker.generate_exclude_list(report, exclude_path)
    
    return report


if __name__ == "__main__":
    import sys
    
    # Default to Windows system directories
    default_dirs = ["C:\\Windows\\System32"]
    
    if len(sys.argv) > 1:
        dirs = sys.argv[1:]
    else:
        dirs = default_dirs
    
    console.print("[bold]YARA Rule False Positive Checker[/bold]")
    console.print(f"Scanning directories: {dirs}\n")
    
    report = check_false_positives(goodware_dirs=dirs, max_files=500)
    console.print(f"\nCheck complete: {report.problematic_rules} problematic rules found")
