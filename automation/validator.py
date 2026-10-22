"""
Sample Validator

Validates that downloaded malware samples match their expected YARA rules.
Compares expected family/tag with actual YARA matches.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from rich.console import Console
from rich.table import Table

from .config import get_config
from .scanner import YARAScanner, ScanResult

console = Console()


@dataclass
class ValidationResult:
    """Result of validating a sample."""
    filepath: Path
    file_hash: str
    expected_family: str
    matched_families: Set[str]
    matched_rules: List[str]
    status: str  # "valid", "mismatch", "no_match", "error"
    error: Optional[str] = None
    
    @property
    def is_valid(self) -> bool:
        """Check if sample matched expected family."""
        return self.status == "valid"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "filepath": str(self.filepath),
            "file_hash": self.file_hash,
            "expected_family": self.expected_family,
            "matched_families": list(self.matched_families),
            "matched_rules": self.matched_rules,
            "status": self.status,
            "error": self.error
        }


@dataclass
class ValidationReport:
    """Aggregated validation report."""
    timestamp: datetime
    total_samples: int = 0
    valid_count: int = 0
    mismatch_count: int = 0
    no_match_count: int = 0
    error_count: int = 0
    results: List[ValidationResult] = field(default_factory=list)
    
    @property
    def summary(self) -> str:
        """Get summary string."""
        return (f"Total: {self.total_samples}, "
                f"Valid: {self.valid_count}, "
                f"Mismatch: {self.mismatch_count}, "
                f"No Match: {self.no_match_count}, "
                f"Errors: {self.error_count}")
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_samples": self.total_samples,
            "valid_count": self.valid_count,
            "mismatch_count": self.mismatch_count,
            "no_match_count": self.no_match_count,
            "error_count": self.error_count,
            "results": [r.to_dict() for r in self.results]
        }
    
    def save_report(self, output_path: Path):
        """Save report to JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2)


class SampleValidator:
    """Validates malware samples against expected YARA matches."""
    
    # Mapping of common family name variations
    FAMILY_ALIASES = {
        "cobaltstrike": ["cobalt_strike", "cobalt-strike", "cs_beacon", "beacon"],
        "asyncrat": ["async_rat", "async-rat"],
        "agenttesla": ["agent_tesla", "agent-tesla"],
        "redline": ["red_line", "red-line", "redlinestealer"],
        "lockbit": ["lock_bit", "lock-bit"],
        "darkgate": ["dark_gate", "dark-gate"],
        "quasar": ["quasarrat", "quasar_rat"],
        "xworm": ["x_worm", "x-worm"],
        "mimikatz": ["mimi_katz"],
        "raccoon": ["raccoonstealer", "raccoon_stealer"],
    }
    
    def __init__(self, scanner: Optional[YARAScanner] = None):
        """
        Initialize validator.
        
        Args:
            scanner: YARAScanner to use for scanning
        """
        self.config = get_config()
        self.scanner = scanner or YARAScanner()
    
    def _normalize_family(self, family: str) -> str:
        """Normalize family name for comparison."""
        normalized = family.lower().replace("-", "_").replace(" ", "_")
        
        # Check aliases
        for canonical, aliases in self.FAMILY_ALIASES.items():
            if normalized == canonical or normalized in aliases:
                return canonical
        
        return normalized
    
    def _families_match(self, expected: str, detected: Set[str]) -> bool:
        """Check if expected family matches any detected families."""
        expected_norm = self._normalize_family(expected)
        
        for family in detected:
            if self._normalize_family(family) == expected_norm:
                return True
            
            # Also check if expected is substring of detected or vice versa
            family_norm = self._normalize_family(family)
            if expected_norm in family_norm or family_norm in expected_norm:
                return True
        
        # Check if expected appears in any rule names
        return False
    
    def validate_sample(self, filepath: Path, expected_family: str) -> ValidationResult:
        """
        Validate a single sample against expected family.
        
        Args:
            filepath: Path to sample file
            expected_family: Expected malware family name
            
        Returns:
            ValidationResult
        """
        # Scan the file
        scan_result = self.scanner.scan_file(filepath)
        
        if scan_result.error:
            return ValidationResult(
                filepath=filepath,
                file_hash=scan_result.file_hash,
                expected_family=expected_family,
                matched_families=set(),
                matched_rules=[],
                status="error",
                error=scan_result.error
            )
        
        if not scan_result.is_malicious:
            return ValidationResult(
                filepath=filepath,
                file_hash=scan_result.file_hash,
                expected_family=expected_family,
                matched_families=set(),
                matched_rules=[],
                status="no_match"
            )
        
        # Check if expected family was matched
        matched_families = scan_result.families
        matched_rules = scan_result.rule_names
        
        # Also check rule names for family matches
        expected_norm = self._normalize_family(expected_family)
        rule_family_match = any(
            expected_norm in self._normalize_family(rule) 
            for rule in matched_rules
        )
        
        if self._families_match(expected_family, matched_families) or rule_family_match:
            status = "valid"
        else:
            status = "mismatch"
        
        return ValidationResult(
            filepath=filepath,
            file_hash=scan_result.file_hash,
            expected_family=expected_family,
            matched_families=matched_families,
            matched_rules=matched_rules,
            status=status
        )
    
    def validate_directory(self, directory: Path, expected_family: str) -> List[ValidationResult]:
        """
        Validate all samples in a directory.
        
        Args:
            directory: Directory containing samples
            expected_family: Expected family for all samples in directory
            
        Returns:
            List of ValidationResults
        """
        results = []
        directory = Path(directory)
        
        if not directory.exists():
            console.print(f"[red]Directory not found: {directory}[/red]")
            return results
        
        files = list(directory.glob("*"))
        files = [f for f in files if f.is_file()]
        
        console.print(f"[cyan]Validating {len(files)} samples in {directory.name}[/cyan]")
        
        for filepath in files:
            result = self.validate_sample(filepath, expected_family)
            results.append(result)
        
        return results
    
    def validate_all_samples(self) -> ValidationReport:
        """
        Validate all samples in the samples directory.
        
        Assumes directory structure: samples/{family}/*.bin
        
        Returns:
            ValidationReport
        """
        report = ValidationReport(timestamp=datetime.now())
        
        samples_dir = self.config.samples_dir
        
        if not samples_dir.exists():
            console.print(f"[yellow]Samples directory not found: {samples_dir}[/yellow]")
            return report
        
        # Get family directories
        family_dirs = [d for d in samples_dir.iterdir() if d.is_dir()]
        
        if not family_dirs:
            console.print("[yellow]No family directories found in samples[/yellow]")
            return report
        
        console.print(f"\n[bold blue]Validating samples in {len(family_dirs)} families[/bold blue]\n")
        
        for family_dir in family_dirs:
            family_name = family_dir.name
            results = self.validate_directory(family_dir, family_name)
            
            for result in results:
                report.results.append(result)
                report.total_samples += 1
                
                if result.status == "valid":
                    report.valid_count += 1
                elif result.status == "mismatch":
                    report.mismatch_count += 1
                elif result.status == "no_match":
                    report.no_match_count += 1
                else:
                    report.error_count += 1
        
        return report
    
    def print_report(self, report: ValidationReport, verbose: bool = False):
        """Print validation report to console."""
        console.print(f"\n[bold]Validation Report[/bold]")
        console.print(f"Timestamp: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        console.print(f"\n{report.summary}\n")
        
        # Summary table
        table = Table(title="Validation Summary", show_header=True, header_style="bold")
        table.add_column("Status", style="cyan")
        table.add_column("Count")
        table.add_column("Percentage")
        
        if report.total_samples > 0:
            table.add_row("Valid", str(report.valid_count), 
                         f"{report.valid_count/report.total_samples*100:.1f}%")
            table.add_row("Mismatch", str(report.mismatch_count),
                         f"{report.mismatch_count/report.total_samples*100:.1f}%")
            table.add_row("No Match", str(report.no_match_count),
                         f"{report.no_match_count/report.total_samples*100:.1f}%")
            table.add_row("Error", str(report.error_count),
                         f"{report.error_count/report.total_samples*100:.1f}%")
        
        console.print(table)
        
        # Show mismatches
        if report.mismatch_count > 0:
            console.print(f"\n[bold yellow]Mismatched Samples:[/bold yellow]\n")
            
            mismatch_table = Table(show_header=True, header_style="bold")
            mismatch_table.add_column("File", style="cyan")
            mismatch_table.add_column("Expected")
            mismatch_table.add_column("Detected", style="yellow")
            
            for result in report.results:
                if result.status == "mismatch":
                    detected = ", ".join(result.matched_families) if result.matched_families else "Unknown"
                    mismatch_table.add_row(
                        result.filepath.name,
                        result.expected_family,
                        detected
                    )
            
            console.print(mismatch_table)
        
        # Show no-match samples
        if report.no_match_count > 0 and verbose:
            console.print(f"\n[bold red]Samples with No YARA Match:[/bold red]\n")
            
            for result in report.results:
                if result.status == "no_match":
                    console.print(f"  • {result.filepath.name} (expected: {result.expected_family})")


def validate_all_samples() -> ValidationReport:
    """Convenience function to validate all samples."""
    validator = SampleValidator()
    report = validator.validate_all_samples()
    validator.print_report(report)
    
    # Save report
    config = get_config()
    report_path = config.reports_dir / f"validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report.save_report(report_path)
    console.print(f"\n[green]Report saved to: {report_path}[/green]")
    
    return report


def validate_sample(filepath: Path, expected_family: str) -> ValidationResult:
    """Convenience function to validate a single sample."""
    validator = SampleValidator()
    return validator.validate_sample(filepath, expected_family)


if __name__ == "__main__":
    # Test validation
    report = validate_all_samples()
    print(f"\nValidation complete: {report.summary}")
