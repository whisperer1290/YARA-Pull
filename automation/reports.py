"""
Report Generation

Generates various reports for the YARA automation system:
- Coverage reports (which families have samples)
- Scan statistics
- Validation summaries
- Rule effectiveness metrics
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

from .config import get_config
from .database import Database

console = Console()


class ReportGenerator:
    """Generates reports for YARA automation."""
    
    def __init__(self):
        self.config = get_config()
        self.db = Database()
    
    def generate_coverage_report(self) -> Dict[str, Any]:
        """
        Generate a coverage report showing which families have samples.
        
        Returns:
            Coverage report dictionary
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "type": "coverage",
            "families": {}
        }
        
        # Get configured families
        configured_families = self.config.malware_families
        
        # Count samples per family
        samples_dir = self.config.samples_dir
        
        for family in configured_families:
            family_dir = samples_dir / family
            sample_count = 0
            
            if family_dir.exists():
                sample_count = len(list(family_dir.glob("*.bin")))
            
            report["families"][family] = {
                "configured": True,
                "sample_count": sample_count,
                "has_samples": sample_count > 0
            }
        
        # Also check for other families in samples dir
        if samples_dir.exists():
            for family_dir in samples_dir.iterdir():
                if family_dir.is_dir() and family_dir.name not in configured_families:
                    sample_count = len(list(family_dir.glob("*.bin")))
                    report["families"][family_dir.name] = {
                        "configured": False,
                        "sample_count": sample_count,
                        "has_samples": sample_count > 0
                    }
        
        # Summary stats
        total_families = len(report["families"])
        families_with_samples = sum(1 for f in report["families"].values() if f["has_samples"])
        total_samples = sum(f["sample_count"] for f in report["families"].values())
        
        report["summary"] = {
            "total_families": total_families,
            "families_with_samples": families_with_samples,
            "families_without_samples": total_families - families_with_samples,
            "total_samples": total_samples,
            "coverage_percentage": (families_with_samples / total_families * 100) if total_families > 0 else 0
        }
        
        return report
    
    def generate_scan_report(self) -> Dict[str, Any]:
        """
        Generate a scan statistics report.
        
        Returns:
            Scan report dictionary
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "type": "scan_statistics",
            "database_stats": self.db.get_statistics(),
            "top_rules": self.db.get_top_rules(limit=20),
            "high_fp_rules": self.db.get_high_fp_rules(min_fp_count=1)
        }
        
        return report
    
    def generate_validation_report(self) -> Dict[str, Any]:
        """
        Generate a validation summary report.
        
        Returns:
            Validation report dictionary
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "type": "validation",
            "stats": self.db.get_validation_stats(),
            "rule_sources": self.db.get_rule_sources()
        }
        
        # Calculate rates
        stats = report["stats"]
        total = sum(stats.values()) if stats else 0
        
        if total > 0:
            report["rates"] = {
                status: count / total * 100 
                for status, count in stats.items()
            }
        else:
            report["rates"] = {}
        
        return report
    
    def generate_full_report(self) -> Dict[str, Any]:
        """Generate a comprehensive report including all metrics."""
        return {
            "timestamp": datetime.now().isoformat(),
            "type": "full",
            "coverage": self.generate_coverage_report(),
            "scans": self.generate_scan_report(),
            "validation": self.generate_validation_report()
        }
    
    def save_report(self, report: Dict[str, Any], 
                    filename: Optional[str] = None) -> Path:
        """
        Save report to JSON file.
        
        Args:
            report: Report dictionary
            filename: Optional filename (auto-generated if None)
            
        Returns:
            Path to saved report
        """
        reports_dir = self.config.reports_dir
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        if not filename:
            report_type = report.get("type", "report")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{report_type}_{timestamp}.json"
        
        output_path = reports_dir / filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        return output_path
    
    def print_coverage_report(self, report: Optional[Dict] = None):
        """Print coverage report to console."""
        if report is None:
            report = self.generate_coverage_report()
        
        summary = report.get("summary", {})
        families = report.get("families", {})
        
        console.print("\n[bold]Sample Coverage Report[/bold]")
        console.print(f"Generated: {report.get('timestamp', 'Unknown')}")
        
        console.print(f"\n[cyan]Summary:[/cyan]")
        console.print(f"  Total families: {summary.get('total_families', 0)}")
        console.print(f"  With samples: {summary.get('families_with_samples', 0)}")
        console.print(f"  Without samples: {summary.get('families_without_samples', 0)}")
        console.print(f"  Total samples: {summary.get('total_samples', 0)}")
        console.print(f"  Coverage: {summary.get('coverage_percentage', 0):.1f}%")
        
        # Families table
        table = Table(title="Family Coverage", show_header=True, header_style="bold")
        table.add_column("Family", style="cyan")
        table.add_column("Samples", justify="right")
        table.add_column("Status")
        table.add_column("Configured")
        
        # Sort by sample count
        sorted_families = sorted(
            families.items(),
            key=lambda x: x[1]["sample_count"],
            reverse=True
        )
        
        for family, info in sorted_families:
            status = "[green]✓[/green]" if info["has_samples"] else "[red]✗[/red]"
            configured = "Yes" if info["configured"] else "No"
            
            table.add_row(
                family,
                str(info["sample_count"]),
                status,
                configured
            )
        
        console.print("\n")
        console.print(table)
    
    def print_scan_report(self, report: Optional[Dict] = None):
        """Print scan statistics report."""
        if report is None:
            report = self.generate_scan_report()
        
        db_stats = report.get("database_stats", {})
        top_rules = report.get("top_rules", [])
        
        console.print("\n[bold]Scan Statistics Report[/bold]")
        
        console.print(f"\n[cyan]Database Statistics:[/cyan]")
        console.print(f"  Total samples: {db_stats.get('total_samples', 0)}")
        console.print(f"  Total scans: {db_stats.get('total_scans', 0)}")
        console.print(f"  Tracked rules: {db_stats.get('tracked_rules', 0)}")
        
        if top_rules:
            console.print(f"\n[cyan]Top Matching Rules:[/cyan]")
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("Rule Name", style="cyan")
            table.add_column("Matches", justify="right")
            table.add_column("FP Count", justify="right")
            
            for rule in top_rules[:10]:
                table.add_row(
                    rule.get("rule_name", "Unknown")[:40],
                    str(rule.get("total_matches", 0)),
                    str(rule.get("fp_count", 0))
                )
            
            console.print(table)


def generate_report(report_type: str = "full") -> Dict[str, Any]:
    """
    Convenience function to generate a report.
    
    Args:
        report_type: Type of report ("coverage", "scan", "validation", "full")
        
    Returns:
        Report dictionary
    """
    generator = ReportGenerator()
    
    if report_type == "coverage":
        report = generator.generate_coverage_report()
        generator.print_coverage_report(report)
    elif report_type == "scan":
        report = generator.generate_scan_report()
        generator.print_scan_report(report)
    elif report_type == "validation":
        report = generator.generate_validation_report()
    else:
        report = generator.generate_full_report()
        generator.print_coverage_report(report.get("coverage"))
        generator.print_scan_report(report.get("scans"))
    
    # Save report
    output_path = generator.save_report(report)
    console.print(f"\n[green]Report saved to: {output_path}[/green]")
    
    return report


if __name__ == "__main__":
    # Generate full report
    generate_report("full")
