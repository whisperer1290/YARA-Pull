"""
YARA Scanner

Enhanced YARA scanner with:
- Batch scanning support
- Family extraction from rule metadata
- Detailed match reporting
- Timeout handling
"""

import hashlib
import os
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from .config import get_config

console = Console()


@dataclass
class ScanMatch:
    """Represents a YARA rule match."""
    rule_name: str
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    strings: List[tuple] = field(default_factory=list)
    namespace: str = ""
    
    @property
    def family(self) -> Optional[str]:
        """Extract malware family from rule metadata or name."""
        # Try common metadata fields
        for key in ['family', 'malware_family', 'malware', 'threat_name', 
                    'tc_detection_name', 'detection_name']:
            if key in self.meta:
                return str(self.meta[key])
        
        # Try to extract from rule name
        # Common patterns: MALWARE_Win_FamilyName, Win_Trojan_FamilyName
        name_parts = self.rule_name.split('_')
        if len(name_parts) >= 3:
            return name_parts[-1]
        
        return None
    
    @property
    def description(self) -> Optional[str]:
        """Get rule description from metadata."""
        return self.meta.get('description', self.meta.get('desc'))
    
    @property
    def author(self) -> Optional[str]:
        """Get rule author from metadata."""
        return self.meta.get('author')
    
    @property
    def reference(self) -> Optional[str]:
        """Get rule reference from metadata."""
        return self.meta.get('reference', self.meta.get('ref', self.meta.get('source_url')))


@dataclass
class ScanResult:
    """Result of scanning a file."""
    filepath: Path
    file_hash: str
    file_size: int
    matches: List[ScanMatch] = field(default_factory=list)
    scan_time: float = 0.0
    error: Optional[str] = None
    
    @property
    def is_malicious(self) -> bool:
        """Check if file matched any rules."""
        return len(self.matches) > 0
    
    @property
    def families(self) -> Set[str]:
        """Get all detected malware families."""
        families = set()
        for match in self.matches:
            if match.family:
                families.add(match.family)
        return families
    
    @property
    def rule_names(self) -> List[str]:
        """Get all matched rule names."""
        return [m.rule_name for m in self.matches]


class YARAScanner:
    """YARA scanner with batch support and metadata extraction."""
    
    def __init__(self, rules_path: Optional[Path] = None):
        """
        Initialize scanner with YARA rules.
        
        Args:
            rules_path: Path to YARA rules file or directory
        """
        if not YARA_AVAILABLE:
            raise ImportError("yara-python is not installed")
        
        self.config = get_config()
        self.rules_path = rules_path or self.config.rules_dir / "all-rules.yar"
        self.rules: Optional[yara.Rules] = None
        self.timeout = self.config.scanner_config.get('timeout', 30)
        self.max_file_size = self.config.scanner_config.get('max_file_size', 104857600)
        
        self._load_rules()
    
    def _load_rules(self) -> None:
        """Load YARA rules from file or directory."""
        if not self.rules_path.exists():
            console.print(f"[yellow]Rules not found: {self.rules_path}[/yellow]")
            console.print("[yellow]Run 'update-rules' command first[/yellow]")
            return
        
        try:
            if self.rules_path.is_file():
                self.rules = yara.compile(filepath=str(self.rules_path))
            else:
                # Compile from directory
                rule_files = {}
                for yar_file in self.rules_path.glob("**/*.yar"):
                    rule_files[yar_file.stem] = str(yar_file)
                for yara_file in self.rules_path.glob("**/*.yara"):
                    rule_files[yara_file.stem] = str(yara_file)
                
                if rule_files:
                    self.rules = yara.compile(filepaths=rule_files)
            
            console.print(f"[green]Loaded YARA rules from {self.rules_path}[/green]")
            
        except yara.SyntaxError as e:
            console.print(f"[red]YARA syntax error: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Failed to load rules: {e}[/red]")
    
    def reload_rules(self) -> None:
        """Reload YARA rules from disk."""
        self._load_rules()
    
    def scan_file(self, filepath: Path, timeout: Optional[int] = None) -> ScanResult:
        """
        Scan a single file with YARA rules.
        
        Args:
            filepath: Path to file to scan
            timeout: Scan timeout in seconds
            
        Returns:
            ScanResult object
        """
        filepath = Path(filepath)
        timeout = timeout or self.timeout
        
        # Calculate file hash and size
        try:
            file_size = filepath.stat().st_size
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            return ScanResult(
                filepath=filepath,
                file_hash="",
                file_size=0,
                error=f"Cannot read file: {e}"
            )
        
        # Check file size
        if file_size > self.max_file_size:
            return ScanResult(
                filepath=filepath,
                file_hash=file_hash,
                file_size=file_size,
                error=f"File too large: {file_size} bytes"
            )
        
        if not self.rules:
            return ScanResult(
                filepath=filepath,
                file_hash=file_hash,
                file_size=file_size,
                error="No YARA rules loaded"
            )
        
        # Scan file
        start_time = time.time()
        matches = []
        error = None
        
        try:
            yara_matches = self.rules.match(str(filepath), timeout=timeout)
            
            for match in yara_matches:
                scan_match = ScanMatch(
                    rule_name=match.rule,
                    tags=list(match.tags) if match.tags else [],
                    meta=dict(match.meta) if match.meta else {},
                    strings=[(s.identifier, s.instances) for s in match.strings] if match.strings else [],
                    namespace=match.namespace
                )
                matches.append(scan_match)
                
        except yara.TimeoutError:
            error = f"Scan timeout after {timeout}s"
        except Exception as e:
            error = str(e)
        
        scan_time = time.time() - start_time
        
        return ScanResult(
            filepath=filepath,
            file_hash=file_hash,
            file_size=file_size,
            matches=matches,
            scan_time=scan_time,
            error=error
        )
    
    def scan_directory(self, directory: Path, recursive: bool = True,
                       extensions: Optional[List[str]] = None,
                       callback: Optional[Callable[[ScanResult], None]] = None) -> List[ScanResult]:
        """
        Scan all files in a directory.
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
            extensions: File extensions to scan (None = all)
            callback: Optional callback for each result
            
        Returns:
            List of ScanResult objects
        """
        directory = Path(directory)
        results = []
        
        if not directory.exists():
            console.print(f"[red]Directory not found: {directory}[/red]")
            return results
        
        # Collect files to scan
        if recursive:
            files = list(directory.rglob("*"))
        else:
            files = list(directory.glob("*"))
        
        # Filter by extension
        if extensions:
            ext_set = {e.lower().lstrip('.') for e in extensions}
            files = [f for f in files if f.is_file() and f.suffix.lower().lstrip('.') in ext_set]
        else:
            files = [f for f in files if f.is_file()]
        
        if not files:
            console.print(f"[yellow]No files found in {directory}[/yellow]")
            return results
        
        console.print(f"[cyan]Scanning {len(files)} files in {directory}[/cyan]")
        
        with Progress() as progress:
            task = progress.add_task("Scanning...", total=len(files))
            
            for filepath in files:
                result = self.scan_file(filepath)
                results.append(result)
                
                if callback:
                    callback(result)
                
                progress.advance(task)
        
        return results
    
    def scan_data(self, data: bytes, filename: str = "unknown") -> ScanResult:
        """
        Scan data in memory.
        
        Args:
            data: Bytes to scan
            filename: Name for reporting
            
        Returns:
            ScanResult object
        """
        if not self.rules:
            return ScanResult(
                filepath=Path(filename),
                file_hash=hashlib.sha256(data).hexdigest(),
                file_size=len(data),
                error="No YARA rules loaded"
            )
        
        start_time = time.time()
        matches = []
        error = None
        
        try:
            yara_matches = self.rules.match(data=data, timeout=self.timeout)
            
            for match in yara_matches:
                scan_match = ScanMatch(
                    rule_name=match.rule,
                    tags=list(match.tags) if match.tags else [],
                    meta=dict(match.meta) if match.meta else {},
                    strings=[(s.identifier, s.instances) for s in match.strings] if match.strings else [],
                    namespace=match.namespace
                )
                matches.append(scan_match)
                
        except yara.TimeoutError:
            error = f"Scan timeout after {self.timeout}s"
        except Exception as e:
            error = str(e)
        
        scan_time = time.time() - start_time
        
        return ScanResult(
            filepath=Path(filename),
            file_hash=hashlib.sha256(data).hexdigest(),
            file_size=len(data),
            matches=matches,
            scan_time=scan_time,
            error=error
        )
    
    def print_results(self, results: List[ScanResult], verbose: bool = False) -> None:
        """Print scan results in a formatted table."""
        # Summary
        total = len(results)
        malicious = sum(1 for r in results if r.is_malicious)
        errors = sum(1 for r in results if r.error)
        
        console.print(f"\n[bold]Scan Summary[/bold]")
        console.print(f"  Total files: {total}")
        console.print(f"  [red]Malicious: {malicious}[/red]")
        console.print(f"  [green]Clean: {total - malicious - errors}[/green]")
        if errors:
            console.print(f"  [yellow]Errors: {errors}[/yellow]")
        
        # Detailed results for matches
        if malicious > 0:
            console.print(f"\n[bold red]Detected Threats:[/bold red]\n")
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("File", style="cyan")
            table.add_column("Hash", style="dim")
            table.add_column("Rules", style="red")
            table.add_column("Families", style="yellow")
            
            for result in results:
                if result.is_malicious:
                    rules = ", ".join(result.rule_names[:3])
                    if len(result.rule_names) > 3:
                        rules += f" (+{len(result.rule_names) - 3} more)"
                    
                    families = ", ".join(result.families) if result.families else "Unknown"
                    
                    table.add_row(
                        result.filepath.name,
                        result.file_hash[:16] + "...",
                        rules,
                        families
                    )
            
            console.print(table)
            
            if verbose:
                console.print(f"\n[bold]Detailed Matches:[/bold]\n")
                for result in results:
                    if result.is_malicious:
                        console.print(f"\n[cyan]{result.filepath}[/cyan]")
                        console.print(f"  SHA256: {result.file_hash}")
                        for match in result.matches:
                            console.print(f"  [red]• {match.rule_name}[/red]")
                            if match.description:
                                console.print(f"    {match.description}")
                            if match.author:
                                console.print(f"    Author: {match.author}")


def scan_file(filepath: Path, rules_path: Optional[Path] = None) -> ScanResult:
    """Convenience function to scan a single file."""
    scanner = YARAScanner(rules_path)
    return scanner.scan_file(filepath)


def scan_directory(directory: Path, rules_path: Optional[Path] = None,
                   recursive: bool = True) -> List[ScanResult]:
    """Convenience function to scan a directory."""
    scanner = YARAScanner(rules_path)
    return scanner.scan_directory(directory, recursive)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <file_or_directory>")
        sys.exit(1)
    
    target = Path(sys.argv[1])
    scanner = YARAScanner()
    
    if target.is_file():
        result = scanner.scan_file(target)
        scanner.print_results([result], verbose=True)
    elif target.is_dir():
        results = scanner.scan_directory(target)
        scanner.print_results(results, verbose=True)
    else:
        print(f"Not found: {target}")
        sys.exit(1)
