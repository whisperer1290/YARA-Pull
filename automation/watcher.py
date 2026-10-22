"""
Folder Watcher

Monitors directories for new files and automatically scans them with YARA rules.
Uses watchdog library for file system events.
"""

import shutil
import threading
import time
from pathlib import Path
from queue import Queue
from typing import Callable, List, Optional

from rich.console import Console

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from .config import get_config
from .scanner import YARAScanner, ScanResult

console = Console()


class SampleHandler(FileSystemEventHandler):
    """Handler for file system events in watched directories."""
    
    def __init__(self, scanner: YARAScanner, 
                 on_match: Optional[Callable[[ScanResult], None]] = None,
                 on_no_match: Optional[Callable[[ScanResult], None]] = None,
                 patterns: Optional[List[str]] = None,
                 ignore_patterns: Optional[List[str]] = None,
                 debounce_seconds: float = 2.0):
        """
        Initialize the handler.
        
        Args:
            scanner: YARAScanner instance to use
            on_match: Callback when file matches YARA rules
            on_no_match: Callback when file doesn't match any rules
            patterns: File patterns to watch (e.g., ["*.exe", "*.dll"])
            ignore_patterns: Patterns to ignore
            debounce_seconds: Wait time before scanning (for file write completion)
        """
        super().__init__()
        self.scanner = scanner
        self.on_match = on_match
        self.on_no_match = on_no_match
        self.patterns = patterns or ["*"]
        self.ignore_patterns = ignore_patterns or []
        self.debounce_seconds = debounce_seconds
        
        # Queue for debouncing file events
        self._pending_files: dict = {}
        self._lock = threading.Lock()
        
        # Start debounce processor thread
        self._running = True
        self._processor_thread = threading.Thread(target=self._process_pending, daemon=True)
        self._processor_thread.start()
    
    def _should_process(self, path: str) -> bool:
        """Check if file should be processed based on patterns."""
        filepath = Path(path)
        
        # Check ignore patterns
        for pattern in self.ignore_patterns:
            if filepath.match(pattern):
                return False
        
        # Check include patterns
        if self.patterns == ["*"]:
            return True
        
        for pattern in self.patterns:
            if filepath.match(pattern):
                return True
        
        return False
    
    def _process_pending(self):
        """Background thread to process pending files after debounce period."""
        while self._running:
            current_time = time.time()
            files_to_scan = []
            
            with self._lock:
                # Find files ready to scan
                for filepath, queued_time in list(self._pending_files.items()):
                    if current_time - queued_time >= self.debounce_seconds:
                        files_to_scan.append(filepath)
                        del self._pending_files[filepath]
            
            # Scan files
            for filepath in files_to_scan:
                self._scan_file(filepath)
            
            time.sleep(0.5)
    
    def _scan_file(self, filepath: str):
        """Scan a file and handle the result."""
        path = Path(filepath)
        
        if not path.exists():
            return
        
        if not path.is_file():
            return
        
        console.print(f"[cyan]Scanning new file: {path.name}[/cyan]")
        
        # Try to reload rules if not loaded (may have been fixed since startup)
        if not self.scanner.rules:
            console.print(f"[yellow]Attempting to reload YARA rules...[/yellow]")
            self.scanner.reload_rules()
        
        result = self.scanner.scan_file(path)
        
        if result.error:
            # If still "No YARA rules loaded", try one more reload
            if "No YARA rules loaded" in result.error and self.scanner.rules_path.exists():
                self.scanner.reload_rules()
                if self.scanner.rules:
                    result = self.scanner.scan_file(path)
            
            if result.error:
                console.print(f"[yellow]Scan error: {result.error}[/yellow]")
                return
        
        if result.is_malicious:
            console.print(f"[red]MATCH: {path.name} -> {', '.join(result.rule_names[:3])}[/red]")
            if self.on_match:
                self.on_match(result)
        else:
            console.print(f"[dim]No match: {path.name}[/dim]")
            if self.on_no_match:
                self.on_no_match(result)
    
    def on_created(self, event):
        """Handle file creation events."""
        if event.is_directory:
            return
        
        if self._should_process(event.src_path):
            with self._lock:
                self._pending_files[event.src_path] = time.time()
    
    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return
        
        if self._should_process(event.src_path):
            with self._lock:
                # Update timestamp for debouncing
                self._pending_files[event.src_path] = time.time()
    
    def stop(self):
        """Stop the handler."""
        self._running = False


class FolderWatcher:
    """Watches folders for new files and scans them automatically."""
    
    def __init__(self, scanner: Optional[YARAScanner] = None):
        """
        Initialize the folder watcher.
        
        Args:
            scanner: YARAScanner to use (creates new one if not provided)
        """
        if not WATCHDOG_AVAILABLE:
            raise ImportError("watchdog library is not installed")
        
        self.config = get_config()
        self.scanner = scanner or YARAScanner()
        self.observer = Observer()
        self._handlers: List[SampleHandler] = []
    
    def add_watch(self, directory: Path,
                  on_match: Optional[Callable[[ScanResult], None]] = None,
                  on_no_match: Optional[Callable[[ScanResult], None]] = None,
                  patterns: Optional[List[str]] = None,
                  ignore_patterns: Optional[List[str]] = None,
                  recursive: bool = True):
        """
        Add a directory to watch.
        
        Args:
            directory: Directory to watch
            on_match: Callback for matched files
            on_no_match: Callback for unmatched files
            patterns: File patterns to include
            ignore_patterns: File patterns to exclude
            recursive: Watch subdirectories
        """
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        
        handler = SampleHandler(
            scanner=self.scanner,
            on_match=on_match,
            on_no_match=on_no_match,
            patterns=patterns or self.config.watcher_config.get('patterns', ["*"]),
            ignore_patterns=ignore_patterns or self.config.watcher_config.get('ignore_patterns', [])
        )
        
        self.observer.schedule(handler, str(directory), recursive=recursive)
        self._handlers.append(handler)
        
        console.print(f"[green]Watching: {directory}[/green]")
    
    def watch_samples_dir(self,
                          on_match: Optional[Callable[[ScanResult], None]] = None,
                          on_no_match: Optional[Callable[[ScanResult], None]] = None):
        """Watch the configured samples directory."""
        self.add_watch(
            self.config.samples_dir,
            on_match=on_match,
            on_no_match=on_no_match
        )
    
    def reload_rules(self) -> bool:
        """
        Reload YARA rules for the scanner.
        
        Call this after rules have been updated to ensure the watcher
        uses the latest rules.
        
        Returns:
            True if rules loaded successfully, False otherwise
        """
        console.print("[cyan]Reloading YARA rules for watcher...[/cyan]")
        self.scanner.reload_rules()
        
        if self.scanner.rules:
            console.print("[green]YARA rules reloaded successfully[/green]")
            return True
        else:
            console.print("[yellow]Failed to reload YARA rules[/yellow]")
            return False
    
    def start(self, blocking: bool = True):
        """
        Start watching directories.
        
        Args:
            blocking: If True, block until interrupted
        """
        self.observer.start()
        console.print("[bold green]Folder watcher started[/bold green]")
        
        if blocking:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()
    
    def stop(self):
        """Stop the watcher."""
        console.print("[yellow]Stopping folder watcher...[/yellow]")
        
        for handler in self._handlers:
            handler.stop()
        
        self.observer.stop()
        self.observer.join()
        
        console.print("[green]Folder watcher stopped[/green]")


def default_match_handler(result: ScanResult):
    """Default handler for matched files - moves to samples dir organized by family."""
    config = get_config()
    
    # Get primary family or use "unknown"
    family = list(result.families)[0] if result.families else "unknown"
    
    # Target directory
    target_dir = config.samples_dir / family
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Move file
    target_path = target_dir / f"{result.file_hash}.bin"
    
    if result.filepath != target_path and result.filepath.exists():
        shutil.move(str(result.filepath), str(target_path))
        console.print(f"[green]Moved to: {target_path}[/green]")


def default_no_match_handler(result: ScanResult):
    """Default handler for unmatched files - moves to quarantine."""
    config = get_config()
    
    # Move to quarantine
    target_dir = config.quarantine_dir / "unmatched"
    target_dir.mkdir(parents=True, exist_ok=True)
    
    target_path = target_dir / f"{result.file_hash}.bin"
    
    if result.filepath != target_path and result.filepath.exists():
        shutil.move(str(result.filepath), str(target_path))
        console.print(f"[yellow]Quarantined: {target_path}[/yellow]")


def start_watcher(watch_dir: Optional[Path] = None, 
                  move_matches: bool = True,
                  quarantine_no_match: bool = True):
    """
    Convenience function to start folder watcher with default handlers.
    
    Args:
        watch_dir: Directory to watch (uses config default if None)
        move_matches: Automatically organize matched files by family
        quarantine_no_match: Move unmatched files to quarantine
    """
    watcher = FolderWatcher()
    
    on_match = default_match_handler if move_matches else None
    on_no_match = default_no_match_handler if quarantine_no_match else None
    
    if watch_dir:
        watcher.add_watch(watch_dir, on_match=on_match, on_no_match=on_no_match)
    else:
        watcher.watch_samples_dir(on_match=on_match, on_no_match=on_no_match)
    
    watcher.start(blocking=True)


if __name__ == "__main__":
    # Test the watcher
    console.print("[bold]Starting folder watcher in test mode[/bold]")
    console.print("Drop files into the samples directory to test scanning")
    console.print("Press Ctrl+C to stop\n")
    
    start_watcher()
