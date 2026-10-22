"""
Logging Module for YARA Automation

Provides dual logging:
- Detailed logs to file (with timestamps, levels, etc.)
- Concise output to terminal (via Rich console)
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

# Console for terminal output
console = Console()


class AutomationLogger:
    """
    Dual-output logger for YARA Automation.
    
    - File: Detailed logs with timestamps
    - Terminal: Concise, formatted output
    """
    
    _instance: Optional['AutomationLogger'] = None
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, log_dir: Optional[Path] = None, log_level: int = logging.DEBUG):
        """
        Initialize the logger.
        
        Args:
            log_dir: Directory for log files
            log_level: Logging level for file output
        """
        if self._initialized:
            return
        
        self._initialized = True
        self.log_dir = log_dir or Path("logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create log filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"automation_{timestamp}.log"
        
        # Set up the main logger
        self.logger = logging.getLogger("yara_automation")
        self.logger.setLevel(log_level)
        self.logger.handlers.clear()
        
        # File handler - detailed output
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
        
        # Also log to a "latest" symlink/copy for easy access
        self.latest_log = self.log_dir / "latest.log"
        
        console.print(f"[dim]Logging to: {self.log_file}[/dim]")
    
    def _log_to_file(self, level: int, message: str, component: str = "main"):
        """Write detailed log to file."""
        logger = logging.getLogger(f"yara_automation.{component}")
        logger.log(level, message)
    
    def debug(self, message: str, component: str = "main"):
        """Debug level - file only."""
        self._log_to_file(logging.DEBUG, message, component)
    
    def info(self, message: str, component: str = "main", console_msg: Optional[str] = None):
        """
        Info level - file detailed, terminal concise.
        
        Args:
            message: Detailed message for log file
            component: Component name (e.g., 'scheduler', 'scanner')
            console_msg: Optional concise message for terminal (if None, not printed)
        """
        self._log_to_file(logging.INFO, message, component)
        if console_msg:
            console.print(f"[cyan]{console_msg}[/cyan]")
    
    def success(self, message: str, component: str = "main", console_msg: Optional[str] = None):
        """Success message - green in terminal."""
        self._log_to_file(logging.INFO, f"SUCCESS: {message}", component)
        if console_msg:
            console.print(f"[green]✓ {console_msg}[/green]")
    
    def warning(self, message: str, component: str = "main", console_msg: Optional[str] = None):
        """Warning level."""
        self._log_to_file(logging.WARNING, message, component)
        if console_msg:
            console.print(f"[yellow]⚠ {console_msg}[/yellow]")
    
    def error(self, message: str, component: str = "main", console_msg: Optional[str] = None):
        """Error level."""
        self._log_to_file(logging.ERROR, message, component)
        if console_msg:
            console.print(f"[red]✗ {console_msg}[/red]")
    
    def task_start(self, task_name: str, details: str = ""):
        """Log task start."""
        self._log_to_file(logging.INFO, f"TASK START: {task_name} - {details}", "scheduler")
        console.print(f"[bold cyan]▶ Starting: {task_name}[/bold cyan]")
    
    def task_complete(self, task_name: str, details: str = "", stats: dict = None):
        """Log task completion with optional stats."""
        stats_str = f" | Stats: {stats}" if stats else ""
        self._log_to_file(logging.INFO, f"TASK COMPLETE: {task_name} - {details}{stats_str}", "scheduler")
        console.print(f"[bold green]✓ Completed: {task_name}[/bold green]")
        if stats:
            for key, value in stats.items():
                console.print(f"  [dim]• {key}: {value}[/dim]")
    
    def task_failed(self, task_name: str, error: str):
        """Log task failure."""
        self._log_to_file(logging.ERROR, f"TASK FAILED: {task_name} - {error}", "scheduler")
        console.print(f"[bold red]✗ Failed: {task_name}[/bold red]")
        console.print(f"  [red]{error}[/red]")
    
    def sample_downloaded(self, sha256: str, source: str, family: str = None):
        """Log sample download."""
        family_str = f" (family: {family})" if family else ""
        self._log_to_file(
            logging.INFO, 
            f"SAMPLE DOWNLOADED: {sha256[:16]}...{family_str} from {source}",
            "samples"
        )
    
    def sample_verified(self, sha256: str, matched_rules: list):
        """Log sample verification."""
        rules_str = ", ".join(matched_rules[:5])
        if len(matched_rules) > 5:
            rules_str += f" (+{len(matched_rules)-5} more)"
        self._log_to_file(
            logging.INFO,
            f"SAMPLE VERIFIED: {sha256[:16]}... matched rules: {rules_str}",
            "scanner"
        )
    
    def rule_update(self, source: str, count: int, status: str = "success"):
        """Log rule update from a source."""
        self._log_to_file(
            logging.INFO if status == "success" else logging.WARNING,
            f"RULE UPDATE: {source} - {count} rules ({status})",
            "aggregator"
        )
    
    def separator(self, title: str = ""):
        """Print a visual separator."""
        if title:
            console.print(f"\n[bold blue]{'─' * 20} {title} {'─' * 20}[/bold blue]")
        else:
            console.print(f"[dim]{'─' * 50}[/dim]")
        self._log_to_file(logging.DEBUG, f"--- {title} ---", "main")
    
    def get_log_path(self) -> Path:
        """Get the current log file path."""
        return self.log_file


def get_logger(log_dir: Optional[Path] = None) -> AutomationLogger:
    """Get or create the singleton logger instance."""
    return AutomationLogger(log_dir)


# Convenience functions for quick access
def log_info(message: str, component: str = "main", console_msg: str = None):
    get_logger().info(message, component, console_msg)

def log_success(message: str, component: str = "main", console_msg: str = None):
    get_logger().success(message, component, console_msg)

def log_warning(message: str, component: str = "main", console_msg: str = None):
    get_logger().warning(message, component, console_msg)

def log_error(message: str, component: str = "main", console_msg: str = None):
    get_logger().error(message, component, console_msg)

def log_debug(message: str, component: str = "main"):
    get_logger().debug(message, component)
