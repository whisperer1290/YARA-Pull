"""
Task Scheduler

Manages scheduled tasks for:
- Periodic YARA rule updates
- Sample fetching from YARAify and MalwareBazaar
- Validation checks
- False positive testing
"""

import functools
import threading
import traceback
from datetime import datetime
from typing import Callable, Dict, List, Optional, TYPE_CHECKING

from rich.console import Console
from rich.table import Table

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False

from .config import get_config

if TYPE_CHECKING:
    from .logger import AutomationLogger

console = Console()


class TaskScheduler:
    """Manages scheduled automation tasks."""
    
    def __init__(self, logger: Optional['AutomationLogger'] = None):
        """
        Initialize the scheduler.
        
        Args:
            logger: Optional AutomationLogger instance for detailed logging
        """
        if not APSCHEDULER_AVAILABLE:
            raise ImportError("APScheduler is not installed")
        
        self.config = get_config()
        
        # Configure scheduler with sensible defaults for long-running jobs
        self.scheduler = BackgroundScheduler(
            job_defaults={
                'coalesce': True,           # Combine multiple missed runs into one
                'max_instances': 1,         # Only one instance of each job at a time
                'misfire_grace_time': 600   # Allow up to 10 minutes late without warning
            }
        )
        
        self._jobs: Dict[str, dict] = {}
        self._logger = logger
        
        # Add event listeners
        self.scheduler.add_listener(self._on_job_executed, EVENT_JOB_EXECUTED)
        self.scheduler.add_listener(self._on_job_error, EVENT_JOB_ERROR)
    
    def _log(self, level: str, message: str, component: str = "scheduler", 
             console_msg: Optional[str] = None):
        """Log with optional logger or fallback to console."""
        if self._logger:
            getattr(self._logger, level)(message, component, console_msg)
        elif console_msg:
            color = {"info": "cyan", "success": "green", "warning": "yellow", "error": "red"}.get(level, "white")
            console.print(f"[{color}]{console_msg}[/{color}]")
    
    def _on_job_executed(self, event):
        """Handle successful job execution."""
        job_id = event.job_id
        job_info = self._jobs.get(job_id, {})
        description = job_info.get('description', job_id)
        
        # Get next run time
        job = self.scheduler.get_job(job_id)
        next_run = ""
        if job and job.next_run_time:
            next_run = f" | Next run: {job.next_run_time.strftime('%Y-%m-%d %H:%M:%S')}"
        
        self._log("success", 
                  f"Task completed: {job_id} - {description}{next_run}",
                  "scheduler",
                  f"✓ Completed: {description}{next_run}")
    
    def _on_job_error(self, event):
        """Handle job execution errors."""
        job_id = event.job_id
        job_info = self._jobs.get(job_id, {})
        description = job_info.get('description', job_id)
        error_msg = str(event.exception) if event.exception else "Unknown error"
        
        # Log full traceback to file
        if self._logger:
            tb = "".join(traceback.format_exception(type(event.exception), event.exception, event.exception.__traceback__))
            self._logger.debug(f"Task {job_id} traceback:\n{tb}", "scheduler")
        
        self._log("error",
                  f"Task failed: {job_id} - {error_msg}",
                  "scheduler",
                  f"✗ Failed: {description} - {error_msg}")
    
    def add_task(self, task_id: str, func: Callable, 
                 interval_seconds: Optional[int] = None,
                 cron: Optional[str] = None,
                 args: tuple = (),
                 kwargs: dict = None,
                 description: str = ""):
        """
        Add a scheduled task.
        
        Args:
            task_id: Unique identifier for the task
            func: Function to execute
            interval_seconds: Run every N seconds
            cron: Cron expression (alternative to interval)
            args: Positional arguments for func
            kwargs: Keyword arguments for func
            description: Human-readable description
        """
        kwargs = kwargs or {}
        
        if interval_seconds:
            trigger = IntervalTrigger(seconds=interval_seconds)
        elif cron:
            trigger = CronTrigger.from_crontab(cron)
        else:
            raise ValueError("Must specify interval_seconds or cron")
        
        job = self.scheduler.add_job(
            func,
            trigger=trigger,
            id=task_id,
            args=args,
            kwargs=kwargs,
            replace_existing=True
        )
        
        self._jobs[task_id] = {
            'job': job,
            'description': description,
            'interval': interval_seconds,
            'cron': cron
        }
        
        console.print(f"[green]Scheduled task: {task_id} - {description}[/green]")
    
    def remove_task(self, task_id: str):
        """Remove a scheduled task."""
        if task_id in self._jobs:
            self.scheduler.remove_job(task_id)
            del self._jobs[task_id]
            console.print(f"[yellow]Removed task: {task_id}[/yellow]")
    
    def run_now(self, task_id: str):
        """Immediately run a scheduled task."""
        if task_id in self._jobs:
            job = self._jobs[task_id]['job']
            job.func(*job.args, **job.kwargs)
        else:
            console.print(f"[red]Task not found: {task_id}[/red]")
    
    def get_next_runs(self) -> Dict[str, str]:
        """Get next run times for all scheduled jobs."""
        next_runs = {}
        for job in self.scheduler.get_jobs():
            if job.next_run_time:
                next_runs[job.id] = job.next_run_time.strftime('%Y-%m-%d %H:%M:%S')
            else:
                next_runs[job.id] = "Not scheduled"
        return next_runs
    
    def print_status(self):
        """Print current scheduler status."""
        jobs = self.scheduler.get_jobs()
        
        if not jobs:
            console.print("[yellow]No scheduled tasks[/yellow]")
            return
        
        console.print("\n[bold cyan]Scheduler Status[/bold cyan]")
        for job in jobs:
            status = "🟢 Active" if job.next_run_time else "🔴 Paused"
            next_time = job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else "N/A"
            console.print(f"  {status} {job.id}: Next run at {next_time}")
    
    def _wrap_task_with_logging(self, task_id: str, func: Callable, description: str) -> Callable:
        """Wrap a task function with logging."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = datetime.now()
            self._log("info", 
                      f"Task started: {task_id} at {start_time.isoformat()}",
                      "scheduler",
                      f"▶ Running: {description}")
            
            try:
                result = func(*args, **kwargs)
                elapsed = (datetime.now() - start_time).total_seconds()
                self._log("info",
                          f"Task {task_id} completed in {elapsed:.1f}s - Result: {result}",
                          "scheduler")
                return result
            except Exception as e:
                elapsed = (datetime.now() - start_time).total_seconds()
                self._log("error",
                          f"Task {task_id} failed after {elapsed:.1f}s: {str(e)}",
                          "scheduler")
                raise
        return wrapper
    
    def setup_default_tasks(self):
        """Set up default automation tasks from config."""
        scheduler_config = self.config.scheduler_config
        
        self._log("info", "Setting up default scheduled tasks", "scheduler", 
                  "Configuring scheduled tasks...")
        
        # Rule update task
        from .rule_aggregator import update_rules
        
        def rule_update_task():
            """Wrapped rule update with logging."""
            self._log("info", "Starting scheduled rule update", "aggregator")
            stats = update_rules()
            self._log("info", f"Rule update stats: {stats}", "aggregator")
            return stats
        
        self.add_task(
            task_id="update_rules",
            func=self._wrap_task_with_logging("update_rules", rule_update_task, 
                                               "Update YARA rules from all sources"),
            interval_seconds=scheduler_config.get('rule_update_interval', 86400),
            description="Update YARA rules from all sources"
        )
        
        # YARAify hunt task - Uses aggregated YARA rules to hunt for matching samples
        # Only searches rules that haven't been searched before (tracked in database)
        from .yaraify import YARAifyClient
        from .database import Database
        
        def yaraify_hunt():
            """Hunt samples on YARAify using UNSEARCHED YARA rules only."""
            client = YARAifyClient()
            db = Database()
            
            # Get unsearched rules from database (limit from config - default 500)
            max_rules_per_run = self.config.max_rules_per_run
            unsearched_rules = db.get_unsearched_rules(limit=max_rules_per_run)
            
            if not unsearched_rules:
                # All rules have been searched - show stats and optionally reset
                search_stats = db.get_rule_search_stats()
                self._log("info", 
                         f"All {search_stats['total_rules']} rules have been searched! "
                         f"Total samples found across all searches: check database.",
                         "yaraify",
                         "✓ All rules searched - hunt cycle complete")
                
                # Optionally: reset to start a new cycle (uncomment if desired)
                # db.reset_all_searched_status()
                # self._log("info", "Reset all rules for new search cycle", "yaraify")
                
                return {
                    "rules_checked": 0, 
                    "rules_with_matches": 0,
                    "samples_downloaded": 0,
                    "status": "cycle_complete",
                    "total_rules_in_db": search_stats['total_rules']
                }
            
            # Show progress
            search_stats = db.get_rule_search_stats()
            self._log("info", 
                     f"Hunting with {len(unsearched_rules)} unsearched rules "
                     f"(Progress: {search_stats['searched']}/{search_stats['total_rules']} = "
                     f"{search_stats['progress_percent']:.1f}% complete)",
                     "yaraify",
                     f"Querying YARAify for samples matching {len(unsearched_rules)} rules...")
            
            total_samples = 0
            rules_with_matches = 0
            samples_found_map = {}
            
            for rule_name in unsearched_rules:
                try:
                    samples = client.download_samples_by_rule(rule_name, max_samples=5)
                    
                    samples_count = len(samples) if samples else 0
                    samples_found_map[rule_name] = samples_count
                    
                    if samples:
                        rules_with_matches += 1
                        total_samples += samples_count
                        self._log("info", f"Downloaded {samples_count} samples for {rule_name}", "yaraify")
                        try:
                            from .stats_tracker import record_detection
                            record_detection(rule_name, samples_count)
                        except Exception:
                            pass
                    
                    # Rate limiting
                    import time
                    time.sleep(0.3)
                    
                except Exception as e:
                    self._log("warning", f"Hunt failed for {rule_name}: {e}", "yaraify")
                    samples_found_map[rule_name] = 0
                    continue
            
            # Mark all processed rules as searched (even if no samples found)
            db.mark_rules_searched(unsearched_rules, samples_found_map)
            
            self._log("info", 
                     f"Hunt complete: {rules_with_matches}/{len(unsearched_rules)} rules had matches, "
                     f"{total_samples} total samples downloaded",
                     "yaraify")
            
            return {
                "rules_checked": len(unsearched_rules), 
                "rules_with_matches": rules_with_matches,
                "samples_downloaded": total_samples,
                "status": "completed"
            }
        
        if self.config.yaraify_config.get('enabled', True):
            self.add_task(
                task_id="yaraify_hunt",
                func=self._wrap_task_with_logging("yaraify_hunt", yaraify_hunt,
                                                   "Hunt samples matching YARA rules"),
                interval_seconds=scheduler_config.get('yaraify_hunt_interval', 21600),
                description="Hunt samples matching YARA rules"
            )
        
        # Validation task
        from .validator import validate_all_samples
        
        def validation_task():
            """Validate samples with logging."""
            self._log("info", "Starting sample validation", "validator")
            report = validate_all_samples()
            self._log("info", f"Validation complete: {report}", "validator")
            return report
        
        self.add_task(
            task_id="validation_check",
            func=self._wrap_task_with_logging("validation_check", validation_task,
                                               "Validate all samples match expected rules"),
            interval_seconds=scheduler_config.get('validation_interval', 86400),
            description="Validate all samples match expected rules"
        )
        
        self._log("info", f"Configured {len(self._jobs)} scheduled tasks", "scheduler")
    
    def start(self, blocking: bool = False):
        """
        Start the scheduler.
        
        Args:
            blocking: If True, block until interrupted
        """
        self.scheduler.start()
        self._log("success", "Scheduler started successfully", "scheduler", "Scheduler started")
        
        self.list_tasks()
        
        if blocking:
            try:
                while True:
                    import time
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()
    
    def stop(self):
        """Stop the scheduler."""
        self.scheduler.shutdown(wait=False)
        self._log("warning", "Scheduler shutdown requested", "scheduler", "Scheduler stopped")
    
    def list_tasks(self):
        """List all scheduled tasks."""
        if not self._jobs:
            console.print("[dim]No tasks scheduled[/dim]")
            return
        
        table = Table(title="Scheduled Tasks", show_header=True, header_style="bold")
        table.add_column("Task ID", style="cyan")
        table.add_column("Description")
        table.add_column("Interval")
        table.add_column("Next Run", style="green")
        
        for task_id, info in self._jobs.items():
            job = info['job']
            next_run = job.next_run_time.strftime("%Y-%m-%d %H:%M:%S") if job.next_run_time else "N/A"
            
            if info['interval']:
                interval_str = self._format_interval(info['interval'])
            else:
                interval_str = info['cron']
            
            table.add_row(
                task_id,
                info['description'],
                interval_str,
                next_run
            )
        
        console.print(table)
    
    def _format_interval(self, seconds: int) -> str:
        """Format interval seconds as human-readable string."""
        if seconds >= 86400:
            return f"{seconds // 86400}d"
        elif seconds >= 3600:
            return f"{seconds // 3600}h"
        elif seconds >= 60:
            return f"{seconds // 60}m"
        else:
            return f"{seconds}s"


def start_scheduler(with_defaults: bool = True, blocking: bool = True):
    """
    Convenience function to start the scheduler.
    
    Args:
        with_defaults: Set up default tasks from config
        blocking: Block until interrupted
    """
    scheduler = TaskScheduler()
    
    if with_defaults:
        scheduler.setup_default_tasks()
    
    scheduler.start(blocking=blocking)
    return scheduler


if __name__ == "__main__":
    # Test the scheduler
    console.print("[bold]Starting scheduler in test mode[/bold]")
    console.print("Press Ctrl+C to stop\n")
    
    start_scheduler(with_defaults=True, blocking=True)
