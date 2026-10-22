#!/usr/bin/env python3
"""
YARA Malware Hunting Automation

A comprehensive automation system for:
- Aggregating YARA rules from multiple sources
- Hunting malware samples using YARAify and MalwareBazaar
- Validating samples match expected YARA rules
- Testing rules for false positives
- Continuous folder monitoring

Usage:
    python main.py <command> [options]

Commands:
    update-rules    Update YARA rules from all configured sources
    hunt            Hunt samples on YARAify matching a rule
    fetch           Fetch samples from MalwareBazaar by tag
    scan            Scan files or directories with YARA
    validate        Validate samples match expected families
    check-fp        Check rules for false positives against clean files
    watch           Start folder watcher for new samples
    start           Start full automation (scheduler + watcher)
    report          Generate statistics report
"""

import argparse
import sys
import time
from pathlib import Path

from rich.console import Console

# Add automation package to path
sys.path.insert(0, str(Path(__file__).parent))

console = Console()


def cmd_update_rules(args):
    """Update YARA rules from all sources."""
    from automation.rule_aggregator import update_rules
    
    console.print("[bold]Updating YARA Rules[/bold]\n")
    stats = update_rules(force=args.force)
    
    console.print(f"\n[green]Rule update complete![/green]")
    console.print(f"Total unique rules: {stats.get('total_unique', 0)}")


def cmd_hunt(args):
    """Hunt samples on YARAify."""
    from automation.yaraify import YARAifyClient
    
    client = YARAifyClient()
    
    if args.list_rules:
        console.print("[bold]Recent YARAify Rules[/bold]\n")
        rules = client.get_recent_rules()
        for rule in rules[:20]:
            console.print(f"  • {rule.get('rule_name')} by {rule.get('author', 'Unknown')}")
        return
    
    # Hunt using a YARA rules file
    if args.file:
        rules_file = Path(args.file)
        if not rules_file.exists():
            console.print(f"[red]Rules file not found: {rules_file}[/red]")
            return
        
        console.print(f"[bold]Hunting samples using rules from: {rules_file.name}[/bold]\n")
        
        results = client.hunt_with_rules_file(
            rules_file,
            max_samples_per_rule=args.max_samples,
            download=args.download
        )
        
        # Summary
        if results:
            console.print(f"\n[bold]Summary:[/bold]")
            for rule_name, samples in results.items():
                if samples:
                    console.print(f"  • {rule_name}: {len(samples)} samples")
        return
    
    # Hunt using a single rule name
    if args.rule:
        console.print(f"[bold]Hunting samples for rule: {args.rule}[/bold]\n")
        
        if args.download:
            samples = client.download_samples_by_rule(
                args.rule, 
                max_samples=args.max_samples
            )
            console.print(f"\n[green]Downloaded {len(samples)} samples[/green]")
        else:
            results = client.query_by_yara_rule(args.rule, max_results=args.max_samples)
            console.print(f"[green]Found {len(results)} matching samples[/green]")
            
            for sample in results[:10]:
                console.print(f"  • {sample.get('sha256_hash', 'Unknown')[:32]}...")
    
    # No rule or file specified
    if not args.rule and not args.file:
        console.print("[yellow]Specify --rule/-r for a single rule name, or --file/-f for a YARA rules file[/yellow]")


def cmd_fetch(args):
    """Fetch samples from MalwareBazaar."""
    from automation.malwarebazaar import MalwareBazaarClient
    
    client = MalwareBazaarClient()
    
    if args.all:
        console.print("[bold]Fetching all configured families[/bold]\n")
        results = client.fetch_all_families(
            max_per_family=args.max_samples,
            verify=args.verify
        )
        
        total = sum(len(samples) for samples in results.values())
        console.print(f"\n[green]Downloaded {total} samples across {len(results)} families[/green]")
    
    elif args.tag:
        console.print(f"[bold]Fetching samples for tag: {args.tag}[/bold]\n")
        verified, unverified = client.download_samples_by_tag(
            args.tag,
            max_samples=args.max_samples,
            verify_with_yara=args.verify
        )
        
        console.print(f"\n[green]Downloaded: {len(verified)} verified, {len(unverified)} unverified[/green]")
    
    else:
        console.print("[yellow]Specify --tag or --all[/yellow]")


def cmd_scan(args):
    """Scan files or directories."""
    from automation.scanner import YARAScanner
    
    target = Path(args.target)
    
    if not target.exists():
        console.print(f"[red]Target not found: {target}[/red]")
        return
    
    rules_path = Path(args.rules) if args.rules else None
    scanner = YARAScanner(rules_path)
    
    if target.is_file():
        console.print(f"[bold]Scanning file: {target}[/bold]\n")
        result = scanner.scan_file(target)
        scanner.print_results([result], verbose=args.verbose)
    else:
        console.print(f"[bold]Scanning directory: {target}[/bold]\n")
        results = scanner.scan_directory(target, recursive=not args.no_recursive)
        scanner.print_results(results, verbose=args.verbose)


def cmd_validate(args):
    """Validate samples match expected families."""
    from automation.validator import validate_all_samples, SampleValidator
    
    if args.sample:
        validator = SampleValidator()
        result = validator.validate_sample(Path(args.sample), args.family or "unknown")
        
        console.print(f"[bold]Validation Result[/bold]")
        console.print(f"Status: {result.status}")
        console.print(f"Expected: {result.expected_family}")
        console.print(f"Detected: {', '.join(result.matched_families) or 'None'}")
        console.print(f"Rules: {', '.join(result.matched_rules[:5]) or 'None'}")
    else:
        console.print("[bold]Validating All Samples[/bold]\n")
        report = validate_all_samples()


def cmd_check_fp(args):
    """Check rules for false positives."""
    from automation.fp_checker import check_false_positives
    
    goodware_dirs = args.goodware if args.goodware else None
    
    console.print("[bold]Checking YARA Rules for False Positives[/bold]\n")
    
    report = check_false_positives(
        goodware_dirs=goodware_dirs,
        threshold=args.threshold,
        max_files=args.max_files
    )
    
    console.print(f"\n[bold]Summary[/bold]")
    console.print(f"Files scanned: {report.total_files_scanned}")
    console.print(f"Problematic rules: {report.problematic_rules}")


def cmd_watch(args):
    """Start folder watcher."""
    from automation.watcher import start_watcher
    
    watch_dir = Path(args.directory) if args.directory else None
    
    console.print("[bold]Starting Folder Watcher[/bold]")
    console.print("Drop files into the watched directory to trigger scanning")
    console.print("Press Ctrl+C to stop\n")
    
    start_watcher(
        watch_dir=watch_dir,
        move_matches=not args.no_move,
        quarantine_no_match=not args.no_quarantine
    )


def cmd_start(args):
    """Start full automation with initialization sequence."""
    import time
    from datetime import datetime
    
    from automation.scheduler import TaskScheduler
    from automation.config import get_config
    from automation.logger import get_logger
    
    config = get_config()
    config.ensure_directories()
    
    # Initialize logging
    logger = get_logger(config.project_root / "logs")
    
    console.print("[bold blue]╔══════════════════════════════════════════════════════════╗[/bold blue]")
    console.print("[bold blue]║         YARA Automation - Full System Startup            ║[/bold blue]")
    console.print("[bold blue]╚══════════════════════════════════════════════════════════╝[/bold blue]\n")
    
    logger.info(f"Automation startup initiated at {datetime.now().isoformat()}", "main", 
                f"Startup initiated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 1: Update YARA Rules
    # ═══════════════════════════════════════════════════════════════════════
    if not args.skip_init:
        logger.separator("PHASE 1: YARA Rule Aggregation")
        
        try:
            logger.task_start("Rule Update", "Aggregating rules from all configured sources")
            logger.debug("Starting rule aggregation from GitHub repos, Malpedia, YARAhub", "aggregator")
            
            from automation.rule_aggregator import update_rules
            stats = update_rules(force=args.force_update)
            
            logger.task_complete("Rule Update", "Successfully aggregated rules", {
                "Total Rules": stats.get('total_unique', 0),
                "Sources": stats.get('sources_processed', 'N/A'),
                "Filtered Rules": stats.get('filtered_rules', 'N/A')
            })
            logger.info(f"Rule aggregation complete: {stats}", "aggregator")
            
        except Exception as e:
            logger.task_failed("Rule Update", str(e))
            logger.error(f"Rule aggregation failed: {e}", "aggregator")
            if not args.continue_on_error:
                console.print("[red]Aborting startup due to rule update failure.[/red]")
                console.print("[dim]Use --continue-on-error to proceed anyway[/dim]")
                return
    
        # ═══════════════════════════════════════════════════════════════════════
        # PHASE 2: False Positive Check
        # ═══════════════════════════════════════════════════════════════════════
        if not args.skip_fp_check:
            logger.separator("PHASE 2: False Positive Check")
            
            try:
                logger.task_start("FP Check", "Testing rules against known clean files")
                logger.debug("Starting FP check against goodware corpus", "fp_checker")
                
                from automation.fp_checker import FalsePositiveChecker
                from automation.scanner import YARAScanner
                
                # Use a fresh scanner with the newly aggregated rules
                scanner = YARAScanner()
                checker = FalsePositiveChecker(scanner)
                
                report = checker.check_rules(max_files=args.fp_max_files)
                
                logger.task_complete("FP Check", "False positive check complete", {
                    "Files Scanned": report.total_files_scanned,
                    "Rules with FP": len([s for s in report.rule_stats.values() if s.fp_count > 0]),
                    "Problematic Rules": report.problematic_rules
                })
                
                # Save FP report
                fp_report_path = config.reports_dir / f"fp_startup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                report.save_report(fp_report_path)
                logger.info(f"FP report saved to {fp_report_path}", "fp_checker")
                
                if report.problematic_rules > 0:
                    logger.warning(
                        f"{report.problematic_rules} rules have high false positive rates",
                        "fp_checker",
                        f"Warning: {report.problematic_rules} rules flagged for high FP rate"
                    )
                
            except Exception as e:
                logger.task_failed("FP Check", str(e))
                logger.error(f"FP check failed: {e}", "fp_checker")
                if not args.continue_on_error:
                    console.print("[yellow]FP check failed, continuing with startup...[/yellow]")
    else:
        logger.info("Skipping initialization phases (--skip-init specified)", "main",
                   "Skipping initial rule update and FP check")
    
    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 3: Start Scheduler
    # ═══════════════════════════════════════════════════════════════════════
    logger.separator("PHASE 3: Starting Automation Services")
    
    scheduler = None
    watcher = None
    
    if not args.no_scheduler:
        try:
            logger.task_start("Scheduler", "Setting up scheduled tasks")
            
            scheduler = TaskScheduler(logger=logger)
            scheduler.setup_default_tasks()
            scheduler.start(blocking=False)
            
            logger.task_complete("Scheduler", "Scheduler started successfully")
            logger.info("Scheduler is now running with configured tasks", "scheduler")
            
        except Exception as e:
            logger.task_failed("Scheduler", str(e))
            logger.error(f"Scheduler failed to start: {e}", "scheduler")
    else:
        logger.info("Scheduler disabled (--no-scheduler specified)", "main", "Scheduler: Disabled")
    
    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 4: Start Folder Watcher
    # ═══════════════════════════════════════════════════════════════════════
    if not args.no_watcher:
        try:
            logger.task_start("Watcher", "Starting folder watcher for new samples")
            
            from automation.scanner import YARAScanner
            from automation.watcher import FolderWatcher, default_match_handler, default_no_match_handler
            
            scanner = YARAScanner()
            watcher = FolderWatcher(scanner)
            watcher.watch_samples_dir(
                on_match=default_match_handler,
                on_no_match=default_no_match_handler
            )
            watcher.start(blocking=False)
            
            logger.task_complete("Watcher", f"Watching directory: {config.samples_dir}")
            logger.info(f"Folder watcher started on {config.samples_dir}", "watcher")
            
        except Exception as e:
            logger.task_failed("Watcher", str(e))
            logger.error(f"Watcher failed to start: {e}", "watcher")
    else:
        logger.info("Watcher disabled (--no-watcher specified)", "main", "Watcher: Disabled")
    
    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 5: Initial Sample Fetch (YARA rule-based hunting via YARAify)
    # Uses ONLY unsearched rules (tracked in database) - never repeats searches
    # ═══════════════════════════════════════════════════════════════════════
    if not args.skip_init and not args.skip_initial_fetch:
        logger.separator("PHASE 5: YARA Rule-Based Sample Hunting")
        
        # Use the aggregated YARA rules to hunt for samples on YARAify
        if config._config.get('yaraify', {}).get('enabled', True):
            try:
                logger.task_start("YARA Hunt", "Hunting samples using UNSEARCHED rules only")
                
                from automation.yaraify import YARAifyClient
                from automation.database import Database
                
                yf_client = YARAifyClient()
                db = Database()
                
                # Get unsearched rules from database (limit from config - default 500)
                from automation.config import get_config
                _cfg = get_config()
                max_rules_to_hunt = getattr(args, 'initial_rules', None) or _cfg.max_rules_per_run
                unsearched_rules = db.get_unsearched_rules(limit=max_rules_to_hunt)
                
                # Show search progress
                search_stats = db.get_rule_search_stats()
                
                if not unsearched_rules:
                    logger.info(
                        f"All {search_stats['total_rules']} rules have already been searched! "
                        "Skipping initial hunt.",
                        "yaraify",
                        f"✓ All rules searched ({search_stats['total_rules']} total)"
                    )
                else:
                    logger.info(
                        f"Found {len(unsearched_rules)} unsearched rules "
                        f"(Progress: {search_stats['searched']}/{search_stats['total_rules']} = "
                        f"{search_stats['progress_percent']:.1f}% complete)",
                        "yaraify",
                        f"Hunting with {len(unsearched_rules)} unsearched YARA rules..."
                    )
                    
                    total_samples = 0
                    rules_with_matches = 0
                    samples_found_map = {}
                    
                    console.print(f"[cyan]Querying YARAify for samples matching {len(unsearched_rules)} rules...[/cyan]\n")
                    
                    for i, rule_name in enumerate(unsearched_rules, 1):
                        logger.debug(f"Hunting rule {i}/{len(unsearched_rules)}: {rule_name}", "yaraify")
                        
                        try:
                            # Download samples matching this rule
                            samples = yf_client.download_samples_by_rule(
                                rule_name, 
                                max_samples=args.initial_samples
                            )
                            
                            samples_count = len(samples) if samples else 0
                            samples_found_map[rule_name] = samples_count
                            
                            if samples:
                                rules_with_matches += 1
                                total_samples += samples_count
                                console.print(f"  [green]✓ {rule_name}: {samples_count} samples[/green]")
                                logger.info(f"Rule {rule_name}: downloaded {samples_count} samples", "yaraify")
                                try:
                                    from automation.stats_tracker import record_detection
                                    record_detection(rule_name, samples_count)
                                except Exception:
                                    pass
                            else:
                                console.print(f"  [dim]○ {rule_name}: no samples found[/dim]")
                            
                            # Rate limiting
                            time.sleep(0.3)
                            
                        except Exception as e:
                            logger.debug(f"Rule {rule_name} hunt failed: {e}", "yaraify")
                            samples_found_map[rule_name] = 0
                            continue
                    
                    # Mark all processed rules as searched
                    db.mark_rules_searched(unsearched_rules, samples_found_map)
                    
                    # Show updated progress
                    new_stats = db.get_rule_search_stats()
                    
                    logger.task_complete("YARA Hunt", "Initial hunt complete", {
                        "Rules Checked": len(unsearched_rules),
                        "Rules with Matches": rules_with_matches,
                        "Total Samples Downloaded": total_samples,
                        "Search Progress": f"{new_stats['progress_percent']:.1f}%"
                    })
                    
            except Exception as e:
                logger.task_failed("YARA Hunt", str(e))
                logger.error(f"YARA hunt failed: {e}", "yaraify")
    elif args.skip_initial_fetch:
        logger.info("Skipping initial sample fetch (--skip-initial-fetch specified)", "main",
                   "Skipping initial sample fetch")
    
    # ═══════════════════════════════════════════════════════════════════════
    # RUNNING STATE
    # ═══════════════════════════════════════════════════════════════════════
    logger.separator("AUTOMATION ACTIVE")
    
    console.print("\n[bold green]╔══════════════════════════════════════════════════════════╗[/bold green]")
    console.print("[bold green]║            🟢 AUTOMATION RUNNING                          ║[/bold green]")
    console.print("[bold green]╚══════════════════════════════════════════════════════════╝[/bold green]")
    console.print(f"\n[dim]Log file: {logger.get_log_path()}[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    
    logger.info("Automation is now fully operational", "main")
    
    # Main loop with periodic status updates
    last_status_time = time.time()
    status_interval = 900  # Log status every 15 minutes
    
    try:
        while True:
            time.sleep(1)
            
            # Periodic status log (every 15 minutes)
            if time.time() - last_status_time >= status_interval:
                # Show scheduler is still active with next run times
                if scheduler:
                    next_runs = []
                    for job in scheduler.scheduler.get_jobs():
                        if job.next_run_time:
                            next_runs.append(f"{job.id}: {job.next_run_time.strftime('%H:%M:%S')}")
                    
                    if next_runs:
                        console.print(f"\n[dim]🔄 Scheduler active | Next runs: {', '.join(next_runs)}[/dim]")
                        logger.debug(f"Scheduler heartbeat - Next runs: {next_runs}", "scheduler")
                
                last_status_time = time.time()
                
    except KeyboardInterrupt:
        logger.separator("SHUTDOWN")
        logger.info("Shutdown requested by user (Ctrl+C)", "main", "Shutting down...")
        
        if scheduler:
            scheduler.stop()
            logger.info("Scheduler stopped", "scheduler")
        
        if watcher:
            try:
                watcher.stop()
                logger.info("Watcher stopped", "watcher")
            except:
                pass
        
        logger.info(f"Automation shutdown complete at {datetime.now().isoformat()}", "main",
                   "Shutdown complete. Goodbye!")
        
        console.print(f"\n[dim]Session log saved to: {logger.get_log_path()}[/dim]")


def cmd_report(args):
    """Generate statistics report."""
    from automation.database import Database
    from automation.config import get_config
    from rich.table import Table
    
    config = get_config()
    db = Database()
    
    console.print("[bold]YARA Automation Statistics Report[/bold]\n")
    
    # Database stats
    db.print_statistics()
    
    # Sample download dates log (for manual 3-month filter verification)
    dates_log = config.reports_dir / "sample_download_dates.csv"
    if dates_log.exists():
        console.print(f"\n[cyan]Sample date log:[/cyan] {dates_log}")
        console.print("[dim]Use this to verify downloaded samples have first_seen within past 3 months.[/dim]")
    
    # Malware family stats CSV
    try:
        from automation.stats_tracker import get_stats_path
        stats_path = get_stats_path()
        if stats_path.exists():
            import csv
            console.print(f"\n[bold]Malware Family Detection Stats[/bold] ({stats_path.name})\n")
            with open(stats_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            if rows:
                table = Table(show_header=True, header_style="bold cyan")
                table.add_column("Malware Family")
                table.add_column("Samples Downloaded", justify="right")
                table.add_column("Rules Detected", justify="right")
                for row in rows:
                    table.add_row(
                        row.get('malware_family', ''),
                        row.get('samples_detected_downloaded', '0'),
                        row.get('rules_detected_count', '0')
                    )
                console.print(table)
            else:
                console.print("[dim]No detection stats yet. Run hunts to populate.[/dim]")
    except Exception as e:
        console.print(f"[dim]Stats: {e}[/dim]")
    
    # Check for reports
    reports_dir = config.reports_dir
    if reports_dir.exists():
        reports = list(reports_dir.glob("*.json"))
        if reports:
            console.print(f"\n[cyan]Recent Reports ({len(reports)} total):[/cyan]")
            for report in sorted(reports, reverse=True)[:5]:
                console.print(f"  • {report.name}")


def cmd_deploy_rules(args):
    """Deploy rules to YARAify for live hunting."""
    from automation.yaraify import YARAifyClient
    from automation.config import get_config
    
    config = get_config()
    client = YARAifyClient()
    
    if args.show:
        console.print("[bold]Your Deployed Rules[/bold]\n")
        rules = client.get_deployed_rules()
        
        if not rules:
            console.print("[dim]No rules deployed[/dim]")
        else:
            for rule in rules:
                console.print(f"  • {rule.get('rule_name')} ({rule.get('yarahub_uuid', 'N/A')[:8]}...)")
    else:
        console.print("[yellow]Rule deployment requires manual YARAhub metadata.[/yellow]")
        console.print("See: https://yaraify.abuse.ch/faq/#yara-rule-guidelines")


def cmd_rule_stats(args):
    """Show rule search statistics and progress."""
    from automation.database import Database
    from rich.table import Table
    
    db = Database()
    stats = db.get_rule_search_stats()
    
    console.print("\n[bold]YARA Rule Search Progress[/bold]\n")
    
    # Create a nice table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    
    table.add_row("Total Rules in Database", str(stats['total_rules']))
    table.add_row("Rules Searched", f"{stats['searched']} ({stats['progress_percent']:.1f}%)")
    table.add_row("Rules Remaining", str(stats['unsearched']))
    
    console.print(table)
    
    if stats['unsearched'] == 0:
        console.print("\n[green]✓ All rules have been searched![/green]")
        console.print("[dim]Run 'python main.py reset-search' to start a new search cycle.[/dim]")
    else:
        from automation.config import get_config
        max_rules = get_config().max_rules_per_run
        console.print(f"\n[yellow]Next scheduled hunt will search up to {max_rules} of the remaining {stats['unsearched']} rules.[/yellow]")


def cmd_reset_search(args):
    """Reset search status for all rules (start a new cycle)."""
    from automation.database import Database
    
    db = Database()
    stats = db.get_rule_search_stats()
    
    if args.confirm:
        db.reset_all_searched_status()
        console.print(f"\n[green]✓ Reset {stats['searched']} rules to unsearched status.[/green]")
        console.print("[cyan]All rules will now be searched again in upcoming hunts.[/cyan]")
    else:
        console.print("\n[bold]Reset Search Status[/bold]\n")
        console.print(f"This will reset {stats['searched']} rules to 'unsearched' status.")
        console.print("All rules will be searched again in upcoming scheduled hunts.\n")
        console.print("[yellow]To confirm, run with --confirm flag:[/yellow]")
        console.print("  python main.py reset-search --confirm")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="YARA Malware Hunting Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # update-rules command
    p_update = subparsers.add_parser('update-rules', help='Update YARA rules from all sources')
    p_update.add_argument('--force', action='store_true', help='Force re-download of all rules')
    p_update.set_defaults(func=cmd_update_rules)
    
    # hunt command
    p_hunt = subparsers.add_parser('hunt', help='Hunt samples on YARAify')
    p_hunt.add_argument('--rule', '-r', help='YARA rule name to hunt for')
    p_hunt.add_argument('--file', '-f', help='YARA rules file to hunt with (uses all rules in file)')
    p_hunt.add_argument('--download', '-d', action='store_true', help='Download matching samples')
    p_hunt.add_argument('--max-samples', '-m', type=int, default=10, help='Max samples per rule')
    p_hunt.add_argument('--list-rules', '-l', action='store_true', help='List recent rules')
    p_hunt.set_defaults(func=cmd_hunt)
    
    # fetch command
    p_fetch = subparsers.add_parser('fetch', help='Fetch samples from MalwareBazaar')
    p_fetch.add_argument('--tag', '-t', help='Malware tag/family to fetch')
    p_fetch.add_argument('--all', '-a', action='store_true', help='Fetch all configured families')
    p_fetch.add_argument('--max-samples', '-m', type=int, default=10, help='Max samples per family')
    p_fetch.add_argument('--verify', '-v', action='store_true', default=True, help='Verify with YARA')
    p_fetch.add_argument('--no-verify', action='store_false', dest='verify', help='Skip YARA verification')
    p_fetch.set_defaults(func=cmd_fetch)
    
    # scan command
    p_scan = subparsers.add_parser('scan', help='Scan files with YARA')
    p_scan.add_argument('target', help='File or directory to scan')
    p_scan.add_argument('--rules', '-r', help='Path to YARA rules file')
    p_scan.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    p_scan.add_argument('--no-recursive', action='store_true', help='Don\'t scan subdirectories')
    p_scan.set_defaults(func=cmd_scan)
    
    # validate command
    p_validate = subparsers.add_parser('validate', help='Validate samples match expected rules')
    p_validate.add_argument('--sample', '-s', help='Specific sample to validate')
    p_validate.add_argument('--family', '-f', help='Expected family for sample')
    p_validate.set_defaults(func=cmd_validate)
    
    # check-fp command
    p_fp = subparsers.add_parser('check-fp', help='Check rules for false positives')
    p_fp.add_argument('--goodware', '-g', nargs='+', help='Directories with known clean files')
    p_fp.add_argument('--threshold', '-t', type=float, default=0.01, help='FP rate threshold (default: 0.01)')
    p_fp.add_argument('--max-files', '-m', type=int, default=1000, help='Max files to scan')
    p_fp.set_defaults(func=cmd_check_fp)
    
    # watch command
    p_watch = subparsers.add_parser('watch', help='Start folder watcher')
    p_watch.add_argument('--directory', '-d', help='Directory to watch')
    p_watch.add_argument('--no-move', action='store_true', help='Don\'t move matched files')
    p_watch.add_argument('--no-quarantine', action='store_true', help='Don\'t quarantine unmatched')
    p_watch.set_defaults(func=cmd_watch)
    
    # start command
    p_start = subparsers.add_parser('start', help='Start full automation')
    p_start.add_argument('--no-scheduler', action='store_true', help='Don\'t start scheduler')
    p_start.add_argument('--no-watcher', action='store_true', help='Don\'t start watcher')
    p_start.add_argument('--skip-init', action='store_true', help='Skip initial rule update, FP check, and sample fetch')
    p_start.add_argument('--skip-fp-check', action='store_true', help='Skip false positive check only')
    p_start.add_argument('--skip-initial-fetch', action='store_true', help='Skip initial sample fetch')
    p_start.add_argument('--force-update', action='store_true', help='Force re-download of all rules')
    p_start.add_argument('--continue-on-error', action='store_true', help='Continue startup even if init fails')
    p_start.add_argument('--fp-max-files', type=int, default=500, help='Max files for FP check (default: 500)')
    p_start.add_argument('--initial-samples', type=int, default=3, help='Max samples per rule for initial fetch (default: 3)')
    p_start.add_argument('--initial-rules', type=int, default=None, help='Max rules for initial hunt (default: use config max_rules_per_run, typically 500)')
    p_start.set_defaults(func=cmd_start)
    
    # report command
    p_report = subparsers.add_parser('report', help='Generate statistics report')
    p_report.set_defaults(func=cmd_report)
    
    # deploy-rules command
    p_deploy = subparsers.add_parser('deploy-rules', help='Deploy rules to YARAify')
    p_deploy.add_argument('--show', '-s', action='store_true', help='Show deployed rules')
    p_deploy.set_defaults(func=cmd_deploy_rules)
    
    # rule-stats command
    p_rule_stats = subparsers.add_parser('rule-stats', help='Show rule search progress')
    p_rule_stats.set_defaults(func=cmd_rule_stats)
    
    # reset-search command
    p_reset = subparsers.add_parser('reset-search', help='Reset search status for all rules')
    p_reset.add_argument('--confirm', action='store_true', help='Confirm reset action')
    p_reset.set_defaults(func=cmd_reset_search)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Print banner
    console.print("\n[bold blue]╔══════════════════════════════════════╗[/bold blue]")
    console.print("[bold blue]║   YARA Malware Hunting Automation    ║[/bold blue]")
    console.print("[bold blue]╚══════════════════════════════════════╝[/bold blue]\n")
    
    # Execute command
    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
