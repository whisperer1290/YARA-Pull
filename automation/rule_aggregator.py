"""
YARA Rule Aggregator

Pulls YARA rules from multiple sources:
- GitHub repositories (Yara-Rules, signature-base, ReversingLabs, etc.)
- YARAhub (abuse.ch)
- Malpedia (Fraunhofer FKIE)

Merges them, removes duplicates, and validates the combined ruleset.
"""

import hashlib
import io
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
from rich.console import Console
from rich.progress import Progress, TaskID

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from .config import get_config

console = Console()


class RuleAggregator:
    """Aggregates YARA rules from multiple sources with incremental updates."""
    
    def __init__(self, incremental: bool = True):
        """
        Initialize the rule aggregator.
        
        Args:
            incremental: If True, only add new rules (don't remove existing).
                        If False, do a full rebuild.
        """
        self.config = get_config()
        self.repos_dir = self.config.project_root / "rule-repos"
        self.output_dir = self.config.rules_dir
        self.rules: Dict[str, str] = {}  # rule_name -> rule_content
        self.rule_hashes: Set[str] = set()  # For deduplication by content
        self.used_names: Set[str] = set()  # Track all used rule names to avoid duplicates
        
        # Incremental update mode
        self.incremental = incremental
        self.new_rules_count = 0  # Track newly added rules in this run
        
        # Setup family filtering
        self.filter_by_family = self.config.target_families_enabled
        self.target_families = [f.lower() for f in self.config.target_families]
        self.filtered_count = 0  # Track filtered rules
        self.duplicate_count = 0  # Track renamed duplicates
        
        # Database for tracking
        from .database import Database
        self.db = Database()
        
        # Load existing rules from database if incremental mode
        if self.incremental:
            self._load_existing_rules()
    
    def _load_existing_rules(self):
        """Load existing rules from database and rules file for incremental updates."""
        # Load existing rule hashes and names from database
        self.rule_hashes = self.db.get_all_rule_hashes()
        self.used_names = {name.lower() for name in self.db.get_all_rule_names()}
        
        # Also load existing rules from the rules file if it exists
        rules_file = self.output_dir / "all-rules.yar"
        if rules_file.exists():
            try:
                content = rules_file.read_text(encoding='utf-8', errors='ignore')
                existing_rules = self._extract_rules(content)
                
                for rule_name, rule_content in existing_rules:
                    # Skip header comments
                    if rule_name.lower() not in self.used_names:
                        self.used_names.add(rule_name.lower())
                    
                    # Add to rules dict for preservation
                    self.rules[rule_name] = rule_content
                    
                    # Add hash for deduplication
                    content_hash = hashlib.md5(rule_content.encode()).hexdigest()
                    self.rule_hashes.add(content_hash)
                
                console.print(f"[dim]Loaded {len(self.rules)} existing rules for incremental update[/dim]")
                
            except Exception as e:
                console.print(f"[yellow]Could not load existing rules: {e}[/yellow]")
        
    def update_all(self, force: bool = False) -> Dict[str, int]:
        """
        Update rules from all configured sources.
        
        Args:
            force: Force re-clone of repositories
            
        Returns:
            Dictionary with counts of rules from each source
        """
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        stats = {}
        self.filtered_count = 0  # Reset filtered count
        self.new_rules_count = 0  # Reset new rules count
        existing_count = len(self.rules)  # Track existing rules before update
        
        console.print("\n[bold blue]Updating YARA Rules from All Sources[/bold blue]\n")
        
        if self.incremental and existing_count > 0:
            console.print(f"[dim]Incremental mode: {existing_count} existing rules will be preserved[/dim]\n")
        
        if self.filter_by_family:
            console.print(f"[yellow]Family filter ENABLED: Only collecting rules for {len(self.target_families)} target families[/yellow]\n")
        
        # Update GitHub repositories
        for source in self.config.rule_sources:
            name = source.get('name', 'Unknown')
            console.print(f"[cyan]Updating {name}...[/cyan]")
            try:
                count = self._update_git_repo(source, force)
                stats[name] = count
                console.print(f"  [green]✓ {count} rules loaded[/green]")
            except Exception as e:
                console.print(f"  [red]✗ Error: {e}[/red]")
                stats[name] = 0
        
        # Download YARAhub rules
        if self.config.yarahub_config.get('enabled', True):
            console.print(f"[cyan]Downloading YARAhub rules...[/cyan]")
            try:
                count = self._download_yarahub()
                stats['YARAhub'] = count
                console.print(f"  [green]✓ {count} rules loaded[/green]")
            except Exception as e:
                console.print(f"  [red]✗ Error: {e}[/red]")
                stats['YARAhub'] = 0
        
        # Download Malpedia rules
        if self.config.malpedia_config.get('enabled', True):
            console.print(f"[cyan]Downloading Malpedia rules...[/cyan]")
            try:
                count = self._download_malpedia()
                stats['Malpedia'] = count
                console.print(f"  [green]✓ {count} rules loaded[/green]")
            except Exception as e:
                console.print(f"  [red]✗ Error: {e}[/red]")
                stats['Malpedia'] = 0
        
        # Merge and deduplicate
        console.print(f"\n[cyan]Merging and deduplicating rules...[/cyan]")
        unique_count = len(self.rules)
        console.print(f"  [green]✓ {unique_count} total unique rules[/green]")
        if self.incremental and self.new_rules_count > 0:
            console.print(f"  [green]✓ {self.new_rules_count} NEW rules added in this update[/green]")
        elif self.incremental and self.new_rules_count == 0:
            console.print(f"  [dim]No new rules found (all rules already in database)[/dim]")
        if self.duplicate_count > 0:
            console.print(f"  [dim]({self.duplicate_count} rules renamed to avoid name conflicts)[/dim]")
        if self.filter_by_family and self.filtered_count > 0:
            console.print(f"  [dim]({self.filtered_count} rules filtered out - not matching target families)[/dim]")
        
        # Write aggregated rules
        console.print(f"\n[cyan]Writing aggregated rules...[/cyan]")
        output_file = self._write_aggregated_rules()
        console.print(f"  [green]✓ Written to {output_file}[/green]")
        
        # Validate rules
        if YARA_AVAILABLE:
            console.print(f"\n[cyan]Validating rules...[/cyan]")
            valid, errors = self._validate_rules(output_file)
            if valid:
                console.print(f"  [green]✓ All rules valid[/green]")
            else:
                console.print(f"  [yellow]⚠ {len(errors)} rules had errors and were excluded[/yellow]")
        
        stats['total_unique'] = len(self.rules)
        stats['new_rules'] = self.new_rules_count
        stats['duplicates_renamed'] = self.duplicate_count
        stats['filtered_rules'] = self.filtered_count
        stats['sources_processed'] = len([s for s in stats.values() if isinstance(s, int) and s > 0])
        
        # Log rule search stats
        search_stats = self.db.get_rule_search_stats()
        console.print(f"\n[cyan]Rule Search Progress:[/cyan]")
        console.print(f"  Total rules: {search_stats['total_rules']}")
        console.print(f"  Searched: {search_stats['searched']} ({search_stats['progress_percent']:.1f}%)")
        console.print(f"  Unsearched: {search_stats['unsearched']}")
        
        return stats
    
    def _update_git_repo(self, source: Dict, force: bool = False) -> int:
        """Clone or pull a Git repository and extract rules."""
        if not GIT_AVAILABLE:
            console.print("  [yellow]GitPython not installed, skipping git repos[/yellow]")
            return 0
        
        name = source['name']
        url = source['url']
        branch = source.get('branch', 'master')
        rules_path = source.get('rules_path', '')
        
        repo_dir = self.repos_dir / name
        
        try:
            if repo_dir.exists():
                if force:
                    shutil.rmtree(repo_dir)
                    repo = git.Repo.clone_from(url, repo_dir, branch=branch, depth=1)
                else:
                    repo = git.Repo(repo_dir)
                    origin = repo.remotes.origin
                    origin.pull()
            else:
                repo = git.Repo.clone_from(url, repo_dir, branch=branch, depth=1)
            
            # Find and parse YARA rules
            search_dir = repo_dir / rules_path if rules_path else repo_dir
            return self._load_rules_from_directory(search_dir, name)
            
        except Exception as e:
            console.print(f"  [red]Git error for {name}: {e}[/red]")
            return 0
    
    def _download_yarahub(self) -> int:
        """Download and extract YARAhub rules package."""
        url = self.config.yarahub_config.get('rules_url', 
            'https://yaraify-api.abuse.ch/download/yaraify-rules.zip')
        
        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            
            # Extract zip to temp directory
            with tempfile.TemporaryDirectory() as tmpdir:
                zip_path = Path(tmpdir) / "yarahub.zip"
                with open(zip_path, 'wb') as f:
                    f.write(response.content)
                
                # Extract
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(tmpdir)
                
                # Load rules from extracted files
                return self._load_rules_from_directory(Path(tmpdir), "YARAhub")
                
        except Exception as e:
            console.print(f"  [red]YARAhub download error: {e}[/red]")
            return 0
    
    def _download_malpedia(self) -> int:
        """Download YARA rules from Malpedia API."""
        from .malpedia import MalpediaClient
        
        malpedia_config = self.config.malpedia_config
        # Support both single tlp_level (legacy) and multiple tlp_levels
        tlp_levels = malpedia_config.get('tlp_levels', [])
        if not tlp_levels:
            # Fallback to legacy single tlp_level config
            legacy_level = malpedia_config.get('tlp_level', 'tlp_white')
            tlp_levels = [legacy_level]
        include_auto = malpedia_config.get('include_auto_rules', True)
        families = malpedia_config.get('families', [])
        
        total_count = 0
        
        try:
            client = MalpediaClient()
            
            # Download rules for each TLP level
            for tlp_level in tlp_levels:
                console.print(f"  [dim]Fetching {tlp_level.upper()} rules...[/dim]")
                try:
                    tlp_rules = client.get_all_yara_rules(tlp_level)
                    if tlp_rules and len(tlp_rules.strip()) > 0:
                        count = self._load_rules_from_content(tlp_rules, f"Malpedia_{tlp_level}")
                        total_count += count
                        console.print(f"  [dim]  {count} rules from {tlp_level.upper()}[/dim]")
                except Exception as e:
                    if "tlp_green" in tlp_level.lower() and "401" in str(e):
                        console.print(f"  [yellow]  {tlp_level.upper()} requires API key (set MALPEDIA_API_KEY)[/yellow]")
                    else:
                        console.print(f"  [yellow]  Could not fetch {tlp_level.upper()}: {e}[/yellow]")
            
            # Download auto-generated rules
            if include_auto:
                console.print(f"  [dim]Fetching auto-generated rules...[/dim]")
                try:
                    auto_rules = client.get_auto_rules()
                    if auto_rules and len(auto_rules.strip()) > 0:
                        count = self._load_rules_from_content(auto_rules, "Malpedia_auto")
                        total_count += count
                        console.print(f"  [dim]  {count} auto-generated rules[/dim]")
                except Exception as e:
                    console.print(f"  [yellow]  Could not fetch auto rules: {e}[/yellow]")
            
            # Download family-specific rules if configured
            if families:
                console.print(f"  [dim]Fetching rules for {len(families)} families...[/dim]")
                for family_id in families:
                    try:
                        family_rules = client.get_yara_rules(family_id)
                        if family_rules and len(family_rules.strip()) > 0:
                            count = self._load_rules_from_content(
                                family_rules, f"Malpedia_{family_id.replace('.', '_')}"
                            )
                            total_count += count
                    except Exception as e:
                        console.print(f"  [yellow]  Could not fetch {family_id}: {e}[/yellow]")
            
            return total_count
            
        except Exception as e:
            console.print(f"  [red]Malpedia download error: {e}[/red]")
            return 0
    
    def _matches_target_family(self, rule_name: str, rule_content: str) -> bool:
        """
        Check if a YARA rule matches any of the target malware families.
        
        Checks:
        - Rule name (e.g., CobaltStrike_Beacon_x64)
        - Rule tags (e.g., rule Name : CobaltStrike { ... })
        - Metadata fields (family, malware_family, malware, threat)
        - File path components from source
        """
        if not self.filter_by_family or not self.target_families:
            return True  # No filtering, accept all
        
        # Combine rule name and content for searching
        search_text = f"{rule_name}\n{rule_content}".lower()
        
        for family in self.target_families:
            # Check for family name in rule (case-insensitive)
            # Also check for common variations (e.g., cobalt_strike, cobaltstrike)
            family_lower = family.lower()
            variations = [
                family_lower,
                family_lower.replace(' ', ''),
                family_lower.replace(' ', '_'),
                family_lower.replace('_', ''),
            ]
            
            for var in variations:
                if var in search_text:
                    return True
        
        return False
    
    def _load_rules_from_content(self, content: str, source_name: str) -> int:
        """Load YARA rules from raw content string."""
        count = 0
        
        try:
            rules = self._extract_rules(content)
            
            for rule_name, rule_content in rules:
                # Apply family filter
                if not self._matches_target_family(rule_name, rule_content):
                    self.filtered_count += 1
                    continue
                
                # Create content hash for deduplication
                content_hash = hashlib.md5(rule_content.encode()).hexdigest()
                
                if content_hash not in self.rule_hashes:
                    self.rule_hashes.add(content_hash)
                    
                    # Generate truly unique name
                    unique_name = self._get_unique_rule_name(rule_name, source_name)
                    
                    # If name was changed, update the rule content to use the new name
                    if unique_name != rule_name:
                        rule_content = self._rename_rule_in_content(rule_content, rule_name, unique_name)
                    
                    # Add source comment
                    rule_with_source = f"/* Source: {source_name} */\n{rule_content}"
                    
                    self.rules[unique_name] = rule_with_source
                    self.used_names.add(unique_name.lower())  # Track lowercase for case-insensitive comparison
                    
                    # Track in database (new rule, not yet searched)
                    if self.db.add_aggregated_rule(unique_name, content_hash, source_name):
                        self.new_rules_count += 1  # Only count if truly new to database
                    
                    count += 1
                    
        except Exception as e:
            console.print(f"  [yellow]Error parsing rules from {source_name}: {e}[/yellow]")
        
        return count
    
    def _get_unique_rule_name(self, rule_name: str, source_name: str) -> str:
        """Generate a unique rule name, handling duplicates."""
        # Clean source name for use in rule name
        clean_source = re.sub(r'[^a-zA-Z0-9_]', '_', source_name)
        
        # Check if original name is available (case-insensitive)
        if rule_name.lower() not in self.used_names:
            return rule_name
        
        # Try with source suffix
        self.duplicate_count += 1
        candidate = f"{rule_name}_{clean_source}"
        if candidate.lower() not in self.used_names:
            return candidate
        
        # Add numeric suffix until unique
        counter = 2
        while True:
            candidate = f"{rule_name}_{clean_source}_{counter}"
            if candidate.lower() not in self.used_names:
                return candidate
            counter += 1
            if counter > 100:  # Safety limit
                # Ultimate fallback: use hash
                hash_suffix = hashlib.md5(f"{rule_name}{source_name}{counter}".encode()).hexdigest()[:8]
                return f"{rule_name}_{hash_suffix}"
    
    def _rename_rule_in_content(self, rule_content: str, old_name: str, new_name: str) -> str:
        """
        Rename a rule inside its content string.
        
        Updates the rule declaration from 'rule old_name' to 'rule new_name'.
        """
        # Pattern matches: rule OldName : tags { or rule OldName {
        # Captures optional modifiers (private/global), preserves tags if present
        pattern = r'((?:private\s+|global\s+)?rule\s+)' + re.escape(old_name) + r'(\s*(?::\s*[^\n{]+)?\s*\{)'
        
        replacement = r'\g<1>' + new_name + r'\g<2>'
        
        new_content = re.sub(pattern, replacement, rule_content, count=1, flags=re.IGNORECASE)
        
        return new_content
    
    def _load_rules_from_directory(self, directory: Path, source_name: str) -> int:
        """Load all YARA rules from a directory recursively."""
        count = 0
        
        if not directory.exists():
            return 0
        
        for yar_file in directory.rglob("*.yar"):
            count += self._load_rules_from_file(yar_file, source_name)
        
        for yara_file in directory.rglob("*.yara"):
            count += self._load_rules_from_file(yara_file, source_name)
        
        return count
    
    def _load_rules_from_file(self, filepath: Path, source_name: str) -> int:
        """Load YARA rules from a single file."""
        count = 0
        
        # Also check filepath for family name (some repos organize by family)
        filepath_str = str(filepath).lower()
        
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            rules = self._extract_rules(content)
            
            for rule_name, rule_content in rules:
                # Apply family filter (include filepath in check)
                combined_content = f"{filepath_str}\n{rule_content}"
                if not self._matches_target_family(rule_name, combined_content):
                    self.filtered_count += 1
                    continue
                
                # Create content hash for deduplication
                content_hash = hashlib.md5(rule_content.encode()).hexdigest()
                
                if content_hash not in self.rule_hashes:
                    self.rule_hashes.add(content_hash)
                    
                    # Generate truly unique name
                    unique_name = self._get_unique_rule_name(rule_name, source_name)
                    
                    # If name was changed, update the rule content to use the new name
                    if unique_name != rule_name:
                        rule_content = self._rename_rule_in_content(rule_content, rule_name, unique_name)
                    
                    # Add source comment
                    rule_with_source = f"/* Source: {source_name} */\n{rule_content}"
                    
                    self.rules[unique_name] = rule_with_source
                    self.used_names.add(unique_name.lower())
                    
                    # Track in database (new rule, not yet searched)
                    if self.db.add_aggregated_rule(unique_name, content_hash, source_name):
                        self.new_rules_count += 1  # Only count if truly new to database
                    
                    count += 1
                    
        except Exception as e:
            # Skip files that can't be read
            pass
        
        return count
    
    def _extract_rules(self, content: str) -> List[Tuple[str, str]]:
        """Extract individual rules from YARA file content."""
        rules = []
        
        # Pattern to match rule definitions
        # Handles: rule Name : tags { ... }
        rule_pattern = re.compile(
            r'^((?:private\s+|global\s+)?rule\s+(\w+)\s*(?::\s*[^\n{]+)?\s*\{)',
            re.MULTILINE
        )
        
        matches = list(rule_pattern.finditer(content))
        
        for i, match in enumerate(matches):
            rule_name = match.group(2)
            start = match.start()
            
            # Find end of rule (next rule start or end of content)
            if i + 1 < len(matches):
                end = matches[i + 1].start()
            else:
                end = len(content)
            
            rule_content = content[start:end].strip()
            
            # Validate rule has closing brace
            if rule_content.count('{') == rule_content.count('}'):
                rules.append((rule_name, rule_content))
        
        return rules
    
    def _write_aggregated_rules(self) -> Path:
        """Write all aggregated rules to output file."""
        output_file = self.output_dir / "all-rules.yar"
        
        # Generate header
        header = f'''/*
 * YARA Rule Package - Aggregated from Multiple Sources
 * Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
 * Total Rules: {len(self.rules)}
 * 
 * Sources:
 *   - Yara-Rules/rules (GitHub)
 *   - Neo23x0/signature-base (GitHub)
 *   - ReversingLabs YARA Rules (GitHub)
 *   - Trellix ATR Rules (GitHub)
 *   - bartblaze Rules (GitHub)
 *   - YARAhub (abuse.ch)
 *   - Malpedia (Fraunhofer FKIE)
 */

'''
        
        # Common imports
        imports = '''import "pe"
import "elf"
import "math"
import "hash"

'''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(imports)
            
            for rule_name, rule_content in self.rules.items():
                f.write(f"\n{rule_content}\n")
        
        return output_file
    
    def _validate_rules(self, rules_file: Path) -> Tuple[bool, List[str]]:
        """Validate the aggregated rules file and auto-fix errors."""
        if not YARA_AVAILABLE:
            return True, []
        
        errors = []
        max_attempts = 5  # Limit fix attempts to avoid infinite loop
        
        for attempt in range(max_attempts):
            try:
                # Try to compile the rules
                yara.compile(filepath=str(rules_file))
                if attempt > 0:
                    console.print(f"  [green]✓ Rules fixed after {attempt} iteration(s)[/green]")
                return True, errors
                
            except yara.SyntaxError as e:
                error_str = str(e)
                errors.append(error_str)
                
                # Check for duplicate identifier error
                if "duplicated identifier" in error_str:
                    # Extract the duplicate rule name
                    match = re.search(r'duplicated identifier "([^"]+)"', error_str)
                    if match:
                        dup_name = match.group(1)
                        console.print(f"    [yellow]Fixing duplicate rule: {dup_name}[/yellow]")
                        self._fix_duplicate_rule(dup_name)
                        self._write_aggregated_rules()
                        continue
                
                # For other errors, try to remove invalid rules
                console.print(f"    [yellow]Removing invalid rules...[/yellow]")
                self._remove_invalid_rules(rules_file, errors)
                break
        
        return False, errors
    
    def _fix_duplicate_rule(self, duplicate_name: str) -> None:
        """Fix a duplicate rule by renaming one instance."""
        # Find all rules that might have this name (check the content for rule name)
        rules_to_fix = []
        
        for stored_name, content in self.rules.items():
            # Extract actual rule name from content (skip source comment)
            match = re.search(r'(?:private\s+|global\s+)?rule\s+(\w+)\s*(?::|{)', content)
            if match and match.group(1).lower() == duplicate_name.lower():
                rules_to_fix.append((stored_name, match.group(1)))  # Store both key and actual name
        
        if len(rules_to_fix) > 1:
            # Rename all but the first occurrence
            for i, (stored_name, actual_name) in enumerate(rules_to_fix[1:], start=2):
                old_content = self.rules[stored_name]
                
                # Generate new unique name
                new_name = f"{duplicate_name}_dup{i}"
                while new_name.lower() in self.used_names:
                    new_name = f"{duplicate_name}_dup{i}_{hashlib.md5(stored_name.encode()).hexdigest()[:4]}"
                
                # Replace rule name in content using the helper
                new_content = self._rename_rule_in_content(old_content, actual_name, new_name)
                
                # Update rules dictionary
                del self.rules[stored_name]
                self.rules[new_name] = new_content
                self.used_names.add(new_name.lower())
                
                console.print(f"      [dim]Renamed to: {new_name}[/dim]")
    
    def _remove_invalid_rules(self, rules_file: Path, errors: List[str]) -> None:
        """Remove invalid rules and rewrite the file."""
        console.print(f"    [dim]Testing {len(self.rules)} rules individually...[/dim]")
        
        valid_rules = {}
        invalid_count = 0
        
        # Test each rule individually
        for rule_name, rule_content in self.rules.items():
            try:
                # Try to compile individual rule with imports
                test_content = '''import "pe"
import "elf"
import "math"
import "hash"

''' + rule_content
                yara.compile(source=test_content)
                valid_rules[rule_name] = rule_content
            except Exception as e:
                invalid_count += 1
                if invalid_count <= 10:  # Only show first 10
                    console.print(f"      [dim]Excluding: {rule_name} ({str(e)[:50]})[/dim]")
                elif invalid_count == 11:
                    console.print(f"      [dim]... and more[/dim]")
        
        if invalid_count > 0:
            console.print(f"    [yellow]Excluded {invalid_count} invalid rules[/yellow]")
        
        self.rules = valid_rules
        self.used_names = {name.lower() for name in valid_rules.keys()}
        self._write_aggregated_rules()
    
    def get_rule_names(self) -> List[str]:
        """Get list of all rule names."""
        return list(self.rules.keys())
    
    def get_rule_count(self) -> int:
        """Get total number of rules."""
        return len(self.rules)
    
    def search_rules(self, pattern: str) -> List[str]:
        """Search for rules by name pattern."""
        regex = re.compile(pattern, re.IGNORECASE)
        return [name for name in self.rules.keys() if regex.search(name)]


def update_rules(force: bool = False) -> Dict[str, int]:
    """Convenience function to update all rules."""
    aggregator = RuleAggregator()
    return aggregator.update_all(force)


if __name__ == "__main__":
    # Test the aggregator
    stats = update_rules()
    print(f"\nRule update complete. Stats: {stats}")
