"""
YARAify API Client

Interacts with the YARAify API (abuse.ch) for:
- Deploying YARA rules for live hunting
- Querying samples that match specific rules
- Downloading malware samples
"""

import io
import json
import os
import re
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.progress import Progress

try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except ImportError:
    PYZIPPER_AVAILABLE = False

from .config import get_config

console = Console()


class YARAifyClient:
    """Client for interacting with the YARAify API."""
    
    API_URL = "https://yaraify-api.abuse.ch/api/v1/"
    
    def __init__(self, auth_key: Optional[str] = None):
        """
        Initialize YARAify client.
        
        Args:
            auth_key: YARAify authentication key (from abuse.ch auth portal)
        """
        self.config = get_config()
        self.auth_key = auth_key or self.config.yaraify_auth_key
        
        if not self.auth_key:
            console.print("[yellow]Warning: No YARAify auth key configured. "
                         "Some features may not work.[/yellow]")
        
        self.session = requests.Session()
        if self.auth_key:
            self.session.headers['Auth-Key'] = self.auth_key
    
    def _request(self, data: Dict[str, Any], files: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an API request to YARAify."""
        try:
            if files:
                response = self.session.post(self.API_URL, files=files, timeout=120)
            else:
                response = self.session.post(self.API_URL, json=data, timeout=60)
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]API request failed: {e}[/red]")
            return {"query_status": "error", "error": str(e)}
    
    # ----- Query Operations -----
    
    def query_by_yara_rule(self, rule_name: str, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Query samples that match a specific YARA rule.
        
        Args:
            rule_name: Name of the YARA rule to query
            max_results: Maximum number of results (up to 1000)
            
        Returns:
            List of matching sample metadata
        """
        data = {
            "query": "get_yara",
            "search_term": rule_name,
            "result_max": min(max_results, 1000)
        }
        
        result = self._request(data)
        
        if result.get("query_status") == "ok":
            return result.get("data", [])
        else:
            console.print(f"[red]Query failed: {result.get('query_status')}[/red]")
            return []
    
    def query_by_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Query a file by its hash (MD5, SHA1, SHA256, or SHA3-384).
        
        Args:
            file_hash: File hash to query
            
        Returns:
            File metadata or None if not found
        """
        data = {
            "query": "lookup_hash",
            "search_term": file_hash
        }
        
        result = self._request(data)
        
        if result.get("query_status") == "ok":
            return result.get("data")
        return None
    
    def get_recent_rules(self) -> List[Dict[str, Any]]:
        """
        Get recently deployed YARA rules.
        
        Returns:
            List of recent YARA rules
        """
        data = {"query": "recent_yararules"}
        result = self._request(data)
        
        if result.get("query_status") == "ok":
            return result.get("data", [])
        return []
    
    # ----- Download Operations -----
    
    def download_sample(self, sha256_hash: str, output_dir: Optional[Path] = None) -> Optional[Path]:
        """
        Download a malware sample by SHA256 hash.
        
        The sample is returned as an AES-encrypted ZIP with password "infected".
        
        Args:
            sha256_hash: SHA256 hash of the sample to download
            output_dir: Directory to save the sample (default: samples dir)
            
        Returns:
            Path to downloaded file or None on failure
        """
        if not PYZIPPER_AVAILABLE:
            console.print("[red]pyzipper not installed. Cannot extract encrypted samples.[/red]")
            return None
        
        data = {
            "query": "get_file",
            "sha256_hash": sha256_hash
        }
        
        try:
            response = self.session.post(self.API_URL, json=data, timeout=120)
            response.raise_for_status()
            
            # Check if response is a ZIP file
            if response.headers.get('Content-Type', '').startswith('application/zip') or \
               response.content[:2] == b'PK':
                
                output_dir = output_dir or self.config.samples_dir
                output_dir.mkdir(parents=True, exist_ok=True)
                
                # Extract from encrypted ZIP
                with pyzipper.AESZipFile(io.BytesIO(response.content)) as zf:
                    zf.setpassword(b'infected')
                    
                    for name in zf.namelist():
                        content = zf.read(name)
                        output_path = output_dir / f"{sha256_hash}.bin"
                        
                        with open(output_path, 'wb') as f:
                            f.write(content)
                        
                        console.print(f"[green]Downloaded: {output_path}[/green]")
                        return output_path
            else:
                # Try to parse as JSON error
                try:
                    error = response.json()
                    console.print(f"[red]Download failed: {error.get('query_status')}[/red]")
                except:
                    console.print(f"[red]Download failed: Unknown error[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Download error: {e}[/red]")
            return None
    
    def _filter_samples_by_date(self, samples: List[Dict[str, Any]], 
                                past_months: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Filter samples to only those with first_seen within the past N months.
        API returns first_seen like "2022-04-15 08:24:20 UTC".
        """
        if not past_months or past_months <= 0:
            return samples
        
        cutoff = datetime.utcnow() - timedelta(days=past_months * 30)
        filtered = []
        for s in samples:
            fs = s.get('first_seen')
            if not fs:
                continue
            try:
                # Parse "2022-04-15 08:24:20 UTC" or similar
                dt_str = re.sub(r'\s+UTC\s*$', '', str(fs).strip())
                dt = datetime.strptime(dt_str[:19], '%Y-%m-%d %H:%M:%S')
                if dt >= cutoff:
                    filtered.append(s)
            except (ValueError, TypeError):
                continue
        return filtered
    
    def download_samples_by_rule(self, rule_name: str, max_samples: int = 10, 
                                  output_dir: Optional[Path] = None,
                                  use_malwarebazaar_fallback: bool = True,
                                  past_months_filter: Optional[int] = None) -> List[Path]:
        """
        Download samples that match a YARA rule.
        
        Only downloads samples with first_seen within the past N months (configurable).
        Tries YARAify first, then falls back to MalwareBazaar if download fails.
        
        Args:
            rule_name: YARA rule name to search for
            max_samples: Maximum number of samples to download
            output_dir: Directory to save samples
            use_malwarebazaar_fallback: Try MalwareBazaar if YARAify fails
            past_months_filter: Only samples first_seen within past N months (None = use config)
            
        Returns:
            List of paths to downloaded samples
        """
        samples = self.query_by_yara_rule(rule_name, max_results=max(max_samples * 3, 100))
        
        if not samples:
            return []
        
        # Filter to only "new" samples (within past N months)
        months = past_months_filter if past_months_filter is not None else self.config.past_months_filter
        samples = self._filter_samples_by_date(samples, past_months=months)
        
        if not samples:
            return []
        
        downloaded = []
        output_dir = output_dir or self.config.samples_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Lazy import MalwareBazaar client for fallback
        mb_client = None
        if use_malwarebazaar_fallback:
            try:
                from .malwarebazaar import MalwareBazaarClient
                mb_client = MalwareBazaarClient()
            except ImportError:
                pass
        
        for sample in samples[:max_samples]:
            sha256 = sample.get('sha256_hash')
            first_seen = sample.get('first_seen', '')
            if not sha256:
                continue
            
            def _log_action(action: str) -> None:
                try:
                    from .download_logger import log_sample_download
                    log_sample_download(rule_name, sha256, first_seen, action, months)
                except Exception:
                    pass
            
            # Check if already exists
            existing_path = output_dir / f"{sha256}.bin"
            if existing_path.exists():
                _log_action('already_existed')
                downloaded.append(existing_path)
                continue
            
            # Try YARAify first
            path = self.download_sample(sha256, output_dir)
            
            # Fallback to MalwareBazaar if YARAify fails
            if not path and mb_client:
                try:
                    path = mb_client.download_sample(sha256, output_dir)
                except Exception:
                    pass
            
            if path:
                _log_action('downloaded')
                downloaded.append(path)
            else:
                _log_action('download_failed')
            
            # Rate limiting
            time.sleep(0.5)
        
        return downloaded
    
    # ----- Rule File Operations -----
    
    def extract_rule_names_from_file(self, rules_file: Path) -> List[str]:
        """
        Extract YARA rule names from a rules file.
        
        Args:
            rules_file: Path to YARA rules file
            
        Returns:
            List of rule names found in the file
        """
        import re
        
        if not rules_file.exists():
            console.print(f"[red]Rules file not found: {rules_file}[/red]")
            return []
        
        try:
            content = rules_file.read_text(encoding='utf-8', errors='ignore')
            
            # Pattern to match rule names: rule RuleName or rule RuleName : tags
            rule_pattern = re.compile(
                r'^(?:private\s+|global\s+)?rule\s+(\w+)',
                re.MULTILINE
            )
            
            rule_names = rule_pattern.findall(content)
            return rule_names
            
        except Exception as e:
            console.print(f"[red]Error reading rules file: {e}[/red]")
            return []
    
    def hunt_with_rules_file(self, rules_file: Path, max_samples_per_rule: int = 10,
                              download: bool = False, output_dir: Optional[Path] = None) -> Dict[str, List]:
        """
        Hunt for samples using all rules from a YARA file.
        
        Args:
            rules_file: Path to YARA rules file
            max_samples_per_rule: Maximum samples to fetch per rule
            download: Whether to download matching samples
            output_dir: Directory to save samples (if downloading)
            
        Returns:
            Dictionary mapping rule names to matching samples/paths
        """
        rule_names = self.extract_rule_names_from_file(rules_file)
        
        if not rule_names:
            console.print("[yellow]No rules found in file[/yellow]")
            return {}
        
        console.print(f"[green]Found {len(rule_names)} rules in file[/green]\n")
        
        results = {}
        total_samples = 0
        
        for i, rule_name in enumerate(rule_names, 1):
            console.print(f"[cyan][{i}/{len(rule_names)}] Hunting with rule: {rule_name}[/cyan]")
            
            if download:
                # Download matching samples
                rule_output_dir = output_dir or self.config.samples_dir / rule_name
                samples = self.download_samples_by_rule(
                    rule_name, 
                    max_samples=max_samples_per_rule,
                    output_dir=rule_output_dir
                )
                results[rule_name] = samples
                total_samples += len(samples)
            else:
                # Just query for matches
                matches = self.query_by_yara_rule(rule_name, max_results=max_samples_per_rule)
                results[rule_name] = matches
                total_samples += len(matches)
                
                if matches:
                    console.print(f"  [green]Found {len(matches)} samples[/green]")
                else:
                    console.print(f"  [dim]No samples found[/dim]")
            
            # Rate limiting between rules
            time.sleep(0.5)
        
        console.print(f"\n[bold green]Hunt complete! Total: {total_samples} samples across {len(rule_names)} rules[/bold green]")
        return results
    
    # ----- Rule Deployment Operations -----
    
    def deploy_rule(self, rule_content: str, rule_name: Optional[str] = None) -> bool:
        """
        Deploy a YARA rule to YARAify for live hunting.
        
        The rule must have proper meta fields including:
        - yarahub_uuid: Unique UUID for the rule
        - yarahub_license: License (e.g., "CC0 1.0")
        - yarahub_rule_matching_tlp: TLP for matches (e.g., "TLP:WHITE")
        - yarahub_rule_sharing_tlp: TLP for sharing (e.g., "TLP:WHITE")
        - yarahub_reference_md5: MD5 of a sample that matches
        - date: Date in YYYY-MM-DD format
        
        Args:
            rule_content: YARA rule content
            rule_name: Optional name for logging
            
        Returns:
            True if deployment successful
        """
        # Create multipart form data
        files = {
            'json_data': (None, json.dumps({}), 'application/json'),
            'file': ('rule.yar', rule_content, 'text/plain')
        }
        
        result = self._request({}, files=files)
        
        if result.get("query_status") == "ok":
            console.print(f"[green]Rule deployed successfully: {rule_name or 'unnamed'}[/green]")
            return True
        else:
            console.print(f"[red]Rule deployment failed: {result.get('query_status')}[/red]")
            return False
    
    def get_deployed_rules(self) -> List[Dict[str, Any]]:
        """
        Get list of your deployed YARA rules.
        
        Returns:
            List of deployed rules
        """
        data = {"query": "show_deployed_yara_rules"}
        result = self._request(data)
        
        if result.get("query_status") == "ok":
            return result.get("data", [])
        return []
    
    def delete_rule(self, yarahub_uuid: str) -> bool:
        """
        Delete a deployed YARA rule.
        
        Args:
            yarahub_uuid: UUID of the rule to delete
            
        Returns:
            True if deletion successful
        """
        data = {
            "query": "delete_yara_rule",
            "yarahub_uuid": yarahub_uuid
        }
        
        result = self._request(data)
        return result.get("query_status") == "ok"
    
    # ----- Scanning Operations -----
    
    def scan_file(self, filepath: Path, share_file: bool = False) -> Optional[Dict[str, Any]]:
        """
        Submit a file for scanning against YARAify rules.
        
        Args:
            filepath: Path to file to scan
            share_file: Whether to share the file publicly
            
        Returns:
            Task ID and initial results
        """
        if not filepath.exists():
            console.print(f"[red]File not found: {filepath}[/red]")
            return None
        
        data = {
            'clamav_scan': 1,
            'unpack': 1,
            'share_file': 1 if share_file else 0
        }
        
        files = {
            'json_data': (None, json.dumps(data), 'application/json'),
            'file': (filepath.name, open(filepath, 'rb'))
        }
        
        try:
            response = self.session.post(self.API_URL, files=files, timeout=120)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            console.print(f"[red]Scan error: {e}[/red]")
            return None
    
    def get_scan_results(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get results for a scan task.
        
        Args:
            task_id: Task ID from scan submission
            
        Returns:
            Scan results
        """
        data = {
            "query": "get_results",
            "task_id": task_id
        }
        
        result = self._request(data)
        
        if result.get("query_status") == "ok":
            return result.get("data")
        return None


def hunt_samples(rule_name: str, max_samples: int = 10, 
                 output_dir: Optional[Path] = None) -> List[Path]:
    """Convenience function to hunt and download samples by rule."""
    client = YARAifyClient()
    return client.download_samples_by_rule(rule_name, max_samples, output_dir)


def query_rule(rule_name: str, max_results: int = 100) -> List[Dict[str, Any]]:
    """Convenience function to query samples by rule."""
    client = YARAifyClient()
    return client.query_by_yara_rule(rule_name, max_results)


if __name__ == "__main__":
    # Test the client
    client = YARAifyClient()
    
    # Get recent rules
    recent = client.get_recent_rules()
    print(f"Recent rules: {len(recent)}")
    
    # Query a common rule
    samples = client.query_by_yara_rule("MALWARE_Win_CobaltStrike", max_results=5)
    print(f"CobaltStrike samples: {len(samples)}")
