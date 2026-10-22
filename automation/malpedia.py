"""
Malpedia API Client

Interacts with the Malpedia API (Fraunhofer FKIE) for:
- Fetching YARA rules by malware family
- Getting all available rules by TLP level
- Downloading auto-generated YARA-Signator rules
- Listing malware families and their metadata
"""

import io
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console

from .config import get_config

console = Console()


class MalpediaClient:
    """Client for interacting with the Malpedia API."""
    
    API_URL = "https://malpedia.caad.fkie.fraunhofer.de/api"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Malpedia client.
        
        Args:
            api_key: Optional API token for TLP:GREEN access
                     Without key: TLP:WHITE + auto-generated rules
                     With key: Additional TLP:GREEN rules
        """
        self.config = get_config()
        self.api_key = api_key or self.config.malpedia_api_key
        
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'YARA-Automation/1.0'
        
        if self.api_key:
            self.session.headers['Authorization'] = f'apitoken {self.api_key}'
    
    def _request(self, endpoint: str, method: str = "GET", 
                 data: Optional[Dict] = None) -> requests.Response:
        """Make an API request to Malpedia."""
        url = f"{self.API_URL}/{endpoint.lstrip('/')}"
        
        try:
            if method == "GET":
                response = self.session.get(url, timeout=60)
            elif method == "POST":
                response = self.session.post(url, json=data, timeout=60)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Malpedia API error: {e}[/red]")
            raise
    
    def check_api_key(self) -> bool:
        """
        Check if the API key is valid.
        
        Returns:
            True if API key is valid, False otherwise
        """
        if not self.api_key:
            return False
        
        try:
            response = self._request("/check/apikey")
            return response.status_code == 200
        except:
            return False
    
    def get_version(self) -> Dict[str, Any]:
        """
        Get the current Malpedia version.
        
        Returns:
            Dictionary with version info (commit, date)
        """
        response = self._request("/get/version")
        return response.json()
    
    # ----- Family Operations -----
    
    def list_families(self) -> List[str]:
        """
        List all malware family IDs.
        
        Returns:
            List of family IDs (e.g., ['win.cobalt_strike', 'win.asyncrat', ...])
        """
        response = self._request("/list/families")
        return response.json()
    
    def get_families(self) -> Dict[str, Any]:
        """
        Get metadata for all families.
        
        Returns:
            Dictionary mapping family ID to metadata
        """
        response = self._request("/get/families")
        return response.json()
    
    def get_family_info(self, family_id: str) -> Dict[str, Any]:
        """
        Get metadata for a specific family.
        
        Args:
            family_id: Malpedia family ID (e.g., 'win.cobalt_strike')
            
        Returns:
            Family metadata dictionary
        """
        response = self._request(f"/get/family/{family_id}")
        return response.json()
    
    def find_family(self, needle: str) -> List[Dict[str, str]]:
        """
        Search for families by name.
        
        Args:
            needle: Search string
            
        Returns:
            List of matching families with names and synonyms
        """
        response = self._request(f"/find/family/{needle}")
        return response.json()
    
    # ----- YARA Rules Operations -----
    
    def get_yara_rules(self, family_id: str) -> str:
        """
        Get YARA rules for a specific malware family.
        
        Args:
            family_id: Malpedia family ID
            
        Returns:
            YARA rules as string (may vary by access level)
        """
        response = self._request(f"/get/yara/{family_id}")
        return response.text
    
    def get_yara_rules_zip(self, family_id: str) -> bytes:
        """
        Get YARA rules for a family as a ZIP archive.
        
        Args:
            family_id: Malpedia family ID
            
        Returns:
            ZIP file contents as bytes
        """
        response = self._request(f"/get/yara/{family_id}/zip")
        return response.content
    
    def get_all_yara_rules(self, tlp: str = "tlp_white") -> str:
        """
        Get all YARA rules for a specific TLP level.
        
        Args:
            tlp: TLP level - 'tlp_white', 'tlp_green', or 'tlp_amber'
                 tlp_white: Public rules (no auth needed)
                 tlp_green: Requires free registration
                 tlp_amber: Requires vetting
                 
        Returns:
            All YARA rules as a single string
        """
        response = self._request(f"/get/yara/{tlp}/raw")
        return response.text
    
    def get_all_yara_rules_zip(self, tlp: str = "tlp_white") -> bytes:
        """
        Get all YARA rules for a TLP level as ZIP.
        
        Args:
            tlp: TLP level
            
        Returns:
            ZIP file contents as bytes
        """
        response = self._request(f"/get/yara/{tlp}/zip")
        return response.content
    
    def get_auto_rules(self) -> str:
        """
        Get auto-generated YARA-Signator rules.
        
        These are automatically generated code-based rules.
        No authentication required.
        
        Returns:
            Auto-generated YARA rules as string
        """
        response = self._request("/get/yara/auto/raw")
        return response.text
    
    def get_auto_rules_zip(self) -> bytes:
        """
        Get auto-generated rules as ZIP archive.
        
        Returns:
            ZIP file contents as bytes
        """
        response = self._request("/get/yara/auto/zip")
        return response.content
    
    def get_rules_after_date(self, date: str) -> str:
        """
        Get YARA rules updated after a specific date.
        
        Useful for incremental updates.
        
        Args:
            date: Date in format 'YYYY-MM-DD'
            
        Returns:
            YARA rules updated after the date
        """
        response = self._request(f"/get/yara/after/{date}")
        return response.text
    
    def list_yara_rules(self) -> Dict[str, Any]:
        """
        List all available YARA rules.
        
        Returns:
            Dictionary with rule information per family
        """
        response = self._request("/list/yara")
        return response.json()
    
    # ----- Convenience Methods -----
    
    def download_all_rules(self, include_auto: bool = True,
                           tlp_levels: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Download all available YARA rules.
        
        Args:
            include_auto: Include auto-generated rules
            tlp_levels: List of TLP levels to fetch (default: ['tlp_white', 'tlp_green'])
            
        Returns:
            Dictionary mapping source to rules content
        """
        if tlp_levels is None:
            tlp_levels = ['tlp_white', 'tlp_green']
        
        rules = {}
        
        # Get TLP rules for each level
        for tlp in tlp_levels:
            console.print(f"[cyan]Fetching Malpedia {tlp.upper()} rules...[/cyan]")
            try:
                tlp_rules = self.get_all_yara_rules(tlp)
                if tlp_rules and len(tlp_rules.strip()) > 0:
                    rules[f"malpedia_{tlp}"] = tlp_rules
                    console.print(f"  [green]✓ Downloaded {tlp.upper()} rules[/green]")
            except Exception as e:
                if "tlp_green" in tlp.lower() and "401" in str(e):
                    console.print(f"  [yellow]⚠ {tlp.upper()} requires API key (set MALPEDIA_API_KEY)[/yellow]")
                else:
                    console.print(f"  [yellow]⚠ Could not fetch {tlp.upper()} rules: {e}[/yellow]")
        
        # Get auto-generated rules
        if include_auto:
            console.print(f"[cyan]Fetching Malpedia auto-generated rules...[/cyan]")
            try:
                auto_rules = self.get_auto_rules()
                if auto_rules and len(auto_rules.strip()) > 0:
                    rules["malpedia_auto"] = auto_rules
                    console.print(f"  [green]✓ Downloaded auto-generated rules[/green]")
            except Exception as e:
                console.print(f"  [yellow]⚠ Could not fetch auto rules: {e}[/yellow]")
        
        return rules
    
    def download_family_rules(self, families: List[str]) -> Dict[str, str]:
        """
        Download YARA rules for specific families.
        
        Args:
            families: List of family IDs
            
        Returns:
            Dictionary mapping family ID to rules content
        """
        rules = {}
        
        for family_id in families:
            console.print(f"[cyan]Fetching rules for {family_id}...[/cyan]")
            try:
                family_rules = self.get_yara_rules(family_id)
                if family_rules and len(family_rules.strip()) > 0:
                    rules[family_id] = family_rules
                    console.print(f"  [green]✓ Downloaded {family_id} rules[/green]")
            except Exception as e:
                console.print(f"  [yellow]⚠ Could not fetch {family_id}: {e}[/yellow]")
        
        return rules
    
    def get_incremental_update(self, last_update: Optional[str] = None) -> str:
        """
        Get rules updated since last update.
        
        Args:
            last_update: Date of last update (YYYY-MM-DD format)
                        If None, defaults to 30 days ago
                        
        Returns:
            YARA rules updated since the date
        """
        if not last_update:
            from datetime import timedelta
            last_update = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        
        return self.get_rules_after_date(last_update)


def list_families() -> List[str]:
    """Convenience function to list all families."""
    client = MalpediaClient()
    return client.list_families()


def download_rules(tlp_levels: Optional[List[str]] = None, include_auto: bool = True) -> Dict[str, str]:
    """Convenience function to download all rules."""
    client = MalpediaClient()
    return client.download_all_rules(include_auto=include_auto, tlp_levels=tlp_levels)


def get_family_rules(family_id: str) -> str:
    """Convenience function to get rules for a family."""
    client = MalpediaClient()
    return client.get_yara_rules(family_id)


if __name__ == "__main__":
    # Test the client
    client = MalpediaClient()
    
    # Check version
    print("Malpedia Version:")
    print(client.get_version())
    
    # List some families
    families = client.list_families()
    print(f"\nTotal families: {len(families)}")
    print(f"Sample families: {families[:10]}")
    
    # Try to get auto-generated rules
    print("\nFetching auto-generated rules...")
    auto_rules = client.get_auto_rules()
    print(f"Auto rules length: {len(auto_rules)} characters")
