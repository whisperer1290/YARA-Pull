"""
Configuration loader for YARA Automation.

Loads settings from config.yaml and environment variables from .env
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from dotenv import load_dotenv


class Config:
    """Configuration manager for YARA Automation."""
    
    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}
    
    def __new__(cls) -> 'Config':
        """Singleton pattern to ensure single config instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self) -> None:
        """Load configuration from files."""
        # Determine project root (parent of automation folder)
        self.project_root = Path(__file__).parent.parent.resolve()
        
        # Load environment variables from .env
        env_file = self.project_root / ".env"
        if env_file.exists():
            load_dotenv(env_file)
        
        # Load config.yaml
        config_file = self.project_root / "config.yaml"
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                self._config = yaml.safe_load(f) or {}
        else:
            raise FileNotFoundError(f"Config file not found: {config_file}")
    
    def reload(self) -> None:
        """Reload configuration from files."""
        self._load_config()
    
    # ----- Path Properties -----
    
    @property
    def rules_dir(self) -> Path:
        """Path to aggregated rules directory."""
        return self.project_root / self._config.get('paths', {}).get('rules_dir', 'aggregated-rules')
    
    @property
    def samples_dir(self) -> Path:
        """Path to malware samples directory."""
        return self.project_root / self._config.get('paths', {}).get('samples_dir', 'samples')
    
    @property
    def quarantine_dir(self) -> Path:
        """Path to quarantine directory for unverified samples."""
        return self.project_root / self._config.get('paths', {}).get('quarantine_dir', 'quarantine')
    
    @property
    def reports_dir(self) -> Path:
        """Path to reports directory."""
        return self.project_root / self._config.get('paths', {}).get('reports_dir', 'reports')
    
    @property
    def database_path(self) -> Path:
        """Path to SQLite database."""
        return self.project_root / self._config.get('paths', {}).get('database', 'yara_automation.db')
    
    # ----- API Keys -----
    
    @property
    def yaraify_auth_key(self) -> Optional[str]:
        """YARAify API authentication key."""
        return os.getenv('YARAIFY_AUTH_KEY')
    
    @property
    def malwarebazaar_api_key(self) -> Optional[str]:
        """MalwareBazaar API key (optional)."""
        return os.getenv('MALWAREBAZAAR_API_KEY')
    
    @property
    def malpedia_api_key(self) -> Optional[str]:
        """Malpedia API token (optional - for TLP:GREEN access)."""
        return os.getenv('MALPEDIA_API_KEY')
    
    # ----- Target Families (Global Filter) -----
    
    @property
    def target_families_config(self) -> Dict[str, Any]:
        """Target families configuration."""
        return self._config.get('target_families', {})
    
    @property
    def target_families(self) -> List[str]:
        """List of target malware families to collect and process."""
        return self._config.get('target_families', {}).get('families', [])
    
    @property
    def target_families_enabled(self) -> bool:
        """Whether family filtering is enabled."""
        return self._config.get('target_families', {}).get('enabled', False)
    
    @property
    def target_families_patterns(self) -> List[str]:
        """
        Get regex patterns for matching target families.
        Returns lowercase patterns for case-insensitive matching.
        """
        families = self.target_families
        if not families:
            return []
        # Create patterns that match family names (case-insensitive, word boundaries)
        return [f.lower() for f in families]
    
    # ----- Rule Sources -----
    
    @property
    def rule_sources(self) -> List[Dict[str, Any]]:
        """List of YARA rule source repositories."""
        sources = self._config.get('rule_sources', [])
        return [s for s in sources if s.get('enabled', True)]
    
    @property
    def yarahub_config(self) -> Dict[str, Any]:
        """YARAhub configuration."""
        return self._config.get('yarahub', {})
    
    @property
    def malpedia_config(self) -> Dict[str, Any]:
        """Malpedia configuration."""
        return self._config.get('malpedia', {})
    
    # ----- MalwareBazaar Settings -----
    
    @property
    def malwarebazaar_config(self) -> Dict[str, Any]:
        """MalwareBazaar configuration."""
        return self._config.get('malwarebazaar', {})
    
    @property
    def malware_families(self) -> List[str]:
        """List of malware families to fetch from MalwareBazaar."""
        mb_config = self._config.get('malwarebazaar', {})
        # Use target families if configured
        if mb_config.get('use_target_families', False) and self.target_families_enabled:
            return self.target_families
        return mb_config.get('families', [])
    
    # ----- YARAify Settings -----
    
    @property
    def yaraify_config(self) -> Dict[str, Any]:
        """YARAify configuration."""
        return self._config.get('yaraify', {})
    
    @property
    def past_months_filter(self) -> int:
        """Only consider samples first_seen within past N months (default: 3)."""
        return self._config.get('yaraify', {}).get('past_months_filter', 3)
    
    # ----- Scheduler Settings -----
    
    @property
    def scheduler_config(self) -> Dict[str, Any]:
        """Scheduler configuration."""
        return self._config.get('scheduler', {})
    
    @property
    def max_rules_per_run(self) -> int:
        """Max YARA rules to process per scheduled hunt (default: 500). Change in config.yaml."""
        return self._config.get('scheduler', {}).get('max_rules_per_run', 500)
    
    # ----- False Positive Checker Settings -----
    
    @property
    def fp_checker_config(self) -> Dict[str, Any]:
        """False positive checker configuration."""
        return self._config.get('fp_checker', {})
    
    @property
    def goodware_paths(self) -> List[str]:
        """List of paths containing known clean files."""
        return self._config.get('fp_checker', {}).get('goodware_paths', [])
    
    @property
    def fp_threshold(self) -> float:
        """False positive rate threshold."""
        return self._config.get('fp_checker', {}).get('fp_threshold', 0.01)
    
    # ----- Scanner Settings -----
    
    @property
    def scanner_config(self) -> Dict[str, Any]:
        """Scanner configuration."""
        return self._config.get('scanner', {})
    
    # ----- Watcher Settings -----
    
    @property
    def watcher_config(self) -> Dict[str, Any]:
        """Folder watcher configuration."""
        return self._config.get('watcher', {})
    
    # ----- Utility Methods -----
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key path (e.g., 'paths.rules_dir')."""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value
    
    def ensure_directories(self) -> None:
        """Create all required directories if they don't exist."""
        directories = [
            self.rules_dir,
            self.samples_dir,
            self.quarantine_dir,
            self.reports_dir,
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)


# Global config instance
def get_config() -> Config:
    """Get the global configuration instance."""
    return Config()
