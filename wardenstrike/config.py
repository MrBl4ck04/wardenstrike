"""
WardenStrike - Configuration Management
Loads config from YAML, environment variables, and .env files.
"""

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "default.yaml"


class Config:
    """Hierarchical configuration: defaults < yaml < env vars < runtime overrides."""

    def __init__(self, config_path: str | Path | None = None):
        load_dotenv()

        self._data = {}
        self._load_defaults()

        if config_path and Path(config_path).exists():
            self._load_yaml(config_path)
        elif DEFAULT_CONFIG_PATH.exists():
            self._load_yaml(DEFAULT_CONFIG_PATH)

        self._apply_env_overrides()

    def _load_defaults(self):
        self._data = {
            "general": {"data_dir": "./data", "max_threads": 10, "timeout": 30, "rate_limit": 10},
            "ai": {"provider": "anthropic", "model": "claude-sonnet-4-20250514", "max_tokens": 8192},
            "burpsuite": {"enabled": False, "api_url": "http://127.0.0.1:1337", "api_key": ""},
            "zap": {"enabled": False, "api_url": "http://127.0.0.1:8081", "api_key": ""},
            "session": {"database": "./data/wardenstrike.db"},
            "reporting": {"output_dir": "./reports", "formats": ["markdown", "html", "json"]},
        }

    def _load_yaml(self, path: str | Path):
        with open(path) as f:
            yaml_data = yaml.safe_load(f) or {}
        self._deep_merge(self._data, yaml_data)

    def _apply_env_overrides(self):
        """Map environment variables to config keys."""
        env_map = {
            # AI (Claude)
            "WARDENSTRIKE_ANTHROPIC_KEY": ("ai", "api_key"),
            "ANTHROPIC_API_KEY": ("ai", "api_key"),
            # Local LLM (Ollama / BaronLLM)
            "LOCAL_LLM_ENABLED": ("ai", "local_enabled"),
            "LOCAL_LLM_MODEL": ("ai", "local_model"),
            "LOCAL_LLM_BASE_URL": ("ai", "local_base_url"),
            "OLLAMA_BASE_URL": ("ai", "local_base_url"),
            # Burp Suite
            "WARDENSTRIKE_BURP_URL": ("burpsuite", "api_url"),
            "WARDENSTRIKE_BURP_KEY": ("burpsuite", "api_key"),
            # ZAP
            "WARDENSTRIKE_ZAP_URL": ("zap", "api_url"),
            "WARDENSTRIKE_ZAP_KEY": ("zap", "api_key"),
            # Proxy
            "WARDENSTRIKE_PROXY": ("general", "proxy"),
            # API keys (legacy section)
            "SHODAN_API_KEY": ("api_keys", "shodan"),
            "VT_API_KEY": ("api_keys", "virustotal"),
            "CENSYS_API_ID": ("api_keys", "censys_id"),
            "CENSYS_API_SECRET": ("api_keys", "censys_secret"),
            "GITHUB_TOKEN": ("api_keys", "github"),
            "SECURITYTRAILS_KEY": ("api_keys", "securitytrails"),
            "CHAOS_KEY": ("api_keys", "chaos"),
            # OSINT module keys (also mapped to osint section)
            "SHODAN_API_KEY": ("osint", "shodan_api_key"),
            "GITHUB_TOKEN": ("osint", "github_token"),
            "CENSYS_API_ID": ("osint", "censys_api_id"),
            "CENSYS_API_SECRET": ("osint", "censys_api_secret"),
            "HIBP_API_KEY": ("osint", "hibp_api_key"),
            "HUNTER_API_KEY": ("osint", "hunter_api_key"),
            "FULLHUNT_API_KEY": ("osint", "fullhunt_api_key"),
            # Metasploit
            "MSF_RPC_PASSWORD": ("metasploit", "password"),
            "MSF_RPC_HOST": ("metasploit", "host"),
            "MSF_RPC_PORT": ("metasploit", "port"),
            # Nessus
            "NESSUS_URL": ("nessus", "url"),
            "NESSUS_ACCESS_KEY": ("nessus", "access_key"),
            "NESSUS_SECRET_KEY": ("nessus", "secret_key"),
            "NESSUS_USERNAME": ("nessus", "username"),
            "NESSUS_PASSWORD": ("nessus", "password"),
            # Cloud
            "AWS_DEFAULT_PROFILE": ("cloud", "aws", "default_profile"),
            "AWS_DEFAULT_REGION": ("cloud", "aws", "default_region"),
            "GCP_PROJECT": ("cloud", "gcp", "default_project"),
            "AZURE_SUBSCRIPTION": ("cloud", "azure", "default_subscription"),
            # Web3
            "ETH_RPC_URL": ("web3", "rpc_url"),
            "ETHERSCAN_API_KEY": ("web3", "etherscan_api_key"),
        }

        for env_var, key_path in env_map.items():
            value = os.environ.get(env_var)
            if value:
                self.set(*key_path, value=value)

    def _deep_merge(self, base: dict, override: dict):
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a nested config value: config.get('ai', 'model')"""
        current = self._data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def set(self, *keys: str, value: Any):
        """Set a nested config value: config.set('ai', 'model', value='...')"""
        current = self._data
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value

    def section(self, name: str) -> dict:
        return self._data.get(name, {})

    @property
    def data(self) -> dict:
        return self._data

    def save(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(self._data, f, default_flow_style=False, sort_keys=False)
