import os
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    'port_scanner': {
        'max_workers': 50,
        'timeout': 1.0,
        'scan_type': 'common',
        'port_range_start': 1,
        'port_range_end': 1024,
    },
    'dns_analyzer': {
        'timeout': 2.0,
        'preferred_dns': ['1.1.1.1', '8.8.8.8'],
    },
    'performance': {
        'latency_samples': 10,
        'jitter_samples': 20,
        'packet_loss_probes': 50,
        'bandwidth_duration': 5.0,
        'timeout': 2.0,
    },
    'security': {
        'error_threshold': 100,
        'drop_threshold': 50,
        'signal_weak_dbm': -70,
        'latency_high_ms': 200,
        'latency_elevated_ms': 100,
        'jitter_high_ms': 30,
        'packet_loss_high_pct': 5,
        'packet_loss_moderate_pct': 1,
    },
    'logging': {
        'level': 'INFO',
        'file': None,
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    },
    'export': {
        'output_dir': './reports',
        'filename_prefix': 'wifg',
    },
}


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Deep merge override dict into base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from YAML file, falling back to defaults."""
    config = DEFAULT_CONFIG.copy()

    if config_path is None:
        # Look for config.yaml in current directory
        for name in ('config.yaml', 'config.yml', 'config.json'):
            if os.path.exists(name):
                config_path = name
                break

    if config_path and os.path.exists(config_path):
        try:
            import yaml
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
            if user_config and isinstance(user_config, dict):
                config = _deep_merge(config, user_config)
                logger.info("Loaded configuration from %s", config_path)
        except ImportError:
            logger.warning("PyYAML not installed, using default configuration")
        except Exception as e:
            logger.warning("Failed to load config from %s: %s", config_path, e)

    return config


def get_nested(config: Dict, *keys: str, default: Any = None) -> Any:
    """Safely get a nested config value."""
    current = config
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current
