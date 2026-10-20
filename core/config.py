"""
Central configuration loader for CapCipCup.

Reads config.yaml from the project root and merges it over built-in
defaults, so monitoring keeps working even if the file is missing
or corrupted.
"""

import copy
from functools import lru_cache
from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"

DEFAULTS = {
    "sniffing": {
        "interface": "wlan0",
    },
    "detection": {
        "detection_threshold": 10,
        "session_timeout": 5.0,
        "well_known_port_max": 1024,
    },
    "severity": {
        "medium_min": 21,
        "high_min": 41,
    },
}


def _deep_merge(base, override):
    """Merge override into base recursively (dict only)."""
    for key, value in override.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


@lru_cache(maxsize=1)
def get_config():
    """
    Return the effective configuration dict.

    Built-in defaults are used as a fallback so a broken config file
    never stops packet monitoring.
    """
    config = copy.deepcopy(DEFAULTS)

    try:
        if CONFIG_PATH.exists():
            data = yaml.safe_load(CONFIG_PATH.read_text())
            if isinstance(data, dict):
                _deep_merge(config, data)
    except (yaml.YAMLError, OSError) as exc:
        print(f"[WARN] could not read config.yaml, using built-in defaults: {exc}")

    return config
