"""
Helper Utilities

Common utility functions.
"""

import yaml
import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime


def load_config(config_path: Path) -> Dict[str, Any]:
    """
    Load configuration from YAML file

    Args:
        config_path: Path to config file

    Returns:
        Configuration dictionary
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    return config


def save_json(data: Any, file_path: Path, indent: int = 2):
    """Save data as JSON"""
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, 'w') as f:
        json.dump(data, f, indent=indent, default=str)


def load_json(file_path: Path) -> Any:
    """Load data from JSON"""
    with open(file_path, 'r') as f:
        return json.load(f)


def format_timestamp(dt: datetime = None) -> str:
    """Format timestamp for filenames"""
    if dt is None:
        dt = datetime.now()

    return dt.strftime('%Y%m%d_%H%M%S')


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string to max length"""
    if len(s) <= max_length:
        return s

    return s[:max_length - 3] + '...'


def get_data_directory(config: Dict[str, Any]) -> Path:
    """Get data directory from config"""
    data_dir = config.get('general', {}).get('data_directory', './data')
    return Path(data_dir)


def ensure_directory(path: Path):
    """Ensure directory exists"""
    path.mkdir(parents=True, exist_ok=True)
