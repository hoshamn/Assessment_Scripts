"""
Logging Configuration

Centralized logging for the application.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional


def setup_logger(
    name: str = 'MSLogAnalyzer',
    log_level: str = 'INFO',
    log_file: Optional[Path] = None,
    console: bool = True
) -> logging.Logger:
    """
    Setup application logger

    Args:
        name: Logger name
        log_level: Logging level
        log_file: Path to log file (None = no file logging)
        console: Enable console logging

    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))

    # Clear existing handlers
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = 'MSLogAnalyzer') -> logging.Logger:
    """Get existing logger"""
    return logging.getLogger(name)
