"""
Base Log Collector

Base class for all log collectors with common functionality.
"""

import sys
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta


class BaseCollector(ABC):
    """Base class for log collectors"""

    def __init__(self, config: Dict[str, Any], logger=None):
        """
        Initialize collector

        Args:
            config: Collector configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.enabled = config.get('enabled', True)
        self.last_collection_time = None

        # Statistics
        self.stats = {
            'total_collections': 0,
            'total_logs_collected': 0,
            'failed_collections': 0,
            'last_collection_time': None,
            'last_collection_count': 0
        }

    @abstractmethod
    def collect(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Collect logs

        Args:
            since: Collect logs since this timestamp (None = use last collection time)

        Returns:
            List of log entries
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connection to log source

        Returns:
            True if connection successful
        """
        pass

    def normalize_log_entry(self, raw_entry: Any) -> Dict[str, Any]:
        """
        Normalize log entry to standard format

        Args:
            raw_entry: Raw log entry

        Returns:
            Normalized log entry
        """
        # Override in subclasses
        return {
            'timestamp': datetime.now().isoformat(),
            'source': 'unknown',
            'level': 'info',
            'message': str(raw_entry),
            'raw': raw_entry
        }

    def filter_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter logs based on configuration

        Args:
            logs: List of log entries

        Returns:
            Filtered log entries
        """
        if not logs:
            return []

        filtered = logs

        # Filter by log level
        if 'event_levels' in self.config:
            allowed_levels = [level.lower() for level in self.config['event_levels']]
            filtered = [
                log for log in filtered
                if log.get('level', '').lower() in allowed_levels
            ]

        # Filter by event IDs
        if 'event_ids' in self.config and self.config['event_ids']:
            allowed_ids = self.config['event_ids']
            filtered = [
                log for log in filtered
                if log.get('event_id') in allowed_ids
            ]

        return filtered

    def update_statistics(self, collected_count: int, success: bool = True):
        """Update collection statistics"""
        self.stats['total_collections'] += 1

        if success:
            self.stats['total_logs_collected'] += collected_count
            self.stats['last_collection_count'] = collected_count
            self.stats['last_collection_time'] = datetime.now().isoformat()
            self.last_collection_time = datetime.now()
        else:
            self.stats['failed_collections'] += 1

    def get_statistics(self) -> Dict[str, Any]:
        """Get collector statistics"""
        return self.stats.copy()

    def log_info(self, message: str):
        """Log info message"""
        if self.logger:
            self.logger.info(f"[{self.__class__.__name__}] {message}")

    def log_warning(self, message: str):
        """Log warning message"""
        if self.logger:
            self.logger.warning(f"[{self.__class__.__name__}] {message}")

    def log_error(self, message: str):
        """Log error message"""
        if self.logger:
            self.logger.error(f"[{self.__class__.__name__}] {message}")

    def log_debug(self, message: str):
        """Log debug message"""
        if self.logger:
            self.logger.debug(f"[{self.__class__.__name__}] {message}")


class WindowsCollector(BaseCollector):
    """Base class for Windows-specific collectors"""

    def __init__(self, config: Dict[str, Any], server_name: str = None, logger=None):
        """
        Initialize Windows collector

        Args:
            config: Collector configuration
            server_name: Target server name (None = local)
            logger: Logger instance
        """
        super().__init__(config, logger)
        self.server_name = server_name

        # Check if running on Windows
        if sys.platform != 'win32':
            self.log_warning("Windows collector running on non-Windows platform. Remote collection only.")

    def get_wmi_connection(self):
        """Get WMI connection to server"""
        if sys.platform != 'win32':
            raise RuntimeError("WMI not available on non-Windows platforms")

        try:
            import wmi
            if self.server_name:
                # Remote connection would require credentials
                # For now, only support local
                return wmi.WMI(computer=self.server_name)
            else:
                return wmi.WMI()
        except ImportError:
            raise ImportError("wmi library not installed. Run: pip install wmi")

    def get_event_log_connection(self):
        """Get connection to Windows Event Log"""
        if sys.platform != 'win32':
            raise RuntimeError("Event Log not available on non-Windows platforms")

        try:
            import win32evtlog
            return win32evtlog
        except ImportError:
            raise ImportError("pywin32 not installed. Run: pip install pywin32")
