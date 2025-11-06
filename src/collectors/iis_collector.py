"""
IIS (Internet Information Services) Log Collector

Collects and analyzes IIS logs.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base_collector import BaseCollector


class IISCollector(BaseCollector):
    """Collects IIS logs"""

    # W3C log format fields (standard IIS format)
    W3C_FIELDS = [
        'date', 'time', 's-ip', 'cs-method', 'cs-uri-stem', 'cs-uri-query',
        's-port', 'cs-username', 'c-ip', 'cs(User-Agent)', 'cs(Referer)',
        'sc-status', 'sc-substatus', 'sc-win32-status', 'time-taken'
    ]

    def __init__(self, config: Dict[str, Any], server_name: str = None, logger=None):
        """
        Initialize IIS collector

        Args:
            config: Configuration
            server_name: Server name
            logger: Logger instance
        """
        super().__init__(config, logger)
        self.log_path = Path(config.get('log_path', r'C:\inetpub\logs\LogFiles'))
        self.monitor_errors = config.get('monitor_errors', True)
        self.monitor_performance = config.get('monitor_performance', True)
        self.server_name = server_name

    def collect(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Collect IIS logs"""
        if not self.enabled:
            return []

        try:
            all_logs = []

            if since is None:
                if self.last_collection_time:
                    since = self.last_collection_time
                else:
                    since = datetime.now() - timedelta(hours=1)

            self.log_info(f"Collecting IIS logs from {self.log_path}")

            # Find log files
            log_files = self._find_log_files(since)

            # Parse each log file
            for log_file in log_files:
                logs = self._parse_log_file(log_file, since)
                all_logs.extend(logs)

            # Filter and enhance logs
            filtered_logs = self._filter_and_enhance(all_logs)

            self.update_statistics(len(filtered_logs), success=True)
            self.log_info(f"Collected {len(filtered_logs)} IIS log entries")

            return filtered_logs

        except Exception as e:
            self.log_error(f"Error collecting IIS logs: {e}")
            self.update_statistics(0, success=False)
            return []

    def _find_log_files(self, since: datetime) -> List[Path]:
        """Find relevant log files"""
        log_files = []

        if not self.log_path.exists():
            self.log_warning(f"IIS log path does not exist: {self.log_path}")
            return []

        # Find all .log files modified since the given time
        for log_file in self.log_path.rglob('*.log'):
            try:
                file_mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                if file_mtime >= since:
                    log_files.append(log_file)
            except:
                continue

        return sorted(log_files, key=lambda x: x.stat().st_mtime)

    def _parse_log_file(self, log_file: Path, since: datetime) -> List[Dict[str, Any]]:
        """Parse IIS log file"""
        logs = []
        fields = self.W3C_FIELDS.copy()

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()

                    # Skip comments except field definition
                    if line.startswith('#'):
                        if line.startswith('#Fields:'):
                            # Parse field definition
                            fields = line.replace('#Fields:', '').strip().split()
                        continue

                    # Parse log entry
                    log_entry = self._parse_log_line(line, fields, log_file.name)

                    if log_entry:
                        # Check timestamp
                        log_time = datetime.fromisoformat(log_entry['timestamp'])
                        if log_time >= since:
                            logs.append(log_entry)

        except Exception as e:
            self.log_error(f"Error parsing log file {log_file}: {e}")

        return logs

    def _parse_log_line(self, line: str, fields: List[str], filename: str) -> Optional[Dict[str, Any]]:
        """Parse a single log line"""
        try:
            parts = line.split()

            if len(parts) < 2:
                return None

            # Build entry dict
            entry = {}
            for i, field in enumerate(fields):
                if i < len(parts):
                    entry[field] = parts[i]

            # Combine date and time
            log_date = entry.get('date', '')
            log_time = entry.get('time', '')
            timestamp = f"{log_date}T{log_time}" if log_date and log_time else datetime.now().isoformat()

            # Determine log level based on status code
            status_code = int(entry.get('sc-status', 200))
            level = self._determine_level(status_code)

            # Build normalized log entry
            log_entry = {
                'timestamp': timestamp,
                'source': f'IIS:{filename}',
                'level': level,
                'status_code': status_code,
                'method': entry.get('cs-method', ''),
                'uri': entry.get('cs-uri-stem', ''),
                'ip': entry.get('c-ip', ''),
                'user_agent': entry.get('cs(User-Agent)', ''),
                'time_taken': int(entry.get('time-taken', 0)),
                'message': f"{entry.get('cs-method', '')} {entry.get('cs-uri-stem', '')} - {status_code}",
                'data': entry
            }

            return log_entry

        except Exception as e:
            return None

    def _determine_level(self, status_code: int) -> str:
        """Determine log level from HTTP status code"""
        if status_code >= 500:
            return 'Error'
        elif status_code >= 400:
            return 'Warning'
        elif status_code >= 300:
            return 'Information'
        else:
            return 'Information'

    def _filter_and_enhance(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter and enhance IIS logs"""
        filtered = []

        for log in logs:
            # Filter by monitoring settings
            if self.monitor_errors:
                if log['level'] in ['Error', 'Warning']:
                    filtered.append(log)
            else:
                # Only include errors
                if log['level'] == 'Error':
                    filtered.append(log)

            # Add performance warnings
            if self.monitor_performance:
                time_taken = log.get('time_taken', 0)
                if time_taken > 5000:  # More than 5 seconds
                    log['performance_issue'] = True
                    log['level'] = 'Warning'
                    filtered.append(log)

        return filtered

    def test_connection(self) -> bool:
        """Test access to IIS logs"""
        return self.log_path.exists()

    def get_statistics_summary(self) -> Dict[str, Any]:
        """Get IIS statistics summary"""
        try:
            # Collect recent logs
            logs = self.collect()

            # Calculate statistics
            status_codes = {}
            methods = {}
            total_time = 0

            for log in logs:
                # Status codes
                status = log.get('status_code', 0)
                status_codes[status] = status_codes.get(status, 0) + 1

                # HTTP methods
                method = log.get('method', 'Unknown')
                methods[method] = methods.get(method, 0) + 1

                # Response times
                total_time += log.get('time_taken', 0)

            return {
                'timestamp': datetime.now().isoformat(),
                'total_requests': len(logs),
                'status_codes': status_codes,
                'methods': methods,
                'average_response_time': total_time / len(logs) if logs else 0,
                'error_rate': sum(1 for log in logs if log.get('status_code', 0) >= 400) / len(logs) if logs else 0
            }

        except Exception as e:
            self.log_error(f"Error getting IIS statistics: {e}")
            return {'error': str(e)}


def get_iis_collector(config: Dict[str, Any], server_name: str = None, logger=None) -> IISCollector:
    """Factory function for IIS collector"""
    return IISCollector(config, server_name, logger)
