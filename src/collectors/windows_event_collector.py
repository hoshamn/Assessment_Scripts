"""
Windows Event Log Collector

Collects logs from Windows Event Logs (System, Application, Security, etc.)
"""

import sys
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base_collector import WindowsCollector


class WindowsEventCollector(WindowsCollector):
    """Collects Windows Event Logs"""

    EVENT_TYPE_MAP = {
        1: 'Error',
        2: 'Warning',
        4: 'Information',
        8: 'Success Audit',
        16: 'Failure Audit'
    }

    def __init__(self, config: Dict[str, Any], server_name: str = None, logger=None):
        """
        Initialize Windows Event collector

        Args:
            config: Collector configuration
            server_name: Target server name (None = local)
            logger: Logger instance
        """
        super().__init__(config, server_name, logger)
        self.log_names = config.get('logs', ['System', 'Application', 'Security'])

    def collect(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Collect Windows Event logs

        Args:
            since: Collect logs since this timestamp

        Returns:
            List of log entries
        """
        if not self.enabled:
            self.log_debug("Collector disabled, skipping")
            return []

        if sys.platform != 'win32':
            self.log_error("Cannot collect Windows Event Logs on non-Windows platform")
            return []

        try:
            all_logs = []

            # Determine time range
            if since is None:
                if self.last_collection_time:
                    since = self.last_collection_time
                else:
                    # Default to last hour
                    since = datetime.now() - timedelta(hours=1)

            self.log_info(f"Collecting logs since {since}")

            # Collect from each log
            for log_name in self.log_names:
                logs = self._collect_from_log(log_name, since)
                all_logs.extend(logs)
                self.log_debug(f"Collected {len(logs)} entries from {log_name}")

            # Filter logs
            filtered_logs = self.filter_logs(all_logs)

            # Update statistics
            self.update_statistics(len(filtered_logs), success=True)

            self.log_info(f"Collected {len(filtered_logs)} log entries total")

            return filtered_logs

        except Exception as e:
            self.log_error(f"Error collecting logs: {e}")
            self.update_statistics(0, success=False)
            return []

    def _collect_from_log(self, log_name: str, since: datetime) -> List[Dict[str, Any]]:
        """Collect from a specific event log"""
        try:
            import win32evtlog
            import win32evtlogutil
            import win32con

            server = self.server_name  # None for local
            logs = []

            # Open event log
            hand = win32evtlog.OpenEventLog(server, log_name)

            # Read flags
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            # Read events
            events = True
            while events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)

                for event in events:
                    # Check timestamp
                    event_time = datetime.fromtimestamp(int(event.TimeGenerated))

                    if event_time < since:
                        # Reached events before our time range
                        events = None
                        break

                    # Normalize event
                    log_entry = self._normalize_event(event, log_name)
                    logs.append(log_entry)

            win32evtlog.CloseEventLog(hand)

            return logs

        except Exception as e:
            self.log_error(f"Error collecting from {log_name}: {e}")
            return []

    def _normalize_event(self, event, log_name: str) -> Dict[str, Any]:
        """Normalize Windows event to standard format"""
        try:
            import win32evtlogutil

            # Get event type
            event_type = self.EVENT_TYPE_MAP.get(event.EventType, 'Unknown')

            # Get message
            try:
                message = win32evtlogutil.SafeFormatMessage(event, log_name)
            except:
                message = str(event.StringInserts) if event.StringInserts else "No message"

            # Build log entry
            log_entry = {
                'timestamp': datetime.fromtimestamp(int(event.TimeGenerated)).isoformat(),
                'source': f"Windows:{log_name}",
                'level': event_type,
                'event_id': event.EventID & 0xFFFF,  # Mask to get actual event ID
                'category': event.EventCategory,
                'computer': event.ComputerName,
                'user': event.Sid,
                'message': message,
                'source_name': event.SourceName,
                'data': {
                    'record_number': event.RecordNumber,
                    'time_written': datetime.fromtimestamp(int(event.TimeWritten)).isoformat(),
                    'string_inserts': list(event.StringInserts) if event.StringInserts else []
                }
            }

            return log_entry

        except Exception as e:
            self.log_error(f"Error normalizing event: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'source': f"Windows:{log_name}",
                'level': 'Unknown',
                'message': str(event),
                'error': str(e)
            }

    def test_connection(self) -> bool:
        """Test connection to Event Log"""
        if sys.platform != 'win32':
            return False

        try:
            import win32evtlog

            # Try to open System log
            hand = win32evtlog.OpenEventLog(self.server_name, 'System')
            win32evtlog.CloseEventLog(hand)

            self.log_info("Event Log connection test successful")
            return True

        except Exception as e:
            self.log_error(f"Event Log connection test failed: {e}")
            return False


class PowerShellEventCollector(WindowsCollector):
    """
    Alternative collector using PowerShell Get-WinEvent
    More flexible and works remotely easier than win32evtlog
    """

    def __init__(self, config: Dict[str, Any], server_name: str = None, logger=None):
        super().__init__(config, server_name, logger)
        self.log_names = config.get('logs', ['System', 'Application', 'Security'])

    def collect(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Collect using PowerShell"""
        if not self.enabled:
            return []

        try:
            import subprocess
            import json

            all_logs = []

            # Determine time range
            if since is None:
                if self.last_collection_time:
                    since = self.last_collection_time
                else:
                    since = datetime.now() - timedelta(hours=1)

            # Build PowerShell command
            for log_name in self.log_names:
                ps_command = self._build_powershell_command(log_name, since)

                # Execute PowerShell
                result = subprocess.run(
                    ['powershell', '-Command', ps_command],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                if result.returncode == 0 and result.stdout:
                    # Parse JSON output
                    events = json.loads(result.stdout)

                    for event in events:
                        log_entry = self._normalize_powershell_event(event, log_name)
                        all_logs.append(log_entry)

            # Filter logs
            filtered_logs = self.filter_logs(all_logs)

            # Update statistics
            self.update_statistics(len(filtered_logs), success=True)

            return filtered_logs

        except Exception as e:
            self.log_error(f"Error collecting logs with PowerShell: {e}")
            self.update_statistics(0, success=False)
            return []

    def _build_powershell_command(self, log_name: str, since: datetime) -> str:
        """Build PowerShell Get-WinEvent command"""
        since_str = since.strftime('%Y-%m-%dT%H:%M:%S')

        computer_param = f"-ComputerName '{self.server_name}'" if self.server_name else ""

        command = f"""
        $startTime = [DateTime]::Parse('{since_str}')
        Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; StartTime=$startTime}} {computer_param} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message, MachineName |
        ConvertTo-Json
        """

        return command

    def _normalize_powershell_event(self, event: Dict, log_name: str) -> Dict[str, Any]:
        """Normalize PowerShell event output"""
        return {
            'timestamp': event.get('TimeCreated'),
            'source': f"Windows:{log_name}",
            'level': event.get('LevelDisplayName', 'Unknown'),
            'event_id': event.get('Id'),
            'source_name': event.get('ProviderName'),
            'computer': event.get('MachineName'),
            'message': event.get('Message', ''),
        }

    def test_connection(self) -> bool:
        """Test PowerShell access"""
        try:
            import subprocess

            result = subprocess.run(
                ['powershell', '-Command', 'Get-EventLog -List'],
                capture_output=True,
                timeout=10
            )

            return result.returncode == 0

        except:
            return False


def get_windows_event_collector(
    config: Dict[str, Any],
    server_name: str = None,
    use_powershell: bool = False,
    logger=None
) -> WindowsCollector:
    """
    Factory function to create Windows Event collector

    Args:
        config: Configuration
        server_name: Server name (None = local)
        use_powershell: Use PowerShell instead of Win32 API
        logger: Logger instance

    Returns:
        Collector instance
    """
    if use_powershell:
        return PowerShellEventCollector(config, server_name, logger)
    else:
        return WindowsEventCollector(config, server_name, logger)
