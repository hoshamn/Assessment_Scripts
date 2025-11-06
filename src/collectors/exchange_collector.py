"""
Microsoft Exchange Log Collector

Collects logs from Microsoft Exchange servers.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .windows_event_collector import PowerShellEventCollector


class ExchangeCollector(PowerShellEventCollector):
    """Collects Microsoft Exchange logs"""

    # Critical Exchange events
    CRITICAL_EXCHANGE_EVENTS = {
        1002: 'Store Service Stopped Unexpectedly',
        1022: 'Database Divergence Detected',
        2080: 'Database Mount Failed',
        9646: 'MailboxDatabase Dismounted',
        1009: 'Store Service Started',
        1026: 'Database Redundancy Lost',
        4999: 'Watson Crash',
        9518: 'Transport Queue Growth'
    }

    def __init__(self, config: Dict[str, Any], server_name: str = None, logger=None):
        """
        Initialize Exchange collector

        Args:
            config: Configuration
            server_name: Exchange server name
            logger: Logger instance
        """
        # Set Exchange-specific log names
        exchange_logs = [
            'Application',  # Exchange logs here
            'MSExchange Management',
            'MSExchangeTransport',
            'MSExchangeIS',
        ]

        config = config.copy()
        config['logs'] = config.get('logs', exchange_logs)

        super().__init__(config, server_name, logger)

        self.monitor_mailflow = config.get('monitor_mailflow', True)
        self.monitor_database = config.get('monitor_database', True)

    def collect(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Collect Exchange logs"""
        logs = super().collect(since)

        # Filter for Exchange-specific events
        exchange_logs = [
            log for log in logs
            if self._is_exchange_log(log)
        ]

        # Enhance with Exchange metadata
        enhanced_logs = [
            self._enhance_exchange_log(log)
            for log in exchange_logs
        ]

        return enhanced_logs

    def _is_exchange_log(self, log: Dict[str, Any]) -> bool:
        """Check if log is Exchange-related"""
        source = log.get('source_name', '').lower()
        message = log.get('message', '').lower()

        exchange_indicators = [
            'msexchange', 'exchange', 'mailbox', 'transport',
            'edgetransport', 'store', 'exrpc'
        ]

        return any(indicator in source or indicator in message
                   for indicator in exchange_indicators)

    def _enhance_exchange_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Add Exchange-specific metadata"""
        event_id = log.get('event_id')

        if event_id in self.CRITICAL_EXCHANGE_EVENTS:
            log['critical'] = True
            log['issue_type'] = self.CRITICAL_EXCHANGE_EVENTS[event_id]

        log['service_type'] = 'exchange'

        return log

    def get_exchange_health(self) -> Dict[str, Any]:
        """Get Exchange server health status"""
        try:
            import subprocess
            import json

            results = {}

            # Check Exchange services
            services_command = """
            Get-Service | Where-Object {$_.Name -like '*Exchange*' -or $_.Name -like '*MSExchange*'} |
            Select-Object Name, Status, StartType | ConvertTo-Json
            """

            result = subprocess.run(
                ['powershell', '-Command', services_command],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                try:
                    results['services'] = json.loads(result.stdout)
                except:
                    results['services'] = {'raw': result.stdout}

            # Check mail queue (if available)
            if self.monitor_mailflow:
                queue_command = """
                if (Get-Command Get-Queue -ErrorAction SilentlyContinue) {
                    Get-Queue | Select-Object Identity, MessageCount, Status | ConvertTo-Json
                }
                """

                result = subprocess.run(
                    ['powershell', '-Command', queue_command],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0 and result.stdout:
                    try:
                        results['mail_queues'] = json.loads(result.stdout)
                    except:
                        pass

            # Check databases (if available)
            if self.monitor_database:
                db_command = """
                if (Get-Command Get-MailboxDatabase -ErrorAction SilentlyContinue) {
                    Get-MailboxDatabase -Status | Select-Object Name, Mounted, DatabaseSize | ConvertTo-Json
                }
                """

                result = subprocess.run(
                    ['powershell', '-Command', db_command],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0 and result.stdout:
                    try:
                        results['databases'] = json.loads(result.stdout)
                    except:
                        pass

            return {
                'timestamp': datetime.now().isoformat(),
                'health_checks': results,
                'overall_status': self._determine_exchange_status(results)
            }

        except Exception as e:
            self.log_error(f"Error getting Exchange health: {e}")
            return {'error': str(e)}

    def _determine_exchange_status(self, results: Dict) -> str:
        """Determine overall Exchange health"""
        # Check services
        services = results.get('services', [])
        if isinstance(services, list):
            stopped_services = [s for s in services if s.get('Status') != 'Running']
            if stopped_services:
                return 'degraded'

        # Check mail queues
        queues = results.get('mail_queues', [])
        if isinstance(queues, list):
            large_queues = [q for q in queues if q.get('MessageCount', 0) > 100]
            if large_queues:
                return 'mail_flow_issues'

        # Check databases
        databases = results.get('databases', [])
        if isinstance(databases, list):
            unmounted = [db for db in databases if not db.get('Mounted', False)]
            if unmounted:
                return 'database_issues'

        return 'healthy'


def get_exchange_collector(
    config: Dict[str, Any],
    server_name: str = None,
    logger=None
) -> ExchangeCollector:
    """Factory function for Exchange collector"""
    return ExchangeCollector(config, server_name, logger)
