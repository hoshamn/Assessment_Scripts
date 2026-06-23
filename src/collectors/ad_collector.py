"""
Active Directory Log Collector

Collects and analyzes Active Directory related logs.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .windows_event_collector import PowerShellEventCollector


class ADCollector(PowerShellEventCollector):
    """Collects Active Directory logs"""

    # Critical AD events to monitor
    CRITICAL_AD_EVENTS = {
        1644: 'AD Database Corruption',
        2042: 'Replication Failure - Too Long',
        4740: 'Account Lockout',
        4625: 'Failed Logon',
        4771: 'Kerberos Pre-authentication Failed',
        5805: 'Authentication Failure',
        1168: 'NTDS Replication Error',
        1311: 'Replication Failed',
        2087: 'DNS Lookup Failure',
        1110: 'ADAM Error',
    }

    def __init__(self, config: Dict[str, Any], dc_name: str = None, logger=None):
        """
        Initialize AD collector

        Args:
            config: Configuration
            dc_name: Domain Controller name
            logger: Logger instance
        """
        # Set AD-specific log names
        ad_logs = [
            'Directory Service',
            'DFS Replication',
            'DNS Server',
            'Active Directory Web Services'
        ]

        # Update config with AD logs
        config = config.copy()
        config['logs'] = config.get('logs', ad_logs)

        super().__init__(config, dc_name, logger)

        # Critical events to monitor
        self.critical_events = config.get('critical_events', list(self.CRITICAL_AD_EVENTS.keys()))

    def collect(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Collect AD logs with enhanced metadata

        Args:
            since: Collect logs since this timestamp

        Returns:
            List of log entries
        """
        # Collect using parent method
        logs = super().collect(since)

        # Enhance with AD-specific information
        enhanced_logs = []
        for log in logs:
            enhanced_log = self._enhance_ad_log(log)
            enhanced_logs.append(enhanced_log)

        return enhanced_logs

    def _enhance_ad_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Add AD-specific metadata to log entry"""
        event_id = log.get('event_id')

        # Add criticality flag
        if event_id in self.critical_events:
            log['critical'] = True
            log['issue_type'] = self.CRITICAL_AD_EVENTS.get(event_id, 'Unknown Critical Event')

        # Add AD-specific context
        log['service_type'] = 'active_directory'

        return log

    def get_ad_health_status(self) -> Dict[str, Any]:
        """
        Get AD health status using PowerShell

        Returns:
            Health status information
        """
        try:
            import subprocess
            import json

            # Run AD health check commands
            commands = {
                'replication': 'Get-ADReplicationFailure -Target (Get-ADDomainController).Name | ConvertTo-Json',
                'services': 'Get-Service -Name NTDS,DNS,Netlogon | Select-Object Name,Status | ConvertTo-Json',
                'dcdiag': 'dcdiag /q'  # Quiet mode only shows errors
            }

            results = {}

            for check_name, command in commands.items():
                try:
                    result = subprocess.run(
                        ['powershell', '-Command', command],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if result.returncode == 0:
                        if check_name == 'dcdiag':
                            results[check_name] = {
                                'status': 'healthy' if not result.stdout.strip() else 'issues_found',
                                'output': result.stdout
                            }
                        else:
                            try:
                                results[check_name] = json.loads(result.stdout)
                            except:
                                results[check_name] = {'raw': result.stdout}
                    else:
                        results[check_name] = {'error': result.stderr}

                except Exception as e:
                    results[check_name] = {'error': str(e)}

            return {
                'timestamp': datetime.now().isoformat(),
                'checks': results,
                'overall_status': self._determine_overall_status(results)
            }

        except Exception as e:
            self.log_error(f"Error getting AD health status: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _determine_overall_status(self, results: Dict) -> str:
        """Determine overall AD health status"""
        # Simple heuristic
        if any('error' in result for result in results.values()):
            return 'degraded'

        dcdiag_result = results.get('dcdiag', {})
        if dcdiag_result.get('status') == 'issues_found':
            return 'issues_detected'

        return 'healthy'


def get_ad_collector(config: Dict[str, Any], dc_name: str = None, logger=None) -> ADCollector:
    """
    Factory function for AD collector

    Args:
        config: Configuration
        dc_name: Domain Controller name
        logger: Logger instance

    Returns:
        ADCollector instance
    """
    return ADCollector(config, dc_name, logger)
