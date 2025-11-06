"""
Alert Manager

Manages alerts and notifications based on analysis results.
"""

import smtplib
import json
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict


class AlertManager:
    """Manages alerts and notifications"""

    def __init__(self, config: Dict[str, Any], logger=None):
        """
        Initialize alert manager

        Args:
            config: Alert configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.enabled = config.get('enabled', True)

        # Alert deduplication
        self.recent_alerts = {}
        self.dedup_window = config.get('rules', {}).get('deduplication_window_minutes', 30)

        # Escalation tracking
        self.escalation_counts = defaultdict(int)
        self.escalation_enabled = config.get('rules', {}).get('escalation', {}).get('enabled', True)
        self.escalation_threshold = config.get('rules', {}).get('escalation', {}).get('threshold', 3)

        # Statistics
        self.stats = {
            'alerts_sent': 0,
            'alerts_deduplicated': 0,
            'escalations': 0,
            'failed_alerts': 0
        }

    def process_analysis(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process analysis results and send alerts

        Args:
            analysis: Analysis results from LLM

        Returns:
            List of alerts sent
        """
        if not self.enabled:
            return []

        alerts_sent = []

        try:
            # Extract issues from analysis
            issues = analysis.get('issues', [])

            for issue in issues:
                # Determine if alert should be sent
                if self._should_alert(issue):
                    alert = self._create_alert(issue, analysis)

                    # Send alert
                    if self._send_alert(alert):
                        alerts_sent.append(alert)
                        self.stats['alerts_sent'] += 1
                    else:
                        self.stats['failed_alerts'] += 1

            # Check for escalation
            if self.escalation_enabled:
                self._check_escalation(issues)

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error processing alerts: {e}")

        return alerts_sent

    def _should_alert(self, issue: Dict[str, Any]) -> bool:
        """Determine if an alert should be sent"""
        severity = issue.get('severity', 'low').lower()

        # Check if auto-alert enabled for this severity
        severity_config = self.config.get('analysis', {}).get('severity_levels', {})
        auto_alert = severity_config.get(severity, {}).get('auto_alert', False)

        if not auto_alert:
            return False

        # Check deduplication
        issue_id = self._generate_issue_id(issue)

        if issue_id in self.recent_alerts:
            last_alert_time = self.recent_alerts[issue_id]
            time_diff = datetime.now() - last_alert_time

            if time_diff < timedelta(minutes=self.dedup_window):
                self.stats['alerts_deduplicated'] += 1
                return False

        # Update recent alerts
        self.recent_alerts[issue_id] = datetime.now()

        # Clean old entries
        self._clean_recent_alerts()

        return True

    def _create_alert(self, issue: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create alert from issue"""
        return {
            'timestamp': datetime.now().isoformat(),
            'severity': issue.get('severity', 'low'),
            'title': issue.get('title', 'Unknown Issue'),
            'description': issue.get('description', ''),
            'affected_systems': issue.get('affected_systems', []),
            'recommendations': self._extract_recommendations(issue, analysis),
            'event_ids': issue.get('event_ids', []),
            'occurrence_count': issue.get('occurrence_count', 1),
            'first_seen': issue.get('first_seen'),
            'last_seen': issue.get('last_seen'),
        }

    def _extract_recommendations(self, issue: Dict[str, Any], analysis: Dict[str, Any]) -> List[str]:
        """Extract relevant recommendations for issue"""
        recommendations = []

        # Get recommendations from analysis
        all_recommendations = analysis.get('recommendations', [])

        for rec in all_recommendations:
            # Simple matching: include if title matches
            if issue.get('title', '').lower() in rec.get('action', '').lower():
                recommendations.append(rec.get('action'))

        return recommendations[:3]  # Limit to top 3

    def _send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert through configured channels"""
        success = True

        # Send email
        if self.config.get('email', {}).get('enabled', False):
            if not self._send_email_alert(alert):
                success = False

        # Send webhook
        if self.config.get('webhook', {}).get('enabled', False):
            if not self._send_webhook_alert(alert):
                success = False

        # Send Teams
        if self.config.get('teams', {}).get('enabled', False):
            if not self._send_teams_alert(alert):
                success = False

        # Send Slack
        if self.config.get('slack', {}).get('enabled', False):
            if not self._send_slack_alert(alert):
                success = False

        return success

    def _send_email_alert(self, alert: Dict[str, Any]) -> bool:
        """Send email alert"""
        try:
            email_config = self.config.get('email', {})

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert['severity'].upper()}] {alert['title']}"
            msg['From'] = email_config.get('from_address')
            msg['To'] = ', '.join(email_config.get('to_addresses', []))

            # Create email body
            body = self._format_email_body(alert)

            msg.attach(MIMEText(body, 'html'))

            # Send email
            with smtplib.SMTP(
                email_config.get('smtp_server'),
                email_config.get('smtp_port', 587)
            ) as server:
                if email_config.get('use_tls', True):
                    server.starttls()

                # Authentication if credentials provided
                # In production, get from credential manager

                server.send_message(msg)

            if self.logger:
                self.logger.info(f"Sent email alert: {alert['title']}")

            return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error sending email alert: {e}")
            return False

    def _format_email_body(self, alert: Dict[str, Any]) -> str:
        """Format email body"""
        severity_colors = {
            'critical': '#ff0000',
            'high': '#ff6600',
            'medium': '#ffcc00',
            'low': '#00cc00'
        }

        color = severity_colors.get(alert['severity'].lower(), '#999999')

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="border-left: 5px solid {color}; padding-left: 20px;">
                <h2 style="color: {color};">{alert['title']}</h2>
                <p><strong>Severity:</strong> {alert['severity'].upper()}</p>
                <p><strong>Time:</strong> {alert['timestamp']}</p>

                <h3>Description</h3>
                <p>{alert['description']}</p>

                <h3>Affected Systems</h3>
                <ul>
                    {''.join(f"<li>{system}</li>" for system in alert['affected_systems'])}
                </ul>

                <h3>Recommended Actions</h3>
                <ol>
                    {''.join(f"<li>{rec}</li>" for rec in alert['recommendations'])}
                </ol>

                <h3>Details</h3>
                <p><strong>First Seen:</strong> {alert.get('first_seen', 'N/A')}</p>
                <p><strong>Last Seen:</strong> {alert.get('last_seen', 'N/A')}</p>
                <p><strong>Occurrences:</strong> {alert.get('occurrence_count', 1)}</p>
            </div>
        </body>
        </html>
        """

        return html

    def _send_webhook_alert(self, alert: Dict[str, Any]) -> bool:
        """Send webhook alert"""
        try:
            webhook_config = self.config.get('webhook', {})

            response = requests.post(
                webhook_config.get('url'),
                json=alert,
                headers=webhook_config.get('headers', {}),
                timeout=10
            )

            response.raise_for_status()

            if self.logger:
                self.logger.info(f"Sent webhook alert: {alert['title']}")

            return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error sending webhook alert: {e}")
            return False

    def _send_teams_alert(self, alert: Dict[str, Any]) -> bool:
        """Send Microsoft Teams alert"""
        try:
            teams_config = self.config.get('teams', {})

            # Format Teams message card
            card = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": alert['title'],
                "themeColor": self._get_severity_color(alert['severity']),
                "title": f"[{alert['severity'].upper()}] {alert['title']}",
                "sections": [
                    {
                        "facts": [
                            {"name": "Severity", "value": alert['severity'].upper()},
                            {"name": "Time", "value": alert['timestamp']},
                            {"name": "Affected Systems", "value": ', '.join(alert['affected_systems'])}
                        ],
                        "text": alert['description']
                    }
                ]
            }

            response = requests.post(
                teams_config.get('webhook_url'),
                json=card,
                timeout=10
            )

            response.raise_for_status()

            return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error sending Teams alert: {e}")
            return False

    def _send_slack_alert(self, alert: Dict[str, Any]) -> bool:
        """Send Slack alert"""
        try:
            slack_config = self.config.get('slack', {})

            payload = {
                "text": f"*[{alert['severity'].upper()}] {alert['title']}*",
                "attachments": [
                    {
                        "color": self._get_severity_color(alert['severity']),
                        "fields": [
                            {"title": "Description", "value": alert['description']},
                            {"title": "Affected Systems", "value": ', '.join(alert['affected_systems'])},
                        ]
                    }
                ]
            }

            response = requests.post(
                slack_config.get('webhook_url'),
                json=payload,
                timeout=10
            )

            response.raise_for_status()

            return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error sending Slack alert: {e}")
            return False

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'critical': 'FF0000',
            'high': 'FF6600',
            'medium': 'FFCC00',
            'low': '00CC00'
        }
        return colors.get(severity.lower(), '999999')

    def _check_escalation(self, issues: List[Dict[str, Any]]):
        """Check if escalation is needed"""
        for issue in issues:
            issue_id = self._generate_issue_id(issue)
            self.escalation_counts[issue_id] += 1

            if self.escalation_counts[issue_id] >= self.escalation_threshold:
                self._escalate(issue)
                self.stats['escalations'] += 1

    def _escalate(self, issue: Dict[str, Any]):
        """Escalate issue"""
        if self.logger:
            self.logger.warning(f"Escalating issue: {issue.get('title')}")

        # In production, send to escalation contacts
        # For now, just log

    def _generate_issue_id(self, issue: Dict[str, Any]) -> str:
        """Generate unique ID for issue"""
        import hashlib
        key = f"{issue.get('title')}_{issue.get('event_ids')}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def _clean_recent_alerts(self):
        """Clean old recent alerts"""
        cutoff = datetime.now() - timedelta(minutes=self.dedup_window * 2)

        self.recent_alerts = {
            k: v for k, v in self.recent_alerts.items()
            if v > cutoff
        }


def get_alert_manager(config: Dict[str, Any], logger=None) -> AlertManager:
    """Factory function for alert manager"""
    alert_config = config.get('alerts', {})
    return AlertManager(alert_config, logger)
