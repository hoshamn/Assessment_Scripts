#!/usr/bin/env python3
"""
Microsoft Logs AI Analyzer - Main Application

Production-ready log analysis system using AI/LLM for Microsoft environments.
"""

import sys
import argparse
import time
import schedule
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from utils.logger import setup_logger, get_logger
from utils.helpers import load_config, save_json, get_data_directory, ensure_directory
from security.credential_manager import get_credential_manager
from security.data_masking import get_data_masker
from analyzers.llm_client import get_llm_client
from analyzers.pattern_analyzer import get_pattern_analyzer
from alerts.alert_manager import get_alert_manager

# Collectors
from collectors.windows_event_collector import get_windows_event_collector
from collectors.ad_collector import get_ad_collector
from collectors.exchange_collector import get_exchange_collector
from collectors.iis_collector import get_iis_collector


class MSLogAnalyzer:
    """Main application class"""

    def __init__(self, config_path: Path):
        """
        Initialize analyzer

        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)

        # Setup logging
        log_level = self.config.get('general', {}).get('log_level', 'INFO')
        data_dir = get_data_directory(self.config)
        log_file = data_dir / 'logs' / f'analyzer_{datetime.now():%Y%m%d}.log'

        self.logger = setup_logger(
            name='MSLogAnalyzer',
            log_level=log_level,
            log_file=log_file
        )

        self.logger.info("Initializing Microsoft Logs AI Analyzer")

        # Initialize components
        self.credential_manager = get_credential_manager(self.config)
        self.data_masker = get_data_masker(self.config)

        # Get LLM API key
        llm_provider = self.config.get('llm', {}).get('provider', 'claude')
        api_key = self.credential_manager.retrieve_credential(f'{llm_provider}_api_key')

        if not api_key:
            self.logger.error(f"No API key found for {llm_provider}. Run setup_credentials.py first.")
            raise ValueError(f"Missing API key for {llm_provider}")

        self.llm_client = get_llm_client(self.config, api_key, self.logger)

        # Initialize pattern analyzer
        patterns_dir = data_dir / 'patterns'
        ensure_directory(patterns_dir)
        self.pattern_analyzer = get_pattern_analyzer(self.config, patterns_dir, self.logger)

        # Initialize alert manager
        self.alert_manager = get_alert_manager(self.config, self.logger)

        # Initialize collectors
        self.collectors = self._init_collectors()

        self.logger.info("Initialization complete")

    def _init_collectors(self) -> List:
        """Initialize log collectors based on configuration"""
        collectors = []

        log_collection_config = self.config.get('log_collection', {})
        sources_config = log_collection_config.get('sources', {})

        # Windows Event Logs
        if sources_config.get('windows_event_logs', {}).get('enabled', False):
            collector = get_windows_event_collector(
                sources_config['windows_event_logs'],
                use_powershell=True,
                logger=self.logger
            )
            collectors.append(('Windows Events', collector))
            self.logger.info("Initialized Windows Event Log collector")

        # Active Directory
        if sources_config.get('active_directory', {}).get('enabled', False):
            collector = get_ad_collector(
                sources_config['active_directory'],
                logger=self.logger
            )
            collectors.append(('Active Directory', collector))
            self.logger.info("Initialized Active Directory collector")

        # Exchange
        if sources_config.get('exchange', {}).get('enabled', False):
            collector = get_exchange_collector(
                sources_config['exchange'],
                logger=self.logger
            )
            collectors.append(('Exchange', collector))
            self.logger.info("Initialized Exchange collector")

        # IIS
        if sources_config.get('iis', {}).get('enabled', False):
            collector = get_iis_collector(
                sources_config['iis'],
                logger=self.logger
            )
            collectors.append(('IIS', collector))
            self.logger.info("Initialized IIS collector")

        return collectors

    def collect_logs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect logs from all configured sources"""
        self.logger.info("Starting log collection")

        all_logs = {}

        for collector_name, collector in self.collectors:
            try:
                self.logger.info(f"Collecting from {collector_name}")
                logs = collector.collect()

                # Mask sensitive data
                masked_logs = [
                    self.data_masker.mask_log_entry(log)
                    for log in logs
                ]

                all_logs[collector_name] = masked_logs
                self.logger.info(f"Collected {len(masked_logs)} logs from {collector_name}")

            except Exception as e:
                self.logger.error(f"Error collecting from {collector_name}: {e}")
                all_logs[collector_name] = []

        total_logs = sum(len(logs) for logs in all_logs.values())
        self.logger.info(f"Total logs collected: {total_logs}")

        return all_logs

    def analyze_logs(self, logs_by_source: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Analyze collected logs using LLM"""
        self.logger.info("Starting log analysis")

        # Combine all logs
        all_logs = []
        for source, logs in logs_by_source.items():
            all_logs.extend(logs)

        if not all_logs:
            self.logger.warning("No logs to analyze")
            return {
                'success': True,
                'summary': 'No logs collected',
                'issues': [],
                'recommendations': []
            }

        # Pattern analysis
        self.logger.info("Performing pattern analysis")
        pattern_results = self.pattern_analyzer.analyze(all_logs)

        # LLM analysis
        self.logger.info(f"Analyzing {len(all_logs)} logs with LLM")

        # Build context from pattern analysis
        context = self._build_context(pattern_results)

        # Analyze with LLM
        analysis = self.llm_client.analyze_logs(
            all_logs,
            context=context,
            analysis_type='general'
        )

        # Enhance analysis with pattern information
        analysis['patterns'] = pattern_results.get('patterns', [])
        analysis['anomalies'] = pattern_results.get('anomalies', [])

        self.logger.info("Analysis complete")

        return analysis

    def _build_context(self, pattern_results: Dict[str, Any]) -> str:
        """Build context string from pattern analysis"""
        context_parts = []

        patterns = pattern_results.get('patterns', [])
        if patterns:
            context_parts.append(f"Detected {len(patterns)} patterns:")
            for pattern in patterns[:5]:  # Top 5
                context_parts.append(f"  - {pattern.get('type')}: {pattern.get('occurrences')} occurrences")

        anomalies = pattern_results.get('anomalies', [])
        if anomalies:
            context_parts.append(f"\nDetected {len(anomalies)} anomalies")

        return '\n'.join(context_parts) if context_parts else None

    def process_alerts(self, analysis: Dict[str, Any]):
        """Process analysis results and send alerts"""
        self.logger.info("Processing alerts")

        alerts = self.alert_manager.process_analysis(analysis)

        if alerts:
            self.logger.info(f"Sent {len(alerts)} alerts")
        else:
            self.logger.info("No alerts to send")

    def save_results(self, logs: Dict[str, List], analysis: Dict[str, Any]):
        """Save analysis results"""
        data_dir = get_data_directory(self.config)
        reports_dir = data_dir / 'reports'
        ensure_directory(reports_dir)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save analysis
        analysis_file = reports_dir / f'analysis_{timestamp}.json'
        save_json(analysis, analysis_file)
        self.logger.info(f"Saved analysis to {analysis_file}")

        # Save logs summary
        summary = {
            'timestamp': datetime.now().isoformat(),
            'log_counts': {source: len(logs) for source, logs in logs.items()},
            'total_logs': sum(len(logs) for logs in logs.values()),
            'analysis_summary': analysis.get('summary'),
            'issue_count': len(analysis.get('issues', [])),
            'health_score': analysis.get('health_score'),
            'risk_level': analysis.get('risk_level')
        }

        summary_file = reports_dir / f'summary_{timestamp}.json'
        save_json(summary, summary_file)

    def run_analysis_cycle(self):
        """Run a single analysis cycle"""
        try:
            self.logger.info("=" * 80)
            self.logger.info("Starting analysis cycle")

            # Collect logs
            logs = self.collect_logs()

            # Analyze logs
            analysis = self.analyze_logs(logs)

            # Process alerts
            self.process_alerts(analysis)

            # Save results
            self.save_results(logs, analysis)

            self.logger.info("Analysis cycle complete")
            self.logger.info("=" * 80)

        except Exception as e:
            self.logger.error(f"Error in analysis cycle: {e}", exc_info=True)

    def run_continuous(self):
        """Run continuous monitoring"""
        interval = self.config.get('log_collection', {}).get('interval_seconds', 300)

        self.logger.info(f"Starting continuous monitoring (interval: {interval}s)")

        # Schedule analysis
        schedule.every(interval).seconds.do(self.run_analysis_cycle)

        # Run immediately
        self.run_analysis_cycle()

        # Keep running
        while True:
            schedule.run_pending()
            time.sleep(1)

    def test_configuration(self):
        """Test configuration and connectivity"""
        self.logger.info("Testing configuration")

        results = {
            'config_valid': True,
            'collectors': {},
            'llm_connection': False,
            'credential_storage': False
        }

        # Test collectors
        for collector_name, collector in self.collectors:
            try:
                connected = collector.test_connection()
                results['collectors'][collector_name] = connected
                status = "OK" if connected else "FAILED"
                self.logger.info(f"  {collector_name}: {status}")
            except Exception as e:
                results['collectors'][collector_name] = False
                self.logger.error(f"  {collector_name}: FAILED - {e}")

        # Test LLM connection (simple check)
        try:
            test_logs = [{
                'timestamp': datetime.now().isoformat(),
                'source': 'test',
                'level': 'info',
                'message': 'Test log entry'
            }]

            response = self.llm_client.analyze_logs(test_logs, context="Test analysis")
            results['llm_connection'] = response.get('success', False)
            status = "OK" if results['llm_connection'] else "FAILED"
            self.logger.info(f"  LLM Connection: {status}")

        except Exception as e:
            self.logger.error(f"  LLM Connection: FAILED - {e}")

        # Test credential storage
        try:
            test_key = 'test_credential'
            test_value = 'test_value'

            self.credential_manager.store_credential(test_key, test_value)
            retrieved = self.credential_manager.retrieve_credential(test_key)
            results['credential_storage'] = (retrieved == test_value)
            self.credential_manager.delete_credential(test_key)

            status = "OK" if results['credential_storage'] else "FAILED"
            self.logger.info(f"  Credential Storage: {status}")

        except Exception as e:
            self.logger.error(f"  Credential Storage: FAILED - {e}")

        return results


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Microsoft Logs AI Analyzer'
    )

    parser.add_argument(
        '--config',
        type=Path,
        default=Path('config/config.yaml'),
        help='Path to configuration file'
    )

    parser.add_argument(
        '--mode',
        choices=['analyze', 'monitor', 'test'],
        default='analyze',
        help='Operation mode: analyze (one-time), monitor (continuous), test (test config)'
    )

    args = parser.parse_args()

    # Check if config exists
    if not args.config.exists():
        print(f"Error: Configuration file not found: {args.config}")
        print("Copy config/config.example.yaml to config/config.yaml and customize it.")
        sys.exit(1)

    # Initialize analyzer
    try:
        analyzer = MSLogAnalyzer(args.config)

        # Run based on mode
        if args.mode == 'test':
            results = analyzer.test_configuration()
            print("\nConfiguration Test Results:")
            print(f"  Config Valid: {results['config_valid']}")
            print(f"  LLM Connection: {results['llm_connection']}")
            print(f"  Credential Storage: {results['credential_storage']}")
            print("  Collectors:")
            for name, status in results['collectors'].items():
                print(f"    {name}: {'OK' if status else 'FAILED'}")

        elif args.mode == 'monitor':
            analyzer.run_continuous()

        else:  # analyze
            analyzer.run_analysis_cycle()

    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        sys.exit(0)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
