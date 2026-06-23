"""
Pattern Analyzer

Learns from historical logs to identify patterns and anomalies.
"""

import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path


class PatternAnalyzer:
    """Analyzes log patterns and learns from historical data"""

    def __init__(self, config: Dict[str, Any], storage_path: Path, logger=None):
        """
        Initialize pattern analyzer

        Args:
            config: Configuration
            storage_path: Path to store patterns
            logger: Logger instance
        """
        self.config = config
        self.storage_path = storage_path
        self.logger = logger

        self.enabled = config.get('enabled', True)
        self.min_occurrences = config.get('min_occurrences', 3)
        self.learning_window_days = config.get('learning_window_days', 7)
        self.auto_update = config.get('auto_update', True)

        # Load existing patterns
        self.patterns = self._load_patterns()

        # Statistics
        self.stats = {
            'patterns_detected': 0,
            'new_patterns': 0,
            'pattern_matches': 0
        }

    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze logs for patterns

        Args:
            logs: List of log entries

        Returns:
            Analysis results
        """
        if not self.enabled or not logs:
            return {'patterns': [], 'anomalies': []}

        try:
            # Detect patterns in current logs
            current_patterns = self._detect_patterns(logs)

            # Compare with known patterns
            pattern_analysis = self._compare_patterns(current_patterns)

            # Identify anomalies
            anomalies = self._identify_anomalies(logs, current_patterns)

            # Update pattern database if auto-update enabled
            if self.auto_update:
                self._update_patterns(current_patterns)

            return {
                'patterns': pattern_analysis,
                'anomalies': anomalies,
                'statistics': self.stats
            }

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in pattern analysis: {e}")
            return {'patterns': [], 'anomalies': [], 'error': str(e)}

    def _detect_patterns(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect patterns in logs"""
        patterns = []

        # Group by various dimensions
        patterns.extend(self._detect_error_patterns(logs))
        patterns.extend(self._detect_temporal_patterns(logs))
        patterns.extend(self._detect_sequence_patterns(logs))

        return patterns

    def _detect_error_patterns(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect recurring error patterns"""
        error_patterns = []

        # Group errors by event ID and source
        error_groups = defaultdict(list)

        for log in logs:
            if log.get('level') in ['Error', 'Critical', 'Warning']:
                key = (
                    log.get('event_id', 'unknown'),
                    log.get('source', 'unknown'),
                    self._normalize_message(log.get('message', ''))
                )
                error_groups[key].append(log)

        # Identify patterns (recurring errors)
        for key, occurrences in error_groups.items():
            if len(occurrences) >= self.min_occurrences:
                event_id, source, normalized_msg = key

                pattern = {
                    'type': 'recurring_error',
                    'event_id': event_id,
                    'source': source,
                    'message_pattern': normalized_msg,
                    'occurrences': len(occurrences),
                    'first_seen': occurrences[0].get('timestamp'),
                    'last_seen': occurrences[-1].get('timestamp'),
                    'severity': occurrences[0].get('level'),
                    'pattern_id': self._generate_pattern_id(key)
                }

                error_patterns.append(pattern)

        return error_patterns

    def _detect_temporal_patterns(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect time-based patterns"""
        temporal_patterns = []

        # Group by hour of day
        hourly_distribution = defaultdict(list)

        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log.get('timestamp', ''))
                hour = timestamp.hour
                hourly_distribution[hour].append(log)
            except:
                continue

        # Identify unusual patterns (spikes)
        if hourly_distribution:
            avg_per_hour = sum(len(logs) for logs in hourly_distribution.values()) / 24

            for hour, hour_logs in hourly_distribution.items():
                if len(hour_logs) > avg_per_hour * 2:  # Spike threshold
                    pattern = {
                        'type': 'temporal_spike',
                        'hour': hour,
                        'log_count': len(hour_logs),
                        'average': avg_per_hour,
                        'spike_ratio': len(hour_logs) / avg_per_hour,
                        'pattern_id': f"temporal_spike_{hour}"
                    }
                    temporal_patterns.append(pattern)

        return temporal_patterns

    def _detect_sequence_patterns(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect event sequences"""
        sequence_patterns = []

        # Look for common event sequences
        sequences = []
        window_size = 5

        for i in range(len(logs) - window_size + 1):
            window = logs[i:i + window_size]
            sequence = tuple(log.get('event_id', 'unknown') for log in window)
            sequences.append(sequence)

        # Count sequences
        sequence_counts = Counter(sequences)

        # Identify common sequences
        for sequence, count in sequence_counts.items():
            if count >= self.min_occurrences:
                pattern = {
                    'type': 'event_sequence',
                    'sequence': list(sequence),
                    'occurrences': count,
                    'pattern_id': self._generate_pattern_id(sequence)
                }
                sequence_patterns.append(pattern)

        return sequence_patterns

    def _compare_patterns(self, current_patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compare current patterns with known patterns"""
        pattern_analysis = []

        for pattern in current_patterns:
            pattern_id = pattern.get('pattern_id')

            if pattern_id in self.patterns:
                # Known pattern
                known_pattern = self.patterns[pattern_id]

                analysis = {
                    **pattern,
                    'status': 'known',
                    'previous_occurrences': known_pattern.get('total_occurrences', 0),
                    'first_detected': known_pattern.get('first_detected'),
                    'severity_trend': self._calculate_trend(pattern, known_pattern)
                }

                self.stats['pattern_matches'] += 1
            else:
                # New pattern
                analysis = {
                    **pattern,
                    'status': 'new',
                    'first_detected': datetime.now().isoformat()
                }

                self.stats['new_patterns'] += 1

            pattern_analysis.append(analysis)
            self.stats['patterns_detected'] += 1

        return pattern_analysis

    def _identify_anomalies(
        self,
        logs: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Identify anomalies in logs"""
        anomalies = []

        # Look for events that don't match known patterns
        for log in logs:
            if self._is_anomalous(log, patterns):
                anomaly = {
                    'timestamp': log.get('timestamp'),
                    'source': log.get('source'),
                    'event_id': log.get('event_id'),
                    'message': log.get('message'),
                    'reason': 'No matching pattern',
                    'severity': log.get('level')
                }
                anomalies.append(anomaly)

        return anomalies

    def _is_anomalous(self, log: Dict[str, Any], patterns: List[Dict[str, Any]]) -> bool:
        """Check if log entry is anomalous"""
        # Simple heuristic: critical/error logs that don't match patterns
        if log.get('level') not in ['Error', 'Critical']:
            return False

        event_id = log.get('event_id')
        normalized_msg = self._normalize_message(log.get('message', ''))

        # Check if matches any known pattern
        for pattern in patterns:
            if pattern.get('event_id') == event_id:
                if pattern.get('message_pattern') == normalized_msg:
                    return False

        return True

    def _normalize_message(self, message: str) -> str:
        """Normalize log message for pattern matching"""
        import re

        # Remove timestamps
        message = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', '[TIMESTAMP]', message)

        # Remove numbers
        message = re.sub(r'\b\d+\b', '[NUMBER]', message)

        # Remove IPs
        message = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', message)

        # Remove GUIDs
        message = re.sub(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '[GUID]', message)

        return message.lower().strip()

    def _generate_pattern_id(self, key: tuple) -> str:
        """Generate unique pattern ID"""
        key_str = str(key)
        return hashlib.md5(key_str.encode()).hexdigest()[:16]

    def _calculate_trend(self, current_pattern: Dict, known_pattern: Dict) -> str:
        """Calculate trend for pattern"""
        current_count = current_pattern.get('occurrences', 0)
        previous_count = known_pattern.get('average_occurrences', 0)

        if previous_count == 0:
            return 'stable'

        ratio = current_count / previous_count

        if ratio > 1.5:
            return 'increasing'
        elif ratio < 0.5:
            return 'decreasing'
        else:
            return 'stable'

    def _update_patterns(self, current_patterns: List[Dict[str, Any]]):
        """Update pattern database"""
        for pattern in current_patterns:
            pattern_id = pattern.get('pattern_id')

            if pattern_id in self.patterns:
                # Update existing pattern
                self.patterns[pattern_id]['total_occurrences'] += pattern.get('occurrences', 0)
                self.patterns[pattern_id]['last_seen'] = datetime.now().isoformat()
                self.patterns[pattern_id]['update_count'] += 1

                # Update average
                total = self.patterns[pattern_id]['total_occurrences']
                count = self.patterns[pattern_id]['update_count']
                self.patterns[pattern_id]['average_occurrences'] = total / count
            else:
                # Add new pattern
                self.patterns[pattern_id] = {
                    **pattern,
                    'first_detected': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'total_occurrences': pattern.get('occurrences', 0),
                    'update_count': 1,
                    'average_occurrences': pattern.get('occurrences', 0)
                }

        # Save patterns
        self._save_patterns()

    def _load_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load patterns from storage"""
        pattern_file = self.storage_path / 'learned_patterns.json'

        if not pattern_file.exists():
            return {}

        try:
            with open(pattern_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error loading patterns: {e}")
            return {}

    def _save_patterns(self):
        """Save patterns to storage"""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        pattern_file = self.storage_path / 'learned_patterns.json'

        try:
            with open(pattern_file, 'w') as f:
                json.dump(self.patterns, f, indent=2)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error saving patterns: {e}")

    def get_pattern_summary(self) -> Dict[str, Any]:
        """Get summary of learned patterns"""
        return {
            'total_patterns': len(self.patterns),
            'pattern_types': Counter(p.get('type') for p in self.patterns.values()),
            'statistics': self.stats
        }


def get_pattern_analyzer(config: Dict[str, Any], storage_path: Path, logger=None) -> PatternAnalyzer:
    """Factory function for pattern analyzer"""
    pattern_config = config.get('analysis', {}).get('pattern_learning', {})
    return PatternAnalyzer(pattern_config, storage_path, logger)
