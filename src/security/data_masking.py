"""
Data Masking for Sensitive Information

Automatically redacts sensitive information from logs before AI analysis.
Protects PII, credentials, and other sensitive data.
"""

import re
import hashlib
from typing import List, Dict, Pattern, Tuple


class DataMasker:
    """Handles data masking for sensitive information"""

    DEFAULT_PATTERNS = [
        # Email addresses
        {
            'name': 'email',
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'replacement': '[EMAIL_REDACTED]'
        },
        # IP addresses (IPv4)
        {
            'name': 'ipv4',
            'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'replacement': '[IP_REDACTED]'
        },
        # IPv6 addresses
        {
            'name': 'ipv6',
            'pattern': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'replacement': '[IP_REDACTED]'
        },
        # Credit card numbers
        {
            'name': 'credit_card',
            'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'replacement': '[CC_REDACTED]'
        },
        # SSN
        {
            'name': 'ssn',
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
            'replacement': '[SSN_REDACTED]'
        },
        # Passwords (various formats)
        {
            'name': 'password',
            'pattern': r'(?:password|pwd|passwd)[\s:=]+["\']?([^\s"\']+)["\']?',
            'replacement': r'password=[PASSWORD_REDACTED]',
            'case_insensitive': True
        },
        # API keys and tokens
        {
            'name': 'api_key',
            'pattern': r'(?:api[_-]?key|token|bearer)[\s:=]+["\']?([A-Za-z0-9_\-]{20,})["\']?',
            'replacement': r'api_key=[TOKEN_REDACTED]',
            'case_insensitive': True
        },
        # Windows SIDs
        {
            'name': 'windows_sid',
            'pattern': r'S-1-\d+-\d+-\d+-\d+-\d+-\d+',
            'replacement': '[SID_REDACTED]'
        },
        # UNC paths with credentials
        {
            'name': 'unc_credentials',
            'pattern': r'\\\\[^\\]+\\[^\\]+',
            'replacement': '[UNC_PATH_REDACTED]'
        },
        # GUID/UUID
        {
            'name': 'guid',
            'pattern': r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
            'replacement': '[GUID_REDACTED]'
        },
        # Connection strings
        {
            'name': 'connection_string',
            'pattern': r'(?:Data Source|Server|Database|UID|Password)=[^;]+',
            'replacement': '[CONNECTION_STRING_REDACTED]',
            'case_insensitive': True
        },
    ]

    def __init__(self, custom_patterns: List[Dict] = None, enabled: bool = True):
        """
        Initialize data masker

        Args:
            custom_patterns: Additional patterns to mask
            enabled: Whether masking is enabled
        """
        self.enabled = enabled
        self.patterns = []

        if enabled:
            # Compile default patterns
            for pattern_def in self.DEFAULT_PATTERNS:
                self._add_pattern(pattern_def)

            # Add custom patterns
            if custom_patterns:
                for pattern_def in custom_patterns:
                    self._add_pattern(pattern_def)

    def _add_pattern(self, pattern_def: Dict):
        """Add a pattern to the masker"""
        flags = re.IGNORECASE if pattern_def.get('case_insensitive', False) else 0

        compiled_pattern = re.compile(pattern_def['pattern'], flags)

        self.patterns.append({
            'name': pattern_def['name'],
            'pattern': compiled_pattern,
            'replacement': pattern_def['replacement']
        })

    def mask_text(self, text: str, preserve_structure: bool = True) -> str:
        """
        Mask sensitive information in text

        Args:
            text: Text to mask
            preserve_structure: If True, preserves original text structure with unique hashes

        Returns:
            Masked text
        """
        if not self.enabled or not text:
            return text

        masked_text = text

        for pattern_info in self.patterns:
            if preserve_structure:
                # Replace with unique hash to preserve structure
                masked_text = self._mask_with_hash(
                    masked_text,
                    pattern_info['pattern'],
                    pattern_info['name']
                )
            else:
                # Simple replacement
                masked_text = pattern_info['pattern'].sub(
                    pattern_info['replacement'],
                    masked_text
                )

        return masked_text

    def _mask_with_hash(self, text: str, pattern: Pattern, name: str) -> str:
        """
        Mask text while preserving structure using hashes

        This allows the same value to be masked consistently throughout the logs,
        which helps maintain relationships in the analysis.
        """
        def replace_with_hash(match):
            matched_text = match.group(0)
            # Create short hash of the matched text
            hash_value = hashlib.md5(matched_text.encode()).hexdigest()[:8]
            return f"[{name.upper()}_{hash_value}]"

        return pattern.sub(replace_with_hash, text)

    def mask_dict(self, data: Dict, keys_to_mask: List[str] = None) -> Dict:
        """
        Mask sensitive information in dictionary

        Args:
            data: Dictionary to mask
            keys_to_mask: Specific keys to mask (in addition to pattern matching)

        Returns:
            Masked dictionary
        """
        if not self.enabled:
            return data

        masked_data = {}

        sensitive_key_patterns = [
            'password', 'pwd', 'secret', 'token', 'key', 'credential',
            'connectionstring', 'apikey'
        ]

        if keys_to_mask:
            sensitive_key_patterns.extend([k.lower() for k in keys_to_mask])

        for key, value in data.items():
            # Check if key itself indicates sensitive data
            is_sensitive_key = any(
                pattern in key.lower()
                for pattern in sensitive_key_patterns
            )

            if is_sensitive_key:
                masked_data[key] = '[REDACTED]'
            elif isinstance(value, str):
                masked_data[key] = self.mask_text(value)
            elif isinstance(value, dict):
                masked_data[key] = self.mask_dict(value, keys_to_mask)
            elif isinstance(value, list):
                masked_data[key] = [
                    self.mask_text(item) if isinstance(item, str)
                    else self.mask_dict(item, keys_to_mask) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                masked_data[key] = value

        return masked_data

    def mask_log_entry(self, log_entry: Dict) -> Dict:
        """
        Mask a complete log entry

        Args:
            log_entry: Log entry dictionary

        Returns:
            Masked log entry
        """
        if not self.enabled:
            return log_entry

        masked_entry = log_entry.copy()

        # Mask message/description fields
        message_fields = ['message', 'description', 'details', 'data', 'event_data']

        for field in message_fields:
            if field in masked_entry and isinstance(masked_entry[field], str):
                masked_entry[field] = self.mask_text(masked_entry[field])

        # Mask entire dict for other sensitive keys
        masked_entry = self.mask_dict(masked_entry)

        return masked_entry

    def get_statistics(self, text: str) -> Dict[str, int]:
        """
        Get statistics on what would be masked

        Args:
            text: Text to analyze

        Returns:
            Dictionary with count of matches for each pattern
        """
        stats = {}

        for pattern_info in self.patterns:
            matches = pattern_info['pattern'].findall(text)
            stats[pattern_info['name']] = len(matches)

        return stats


def get_data_masker(config: Dict) -> DataMasker:
    """
    Factory function to get configured data masker

    Args:
        config: Configuration dictionary

    Returns:
        DataMasker instance
    """
    security_config = config.get('security', {})
    masking_config = security_config.get('data_masking', {})

    enabled = masking_config.get('enabled', True)
    custom_patterns = masking_config.get('mask_patterns', [])

    return DataMasker(custom_patterns=custom_patterns, enabled=enabled)
