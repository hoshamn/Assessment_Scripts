"""
LLM Client for Microsoft Logs AI Analyzer

Unified interface for multiple LLM providers: Claude, ChatGPT, and Google Gemini.
Handles API calls, rate limiting, error handling, and response parsing.
"""

import time
import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from collections import deque
import traceback

# Import LLM client libraries
try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


class RateLimiter:
    """Simple rate limiter for API calls"""

    def __init__(self, requests_per_minute: int = 50, requests_per_day: int = 5000):
        self.requests_per_minute = requests_per_minute
        self.requests_per_day = requests_per_day

        self.minute_requests = deque()
        self.day_requests = deque()

    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = datetime.now()

        # Clean old requests
        minute_ago = now - timedelta(minutes=1)
        day_ago = now - timedelta(days=1)

        while self.minute_requests and self.minute_requests[0] < minute_ago:
            self.minute_requests.popleft()

        while self.day_requests and self.day_requests[0] < day_ago:
            self.day_requests.popleft()

        # Check limits
        if len(self.minute_requests) >= self.requests_per_minute:
            sleep_time = (self.minute_requests[0] - minute_ago).total_seconds()
            if sleep_time > 0:
                time.sleep(sleep_time + 1)
                return self.wait_if_needed()

        if len(self.day_requests) >= self.requests_per_day:
            sleep_time = (self.day_requests[0] - day_ago).total_seconds()
            if sleep_time > 0:
                raise Exception(f"Daily rate limit reached. Wait {sleep_time/3600:.1f} hours.")

    def record_request(self):
        """Record a request"""
        now = datetime.now()
        self.minute_requests.append(now)
        self.day_requests.append(now)


class LLMClient:
    """Unified LLM client for multiple providers"""

    def __init__(self, config: Dict[str, Any], api_key: str, logger=None):
        """
        Initialize LLM client

        Args:
            config: LLM configuration
            api_key: API key for the provider
            logger: Logger instance
        """
        self.config = config
        self.api_key = api_key
        self.logger = logger
        self.provider = config.get('provider', 'claude')

        # Initialize rate limiter
        rate_limit_config = config.get('rate_limit', {})
        self.rate_limiter = RateLimiter(
            requests_per_minute=rate_limit_config.get('requests_per_minute', 50),
            requests_per_day=rate_limit_config.get('requests_per_day', 5000)
        )

        # Initialize provider-specific client
        self.client = None
        self._init_client()

        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_tokens': 0,
        }

    def _init_client(self):
        """Initialize provider-specific client"""
        if self.provider == 'claude':
            if not ANTHROPIC_AVAILABLE:
                raise ImportError("anthropic library not installed. Run: pip install anthropic")
            self.client = Anthropic(api_key=self.api_key)

        elif self.provider == 'openai':
            if not OPENAI_AVAILABLE:
                raise ImportError("openai library not installed. Run: pip install openai")
            openai.api_key = self.api_key
            self.client = openai

        elif self.provider == 'gemini':
            if not GEMINI_AVAILABLE:
                raise ImportError("google-generativeai library not installed. Run: pip install google-generativeai")
            genai.configure(api_key=self.api_key)
            model_name = self.config.get('gemini', {}).get('model', 'gemini-pro')
            self.client = genai.GenerativeModel(model_name)

        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def analyze_logs(
        self,
        logs: List[Dict[str, Any]],
        context: Optional[str] = None,
        analysis_type: str = 'general'
    ) -> Dict[str, Any]:
        """
        Analyze logs using LLM

        Args:
            logs: List of log entries
            context: Additional context for analysis
            analysis_type: Type of analysis ('general', 'security', 'performance', 'error')

        Returns:
            Analysis results
        """
        try:
            # Wait for rate limit
            self.rate_limiter.wait_if_needed()

            # Build prompt
            prompt = self._build_analysis_prompt(logs, context, analysis_type)

            # Call LLM
            response = self._call_llm(prompt)

            # Parse response
            analysis = self._parse_analysis_response(response)

            # Record request
            self.rate_limiter.record_request()
            self.stats['total_requests'] += 1
            self.stats['successful_requests'] += 1

            if self.logger:
                self.logger.info(f"Successfully analyzed {len(logs)} log entries")

            return analysis

        except Exception as e:
            self.stats['total_requests'] += 1
            self.stats['failed_requests'] += 1

            if self.logger:
                self.logger.error(f"Error analyzing logs: {e}")
                self.logger.debug(traceback.format_exc())

            return {
                'success': False,
                'error': str(e),
                'issues': [],
                'recommendations': []
            }

    def _build_analysis_prompt(
        self,
        logs: List[Dict[str, Any]],
        context: Optional[str],
        analysis_type: str
    ) -> str:
        """Build prompt for log analysis"""

        # System prompt based on analysis type
        system_prompts = {
            'general': "You are an expert in Microsoft infrastructure and system administration. Analyze the provided logs and identify any issues, anomalies, or areas of concern.",
            'security': "You are a cybersecurity expert specializing in Microsoft environments. Analyze the provided logs for security issues, potential threats, and vulnerabilities.",
            'performance': "You are a performance optimization expert for Microsoft infrastructure. Analyze the provided logs for performance issues, bottlenecks, and optimization opportunities.",
            'error': "You are a troubleshooting expert for Microsoft systems. Analyze the provided error logs and identify root causes and solutions."
        }

        system_prompt = system_prompts.get(analysis_type, system_prompts['general'])

        # Format logs
        log_text = self._format_logs_for_prompt(logs)

        # Build prompt
        prompt = f"""{system_prompt}

# Context
{context if context else 'No additional context provided.'}

# Logs to Analyze
{log_text}

# Analysis Requirements
Please provide a comprehensive analysis in the following JSON format:

{{
  "summary": "Brief summary of findings",
  "issues": [
    {{
      "severity": "critical|high|medium|low",
      "title": "Issue title",
      "description": "Detailed description",
      "affected_systems": ["system1", "system2"],
      "event_ids": ["event_id1", "event_id2"],
      "first_seen": "timestamp",
      "last_seen": "timestamp",
      "occurrence_count": 10
    }}
  ],
  "patterns": [
    {{
      "pattern_type": "Type of pattern detected",
      "description": "Pattern description",
      "frequency": "How often this occurs",
      "significance": "Why this matters"
    }}
  ],
  "recommendations": [
    {{
      "priority": "critical|high|medium|low",
      "action": "Recommended action",
      "reason": "Why this action is needed",
      "steps": ["step 1", "step 2", "step 3"],
      "expected_outcome": "What will be achieved"
    }}
  ],
  "health_score": 85,
  "risk_level": "low|medium|high|critical"
}}

Focus on:
1. Critical issues that need immediate attention
2. Patterns that indicate underlying problems
3. Proactive recommendations to prevent future issues
4. Clear, actionable steps for resolution

Provide your analysis:"""

        return prompt

    def _format_logs_for_prompt(self, logs: List[Dict[str, Any]]) -> str:
        """Format logs for inclusion in prompt"""
        formatted_logs = []

        for i, log in enumerate(logs[:100], 1):  # Limit to 100 logs to avoid token limits
            log_str = f"\n--- Log Entry {i} ---\n"
            log_str += f"Timestamp: {log.get('timestamp', 'N/A')}\n"
            log_str += f"Source: {log.get('source', 'N/A')}\n"
            log_str += f"Level: {log.get('level', 'N/A')}\n"
            log_str += f"Event ID: {log.get('event_id', 'N/A')}\n"
            log_str += f"Message: {log.get('message', 'N/A')}\n"

            if 'data' in log:
                log_str += f"Additional Data: {json.dumps(log['data'], indent=2)}\n"

            formatted_logs.append(log_str)

        if len(logs) > 100:
            formatted_logs.append(f"\n... and {len(logs) - 100} more log entries\n")

        return "\n".join(formatted_logs)

    def _call_llm(self, prompt: str) -> str:
        """Call the LLM API"""
        if self.provider == 'claude':
            return self._call_claude(prompt)
        elif self.provider == 'openai':
            return self._call_openai(prompt)
        elif self.provider == 'gemini':
            return self._call_gemini(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _call_claude(self, prompt: str) -> str:
        """Call Claude API"""
        config = self.config.get('claude', {})

        response = self.client.messages.create(
            model=config.get('model', 'claude-3-5-sonnet-20241022'),
            max_tokens=config.get('max_tokens', 4096),
            temperature=config.get('temperature', 0.3),
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        # Track tokens
        self.stats['total_tokens'] += response.usage.input_tokens + response.usage.output_tokens

        return response.content[0].text

    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API"""
        config = self.config.get('openai', {})

        response = self.client.chat.completions.create(
            model=config.get('model', 'gpt-4-turbo-preview'),
            max_tokens=config.get('max_tokens', 4096),
            temperature=config.get('temperature', 0.3),
            messages=[
                {"role": "system", "content": "You are an expert system administrator and log analyst."},
                {"role": "user", "content": prompt}
            ]
        )

        # Track tokens
        self.stats['total_tokens'] += response.usage.total_tokens

        return response.choices[0].message.content

    def _call_gemini(self, prompt: str) -> str:
        """Call Google Gemini API"""
        config = self.config.get('gemini', {})

        generation_config = {
            "temperature": config.get('temperature', 0.3),
            "max_output_tokens": config.get('max_tokens', 4096),
        }

        response = self.client.generate_content(
            prompt,
            generation_config=generation_config
        )

        return response.text

    def _parse_analysis_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response into structured format"""
        try:
            # Try to extract JSON from response
            # LLMs sometimes wrap JSON in markdown code blocks
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                analysis = json.loads(json_str)
                analysis['success'] = True
                return analysis
            else:
                # If no JSON found, return raw response
                return {
                    'success': True,
                    'summary': response,
                    'issues': [],
                    'recommendations': [],
                    'raw_response': response
                }

        except json.JSONDecodeError:
            # If JSON parsing fails, return raw response
            return {
                'success': True,
                'summary': response,
                'issues': [],
                'recommendations': [],
                'raw_response': response
            }

    def get_statistics(self) -> Dict[str, Any]:
        """Get client statistics"""
        return self.stats.copy()


def get_llm_client(config: Dict[str, Any], api_key: str, logger=None) -> LLMClient:
    """
    Factory function to create LLM client

    Args:
        config: Configuration dictionary
        api_key: API key for the provider
        logger: Logger instance

    Returns:
        LLMClient instance
    """
    llm_config = config.get('llm', {})
    return LLMClient(llm_config, api_key, logger)
