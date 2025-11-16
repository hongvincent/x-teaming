"""
LLM Client Module
Provides interface to OpenAI GPT models with caching and rate limiting
"""

import time
from typing import Optional, List, Dict, Any
from functools import lru_cache
import hashlib
import json
from openai import OpenAI
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from .logger import get_logger
from .config_loader import get_config
from config.api_keys import APIKeyManager

logger = get_logger(__name__)


class RateLimiter:
    """Simple rate limiter"""

    def __init__(self, max_calls: int = 60, period: int = 60):
        """
        Initialize rate limiter

        Args:
            max_calls: Maximum number of calls allowed
            period: Time period in seconds
        """
        self.max_calls = max_calls
        self.period = period
        self.calls = []

    def __call__(self, func):
        """Rate limit decorator"""

        def wrapper(*args, **kwargs):
            now = time.time()

            # Remove old calls outside the period
            self.calls = [call for call in self.calls if call > now - self.period]

            if len(self.calls) >= self.max_calls:
                sleep_time = self.period - (now - self.calls[0])
                logger.warning(f"Rate limit reached. Sleeping for {sleep_time:.2f}s")
                time.sleep(sleep_time)
                self.calls = []

            self.calls.append(now)
            return func(*args, **kwargs)

        return wrapper


class LLMClient:
    """
    LLM Client for interacting with OpenAI models
    Provides caching, rate limiting, and error handling
    """

    def __init__(self, use_cache: bool = True):
        """
        Initialize LLM client

        Args:
            use_cache: Enable response caching
        """
        self.config = get_config()
        self.openai_config = self.config.get_openai_config()

        # Initialize OpenAI client
        api_key = APIKeyManager.get_openai_key()
        if not api_key:
            raise ValueError("OpenAI API key not configured")

        self.client = OpenAI(api_key=api_key)
        self.use_cache = use_cache
        self._cache: Dict[str, Any] = {}

        logger.info("LLM Client initialized with model: %s", self.openai_config.model)

    def _generate_cache_key(self, prompt: str, **kwargs) -> str:
        """
        Generate cache key for prompt

        Args:
            prompt: User prompt
            **kwargs: Additional parameters

        Returns:
            str: Cache key
        """
        cache_data = {"prompt": prompt, **kwargs}
        cache_str = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_str.encode()).hexdigest()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(Exception),
    )
    def complete(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        system_message: Optional[str] = None,
        **kwargs,
    ) -> str:
        """
        Generate completion for prompt

        Args:
            prompt: User prompt
            model: Model name (default from config)
            temperature: Sampling temperature (default from config)
            max_tokens: Maximum tokens to generate (default from config)
            system_message: System message for context
            **kwargs: Additional parameters

        Returns:
            str: Generated completion
        """
        # Use config defaults if not provided
        model = model or self.openai_config.model
        temperature = (
            temperature
            if temperature is not None
            else self.openai_config.temperature
        )
        max_tokens = max_tokens or self.openai_config.max_tokens

        # Check cache
        cache_key = self._generate_cache_key(
            prompt, model=model, temperature=temperature, max_tokens=max_tokens
        )

        if self.use_cache and cache_key in self._cache:
            logger.debug("Cache hit for prompt")
            return self._cache[cache_key]

        # Build messages
        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})

        logger.info(f"Calling OpenAI API with model: {model}")

        try:
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                top_p=self.openai_config.top_p,
                frequency_penalty=self.openai_config.frequency_penalty,
                presence_penalty=self.openai_config.presence_penalty,
                **kwargs,
            )

            # Extract completion
            completion = response.choices[0].message.content

            # Cache result
            if self.use_cache:
                self._cache[cache_key] = completion

            logger.info("OpenAI API call successful")
            return completion

        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise

    def complete_with_json(
        self, prompt: str, schema: Optional[Dict] = None, **kwargs
    ) -> Dict[str, Any]:
        """
        Generate completion with JSON response

        Args:
            prompt: User prompt
            schema: Expected JSON schema
            **kwargs: Additional parameters

        Returns:
            Dict: Parsed JSON response
        """
        # Add JSON instruction to prompt
        json_prompt = f"{prompt}\n\nRespond with valid JSON only."

        if schema:
            json_prompt += f"\n\nExpected schema:\n{json.dumps(schema, indent=2)}"

        # Get completion
        completion = self.complete(json_prompt, **kwargs)

        # Parse JSON
        try:
            # Extract JSON from markdown code blocks if present
            if "```json" in completion:
                completion = completion.split("```json")[1].split("```")[0].strip()
            elif "```" in completion:
                completion = completion.split("```")[1].split("```")[0].strip()

            return json.loads(completion)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Response: {completion}")
            raise ValueError(f"Invalid JSON response: {e}")

    def analyze_code(
        self, code: str, language: str, task: str = "analyze", **kwargs
    ) -> str:
        """
        Analyze code for security issues

        Args:
            code: Source code to analyze
            language: Programming language
            task: Analysis task (analyze, detect_vulnerabilities, etc.)
            **kwargs: Additional parameters

        Returns:
            str: Analysis result
        """
        system_message = f"""You are a security expert analyzing {language} code.
Focus on identifying security vulnerabilities, bugs, and best practices violations.
Provide detailed explanations and remediation suggestions."""

        prompt = f"""Task: {task}

Language: {language}

Code:
```{language}
{code}
```

Provide a comprehensive security analysis."""

        return self.complete(prompt, system_message=system_message, **kwargs)

    def detect_threats(self, text: str, threat_type: str = "general", **kwargs) -> Dict:
        """
        Detect security threats in text

        Args:
            text: Text to analyze
            threat_type: Type of threat (phishing, malware, etc.)
            **kwargs: Additional parameters

        Returns:
            Dict: Threat analysis
        """
        system_message = """You are a cybersecurity threat detection expert.
Analyze the provided content for security threats and indicators of compromise."""

        prompt = f"""Threat Type: {threat_type}

Content:
{text}

Analyze for security threats and provide:
1. Threat classification
2. Risk level (low/medium/high/critical)
3. Indicators of compromise
4. Recommended actions

Respond in JSON format."""

        schema = {
            "classification": "string",
            "risk_level": "string",
            "indicators": ["string"],
            "recommendations": ["string"],
        }

        return self.complete_with_json(prompt, schema=schema, **kwargs)

    def generate_security_report(
        self, findings: List[Dict], report_type: str = "vulnerability", **kwargs
    ) -> str:
        """
        Generate security report from findings

        Args:
            findings: List of security findings
            report_type: Type of report
            **kwargs: Additional parameters

        Returns:
            str: Generated report
        """
        system_message = """You are a security report writer.
Generate clear, comprehensive security reports with executive summaries,
detailed findings, and actionable recommendations."""

        findings_json = json.dumps(findings, indent=2)

        prompt = f"""Report Type: {report_type}

Findings:
{findings_json}

Generate a comprehensive security report including:
1. Executive Summary
2. Detailed Findings
3. Risk Assessment
4. Remediation Recommendations
5. Next Steps"""

        return self.complete(prompt, system_message=system_message, **kwargs)

    def clear_cache(self) -> None:
        """Clear response cache"""
        self._cache = {}
        logger.info("Cache cleared")

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics"""
        return {"cache_size": len(self._cache), "cache_enabled": self.use_cache}


# Example usage
if __name__ == "__main__":
    # Test LLM client
    client = LLMClient()

    # Test basic completion
    response = client.complete("What are the OWASP Top 10 vulnerabilities?")
    print("Response:", response[:200], "...")

    # Test code analysis
    vulnerable_code = """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query)
"""

    analysis = client.analyze_code(
        vulnerable_code, language="python", task="detect_vulnerabilities"
    )
    print("\nCode Analysis:", analysis[:200], "...")

    # Test threat detection
    phishing_email = """
Subject: Urgent: Your account will be closed

Dear user,
Your account will be closed in 24 hours. Click here to verify: http://evil-site.com
"""

    threat = client.detect_threats(phishing_email, threat_type="phishing")
    print("\nThreat Detection:", threat)

    # Cache stats
    print("\nCache Stats:", client.get_cache_stats())
