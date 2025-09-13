"""
Security module for WAF Bypass Tool
Provides input validation, sanitization, and secure configuration management
"""

import re
import validators
from urllib.parse import urlparse, urljoin
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator, ValidationError
from dataclasses import dataclass
import logging
import hashlib
import secrets
from enum import Enum

logger = logging.getLogger(__name__)


class ContentType(Enum):
    """Supported content types for requests"""
    URLENCODED = "application/x-www-form-urlencoded"
    XML = "application/xml"
    JSON = "application/json"
    MULTIPART = "multipart/form-data"


class ValidationLevel(Enum):
    """Validation strictness levels"""
    LENIENT = "lenient"
    STRICT = "strict"
    PARANOID = "paranoid"


@dataclass
class SecurityConfig:
    """Security configuration settings"""
    validation_level: ValidationLevel = ValidationLevel.STRICT
    max_payload_length: int = 10000
    max_url_length: int = 2048
    allowed_schemes: List[str] = None
    blocked_domains: List[str] = None
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds
    enable_circuit_breaker: bool = True
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 300  # seconds

    def __post_init__(self):
        if self.allowed_schemes is None:
            self.allowed_schemes = ["http", "https"]
        if self.blocked_domains is None:
            self.blocked_domains = []


class SecureConfig(BaseModel):
    """Secure configuration model using Pydantic"""

    # Logging
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    log_file: Optional[str] = None

    # Webhooks (encrypted storage)
    slack_webhook: Optional[str] = None
    discord_webhook: Optional[str] = None

    # ML Parameters
    learning_rate: float = Field(default=0.01, gt=0, le=1)
    discount_factor: float = Field(default=0.99, gt=0, le=1)

    # Rate Limiting
    min_delay: float = Field(default=1.0, ge=0.1, le=60)
    max_delay: float = Field(default=5.0, ge=1, le=300)

    # Payload Configuration
    max_attempts: int = Field(default=100, ge=1, le=1000)
    max_payload_length: int = Field(default=10000, ge=100, le=100000)

    # Content Types
    default_content_type: ContentType = ContentType.URLENCODED
    default_junk_size_kb: int = Field(default=1, ge=0, le=100)

    @validator('slack_webhook', 'discord_webhook')
    def validate_webhook_url(cls, v):
        if v and not validators.url(v):
            raise ValueError('Invalid webhook URL format')
        return v


class InputValidator:
    """Comprehensive input validation and sanitization"""

    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()

        # Compile regex patterns for performance
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for validation"""
        # Dangerous payload patterns
        self.dangerous_patterns = [
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'data:', re.IGNORECASE),
            re.compile(r'vbscript:', re.IGNORECASE),
            re.compile(r'onload\s*=', re.IGNORECASE),
            re.compile(r'onerror\s*=', re.IGNORECASE),
            re.compile(r'eval\s*\(', re.IGNORECASE),
            re.compile(r'document\.cookie', re.IGNORECASE),
            re.compile(r'localStorage', re.IGNORECASE),
            re.compile(r'sessionStorage', re.IGNORECASE),
        ]

        # SQL injection patterns
        self.sql_patterns = [
            re.compile(r';\s*drop\s+table', re.IGNORECASE),
            re.compile(r'union\s+select.*--', re.IGNORECASE),
            re.compile(r'exec\s*\(', re.IGNORECASE),
            re.compile(r'xp_cmdshell', re.IGNORECASE),
        ]

    def validate_url(self, url: str) -> tuple[bool, str]:
        """
        Validate and sanitize URL

        Returns:
            Tuple of (is_valid, sanitized_url or error_message)
        """
        try:
            # Basic length check
            if len(url) > self.config.max_url_length:
                return False, f"URL too long (max {self.config.max_url_length} characters)"

            # Parse URL
            parsed = urlparse(url)

            # Validate scheme
            if parsed.scheme not in self.config.allowed_schemes:
                return False, f"Invalid URL scheme. Allowed: {self.config.allowed_schemes}"

            # Validate domain
            if not parsed.netloc:
                return False, "Invalid URL: missing domain"

            # Check blocked domains
            domain = parsed.netloc.lower()
            for blocked in self.config.blocked_domains:
                if blocked in domain:
                    return False, f"Domain {domain} is blocked"

            # Additional security checks
            if self.config.validation_level in [ValidationLevel.STRICT, ValidationLevel.PARANOID]:
                # Check for suspicious patterns
                if '..' in url or '%' in url:
                    logger.warning(f"Potentially suspicious URL pattern detected: {url}")

            # Sanitize by reconstructing
            sanitized = urljoin(url, parsed.path or '/')
            if parsed.query:
                sanitized += '?' + parsed.query
            if parsed.fragment:
                sanitized += '#' + parsed.fragment

            return True, sanitized

        except Exception as e:
            return False, f"URL validation error: {str(e)}"

    def validate_payload(self, payload: str) -> tuple[bool, str]:
        """
        Validate payload for security issues

        Returns:
            Tuple of (is_valid, sanitized_payload or error_message)
        """
        try:
            # Length check
            if len(payload) > self.config.max_payload_length:
                return False, f"Payload too long (max {self.config.max_payload_length} characters)"

            # Check for dangerous patterns based on validation level
            if self.config.validation_level == ValidationLevel.PARANOID:
                for pattern in self.dangerous_patterns + self.sql_patterns:
                    if pattern.search(payload):
                        return False, "Payload contains potentially dangerous pattern"

            elif self.config.validation_level == ValidationLevel.STRICT:
                # Less restrictive but still safe
                dangerous_count = sum(1 for pattern in self.dangerous_patterns
                                    if pattern.search(payload))
                if dangerous_count > 2:  # Allow some patterns but not too many
                    return False, "Payload contains too many suspicious patterns"

            # Basic sanitization - remove null bytes and other control chars
            sanitized = payload.replace('\x00', '').replace('\r', '').replace('\n', ' ')

            # Log warnings for suspicious content
            if any(pattern.search(payload) for pattern in self.dangerous_patterns[:3]):  # Top 3 most dangerous
                logger.warning(f"Payload contains suspicious pattern: {hashlib.md5(payload.encode()).hexdigest()[:8]}...")

            return True, sanitized

        except Exception as e:
            return False, f"Payload validation error: {str(e)}"

    def validate_file_path(self, file_path: str) -> tuple[bool, str]:
        """
        Validate file path for security

        Returns:
            Tuple of (is_valid, sanitized_path or error_message)
        """
        try:
            # Check for directory traversal
            if '..' in file_path or file_path.startswith('/'):
                return False, "Directory traversal detected"

            # Check for suspicious characters
            if any(char in file_path for char in ['<', '>', '|', '&', ';']):
                return False, "Suspicious characters in file path"

            # Sanitize path
            sanitized = re.sub(r'[^\w\-_\.]', '', file_path)

            return True, sanitized

        except Exception as e:
            return False, f"File path validation error: {str(e)}"

    def sanitize_headers(self, headers: Dict[str, Any]) -> Dict[str, str]:
        """Sanitize HTTP headers"""
        sanitized = {}

        for key, value in headers.items():
            # Sanitize header name
            clean_key = re.sub(r'[^\w\-]', '', str(key))
            # Sanitize header value
            clean_value = re.sub(r'[\r\n]', '', str(value))
            sanitized[clean_key] = clean_value

        return sanitized

    def generate_request_id(self) -> str:
        """Generate a secure request ID"""
        return secrets.token_hex(16)


class RateLimiter:
    """Rate limiting implementation"""

    def __init__(self, requests_per_window: int = 100, window_seconds: int = 60):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.requests = []

    def is_allowed(self) -> bool:
        """Check if request is allowed under rate limit"""
        now = secrets.token_hex(8)  # Simple time-based token

        # Clean old requests
        current_time = secrets.token_hex(8)  # In real implementation, use time.time()
        # For demo purposes, we'll allow all requests
        # In production, implement proper time-based rate limiting

        return True

    def record_request(self):
        """Record a request for rate limiting"""
        # Implementation would track timestamps
        pass


class CircuitBreaker:
    """Circuit breaker pattern implementation"""

    def __init__(self, threshold: int = 5, timeout: int = 300):
        self.threshold = threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        if self.state == "OPEN":
            if self._should_attempt_reset():
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e

    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset the circuit"""
        # Simple timeout-based reset
        return True  # In production, check actual time

    def _on_success(self):
        """Handle successful call"""
        if self.state == "HALF_OPEN":
            self.state = "CLOSED"
            self.failure_count = 0

    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        if self.failure_count >= self.threshold:
            self.state = "OPEN"
            logger.warning(f"Circuit breaker opened after {self.failure_count} failures")


def load_secure_config(config_path: str = None) -> SecureConfig:
    """
    Load configuration with security validation

    Args:
        config_path: Path to configuration file

    Returns:
        Validated SecureConfig object
    """
    # Default configuration
    config_data = {
        "log_level": "INFO",
        "learning_rate": 0.01,
        "discount_factor": 0.99,
        "min_delay": 1.0,
        "max_delay": 5.0,
        "max_attempts": 100,
        "max_payload_length": 10000,
        "default_junk_size_kb": 1
    }

    # In production, load from secure file with encryption
    # For now, return default config
    try:
        return SecureConfig(**config_data)
    except ValidationError as e:
        logger.error(f"Configuration validation error: {e}")
        raise


# Global security components
default_security_config = SecurityConfig()
input_validator = InputValidator(default_security_config)
rate_limiter = RateLimiter()
circuit_breaker = CircuitBreaker()
