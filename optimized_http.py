"""
Optimized HTTP Client for WAF Bypass Tool
Provides high-performance HTTP operations with connection pooling and async support
"""

import asyncio
import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass
import logging
from concurrent.futures import ThreadPoolExecutor
import threading

from config_manager import NetworkConfig
from exceptions import error_handler, ErrorContext, NetworkException

logger = logging.getLogger(__name__)


@dataclass
class HTTPStats:
    """HTTP client performance statistics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    connection_pool_hits: int = 0
    connection_pool_misses: int = 0
    total_bytes_transferred: int = 0


class OptimizedHTTPClient:
    """
    Optimized HTTP client with connection pooling, retries, and performance monitoring
    """

    def __init__(self, config: NetworkConfig):
        self.config = config
        self.stats = HTTPStats()

        # Create session with optimized settings
        self.session = self._create_optimized_session()

        # Response cache for repeated requests
        self.response_cache = {}
        self.cache_max_size = 1000
        self.cache_ttl = 300  # 5 minutes

        # Rate limiting
        self.request_times = []
        self.rate_limit_window = 60  # seconds
        self.max_requests_per_window = 100

        logger.info("OptimizedHTTPClient initialized with connection pooling")

    def _create_optimized_session(self) -> requests.Session:
        """Create session with optimized connection pooling and retries"""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )

        # Create HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config.connection_pool_size,
            pool_maxsize=self.config.max_connections,
            pool_block=False
        )

        # Mount adapter for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default timeout
        session.timeout = self.config.default_timeout

        # Set user agent
        session.headers.update({"User-Agent": self.config.user_agent})

        # Keep-alive settings
        if self.config.keep_alive:
            session.headers.update({"Connection": "keep-alive"})
        else:
            session.headers.update({"Connection": "close"})

        return session

    def _check_rate_limit(self) -> bool:
        """Check if request is within rate limits"""
        current_time = time.time()

        # Clean old request times
        self.request_times = [
            t for t in self.request_times
            if current_time - t < self.rate_limit_window
        ]

        # Check if under limit
        if len(self.request_times) >= self.max_requests_per_window:
            return False

        return True

    def _record_request(self):
        """Record request time for rate limiting"""
        self.request_times.append(time.time())

    def _get_cache_key(self, url: str, params: Optional[Dict[str, Any]] = None,
                      headers: Optional[Dict[str, str]] = None) -> str:
        """Generate cache key for request"""
        import hashlib
        import json

        cache_data = {
            "url": url,
            "params": params or {},
            "headers": {k: v for k, v in (headers or {}).items() if k.lower() not in ['authorization', 'cookie']}
        }

        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_string.encode()).hexdigest()

    def _get_cached_response(self, cache_key: str) -> Optional[requests.Response]:
        """Get cached response if valid"""
        if cache_key in self.response_cache:
            cached_item = self.response_cache[cache_key]
            if time.time() - cached_item["timestamp"] < self.cache_ttl:
                self.stats.connection_pool_hits += 1
                return cached_item["response"]

        self.stats.connection_pool_misses += 1
        return None

    def _cache_response(self, cache_key: str, response: requests.Response):
        """Cache response if cache is not full"""
        if len(self.response_cache) < self.cache_max_size:
            self.response_cache[cache_key] = {
                "response": response,
                "timestamp": time.time(),
                "url": response.url
            }

    def get(self, url: str, **kwargs) -> requests.Response:
        """Optimized GET request with caching and rate limiting"""
        start_time = time.time()

        try:
            # Check rate limit
            if not self._check_rate_limit():
                raise NetworkException(
                    f"Rate limit exceeded ({self.max_requests_per_window}/{self.rate_limit_window}s)",
                    url=url
                )

            # Check cache first
            cache_key = self._get_cache_key(url, kwargs.get('params'), kwargs.get('headers'))
            cached_response = self._get_cached_response(cache_key)

            if cached_response:
                logger.debug(f"Cache hit for {url}")
                return cached_response

            # Record request
            self._record_request()

            # Set default timeout if not provided
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.config.default_timeout

            # Make request
            response = self.session.get(url, **kwargs)

            # Update statistics
            self.stats.total_requests += 1
            if response.status_code < 400:
                self.stats.successful_requests += 1
            else:
                self.stats.failed_requests += 1

            # Cache successful responses
            if response.status_code == 200:
                self._cache_response(cache_key, response)

            # Track response time
            response_time = time.time() - start_time
            self.stats.average_response_time = (
                self.stats.average_response_time + response_time
            ) / 2

            # Track bytes transferred
            if hasattr(response, 'content'):
                self.stats.total_bytes_transferred += len(response.content)

            return response

        except requests.RequestException as e:
            self.stats.failed_requests += 1
            raise NetworkException(f"HTTP request failed: {e}", url=url) from e

    def post(self, url: str, **kwargs) -> requests.Response:
        """Optimized POST request"""
        start_time = time.time()

        try:
            # Check rate limit
            if not self._check_rate_limit():
                raise NetworkException(
                    f"Rate limit exceeded ({self.max_requests_per_window}/{self.rate_limit_window}s)",
                    url=url
                )

            # Record request
            self._record_request()

            # Set default timeout
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.config.default_timeout

            # Make request
            response = self.session.post(url, **kwargs)

            # Update statistics
            self.stats.total_requests += 1
            if response.status_code < 400:
                self.stats.successful_requests += 1
            else:
                self.stats.failed_requests += 1

            # Track response time
            response_time = time.time() - start_time
            self.stats.average_response_time = (
                self.stats.average_response_time + response_time
            ) / 2

            return response

        except requests.RequestException as e:
            self.stats.failed_requests += 1
            raise NetworkException(f"HTTP POST failed: {e}", url=url) from e

    def batch_get(self, urls: List[str], **kwargs) -> List[Tuple[str, Optional[requests.Response]]]:
        """
        Batch GET requests for improved performance

        Args:
            urls: List of URLs to request
            **kwargs: Additional request parameters

        Returns:
            List of (url, response) tuples
        """
        results = []

        # Process in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(len(urls), 10)) as executor:
            futures = [executor.submit(self.get, url, **kwargs) for url in urls]

            for i, future in enumerate(futures):
                try:
                    response = future.result(timeout=self.config.default_timeout * 2)
                    results.append((urls[i], response))
                except Exception as e:
                    logger.warning(f"Batch request failed for {urls[i]}: {e}")
                    results.append((urls[i], None))

        return results

    def clear_cache(self):
        """Clear response cache"""
        self.response_cache.clear()
        logger.info("HTTP cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get HTTP client statistics"""
        cache_hit_rate = 0.0
        total_cache_requests = self.stats.connection_pool_hits + self.stats.connection_pool_misses
        if total_cache_requests > 0:
            cache_hit_rate = self.stats.connection_pool_hits / total_cache_requests

        success_rate = 0.0
        if self.stats.total_requests > 0:
            success_rate = self.stats.successful_requests / self.stats.total_requests

        return {
            "total_requests": self.stats.total_requests,
            "successful_requests": self.stats.successful_requests,
            "failed_requests": self.stats.failed_requests,
            "success_rate": success_rate,
            "average_response_time_ms": self.stats.average_response_time * 1000,
            "cache_hit_rate": cache_hit_rate,
            "cache_size": len(self.response_cache),
            "total_bytes_transferred_mb": self.stats.total_bytes_transferred / (1024 * 1024),
            "active_connections": len(self.session.adapters),
        }

    def close(self):
        """Close HTTP session and cleanup"""
        self.session.close()
        self.clear_cache()
        logger.info("HTTP client closed")


class AsyncHTTPClient:
    """
    Asynchronous HTTP client for high-performance concurrent requests
    """

    def __init__(self, config: NetworkConfig):
        self.config = config
        self.stats = HTTPStats()
        self._session = None
        self._connector = None

    async def __aenter__(self):
        """Async context manager entry"""
        await self._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._close_session()

    async def _create_session(self):
        """Create aiohttp session with optimized settings"""
        # Configure connector with connection pooling
        self._connector = aiohttp.TCPConnector(
            limit=self.config.max_connections,
            limit_per_host=self.config.connection_pool_size,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=60,
            enable_cleanup_closed=True,
        )

        # Configure timeout
        timeout = aiohttp.ClientTimeout(total=self.config.default_timeout)

        # Create session
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=timeout,
            headers={"User-Agent": self.config.user_agent}
        )

        logger.info("AsyncHTTPClient session created")

    async def _close_session(self):
        """Close aiohttp session"""
        if self._session:
            await self._session.close()
        if self._connector:
            await self._connector.close()
        logger.info("AsyncHTTPClient session closed")

    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Async GET request"""
        if not self._session:
            await self._create_session()

        start_time = time.time()

        try:
            async with self._session.get(url, **kwargs) as response:
                # Read response content
                content = await response.read()

                # Update statistics
                self.stats.total_requests += 1
                if response.status < 400:
                    self.stats.successful_requests += 1
                else:
                    self.stats.failed_requests += 1

                # Track response time and bytes
                response_time = time.time() - start_time
                self.stats.average_response_time = (
                    self.stats.average_response_time + response_time
                ) / 2
                self.stats.total_bytes_transferred += len(content)

                # Create response-like object for compatibility
                response._content = content
                return response

        except Exception as e:
            self.stats.failed_requests += 1
            raise NetworkException(f"Async HTTP request failed: {e}", url=url) from e

    async def batch_get(self, urls: List[str], **kwargs) -> List[Tuple[str, Optional[aiohttp.ClientResponse]]]:
        """Async batch GET requests"""
        if not self._session:
            await self._create_session()

        async def fetch_url(url: str):
            try:
                return url, await self.get(url, **kwargs)
            except Exception as e:
                logger.warning(f"Async request failed for {url}: {e}")
                return url, None

        # Execute all requests concurrently
        tasks = [fetch_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Async batch request error: {result}")
                processed_results.append(("", None))
            else:
                processed_results.append(result)

        return processed_results

    def get_stats(self) -> Dict[str, Any]:
        """Get async HTTP client statistics"""
        success_rate = 0.0
        if self.stats.total_requests > 0:
            success_rate = self.stats.successful_requests / self.stats.total_requests

        return {
            "total_requests": self.stats.total_requests,
            "successful_requests": self.stats.successful_requests,
            "failed_requests": self.stats.failed_requests,
            "success_rate": success_rate,
            "average_response_time_ms": self.stats.average_response_time * 1000,
            "total_bytes_transferred_mb": self.stats.total_bytes_transferred / (1024 * 1024),
        }


# Thread-safe singleton for HTTP clients
_http_client_lock = threading.Lock()
_http_clients = {}


def get_optimized_http_client(config: NetworkConfig) -> OptimizedHTTPClient:
    """Get or create optimized HTTP client singleton"""
    with _http_client_lock:
        config_hash = hash((config.max_connections, config.connection_pool_size,
                          config.default_timeout, config.keep_alive))

        if config_hash not in _http_clients:
            _http_clients[config_hash] = OptimizedHTTPClient(config)

        return _http_clients[config_hash]


async def create_async_http_client(config: NetworkConfig) -> AsyncHTTPClient:
    """Create async HTTP client"""
    client = AsyncHTTPClient(config)
    await client._create_session()
    return client
