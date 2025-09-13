"""
Pytest configuration and shared fixtures for WAF Bypass tool tests
"""

import pytest
import sys
import os
from unittest.mock import Mock, MagicMock

# Add src to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config_manager import MLConfig
from optimized_features import OptimizedFeatureExtractor
from optimized_ml import OptimizedActorCritic
from optimized_http import OptimizedHTTPClient, NetworkConfig


@pytest.fixture
def sample_payloads():
    """Sample payloads for testing"""
    return [
        "<script>alert(1)</script>",
        "1' OR '1'='1",
        "<img src=x onerror=alert(1)>",
        "' UNION SELECT null--",
        "<div onmouseover=alert(1)>test</div>",
    ]


@pytest.fixture
def ml_config():
    """Default ML configuration for tests"""
    return MLConfig(
        learning_rate=0.01,
        discount_factor=0.99,
        batch_size=8,  # Smaller for faster tests
        epochs=10,
    )


@pytest.fixture
def feature_extractor():
    """Optimized feature extractor instance"""
    return OptimizedFeatureExtractor()


@pytest.fixture
def actor_critic(ml_config, feature_extractor):
    """Initialized actor-critic model"""
    return OptimizedActorCritic(ml_config, feature_extractor)


@pytest.fixture
def mock_response():
    """Mock HTTP response for testing"""
    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.text = "OK"
    mock_resp.headers = {"Content-Type": "text/html"}
    return mock_resp


@pytest.fixture
def network_config():
    """Network configuration for HTTP client"""
    return NetworkConfig(
        default_timeout=5.0,  # Shorter for tests
        max_retries=1,
    )


@pytest.fixture
def http_client(network_config):
    """HTTP client instance"""
    return OptimizedHTTPClient(network_config)
