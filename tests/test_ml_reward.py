"""
Critical test for ML reward function - the core bug that was preventing learning
"""

import pytest
from waf_bypass_service import WAFBypassService


class TestMLRewardFunction:
    """Test the fixed reward function that enables proper ML learning"""

    @pytest.fixture
    def bypass_service(self):
        """Create bypass service for testing"""
        return WAFBypassService()

    def test_reward_successful_responses(self, bypass_service):
        """Test that successful HTTP responses (200, 201, 202, etc.) get positive reward"""
        # Mock responses for successful requests
        mock_responses = [
            self._mock_response(200),  # OK
            self._mock_response(201),  # Created
            self._mock_response(202),  # Accepted
            self._mock_response(301),  # Moved Permanently
            self._mock_response(302),  # Found
            self._mock_response(404),  # Not Found (acceptable if no WAF)
            self._mock_response(500),  # Internal Server Error (can indicate bypass)
        ]

        for response in mock_responses:
            reward = bypass_service._calculate_reward(response)
            assert reward == 1, f"Expected reward=1 for status {response.status_code}, got {reward}"

    def test_reward_blocked_responses(self, bypass_service):
        """Test that blocked responses get negative reward"""
        mock_responses = [
            self._mock_response(403),  # Forbidden (typical WAF block)
            self._mock_response(406),  # Not Acceptable
            self._mock_response(429),  # Too Many Requests
        ]

        for response in mock_responses:
            reward = bypass_service._calculate_reward(response)
            assert reward == -1, f"Expected reward=-1 for status {response.status_code}, got {reward}"

    def test_reward_neutral_responses(self, bypass_service):
        """Test that other status codes get neutral reward"""
        mock_responses = [
            self._mock_response(400),  # Bad Request
            self._mock_response(401),  # Unauthorized
            self._mock_response(405),  # Method Not Allowed
            self._mock_response(412),  # Precondition Failed
            self._mock_response(415),  # Unsupported Media Type
            self._mock_response(422),  # Unprocessable Entity
        ]

        for response in mock_responses:
            reward = bypass_service._calculate_reward(response)
            assert reward == 0, f"Expected reward=0 for status {response.status_code}, got {reward}"

    def test_no_keyword_penalties(self, bypass_service):
        """CRITICAL: Ensure payload content doesn't affect rewards"""
        # This was the main bug - the old function punished payloads containing 'alert' or 'javascript'
        # even when the HTTP response was successful. This prevented learning when mutations
        # legitimately removed XSS keywords.

        xss_payloads = [
            "<script>alert(1)</script>",  # Contains 'script' and 'alert'
            "<img src=x onerror=javascript:alert('XSS')>",  # Contains 'javascript', 'alert'
            "javascript:alert('test')",  # Contains 'javascript', 'alert'
            "<iframe src=\"data:text/html,<script>alert('XSS')</script>\">",  # Contains 'script', 'alert'
        ]

        # These should get +1 reward regardless of content when status is 200
        for payload in xss_payloads:
            response = self._mock_response(200, payload)
            reward = bypass_service._calculate_reward(response)
            assert reward == 1, f"XSS payload should get +1 reward for 200 status, got {reward}: {payload}"

        # These should get -1 reward when blocked, regardless of content
        for payload in xss_payloads:
            response = self._mock_response(403, payload)
            reward = bypass_service._calculate_reward(response)
            assert reward == -1, f"Blocked payload should get -1 reward for 403 status, got {reward}: {payload}"

    def test_learning_potential(self, bypass_service):
        """Test that the reward function enables proper learning scenarios"""
        # Simulate a learning scenario where mutations improve rewards

        # Scenario 1: Original payload blocked -> mutation bypasses
        blocked_payload = "<script>alert(1)</script>"
        bypassed_payload = "<scr+ipt>alert(1)</scr+ipt>"

        blocked_response = self._mock_response(403, blocked_payload)
        bypassed_response = self._mock_response(200, bypassed_payload)

        blocked_reward = bypass_service._calculate_reward(blocked_response)
        bypassed_reward = bypass_service._calculate_reward(bypassed_response)

        assert blocked_reward == -1, "Blocked payload should get -1"
        assert bypassed_reward == 1, "Bypassed payload should get +1"

        # This reward differential is what enables ML learning!

    def _mock_response(self, status_code, url_payload=None):
        """Create a mock response for testing"""
        from unittest.mock import Mock
        response = Mock()
        response.status_code = status_code

        if url_payload:
            response.url = f"https://example.com/test?q={url_payload}"
        else:
            response.url = "https://example.com/test"

        return response
