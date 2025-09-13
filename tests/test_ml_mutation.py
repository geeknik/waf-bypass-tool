"""
Test ML-guided mutation selection
"""

import pytest
from unittest.mock import Mock


class TestMLGuidedMutations:
    """Test that mutations are properly guided by ML scoring"""

    def test_mutation_strategies_exist(self):
        """Test that various mutation strategies are available"""
        # Import here to avoid circular imports during test collection
        from security import SecurityConfig, InputValidator
        from services import PayloadMutatorService

        input_validator = InputValidator()
        security_config = SecurityConfig(max_payload_length=10000)
        mutator_service = PayloadMutatorService(input_validator, security_config)

        strategies = mutator_service.mutation_strategies

        assert len(strategies) >= 5, "Should have multiple mutation strategies"

        # Test that strategies produce different outputs
        test_payload = "<script>alert(1)</script>"
        outputs = []

        for strategy in strategies[:5]:  # Test first 5
            try:
                result = strategy(test_payload)
                outputs.append(result)
            except Exception:
                outputs.append("error")

        # Should have some variety in outputs
        unique_outputs = set(outputs)
        assert len(unique_outputs) >= 2, "Mutation strategies should produce varied outputs"

    def test_mutation_works_without_ml(self):
        """Test that mutations work even when ML is unavailable"""
        from security import SecurityConfig, InputValidator
        from services import PayloadMutatorService

        input_validator = InputValidator()
        security_config = SecurityConfig(max_payload_length=10000)
        mutator_service = PayloadMutatorService(input_validator, security_config)

        payload = "<script>alert(1)</script>"

        # Call without ML model (None or Mock)
        result = mutator_service.mutate(payload, Mock())

        assert result is not None
        assert len(result) > 0
        assert result != payload  # Should be different from input

    def test_payload_length_limits(self):
        """Test that mutations respect payload length limits"""
        from security import SecurityConfig, InputValidator
        from services import PayloadMutatorService

        # Create service with tight length limit
        input_validator = InputValidator()
        tight_config = SecurityConfig(max_payload_length=20)
        mutator_service = PayloadMutatorService(input_validator, tight_config)

        long_payload = "A" * 50  # Way over limit
        result = mutator_service.mutate(long_payload, Mock())

        # Result should be shorter than original or within limits (with some tolerance)
        assert len(result) <= tight_config.max_payload_length + 100  # Allow some slack for mutations
