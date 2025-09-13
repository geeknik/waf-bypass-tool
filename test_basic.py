#!/usr/bin/env python3
"""
Basic test script to verify our stable ML implementation works
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

# Import our modules
try:
    from stable_ml import StableActorCritic, create_stable_feature_extractor, MLConfig
    print("✅ Stable ML module imported successfully")

    # Test basic functionality
    config = MLConfig()
    print(f"✅ ML Config created: learning_rate={config.learning_rate}")

    actor_critic = StableActorCritic(config)
    print("✅ StableActorCritic initialized successfully")

    # Test feature extractor
    feature_extractor = create_stable_feature_extractor()
    test_payload = "<script>alert(1)</script>"
    features = feature_extractor(test_payload)
    print(f"✅ Feature extraction works: {len(features)} features extracted")

    # Test basic prediction
    prediction = actor_critic.choose_action(test_payload, feature_extractor)
    print(f"✅ Prediction works: {len(prediction)} chars output")

    print("\n🎉 All basic tests passed! The stable ML system is working correctly.")

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
