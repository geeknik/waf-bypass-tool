"""
Stable Machine Learning Components for WAF Bypass Tool
Addresses numerical instability issues in the Actor-Critic implementation
"""

import numpy as np
import joblib
import os
import logging
from typing import Optional, Tuple, List
from sklearn.linear_model import SGDRegressor
from sklearn.preprocessing import StandardScaler
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)


@dataclass
class MLConfig:
    """Configuration for stable ML components"""
    learning_rate: float = 0.01
    discount_factor: float = 0.99
    gradient_clip_value: float = 10.0
    td_error_clip_value: float = 1000.0
    feature_scaling: bool = True
    model_checkpoint_interval: int = 100
    max_model_history: int = 10


class StableActorCritic:
    """
    Stable Actor-Critic implementation with numerical stability improvements

    Key improvements:
    - Gradient clipping to prevent explosion
    - Feature scaling for stable training
    - TD error bounds to prevent numerical instability
    - Model checkpointing and rollback
    - Proper initialization and regularization
    """

    def __init__(self, config: MLConfig = None):
        self.config = config or MLConfig()

        # Initialize scalers for feature normalization
        self.feature_scaler = StandardScaler() if self.config.feature_scaling else None
        self.target_scaler = StandardScaler() if self.config.feature_scaling else None

        # Initialize models with better defaults
        self.actor = self._create_stable_model()
        self.critic = self._create_stable_model()

        # Training state
        self.success_count = 0
        self.failure_count = 0
        self.training_step = 0

        # Model history for rollback
        self.model_history: List[Tuple[int, SGDRegressor, SGDRegressor]] = []

        # Initialize models properly
        self._initialize_models()

        # Load existing models if available
        self._load_models()

    def _create_stable_model(self) -> SGDRegressor:
        """Create a stable SGDRegressor with optimized parameters"""
        return SGDRegressor(
            learning_rate="constant",
            eta0=self.config.learning_rate,
            penalty="l2",  # L2 regularization for stability
            alpha=0.0001,  # Small regularization term
            max_iter=1,  # Single pass per update for online learning
            random_state=42,  # Reproducible results
            tol=None  # Disable convergence check for online learning
        )

    def _initialize_models(self):
        """Initialize models with dummy data for proper setup"""
        # Create dummy features matching the expected dimensionality
        dummy_features = np.zeros((1, 11))  # 11 features based on feature extraction

        # Initialize scalers with dummy data
        if self.config.feature_scaling:
            self.feature_scaler.fit(dummy_features)
            self.target_scaler.fit(np.array([[0.0]]))

        # Partial fit models with dummy data
        self.actor.partial_fit(dummy_features, [0.0])
        self.critic.partial_fit(dummy_features, [0.0])

    def _load_models(self):
        """Load existing models if available"""
        actor_path = "actor_model.pkl"
        critic_path = "critic_model.pkl"

        if os.path.exists(actor_path):
            try:
                self.actor = joblib.load(actor_path)
                logger.info("Loaded existing actor model")
            except Exception as e:
                logger.warning(f"Failed to load actor model: {e}")

        if os.path.exists(critic_path):
            try:
                self.critic = joblib.load(critic_path)
                logger.info("Loaded existing critic model")
            except Exception as e:
                logger.warning(f"Failed to load critic model: {e}")

    def _clip_gradient(self, value: float) -> float:
        """Clip gradient to prevent explosion"""
        return np.clip(value, -self.config.gradient_clip_value, self.config.gradient_clip_value)

    def _clip_td_error(self, td_error: float) -> float:
        """Clip TD error to prevent numerical instability"""
        return np.clip(td_error, -self.config.td_error_clip_value, self.config.td_error_clip_value)

    def _scale_features(self, features: np.ndarray) -> np.ndarray:
        """Scale features for stable training"""
        if self.config.feature_scaling and self.feature_scaler:
            return self.feature_scaler.transform(features.reshape(1, -1))
        return features

    def _update_scalers(self, features: np.ndarray, target: float):
        """Update feature and target scalers with new data"""
        if self.config.feature_scaling:
            self.feature_scaler.partial_fit(features.reshape(1, -1))
            self.target_scaler.partial_fit(np.array([[target]]))

    def choose_action(self, payload: str, feature_extractor) -> str:
        """
        Choose the best action (payload mutation) using the actor

        Args:
            payload: Input payload to mutate
            feature_extractor: Function to extract features from payload

        Returns:
            Best mutated payload
        """
        try:
            features = feature_extractor(payload)
            scaled_features = self._scale_features(features)

            # Get actor prediction with error handling
            prediction = self.actor.predict(scaled_features)[0]

            # Log prediction for debugging (with bounds checking)
            if abs(prediction) > 1e10:  # Log if prediction is unreasonably large
                logger.warning(f"Large actor prediction detected: {prediction}")

            return payload  # For now, return original - will be enhanced with mutation logic

        except Exception as e:
            logger.error(f"Error in choose_action: {e}")
            return payload  # Return original payload on error

    def update(self, payload: str, reward: int, feature_extractor):
        """
        Update the actor and critic models with new experience

        Args:
            payload: The payload that was used
            reward: Reward received (1 for success, -1 for failure, 0 for neutral)
            feature_extractor: Function to extract features from payload
        """
        try:
            self.training_step += 1

            # Extract and scale features
            features = feature_extractor(payload)
            scaled_features = self._scale_features(features)

            # Update scalers with new data
            self._update_scalers(features, reward)

            # Get current predictions
            actor_prediction = self.actor.predict(scaled_features)[0]
            critic_prediction = self.critic.predict(scaled_features)[0]

            # Calculate TD error with clipping
            td_error = reward - critic_prediction
            clipped_td_error = self._clip_td_error(td_error)

            # Log TD error for monitoring
            if abs(clipped_td_error) > 100:  # Log large TD errors
                logger.info(f"Large TD error: {clipped_td_error} (original: {td_error})")

            # Update Critic with clipped TD error
            self.critic.partial_fit(scaled_features, [reward])

            # Update Actor with gradient clipping
            actor_update = self.config.discount_factor * clipped_td_error
            clipped_actor_update = self._clip_gradient(actor_update)

            # Apply adaptive learning rate based on success
            learning_multiplier = 1.5 if reward == 1 else 1.0
            final_actor_update = clipped_actor_update * learning_multiplier

            self.actor.partial_fit(scaled_features, [final_actor_update])

            # Update success/failure counts
            if reward == 1:
                self.success_count += 1
            else:
                self.failure_count += 1

            # Checkpoint model periodically
            if self.training_step % self.config.model_checkpoint_interval == 0:
                self._checkpoint_models()

        except Exception as e:
            logger.error(f"Error in update: {e}")
            # Continue execution rather than crashing

    def _checkpoint_models(self):
        """Save model checkpoint for potential rollback"""
        try:
            # Save current state
            checkpoint = (self.training_step, self.actor, self.critic)
            self.model_history.append(checkpoint)

            # Keep only recent checkpoints
            if len(self.model_history) > self.config.max_model_history:
                self.model_history.pop(0)

            # Save to disk
            self.save_models()

            logger.debug(f"Model checkpoint saved at step {self.training_step}")

        except Exception as e:
            logger.error(f"Error saving checkpoint: {e}")

    def save_models(self):
        """Save models to disk"""
        try:
            joblib.dump(self.actor, "actor_model.pkl")
            joblib.dump(self.critic, "critic_model.pkl")

            # Save scaler state if using scaling
            if self.config.feature_scaling:
                joblib.dump(self.feature_scaler, "feature_scaler.pkl")
                joblib.dump(self.target_scaler, "target_scaler.pkl")

        except Exception as e:
            logger.error(f"Error saving models: {e}")

    def rollback_model(self, steps_back: int = 1):
        """
        Rollback to a previous model checkpoint

        Args:
            steps_back: Number of checkpoints to go back
        """
        try:
            if len(self.model_history) >= steps_back:
                checkpoint = self.model_history[-steps_back]
                self.training_step, self.actor, self.critic = checkpoint
                logger.info(f"Rolled back to step {self.training_step}")
            else:
                logger.warning("Not enough checkpoints for rollback")
        except Exception as e:
            logger.error(f"Error during rollback: {e}")

    def get_stats(self) -> dict:
        """Get training statistics"""
        total_attempts = self.success_count + self.failure_count
        success_rate = (self.success_count / total_attempts * 100) if total_attempts > 0 else 0

        return {
            "total_attempts": total_attempts,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": success_rate,
            "training_steps": self.training_step,
            "checkpoints_available": len(self.model_history)
        }

    def print_summary(self):
        """Print training summary"""
        stats = self.get_stats()
        print("\n--- Stable Actor-Critic Summary ---")
        print(f"Training Steps: {stats['training_steps']}")
        print(f"Total Attempts: {stats['total_attempts']}")
        print(f"Successful Actions: {stats['success_count']}")
        print(f"Failed Actions: {stats['failure_count']}")
        print(".2f")
        print(f"Checkpoints Available: {stats['checkpoints_available']}")


def create_stable_feature_extractor():
    """
    Create a stable feature extractor that prevents numerical issues

    Returns:
        Function that extracts features from payload
    """
    def extract_features(payload: str) -> np.ndarray:
        """Extract features from payload with bounds checking"""
        try:
            # Basic features with bounds checking
            length = min(len(payload), 10000)  # Cap length to prevent issues
            angle_brackets = payload.count('<') + payload.count('>')
            quotes = payload.count("'") + payload.count('"')
            double_dash = payload.count("--")
            alert_count = payload.count("alert")
            select_count = payload.count("SELECT")
            union_count = payload.count("UNION")
            drop_count = payload.count("DROP")

            # Numeric character counts with bounds
            digit_count = sum(c.isdigit() for c in payload[:10000])  # Limit string length
            alpha_count = sum(c.isalpha() for c in payload[:10000])  # Limit string length

            features = np.array([
                length,
                angle_brackets,
                quotes,
                double_dash,
                alert_count,
                select_count,
                union_count,
                drop_count,
                digit_count,
                alpha_count,
                len(payload)  # Duplicate length for now, can be enhanced
            ], dtype=np.float64)

            # Ensure no NaN or infinite values
            features = np.nan_to_num(features, nan=0.0, posinf=10000.0, neginf=0.0)

            return features

        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            # Return zero features on error
            return np.zeros(11, dtype=np.float64)

    return extract_features
