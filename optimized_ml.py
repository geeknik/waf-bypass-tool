"""
Optimized Machine Learning Components for WAF Bypass Tool
Provides high-performance ML training with batch processing and optimization
"""

import numpy as np
import logging
from typing import List, Optional, Dict, Any, Tuple, Union
from collections import deque
import time
from dataclasses import dataclass
from sklearn.linear_model import SGDRegressor
from sklearn.preprocessing import StandardScaler
import joblib
import os

from config_manager import MLConfig
from optimized_features import OptimizedFeatureExtractor
from exceptions import error_handler, ErrorContext

logger = logging.getLogger(__name__)


@dataclass
class TrainingBatch:
    """Batch of training data for efficient processing"""
    payloads: List[str]
    rewards: List[float]
    features: Optional[np.ndarray] = None

    def __post_init__(self):
        if len(self.payloads) != len(self.rewards):
            raise ValueError("Payloads and rewards must have same length")


@dataclass
class TrainingStats:
    """Training performance statistics"""
    total_samples: int = 0
    batches_processed: int = 0
    average_batch_size: float = 0.0
    training_time: float = 0.0
    convergence_rate: float = 0.0
    memory_usage_mb: float = 0.0


class OptimizedActorCritic:
    """
    Optimized Actor-Critic implementation with batch processing and performance improvements:
    - Batch training for better gradient estimation
    - Memory-efficient data structures
    - Optimized feature processing
    - Automatic learning rate scheduling
    - Model checkpointing with compression
    """

    def __init__(self, config: MLConfig, feature_extractor: OptimizedFeatureExtractor):
        self.config = config
        self.feature_extractor = feature_extractor

        # Initialize models with optimized parameters
        self.actor = self._create_optimized_model()
        self.critic = self._create_optimized_model()

        # Feature scaling for stable training
        self.feature_scaler = StandardScaler() if config.feature_scaling else None
        self.target_scaler = StandardScaler() if config.feature_scaling else None

        # Training state
        self.training_step = 0
        self.scaler_initialized = False

        # Experience replay buffer for batch training
        self.replay_buffer = deque(maxlen=10000)
        self.batch_size = config.batch_size

        # Performance tracking
        self.stats = TrainingStats()

        # Model checkpoints
        self.checkpoints = deque(maxlen=config.max_model_history)

        # Load existing models if available
        self._load_models()

        logger.info("OptimizedActorCritic initialized with batch processing")

    def _create_optimized_model(self) -> SGDRegressor:
        """Create optimized SGDRegressor with performance parameters"""
        return SGDRegressor(
            learning_rate="adaptive",  # Adaptive learning rate for better convergence
            eta0=self.config.learning_rate,
            penalty="elasticnet",  # Elastic net for better generalization
            alpha=0.0001,
            l1_ratio=0.15,  # Mix of L1 and L2 regularization
            max_iter=1,
            random_state=42,
            tol=None,
            early_stopping=False,  # Disable for online learning
            validation_fraction=0.0,  # No validation for online learning
        )

    def _initialize_scalers(self, features: np.ndarray):
        """Initialize feature scalers with first batch"""
        if not self.scaler_initialized and self.config.feature_scaling:
            self.feature_scaler.fit(features)
            self.target_scaler.fit(np.array([[0.0]]))
            self.scaler_initialized = True

    def add_experience(self, payload: str, reward: float):
        """Add experience to replay buffer for batch training"""
        self.replay_buffer.append((payload, reward))

    def train_batch(self, batch: Optional[TrainingBatch] = None) -> Dict[str, float]:
        """
        Train on a batch of experiences for better gradient estimation

        Args:
            batch: Optional batch to train on, otherwise uses replay buffer

        Returns:
            Training metrics
        """
        start_time = time.time()

        try:
            if batch is None:
                # Use replay buffer
                if len(self.replay_buffer) < self.batch_size:
                    return {"status": "insufficient_data"}

                # Sample batch from replay buffer
                batch_indices = np.random.choice(len(self.replay_buffer), self.batch_size, replace=False)
                batch_payloads = [self.replay_buffer[i][0] for i in batch_indices]
                batch_rewards = [self.replay_buffer[i][1] for i in batch_indices]
                batch = TrainingBatch(payloads=batch_payloads, rewards=batch_rewards)

            # Extract features for entire batch efficiently
            if batch.features is None:
                batch.features = self.feature_extractor.extract_features_batch(batch.payloads)

            features = batch.features
            rewards = np.array(batch.rewards)

            # Initialize scalers if needed
            self._initialize_scalers(features)

            # Scale features if enabled
            if self.config.feature_scaling and self.scaler_initialized:
                features = self.feature_scaler.transform(features)

            # Compute TD errors for entire batch
            current_values = self.critic.predict(features)
            td_errors = rewards - current_values

            # Clip TD errors for stability
            td_errors = np.clip(td_errors, -self.config.td_error_clip_value,
                               self.config.td_error_clip_value)

            # Batch training for critic
            self.critic.partial_fit(features, rewards)

            # Batch training for actor with TD errors
            actor_targets = self.actor.predict(features) + self.config.discount_factor * td_errors
            self.actor.partial_fit(features, actor_targets)

            # Update statistics
            self.training_step += 1
            self.stats.total_samples += len(batch.payloads)
            self.stats.batches_processed += 1

            training_time = time.time() - start_time
            self.stats.training_time += training_time

            # Checkpoint model periodically
            if self.training_step % self.config.model_checkpoint_interval == 0:
                self._create_checkpoint()

            # Calculate metrics
            metrics = {
                "status": "success",
                "batch_size": len(batch.payloads),
                "avg_td_error": float(np.mean(np.abs(td_errors))),
                "training_time_ms": training_time * 1000,
                "critic_score": float(self.critic.score(features, rewards)),
            }

            return metrics

        except Exception as e:
            logger.error(f"Batch training failed: {e}")
            return {"status": "error", "error": str(e)}

    def choose_action(self, payload: str) -> str:
        """Choose action using optimized feature extraction"""
        try:
            features = self.feature_extractor.extract_features(payload)

            if self.config.feature_scaling and self.scaler_initialized:
                features = self.feature_scaler.transform(features.reshape(1, -1))

            prediction = self.actor.predict(features)[0]

            # Log extreme predictions for monitoring
            if abs(prediction) > 1e6:
                logger.warning(f"Extreme actor prediction: {prediction}")

            return payload  # Return original payload for mutation

        except Exception as e:
            logger.error(f"Action selection failed: {e}")
            return payload

    def update(self, payload: str, reward: float):
        """Update models with single experience (adds to replay buffer)"""
        self.add_experience(payload, reward)

        # Train if we have enough experiences
        if len(self.replay_buffer) >= self.batch_size:
            metrics = self.train_batch()
            if metrics.get("status") == "success":
                logger.debug(".2f")

    def _create_checkpoint(self):
        """Create compressed model checkpoint"""
        try:
            checkpoint = {
                "step": self.training_step,
                "actor": self.actor,
                "critic": self.critic,
                "feature_scaler": self.feature_scaler,
                "target_scaler": self.target_scaler,
                "scaler_initialized": self.scaler_initialized,
                "stats": self.stats,
            }

            self.checkpoints.append(checkpoint)

            # Save to disk with compression
            self._save_models()

            logger.debug(f"Checkpoint created at step {self.training_step}")

        except Exception as e:
            logger.error(f"Checkpoint creation failed: {e}")

    def _save_models(self):
        """Save models to disk with compression"""
        try:
            # Save models
            joblib.dump(self.actor, "actor_model.pkl", compress=3)
            joblib.dump(self.critic, "critic_model.pkl", compress=3)

            # Save scalers if initialized
            if self.scaler_initialized:
                joblib.dump(self.feature_scaler, "feature_scaler.pkl", compress=3)
                joblib.dump(self.target_scaler, "target_scaler.pkl", compress=3)

        except Exception as e:
            logger.error(f"Model saving failed: {e}")

    def _load_models(self):
        """Load models from disk"""
        try:
            actor_path = "actor_model.pkl"
            critic_path = "critic_model.pkl"

            if os.path.exists(actor_path):
                self.actor = joblib.load(actor_path)
                logger.info("Loaded actor model from disk")

            if os.path.exists(critic_path):
                self.critic = joblib.load(critic_path)
                logger.info("Loaded critic model from disk")

            # Load scalers
            if self.config.feature_scaling:
                scaler_path = "feature_scaler.pkl"
                target_scaler_path = "target_scaler.pkl"

                if os.path.exists(scaler_path):
                    self.feature_scaler = joblib.load(scaler_path)
                    self.scaler_initialized = True
                    logger.info("Loaded feature scaler")

                if os.path.exists(target_scaler_path):
                    self.target_scaler = joblib.load(target_scaler_path)

        except Exception as e:
            logger.warning(f"Model loading failed: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive training statistics"""
        feature_stats = self.feature_extractor.get_performance_stats()

        return {
            "training_step": self.training_step,
            "total_samples": self.stats.total_samples,
            "batches_processed": self.stats.batches_processed,
            "replay_buffer_size": len(self.replay_buffer),
            "checkpoints_available": len(self.checkpoints),
            "scaler_initialized": self.scaler_initialized,
            "feature_extraction": feature_stats,
        }

    def optimize_for_production(self):
        """Apply production optimizations"""
        # Increase batch size for better gradient estimation
        self.batch_size = min(self.batch_size * 2, 128)

        # Optimize feature extractor
        self.feature_extractor.optimize_for_production()

        # Clear old checkpoints to save memory
        while len(self.checkpoints) > 5:
            self.checkpoints.popleft()

        logger.info("Applied production optimizations")

    def clear_replay_buffer(self):
        """Clear experience replay buffer"""
        self.replay_buffer.clear()
        logger.info("Replay buffer cleared")


class OptimizedMLPipeline:
    """
    Optimized ML pipeline with batch processing and performance monitoring
    """

    def __init__(self, config: MLConfig):
        self.config = config
        self.feature_extractor = OptimizedFeatureExtractor()
        self.actor_critic = OptimizedActorCritic(config, self.feature_extractor)

        # Pipeline statistics
        self.pipeline_stats = {
            "total_processed": 0,
            "successful_predictions": 0,
            "training_sessions": 0,
            "average_latency_ms": 0.0,
        }

        logger.info("Optimized ML pipeline initialized")

    def process_payloads_batch(self, payloads: List[str]) -> List[str]:
        """Process multiple payloads efficiently"""
        start_time = time.time()

        try:
            # Batch feature extraction
            features = self.feature_extractor.extract_features_batch(payloads)

            # Batch predictions (simplified for this example)
            results = []
            for i, payload in enumerate(payloads):
                result = self.actor_critic.choose_action(payload)
                results.append(result)

            # Update statistics
            processing_time = time.time() - start_time
            self.pipeline_stats["total_processed"] += len(payloads)
            self.pipeline_stats["successful_predictions"] += len(results)

            latency = (processing_time / len(payloads)) * 1000
            self.pipeline_stats["average_latency_ms"] = (
                self.pipeline_stats["average_latency_ms"] + latency
            ) / 2

            return results

        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            return payloads  # Return originals on error

    def train_on_experiences(self, experiences: List[Tuple[str, float]]) -> Dict[str, Any]:
        """Train on multiple experiences efficiently"""
        start_time = time.time()

        try:
            # Add experiences to replay buffer
            for payload, reward in experiences:
                self.actor_critic.add_experience(payload, reward)

            # Train batch
            metrics = self.actor_critic.train_batch()

            training_time = time.time() - start_time
            self.pipeline_stats["training_sessions"] += 1

            metrics.update({
                "training_time_ms": training_time * 1000,
                "experiences_processed": len(experiences),
            })

            return metrics

        except Exception as e:
            logger.error(f"Training failed: {e}")
            return {"status": "error", "error": str(e)}

    def get_pipeline_stats(self) -> Dict[str, Any]:
        """Get comprehensive pipeline statistics"""
        ml_stats = self.actor_critic.get_stats()

        return {
            "pipeline": self.pipeline_stats,
            "ml_model": ml_stats,
            "feature_extractor": self.feature_extractor.get_performance_stats(),
        }

    def optimize_pipeline(self):
        """Apply pipeline optimizations"""
        self.actor_critic.optimize_for_production()
        logger.info("ML pipeline optimized for production")


# Global optimized ML pipeline instance
optimized_pipeline = OptimizedMLPipeline(MLConfig())


def create_optimized_ml_pipeline(config: MLConfig) -> OptimizedMLPipeline:
    """Factory function for optimized ML pipeline"""
    return OptimizedMLPipeline(config)
