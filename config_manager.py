"""
Comprehensive Configuration Management System
Provides centralized configuration with validation, multiple sources, and hot-reloading
"""

import os
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod

from pydantic import BaseModel, Field, validator, ValidationError
from pydantic_settings import BaseSettings

from exceptions import ConfigurationException, error_handler, ErrorContext
from interfaces import IConfigurationManager


logger = logging.getLogger(__name__)


class AppConfig(BaseModel):
    """Main application configuration model"""

    # Application settings
    app_name: str = Field(default="WAF Bypass Tool", description="Application name")
    version: str = Field(default="2.0.0", description="Application version")
    environment: str = Field(default="development", pattern="^(development|staging|production)$")

    # ML Configuration
    ml_config: "MLConfig" = Field(default_factory=lambda: MLConfig())

    # Security Configuration
    security_config: "SecurityConfig" = Field(default_factory=lambda: SecurityConfig())

    # Network Configuration
    network_config: "NetworkConfig" = Field(default_factory=lambda: NetworkConfig())

    # Logging Configuration
    logging_config: "LoggingConfig" = Field(default_factory=lambda: LoggingConfig())

    # Webhook Configuration
    webhook_config: "WebhookConfig" = Field(default_factory=lambda: WebhookConfig())

    class Config:
        validate_assignment = True


class MLConfig(BaseModel):
    """Machine Learning configuration"""
    learning_rate: float = Field(default=0.01, gt=0, le=1)
    discount_factor: float = Field(default=0.99, gt=0, le=1)
    gradient_clip_value: float = Field(default=10.0, gt=0)
    td_error_clip_value: float = Field(default=1000.0, gt=0)
    feature_scaling: bool = Field(default=True)
    model_checkpoint_interval: int = Field(default=100, ge=10)
    max_model_history: int = Field(default=10, ge=1)
    batch_size: int = Field(default=1, ge=1, le=1000)
    epochs: int = Field(default=100, ge=1, le=10000)


class SecurityConfig(BaseModel):
    """Security configuration"""
    validation_level: str = Field(default="strict", pattern="^(lenient|strict|paranoid)$")
    max_payload_length: int = Field(default=10000, ge=100, le=100000)
    max_url_length: int = Field(default=2048, ge=100, le=10000)
    allowed_schemes: List[str] = Field(default_factory=lambda: ["http", "https"])
    blocked_domains: List[str] = Field(default_factory=list)
    enable_circuit_breaker: bool = Field(default=True)
    circuit_breaker_threshold: int = Field(default=5, ge=1)
    circuit_breaker_timeout: int = Field(default=300, ge=30)
    rate_limit_requests: int = Field(default=100, ge=1)
    rate_limit_window: int = Field(default=60, ge=10)


class NetworkConfig(BaseModel):
    """Network configuration"""
    default_timeout: float = Field(default=10.0, gt=0)
    max_retries: int = Field(default=3, ge=0)
    retry_delay: float = Field(default=1.0, ge=0)
    user_agent: str = Field(default="WAF-Bypass-Tool/2.0")
    max_connections: int = Field(default=100, ge=1)
    connection_pool_size: int = Field(default=10, ge=1)
    keep_alive: bool = Field(default=True)


class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    format: str = Field(default="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    file_path: Optional[str] = Field(default=None)
    max_file_size: int = Field(default=10*1024*1024, ge=1024)  # 10MB
    backup_count: int = Field(default=5, ge=1)
    enable_console: bool = Field(default=True)
    console_level: str = Field(default="WARNING", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")


class WebhookConfig(BaseModel):
    """Webhook configuration"""
    slack_webhook: Optional[str] = Field(default=None)
    discord_webhook: Optional[str] = Field(default=None)
    enable_webhooks: bool = Field(default=False)
    webhook_timeout: float = Field(default=5.0, gt=0)
    retry_attempts: int = Field(default=2, ge=0)

    @validator('slack_webhook', 'discord_webhook')
    def validate_webhook_url(cls, v):
        if v and not v.startswith(('http://', 'https://')):
            raise ValueError('Webhook URL must start with http:// or https://')
        return v


class ConfigurationSource(ABC):
    """Abstract base class for configuration sources"""

    @abstractmethod
    def load(self) -> Dict[str, Any]:
        """Load configuration from this source"""
        pass

    @abstractmethod
    def can_load(self) -> bool:
        """Check if this source can provide configuration"""
        pass


class FileConfigSource(ConfigurationSource):
    """Load configuration from files (JSON, YAML, etc.)"""

    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)

    def can_load(self) -> bool:
        return self.file_path.exists() and self.file_path.is_file()

    def load(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                if self.file_path.suffix.lower() in ['.yaml', '.yml']:
                    import yaml
                    return yaml.safe_load(f) or {}
                elif self.file_path.suffix.lower() == '.json':
                    return json.load(f)
                else:
                    # Try JSON first, then YAML
                    try:
                        return json.load(f)
                    except json.JSONDecodeError:
                        f.seek(0)
                        import yaml
                        return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Failed to load config from {self.file_path}: {e}")
            return {}


class EnvironmentConfigSource(ConfigurationSource):
    """Load configuration from environment variables"""

    def __init__(self, prefix: str = "WAF_"):
        self.prefix = prefix

    def can_load(self) -> bool:
        return True  # Environment is always available

    def load(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        config = {}

        for key, value in os.environ.items():
            if key.startswith(self.prefix):
                # Remove prefix and convert to nested structure
                clean_key = key[len(self.prefix):].lower()
                self._set_nested_value(config, clean_key.split('_'), value)

        return config

    def _set_nested_value(self, config: Dict[str, Any], keys: List[str], value: str):
        """Set a nested value in the configuration dictionary"""
        current = config
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        # Convert string values to appropriate types
        final_key = keys[-1]
        current[final_key] = self._convert_value(value)

    def _convert_value(self, value: str) -> Union[str, int, float, bool]:
        """Convert string value to appropriate type"""
        # Try boolean
        if value.lower() in ['true', 'false']:
            return value.lower() == 'true'

        # Try int
        try:
            return int(value)
        except ValueError:
            pass

        # Try float
        try:
            return float(value)
        except ValueError:
            pass

        # Return as string
        return value


class DefaultConfigSource(ConfigurationSource):
    """Provide default configuration values"""

    def __init__(self):
        self._defaults = {
            "app_name": "WAF Bypass Tool",
            "version": "2.0.0",
            "environment": "development",
            "ml_config": {
                "learning_rate": 0.01,
                "discount_factor": 0.99,
                "gradient_clip_value": 10.0,
                "td_error_clip_value": 1000.0,
                "feature_scaling": True,
                "model_checkpoint_interval": 100,
                "max_model_history": 10,
                "batch_size": 32,
                "epochs": 100
            },
            "security_config": {
                "validation_level": "strict",
                "max_payload_length": 10000,
                "max_url_length": 2048,
                "allowed_schemes": ["http", "https"],
                "blocked_domains": [],
                "enable_circuit_breaker": True,
                "circuit_breaker_threshold": 5,
                "circuit_breaker_timeout": 300,
                "rate_limit_requests": 100,
                "rate_limit_window": 60
            },
            "network_config": {
                "default_timeout": 10.0,
                "max_retries": 3,
                "retry_delay": 1.0,
                "user_agent": "WAF-Bypass-Tool/2.0",
                "max_connections": 100,
                "connection_pool_size": 10,
                "keep_alive": True
            },
            "logging_config": {
                "level": "INFO",
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                "max_file_size": 10*1024*1024,
                "backup_count": 5,
                "enable_console": True,
                "console_level": "WARNING"
            },
            "webhook_config": {
                "enable_webhooks": False,
                "webhook_timeout": 5.0,
                "retry_attempts": 2
            }
        }

    def can_load(self) -> bool:
        return True

    def load(self) -> Dict[str, Any]:
        return self._defaults.copy()


class ConfigurationManager(IConfigurationManager):
    """
    Comprehensive configuration manager with multiple sources and validation
    """

    def __init__(self):
        self._config: Optional[AppConfig] = None
        self._config_sources: List[ConfigurationSource] = []
        self._config_file_path: Optional[Path] = None
        self._auto_reload = False
        self._last_modified: Optional[float] = None

        # Set up default configuration sources
        self._setup_default_sources()

    def _setup_default_sources(self):
        """Set up default configuration sources in priority order"""
        # Priority: Environment > Config File > Defaults
        self._config_sources = [
            EnvironmentConfigSource(),
            DefaultConfigSource()
        ]

    def add_config_file(self, file_path: Union[str, Path]):
        """Add a configuration file source"""
        file_path = Path(file_path)
        file_source = FileConfigSource(file_path)

        logger.debug(f"Trying to load config file: {file_path}")
        logger.debug(f"File exists: {file_path.exists()}")
        logger.debug(f"File readable: {file_path.is_file()}")

        if file_source.can_load():
            # Insert before defaults but after environment
            self._config_sources.insert(1, file_source)
            self._config_file_path = file_path
            logger.info(f"Added configuration file: {file_path}")

            if self._auto_reload:
                self._last_modified = file_path.stat().st_mtime
        else:
            logger.warning(f"Configuration file not found or not readable: {file_path}")

    def enable_auto_reload(self, interval: float = 5.0):
        """Enable automatic configuration reloading"""
        self._auto_reload = True
        logger.info(f"Auto-reload enabled with {interval}s interval")

    def load_config(self) -> AppConfig:
        """Load configuration from all sources"""
        with ErrorContext(error_handler, "config_loading"):
            try:
                # Check for auto-reload
                if self._auto_reload and self._config_file_path:
                    self._check_for_changes()

                # Merge configuration from all sources
                merged_config = {}
                for source in self._config_sources:
                    if source.can_load():
                        source_config = source.load()
                        self._deep_merge(merged_config, source_config)

                # Validate and create configuration object
                self._config = AppConfig(**merged_config)
                logger.info("Configuration loaded successfully")

                return self._config

            except ValidationError as e:
                raise ConfigurationException(
                    f"Configuration validation failed: {e}",
                    config_key="validation"
                )
            except Exception as e:
                raise ConfigurationException(
                    f"Failed to load configuration: {e}",
                    config_key="loading"
                )

    def _check_for_changes(self):
        """Check if configuration file has changed"""
        if not self._config_file_path or not self._last_modified:
            return

        try:
            current_modified = self._config_file_path.stat().st_mtime
            if current_modified > self._last_modified:
                logger.info("Configuration file changed, reloading...")
                self._last_modified = current_modified
                self._config = None  # Force reload
        except Exception as e:
            logger.warning(f"Failed to check config file modification: {e}")

    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]):
        """Deep merge two dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def get_config(self) -> AppConfig:
        """Get current configuration, loading if necessary"""
        if self._config is None:
            self.load_config()
        return self._config

    def update_config(self, updates: Dict[str, Any]) -> None:
        """Update configuration with new values"""
        with ErrorContext(error_handler, "config_update"):
            try:
                if self._config is None:
                    self.load_config()

                # Apply updates
                for key, value in updates.items():
                    if hasattr(self._config, key):
                        setattr(self._config, key, value)

                # Validate updated configuration
                self._config = AppConfig(**self._config.dict())

                logger.info("Configuration updated successfully")

            except Exception as e:
                raise ConfigurationException(
                    f"Failed to update configuration: {e}",
                    config_key="update"
                )

    def validate_config(self) -> bool:
        """Validate current configuration"""
        try:
            if self._config is None:
                self.load_config()
            return True
        except Exception:
            return False

    def save_config(self, file_path: Optional[Union[str, Path]] = None) -> None:
        """Save current configuration to file"""
        if self._config is None:
            raise ConfigurationException("No configuration loaded", config_key="save")

        save_path = Path(file_path) if file_path else self._config_file_path
        if not save_path:
            raise ConfigurationException("No file path specified", config_key="save")

        try:
            config_dict = self._config.dict()
            with open(save_path, 'w', encoding='utf-8') as f:
                if save_path.suffix.lower() in ['.yaml', '.yml']:
                    import yaml
                    yaml.dump(config_dict, f, default_flow_style=False)
                else:
                    json.dump(config_dict, f, indent=2, ensure_ascii=False)

            logger.info(f"Configuration saved to {save_path}")

        except Exception as e:
            raise ConfigurationException(
                f"Failed to save configuration: {e}",
                config_key="save"
            )

    def get_config_summary(self) -> Dict[str, Any]:
        """Get a summary of current configuration"""
        if self._config is None:
            return {"status": "not_loaded"}

        return {
            "status": "loaded",
            "environment": self._config.environment,
            "version": self._config.version,
            "ml_enabled": True,
            "security_level": self._config.security_config.validation_level,
            "network_timeout": self._config.network_config.default_timeout,
            "logging_level": self._config.logging_config.level,
            "webhooks_enabled": self._config.webhook_config.enable_webhooks
        }


# Global configuration manager instance
config_manager = ConfigurationManager()


def get_config_manager() -> ConfigurationManager:
    """Get the global configuration manager"""
    return config_manager


def load_app_config(config_file: Optional[str] = None) -> AppConfig:
    """Load application configuration"""
    manager = get_config_manager()

    if config_file:
        manager.add_config_file(config_file)

    config = manager.load_config()
    logger.debug(f"Loaded ML batch_size: {config.ml_config.batch_size}")
    return config


# Initialize configuration on module import
try:
    config_manager.load_config()
except Exception as e:
    logger.warning(f"Failed to load initial configuration: {e}")
    # Continue with defaults
