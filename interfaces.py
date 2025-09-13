"""
Service interfaces and abstractions for WAF Bypass Tool
Provides clean contracts for dependency injection and testing
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Any
import numpy as np


class IMLModel(ABC):
    """Interface for machine learning models"""

    @abstractmethod
    def choose_action(self, payload: str) -> str:
        """Choose the best action for a given payload"""
        pass

    @abstractmethod
    def update(self, payload: str, reward: int) -> None:
        """Update the model with feedback"""
        pass

    @abstractmethod
    def get_stats(self) -> dict:
        """Get model statistics"""
        pass


class IPayloadMutator(ABC):
    """Interface for payload mutation strategies"""

    @abstractmethod
    def mutate(self, payload: str, ml_model: IMLModel) -> str:
        """Mutate a payload using the ML model"""
        pass


class IInputValidator(ABC):
    """Interface for input validation and sanitization"""

    @abstractmethod
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate and sanitize URL"""
        pass

    @abstractmethod
    def validate_payload(self, payload: str) -> Tuple[bool, str]:
        """Validate and sanitize payload"""
        pass

    @abstractmethod
    def validate_file_path(self, file_path: str) -> Tuple[bool, str]:
        """Validate file path"""
        pass


class IWAFDetector(ABC):
    """Interface for WAF detection"""

    @abstractmethod
    def detect_waf(self, url: str) -> bool:
        """Detect if WAF is present on a URL"""
        pass


class IWAFBypassService(ABC):
    """Interface for the main WAF bypass service"""

    @abstractmethod
    def evade_waf(self, url: str) -> bool:
        """Attempt to bypass WAF on a URL"""
        pass

    @abstractmethod
    def get_statistics(self) -> dict:
        """Get bypass statistics"""
        pass


class IConfigurationManager(ABC):
    """Interface for configuration management"""

    @abstractmethod
    def get_config(self) -> Any:
        """Get current configuration"""
        pass

    @abstractmethod
    def update_config(self, config: Any) -> None:
        """Update configuration"""
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """Validate current configuration"""
        pass


class IFeatureExtractor(ABC):
    """Interface for feature extraction"""

    @abstractmethod
    def extract_features(self, payload: str) -> np.ndarray:
        """Extract features from payload"""
        pass


class ILogger(ABC):
    """Interface for logging"""

    @abstractmethod
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message"""
        pass

    @abstractmethod
    def info(self, message: str, **kwargs) -> None:
        """Log info message"""
        pass

    @abstractmethod
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message"""
        pass

    @abstractmethod
    def error(self, message: str, **kwargs) -> None:
        """Log error message"""
        pass

    @abstractmethod
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message"""
        pass


class IHTTPClient(ABC):
    """Interface for HTTP operations"""

    @abstractmethod
    def get(self, url: str, **kwargs) -> Any:
        """Make GET request"""
        pass

    @abstractmethod
    def post(self, url: str, **kwargs) -> Any:
        """Make POST request"""
        pass


class IErrorHandler(ABC):
    """Interface for error handling"""

    @abstractmethod
    def handle_exception(self, exception: Exception, context: Optional[dict] = None) -> Optional[Any]:
        """Handle an exception"""
        pass

    @abstractmethod
    def get_error_stats(self) -> dict:
        """Get error statistics"""
        pass
