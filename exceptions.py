"""
Custom exceptions and error handling for WAF Bypass Tool
Provides structured error handling with proper logging and recovery mechanisms
"""

import logging
from typing import Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for better classification"""
    NETWORK = "network"
    SECURITY = "security"
    VALIDATION = "validation"
    ML_MODEL = "ml_model"
    CONFIGURATION = "configuration"
    RESOURCE = "resource"
    UNKNOWN = "unknown"


class WAFException(Exception):
    """Base exception for WAF bypass tool"""

    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        recoverable: bool = True,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.recoverable = recoverable
        self.context = context or {}

    def log_error(self):
        """Log the error with appropriate level"""
        log_message = f"[{self.category.value}] {self.message}"
        if self.context:
            log_message += f" | Context: {self.context}"

        if self.severity == ErrorSeverity.CRITICAL:
            logger.critical(log_message)
        elif self.severity == ErrorSeverity.HIGH:
            logger.error(log_message)
        elif self.severity == ErrorSeverity.MEDIUM:
            logger.warning(log_message)
        else:
            logger.info(log_message)


class NetworkException(WAFException):
    """Network-related exceptions"""

    def __init__(self, message: str, url: Optional[str] = None, status_code: Optional[int] = None, **context):
        context.update({
            "url": url,
            "status_code": status_code
        })
        super().__init__(
            message,
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.HIGH,
            context=context
        )


class SecurityException(WAFException):
    """Security-related exceptions"""

    def __init__(self, message: str, violation_type: str, **context):
        context["violation_type"] = violation_type
        super().__init__(
            message,
            category=ErrorCategory.SECURITY,
            severity=ErrorSeverity.CRITICAL,
            recoverable=False,
            context=context
        )


class ValidationException(WAFException):
    """Input validation exceptions"""

    def __init__(self, message: str, field: str, value: Any, **context):
        context.update({
            "field": field,
            "value": str(value)[:100] + "..." if len(str(value)) > 100 else str(value)
        })
        super().__init__(
            message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            context=context
        )


class MLModelException(WAFException):
    """Machine learning model exceptions"""

    def __init__(self, message: str, model_type: str, operation: str, **context):
        context.update({
            "model_type": model_type,
            "operation": operation
        })
        super().__init__(
            message,
            category=ErrorCategory.ML_MODEL,
            severity=ErrorSeverity.HIGH,
            context=context
        )


class ConfigurationException(WAFException):
    """Configuration-related exceptions"""

    def __init__(self, message: str, config_key: str, **context):
        context["config_key"] = config_key
        super().__init__(
            message,
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.MEDIUM,
            context=context
        )


class ResourceException(WAFException):
    """Resource-related exceptions (memory, disk, etc.)"""

    def __init__(self, message: str, resource_type: str, **context):
        context["resource_type"] = resource_type
        super().__init__(
            message,
            category=ErrorCategory.RESOURCE,
            severity=ErrorSeverity.HIGH,
            context=context
        )


class ErrorHandler:
    """Centralized error handling and recovery"""

    def __init__(self):
        self.error_counts = {}
        self.recovery_strategies = {
            ErrorCategory.NETWORK: self._recover_network_error,
            ErrorCategory.SECURITY: self._recover_security_error,
            ErrorCategory.VALIDATION: self._recover_validation_error,
            ErrorCategory.ML_MODEL: self._recover_ml_error,
            ErrorCategory.CONFIGURATION: self._recover_config_error,
            ErrorCategory.RESOURCE: self._recover_resource_error,
        }

    def handle_exception(self, exception: Exception, context: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """
        Handle an exception with appropriate logging and recovery

        Args:
            exception: The exception to handle
            context: Additional context information

        Returns:
            Recovery result if recovery was successful, None otherwise
        """
        # Track error counts
        error_type = type(exception).__name__
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1

        if isinstance(exception, WAFException):
            exception.log_error()

            # Attempt recovery if recoverable
            if exception.recoverable:
                return self._attempt_recovery(exception, context)
        else:
            # Handle non-WAF exceptions
            logger.error(f"Unexpected error: {exception}", exc_info=True)

        return None

    def _attempt_recovery(self, exception: WAFException, context: Optional[Dict[str, Any]]) -> Optional[Any]:
        """Attempt to recover from an exception"""
        recovery_func = self.recovery_strategies.get(exception.category)

        if recovery_func:
            try:
                return recovery_func(exception, context)
            except Exception as recovery_error:
                logger.error(f"Recovery failed: {recovery_error}")
                return None

        return None

    def _recover_network_error(self, exception: NetworkException, context: Optional[Dict[str, Any]]) -> Optional[Any]:
        """Recover from network errors"""
        # Implement exponential backoff, retry with different proxy, etc.
        logger.info("Attempting network error recovery")

        # For demonstration, just return a retry signal
        if context and context.get("retry_count", 0) < 3:
            return {"action": "retry", "delay": 2 ** context.get("retry_count", 0)}

        return None

    def _recover_security_error(self, exception: SecurityException, context: Optional[Dict[str, Any]]) -> Optional[Any]:
        """Recover from security errors (usually not recoverable)"""
        logger.warning("Security error detected - manual intervention required")
        return {"action": "alert_admin", "severity": "high"}

    def _recover_validation_error(self, exception: ValidationException, context: Optional[Dict[str, Any]]) -> Optional[Any]:
        """Recover from validation errors by sanitizing input"""
        logger.info("Attempting validation error recovery")

        # Try to sanitize the input
        if hasattr(exception, 'field') and hasattr(exception, 'value'):
            # Return sanitized version
            return {"action": "sanitize", "field": exception.field, "original": exception.value}

        return None

    def _recover_ml_error(self, exception: MLModelException, context: Optional[Dict[str, Any]]) -> Optional[Any]:
        """Recover from ML model errors"""
        logger.info("Attempting ML model error recovery")

        # Try model rollback or reinitialization
        return {"action": "rollback_model", "model_type": exception.context.get("model_type")}

    def _recover_config_error(self, exception: ConfigurationException, context: Optional[Dict[str, Any]]) -> Optional[Any]:
        """Recover from configuration errors"""
        logger.info("Attempting configuration error recovery")

        # Try loading default configuration
        return {"action": "load_defaults", "config_key": exception.context.get("config_key")}

    def _recover_resource_error(self, exception: ResourceException, context: Optional[Dict[str, Any]]) -> Optional[Any]:
        """Recover from resource errors"""
        logger.info("Attempting resource error recovery")

        resource_type = exception.context.get("resource_type")

        if resource_type == "memory":
            # Try garbage collection, reduce batch size, etc.
            return {"action": "reduce_memory_usage"}
        elif resource_type == "disk":
            # Try cleanup, compression, etc.
            return {"action": "cleanup_disk"}

        return None

    def get_error_stats(self) -> Dict[str, int]:
        """Get error statistics"""
        return self.error_counts.copy()

    def reset_error_counts(self):
        """Reset error counters"""
        self.error_counts.clear()


class ErrorContext:
    """Context manager for error handling"""

    def __init__(self, error_handler: ErrorHandler, operation_name: str):
        self.error_handler = error_handler
        self.operation_name = operation_name
        self.context = {"operation": operation_name}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val:
            self.context.update({
                "exception_type": exc_type.__name__ if exc_type else "Unknown",
                "exception_message": str(exc_val)
            })

            result = self.error_handler.handle_exception(exc_val, self.context)

            # If recovery was successful, suppress the exception
            if result and result.get("action") != "alert_admin":
                return True  # Suppress exception

        return False  # Don't suppress if no recovery or critical error


# Global error handler instance
error_handler = ErrorHandler()


def safe_execute(func, *args, **kwargs):
    """
    Safely execute a function with error handling

    Args:
        func: Function to execute
        *args: Positional arguments
        **kwargs: Keyword arguments

    Returns:
        Tuple of (result, error) where error is None if successful
    """
    try:
        with ErrorContext(error_handler, func.__name__):
            result = func(*args, **kwargs)
            return result, None
    except Exception as e:
        return None, e


def create_error_report() -> Dict[str, Any]:
    """Create a comprehensive error report"""
    return {
        "error_counts": error_handler.get_error_stats(),
        "total_errors": sum(error_handler.get_error_stats().values()),
        "recovery_attempts": 0,  # Would track in real implementation
        "critical_errors": [],  # Would track critical errors
        "timestamp": "2024-01-01T00:00:00Z"  # Would use real timestamp
    }
