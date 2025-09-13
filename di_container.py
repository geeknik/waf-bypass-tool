"""
Dependency Injection Container for WAF Bypass Tool
Provides centralized dependency management and service registration
"""

from typing import Dict, Type, Any, Optional, Callable
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


class DependencyContainer:
    """
    Simple dependency injection container with singleton and transient support
    """

    def __init__(self):
        self._services: Dict[str, ServiceRegistration] = {}
        self._singletons: Dict[str, Any] = {}

    def register_singleton(self, service_type: Type, implementation: Optional[Any] = None,
                          factory: Optional[Callable] = None, name: str = None):
        """Register a singleton service"""
        service_name = name or service_type.__name__

        if factory:
            self._services[service_name] = ServiceRegistration(
                service_type=service_type,
                implementation=None,
                factory=factory,
                lifetime=Lifetime.Singleton
            )
        elif implementation:
            self._services[service_name] = ServiceRegistration(
                service_type=service_type,
                implementation=implementation,
                factory=None,
                lifetime=Lifetime.Singleton
            )
            self._singletons[service_name] = implementation
        else:
            raise ValueError("Either implementation or factory must be provided for singleton")

    def register_transient(self, service_type: Type, factory: Callable, name: str = None):
        """Register a transient service"""
        service_name = name or service_type.__name__
        self._services[service_name] = ServiceRegistration(
            service_type=service_type,
            implementation=None,
            factory=factory,
            lifetime=Lifetime.Transient
        )

    def resolve(self, service_type: Type, name: str = None) -> Any:
        """Resolve a service from the container"""
        service_name = name or service_type.__name__

        if service_name not in self._services:
            raise ValueError(f"Service {service_name} not registered")

        registration = self._services[service_name]

        if registration.lifetime == Lifetime.Singleton:
            if service_name not in self._singletons:
                if registration.factory:
                    self._singletons[service_name] = registration.factory(self)
                else:
                    self._singletons[service_name] = registration.implementation
            return self._singletons[service_name]

        elif registration.lifetime == Lifetime.Transient:
            return registration.factory(self)

        else:
            raise ValueError(f"Unknown lifetime for service {service_name}")

    def has_service(self, service_type: Type, name: str = None) -> bool:
        """Check if a service is registered"""
        service_name = name or service_type.__name__
        return service_name in self._services

    def get_registered_services(self) -> Dict[str, Type]:
        """Get all registered services"""
        return {name: reg.service_type for name, reg in self._services.items()}


@dataclass
class ServiceRegistration:
    """Service registration metadata"""
    service_type: Type
    implementation: Optional[Any]
    factory: Optional[Callable]
    lifetime: 'Lifetime'


class Lifetime:
    """Service lifetime enumeration"""
    Singleton = "singleton"
    Transient = "transient"


# Global container instance
container = DependencyContainer()


def get_container() -> DependencyContainer:
    """Get the global dependency container"""
    return container


def configure_services():
    """
    Configure all services in the dependency injection container
    """
    from security import InputValidator
    from exceptions import error_handler
    from services import (
        MLModelService, PayloadMutatorService, InputValidatorService,
        WAFDetectorService, HTTPClientService, LoggerService, ErrorHandlerService
    )
    from interfaces import (
        IMLModel, IPayloadMutator, IInputValidator, IWAFDetector,
        ILogger, IHTTPClient, IErrorHandler, IFeatureExtractor
    )
    from config_manager import get_config_manager, AppConfig
    from optimized_features import OptimizedFeatureExtractor, create_optimized_feature_extractor
    from optimized_ml import OptimizedActorCritic, create_optimized_ml_pipeline
    from optimized_http import OptimizedHTTPClient, get_optimized_http_client

    # Configure core services using configuration manager
    def create_app_config(container):
        return get_config_manager().get_config()

    def create_ml_config(container):
        app_config = container.resolve(AppConfig)
        return app_config.ml_config

    def create_optimized_actor_critic(container):
        app_config = container.resolve(AppConfig)
        ml_config = app_config.ml_config
        feature_extractor = container.resolve(IFeatureExtractor)
        return OptimizedActorCritic(ml_config, feature_extractor)

    def create_optimized_feature_extractor(container):
        from optimized_features import OptimizedFeatureExtractor
        return OptimizedFeatureExtractor()

    def create_feature_extractor_service(container):
        extractor = container.resolve(OptimizedFeatureExtractor)
        return extractor  # OptimizedFeatureExtractor implements IFeatureExtractor directly

    # Configure security services
    def create_security_config(container):
        app_config = container.resolve(AppConfig)
        return app_config.security_config

    def create_input_validator(container):
        app_config = container.resolve(AppConfig)
        security_config = app_config.security_config
        # Convert Pydantic model to dict for InputValidator
        from security import SecurityConfig as SecurityConfigClass
        security_dict = {
            'validation_level': security_config.validation_level,
            'max_payload_length': security_config.max_payload_length,
            'max_url_length': security_config.max_url_length,
            'allowed_schemes': security_config.allowed_schemes,
            'blocked_domains': security_config.blocked_domains,
            'enable_circuit_breaker': security_config.enable_circuit_breaker,
            'circuit_breaker_threshold': security_config.circuit_breaker_threshold,
            'circuit_breaker_timeout': security_config.circuit_breaker_timeout,
            'rate_limit_requests': security_config.rate_limit_requests,
            'rate_limit_window': security_config.rate_limit_window
        }
        return InputValidator(SecurityConfigClass(**security_dict))

    # Configure service wrappers
    def create_ml_model_service(container):
        actor_critic = container.resolve(OptimizedActorCritic)
        feature_extractor = container.resolve(IFeatureExtractor)
        return MLModelService(actor_critic, feature_extractor)

    def create_payload_mutator_service(container):
        input_validator = container.resolve(IInputValidator)
        app_config = container.resolve(AppConfig)
        security_config = app_config.security_config
        return PayloadMutatorService(input_validator, security_config)

    def create_input_validator_service(container):
        input_validator = container.resolve(InputValidator)
        return InputValidatorService(input_validator)

    def create_waf_detector_service(container):
        http_client = container.resolve(IHTTPClient)
        input_validator = container.resolve(IInputValidator)
        return WAFDetectorService(http_client, input_validator)

    def create_http_client_service(container):
        app_config = container.resolve(AppConfig)
        optimized_client = get_optimized_http_client(app_config.network_config)
        return HTTPClientService(optimized_client)

    def create_logger_service(container):
        return LoggerService("waf_bypass")

    def create_error_handler_service(container):
        return ErrorHandlerService()

    # Register configuration
    container.register_singleton(AppConfig, factory=create_app_config)

    # Register core implementations
    container.register_singleton(OptimizedActorCritic, factory=create_optimized_actor_critic)
    container.register_singleton(OptimizedFeatureExtractor, factory=create_optimized_feature_extractor)
    container.register_singleton(IFeatureExtractor, factory=create_feature_extractor_service)

    container.register_singleton(InputValidator, factory=create_input_validator)

    # Register infrastructure services
    container.register_singleton(IHTTPClient, factory=create_http_client_service)
    container.register_singleton(ILogger, factory=create_logger_service)
    container.register_singleton(IErrorHandler, factory=create_error_handler_service)

    # Register domain services
    container.register_singleton(IMLModel, factory=create_ml_model_service)
    container.register_singleton(IPayloadMutator, factory=create_payload_mutator_service)
    container.register_singleton(IInputValidator, factory=create_input_validator_service)
    container.register_singleton(IWAFDetector, factory=create_waf_detector_service)

    logger.info("Dependency injection container configured with configuration management")


# Initialize services on module import
configure_services()
