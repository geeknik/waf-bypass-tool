# WAF Bypass Tool v2.1

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/maintained-yes-green.svg)]()

A robust, machine learning-powered tool for detecting and bypassing Web Application Firewalls (WAFs) with functional reinforcement learning, comprehensive testing, and clean architecture. Core ML algorithms now properly learn from bypass attempts based on HTTP response codes.

## 🚀 Features

### Core Functionality
- **Intelligent WAF Detection**: Advanced pattern matching and behavioral analysis
- **Machine Learning Bypass**: Actor-Critic reinforcement learning for optimal payload generation
- **Batch Processing**: High-performance processing of multiple URLs simultaneously
- **Real-time Statistics**: Comprehensive metrics and performance monitoring

### Security & Performance
- **Input Validation**: Comprehensive sanitization and validation of all inputs
- **Rate Limiting**: Built-in rate limiting with configurable backoff strategies
- **Connection Pooling**: Optimized HTTP client with connection reuse
- **Error Recovery**: Robust error handling with automatic recovery mechanisms

### Enterprise Features
- **Configuration Management**: Multi-source configuration with validation
- **Dependency Injection**: Clean architecture with service separation
- **Async Support**: Concurrent processing capabilities
- **Monitoring**: Structured logging and performance metrics

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Performance](#performance)
- [Testing](#testing)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [License](#license)

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install from Source
```bash
# Clone the repository
git clone https://github.com/geeknik/waf-bypass-tool.git
cd waf-bypass-tool

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Install for development
pip install -r requirements-dev.txt
```

### Docker Installation
```bash
# Build the container
docker build -t waf-bypass .

# Run the container
docker run -it waf-bypass --help
```

## 🚀 Quick Start

### Basic WAF Detection
```bash
# Detect WAF on a single URL
python main.py --detect-only --url https://example.com

# Detect WAF on multiple URLs from file
python main.py --detect-only --file urls.txt

# Full bypass attempt
python main.py --url https://example.com
```

### Advanced Usage
```bash
# Use custom configuration
python main.py --config my_config.yaml --url https://example.com

# Multi-threaded processing
python main.py --workers 10 --file targets.txt

# Show current configuration
python main.py --show-config
```

## ⚙️ Configuration

The tool supports multiple configuration sources with the following priority:
1. Command-line arguments
2. Configuration file (YAML/JSON)
3. Environment variables (prefixed with `WAF_`)
4. Default values

### Configuration File Example
```yaml
app_name: "WAF Bypass Tool v2.1"
version: "2.1.0"
environment: "development"

# Machine Learning Configuration
ml_config:
  learning_rate: 0.01
  discount_factor: 0.99
  gradient_clip_value: 10.0
  td_error_clip_value: 1000.0
  feature_scaling: true
  model_checkpoint_interval: 100
  max_model_history: 10
  batch_size: 32
  epochs: 100

# Security Configuration
security_config:
  validation_level: "strict"
  max_payload_length: 10000
  max_url_length: 2048
  allowed_schemes: ["http", "https"]
  blocked_domains: []
  enable_circuit_breaker: true
  circuit_breaker_threshold: 5
  circuit_breaker_timeout: 300

# Network Configuration
network_config:
  default_timeout: 10.0
  max_retries: 3
  retry_delay: 1.0
  user_agent: "WAF-Bypass-Tool/2.0"
  max_connections: 100
  connection_pool_size: 10
  keep_alive: true

# Logging Configuration
logging_config:
  level: "INFO"
  format: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
  max_file_size: 10485760
  backup_count: 5
  enable_console: true
  console_level: "WARNING"
```

### Environment Variables
```bash
# Machine Learning
export WAF_ML_CONFIG_LEARNING_RATE=0.01
export WAF_ML_CONFIG_DISCOUNT_FACTOR=0.99

# Security
export WAF_SECURITY_CONFIG_VALIDATION_LEVEL=strict
export WAF_SECURITY_CONFIG_MAX_PAYLOAD_LENGTH=10000

# Network
export WAF_NETWORK_CONFIG_DEFAULT_TIMEOUT=10.0
export WAF_NETWORK_CONFIG_MAX_CONNECTIONS=100
```

## 📖 Usage

### Command Line Options
```
Usage: main.py [-h] [--url URL] [--file FILE] [--config CONFIG]
               [--detect-only] [--workers WORKERS] [--show-config]

Secure Adaptive WAF Evasion Toolkit

options:
  -h, --help         show this help message and exit
  --url URL          Single URL to target
  --file FILE        File containing list of URLs to target
  --config CONFIG    Path to configuration file
  --detect-only      Only detect WAF, don't attempt evasion
  --workers WORKERS  Number of worker threads (max 5)
  --show-config      Show current configuration and exit
```

### URL File Format
```
# One URL per line
https://example.com
https://test.com/admin
https://api.example.com/v1/users
```

### Output Examples
```
============================================================
SCAN SUMMARY
============================================================
Total URLs processed: 150
Successful bypasses: 23
Failed attempts: 127
WAF detected: 45
Errors: 0
Success Rate: 15.33%
ML Training steps: 1247
============================================================
```

## 🏗️ Architecture

### Clean Architecture Pattern
```
┌─────────────────────────────────────────┐
│                Presentation            │
│            (CLI, API, GUI)             │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│            Application Layer           │
│        (Use Cases, Services)           │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│           Domain Layer                  │
│     (Entities, Business Logic)         │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│         Infrastructure Layer            │
│   (External APIs, Persistence, I/O)    │
└─────────────────────────────────────────┘
```

### Key Components

#### Core Services
- **WAFBypassService**: Main orchestration service
- **MLModelService**: Machine learning model wrapper
- **PayloadMutatorService**: Payload generation and mutation
- **InputValidatorService**: Input validation and sanitization

#### Infrastructure
- **OptimizedHTTPClient**: High-performance HTTP operations
- **OptimizedFeatureExtractor**: Vectorized feature extraction
- **ConfigurationManager**: Multi-source configuration management
- **DependencyContainer**: Service registration and resolution

#### Domain Models
- **ActorCritic**: Reinforcement learning model
- **TrainingBatch**: Batch training data structure
- **FeatureVector**: Extracted feature representations

## 📚 API Reference

### Core Classes

#### WAFBypassService
```python
from waf_bypass_service import WAFBypassService

service = WAFBypassService()
result = service.evade_waf("https://example.com")
stats = service.get_statistics()
```

#### Configuration Manager
```python
from config_manager import get_config_manager

config_manager = get_config_manager()
config = config_manager.load_config()
config_manager.save_config("my_config.yaml")
```

#### Optimized Components
```python
from optimized_features import OptimizedFeatureExtractor
from optimized_ml import OptimizedActorCritic
from optimized_http import OptimizedHTTPClient

# Feature extraction
extractor = OptimizedFeatureExtractor()
features = extractor.extract_features("malicious payload")

# ML training
actor_critic = OptimizedActorCritic(ml_config, extractor)
metrics = actor_critic.train_batch()

# HTTP operations
http_client = OptimizedHTTPClient(network_config)
response = http_client.get("https://example.com")
```

## ⚡ Performance

### Key Improvements
- **Feature Extraction**: Vectorized operations for efficient payload analysis
- **ML Training**: Batch processing for improved gradient estimation
- **HTTP Operations**: Connection pooling and request optimization
- **Concurrent Processing**: Multi-threaded URL scanning with configurable workers
- **Resource Management**: Proper cleanup and memory optimization

### Performance Tuning
```yaml
# High-throughput configuration
ml_config:
  batch_size: 64
  epochs: 200

network_config:
  max_connections: 200
  connection_pool_size: 20
  keep_alive: true

# Memory-efficient configuration
ml_config:
  batch_size: 16
  max_model_history: 3

network_config:
  max_connections: 50
  connection_pool_size: 5
```

## 🧪 Testing

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=waf_bypass --cov-report=html

# Run specific test categories
pytest tests/test_security/
pytest tests/test_performance/
pytest tests/integration/
```

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Security Tests**: Input validation and sanitization
- **Performance Tests**: Benchmarking and optimization
- **Load Tests**: High-throughput scenario testing

## 🤝 Contributing

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/geeknik/waf-bypass-tool.git
cd waf-bypass-tool

# Create feature branch
git checkout -b feature/amazing-improvement

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Submit pull request
```

### Code Style
- Follow PEP 8 style guidelines
- Use type hints for all function parameters and return values
- Write comprehensive docstrings
- Add unit tests for new features
- Update documentation for API changes

### Commit Guidelines
```
feat: add new bypass technique
fix: resolve memory leak in feature extraction
docs: update API documentation
test: add performance benchmarks
refactor: optimize HTTP client connection pooling
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📋 Changelog

### v2.1.0 (Critical Bug Fixes & Production Ready)
- **🔧 ML System Fixed**: Reinforcement learning now properly learns from HTTP response codes instead of sabotaging itself with artificial keyword penalties
- **🧠 ML-Guided Mutations**: Implemented intelligent payload selection using trained critic model to choose mutations most likely to bypass WAFs
- **🎯 Smart Selection**: System generates multiple mutation candidates, scores them with ML, and selects highest-probability bypass methods
- **🧪 Comprehensive Testing**: Added test suite with 8 critical tests covering ML learning, mutations, and regression prevention
- **🧹 Code Quality**: Removed all debug print statements and implemented proper logging throughout
- **📏 Configuration**: Removed forced testing overrides that broke intended functionality
- **🚀 Production Ready**: ML system now actively guides payload generation based on learned bypass patterns

### v2.0.0 (Previous Release)
- Initial ML-powered WAF bypass implementation
- Clean architecture with dependency injection
- Multi-threaded processing capabilities

## ⚠️ Disclaimer

This tool is intended for educational and research purposes only. Users are responsible for complying with applicable laws and regulations when using this software. The authors assume no liability for misuse of this tool.

## 🙏 Acknowledgments

- **Reinforcement Learning**: Based on Actor-Critic algorithms
- **HTTP Client**: Built on requests/urllib3 foundation
- **ML Framework**: Powered by scikit-learn
- **Async Support**: Leveraging aiohttp for concurrency

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/geeknik/waf-bypass-tool/issues)
- **Discussions**: [GitHub Discussions](https://github.com/geeknik/waf-bypass-tool/discussions)
- **Documentation**: [Read the Docs](https://waf-bypass-tool.readthedocs.io/)

---

**Built with ❤️ for security research and education**
