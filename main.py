#!/usr/bin/env python3
"""
WAF Bypass Tool - Clean Architecture Implementation
Uses dependency injection and modular design for maintainability
"""

import argparse
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

# Import our new modular architecture
from waf_bypass_service import WAFBypassService, create_waf_bypass_service
from interfaces import IWAFBypassService
from di_container import get_container
from exceptions import ErrorContext, error_handler
from config_manager import get_config_manager, load_app_config


# Initialize logging with better configuration
log_filename = "waf_evasion.log"
log_location = os.path.join(os.getcwd(), log_filename)

logging.basicConfig(
    filename=log_location,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)

# Add console logging for important messages
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
logging.getLogger('').addHandler(console)

logger = logging.getLogger(__name__)


class WAFBypassApplication:
    """Clean application class using dependency injection"""

    def __init__(self, config_path: str = None):
        with ErrorContext(error_handler, "application_initialization"):
            self.config_path = config_path
            self.bypass_service: IWAFBypassService = create_waf_bypass_service()
            logger.info("WAF Bypass Application initialized successfully")

    def run_detection_only(self, urls: List[str], workers: int = 3) -> dict:
        """Run WAF detection only"""
        return self.bypass_service.scan_urls(urls, workers, detect_only=True)

    def run_full_bypass(self, urls: List[str], workers: int = 3) -> dict:
        """Run full WAF bypass attempts"""
        return self.bypass_service.scan_urls(urls, workers, detect_only=False)

    def get_statistics(self) -> dict:
        """Get comprehensive statistics"""
        return self.bypass_service.get_statistics()

    def reset_statistics(self):
        """Reset statistics"""
        self.bypass_service.reset_statistics()


def load_urls_from_file(file_path: str) -> List[str]:
    """Load URLs from file with validation"""
    with ErrorContext(error_handler, "url_loading"):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                urls = [line.strip() for line in file if line.strip()]

            # Basic URL validation
            valid_urls = []
            for url in urls:
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                valid_urls.append(url)

            logger.info(f"Loaded {len(valid_urls)} URLs from {file_path}")
            return valid_urls

        except Exception as e:
            logger.error(f"Failed to load URLs from {file_path}: {e}")
            raise


def main():
    """Main execution function with comprehensive error handling"""
    with ErrorContext(error_handler, "main_execution"):
        try:
            parser = argparse.ArgumentParser(description="Secure Adaptive WAF Evasion Toolkit")
            parser.add_argument("--url", type=str, help="Single URL to target")
            parser.add_argument("--file", type=str, help="File containing list of URLs to target")
            parser.add_argument("--config", type=str, help="Path to configuration file")
            parser.add_argument("--detect-only", action="store_true", help="Only detect WAF, don't attempt evasion")
            parser.add_argument("--workers", type=int, default=3, help="Number of worker threads (max 5)")
            parser.add_argument("--show-config", action="store_true", help="Show current configuration and exit")

            args = parser.parse_args()

            # Load configuration first
            config_manager = get_config_manager()
            if args.config:
                config_manager.add_config_file(args.config)

            app_config = config_manager.load_config()

            # Show configuration if requested
            if args.show_config:
                config_summary = config_manager.get_config_summary()
                print("=== Configuration Summary ===")
                for key, value in config_summary.items():
                    print(f"{key}: {value}")
                print("============================")
                return 0

            # Validate arguments
            if not args.url and not args.file:
                parser.error("You must provide either --url or --file")

            # Initialize the application
            logger.info(f"Initializing Secure WAF Bypass Application v{app_config.version}...")
            app = WAFBypassApplication(args.config)

            # Load URLs
            if args.file:
                urls = load_urls_from_file(args.file)
            else:
                urls = [args.url]

            logger.info(f"Starting scan of {len(urls)} URLs")

            # Process URLs
            workers = min(max(args.workers, 1), 5)  # Limit to reasonable range

            if args.detect_only:
                logger.info("Running WAF detection only...")
                results = app.run_detection_only(urls, workers)

                waf_count = len(results.get("detected", []))
                logger.info(f"WAF detected on {waf_count}/{len(urls)} URLs")
                print(f"WAF Detection Results: {waf_count}/{len(urls)} URLs have WAF protection")

            else:
                logger.info("Running full WAF bypass attempts...")
                results = app.run_full_bypass(urls, workers)

            # Print summary and statistics
            stats = app.get_statistics()
            print("\n" + "="*60)
            print("SCAN SUMMARY")
            print("="*60)
            print(f"Total URLs processed: {stats['service_stats']['total_urls_processed']}")
            print(f"Successful bypasses: {stats['service_stats']['successful_bypasses']}")
            print(f"Failed attempts: {stats['service_stats']['failed_bypasses']}")
            print(f"WAF detected: {stats['service_stats']['waf_detected']}")
            print(f"Errors: {stats['service_stats']['errors']}")

            if stats['service_stats']['total_urls_processed'] > 0:
                success_rate = stats['service_stats']['successful_bypasses'] / stats['service_stats']['total_urls_processed'] * 100
                print(".2f")

            print(f"ML Training steps: {stats['ml_stats'].get('training_steps', stats['ml_stats'].get('training_step', 0))}")
            print("="*60)

        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            print("\nScan interrupted by user")
        except SystemExit as e:
            # This is normal for --help, don't treat as error
            return e.code
        except Exception as e:
            logger.error(f"Fatal error during execution: {e}")
            print(f"Fatal error: {e}")
            return 1

        return 0


if __name__ == "__main__":
    exit(main())
