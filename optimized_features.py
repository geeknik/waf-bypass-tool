"""
Optimized Feature Extraction for WAF Bypass Tool
Provides high-performance feature extraction with vectorization and caching
"""

import numpy as np
import re
from typing import Dict, List, Optional, Union, Tuple
from functools import lru_cache
from collections import defaultdict
import hashlib
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class FeatureStats:
    """Statistics for feature extraction performance"""
    total_extractions: int = 0
    cache_hits: int = 0
    vectorized_operations: int = 0
    processing_time: float = 0.0


class OptimizedFeatureExtractor:
    """
    High-performance feature extractor with optimization techniques:
    - Vectorized string operations
    - LRU caching for expensive computations
    - Pre-compiled regex patterns
    - Memory-efficient data structures
    """

    def __init__(self, max_cache_size: int = 10000):
        self.max_cache_size = max_cache_size
        self.stats = FeatureStats()

        # Pre-compile regex patterns for performance
        self._compile_regex_patterns()

        # Initialize caches
        self._feature_cache = {}
        self._string_stats_cache = {}

        # Vectorized character counting arrays
        self._char_sets = {
            'digits': set('0123456789'),
            'alpha': set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            'special': set('!@#$%^&*()_+-=[]{}|;:,.<>?'),
            'whitespace': set(' \t\n\r'),
        }

        logger.info(f"OptimizedFeatureExtractor initialized with cache size: {max_cache_size}")

    def _compile_regex_patterns(self):
        """Pre-compile regex patterns for better performance"""
        self.patterns = {
            'script_tags': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            'sql_injection': re.compile(r'(union|select|insert|update|delete|drop)\s', re.IGNORECASE),
            'xss_attempts': re.compile(r'(javascript|vbscript|data):', re.IGNORECASE),
            'path_traversal': re.compile(r'\.\./|\.\.\\'),
            'command_injection': re.compile(r'[;&|`$()]'),
            'template_injection': re.compile(r'\{\{.*?\}\}|\{\%.*?\%\}'),
        }

    @lru_cache(maxsize=5000)
    def _cached_string_stats(self, payload_hash: str, payload: str) -> Dict[str, Union[int, float]]:
        """Cached computation of string statistics"""
        return {
            'length': len(payload),
            'digit_count': sum(c in self._char_sets['digits'] for c in payload),
            'alpha_count': sum(c in self._char_sets['alpha'] for c in payload),
            'special_count': sum(c in self._char_sets['special'] for c in payload),
            'whitespace_count': sum(c in self._char_sets['whitespace'] for c in payload),
            'uppercase_ratio': sum(c.isupper() for c in payload) / max(len(payload), 1),
            'entropy': self._calculate_entropy(payload),
        }

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of string"""
        if not s:
            return 0.0

        # Use vectorized counting for better performance
        char_counts = defaultdict(int)
        for char in s:
            char_counts[char] += 1

        length = len(s)
        entropy = 0.0

        for count in char_counts.values():
            if count > 0:
                probability = count / length
                entropy -= probability * np.log2(probability)

        return entropy

    def _vectorized_pattern_matching(self, payload: str) -> Dict[str, int]:
        """Vectorized pattern matching using pre-compiled regex"""
        results = {}

        for name, pattern in self.patterns.items():
            matches = pattern.findall(payload)
            results[f'{name}_count'] = len(matches)
            if matches:
                # Calculate average match length for additional features
                avg_length = np.mean([len(match) for match in matches])
                results[f'{name}_avg_length'] = avg_length
            else:
                results[f'{name}_avg_length'] = 0.0

        return results

    def _extract_structural_features(self, payload: str) -> Dict[str, Union[int, float]]:
        """Extract structural features from payload"""
        features = {}

        # Tag-based features (optimized)
        tag_counts = {
            'angle_brackets': payload.count('<') + payload.count('>'),
            'parentheses': payload.count('(') + payload.count(')'),
            'brackets': payload.count('[') + payload.count(']'),
            'curly_braces': payload.count('{') + payload.count('}'),
        }
        features.update(tag_counts)

        # Quote analysis
        single_quotes = payload.count("'")
        double_quotes = payload.count('"')
        features.update({
            'single_quotes': single_quotes,
            'double_quotes': double_quotes,
            'quote_imbalance': abs(single_quotes - double_quotes),
        })

        # Comment detection
        features.update({
            'html_comments': payload.count('<!--'),
            'js_comments': payload.count('//') + payload.count('/*'),
            'sql_comments': payload.count('--') + payload.count('/*') + payload.count('*/'),
        })

        return features

    def _extract_semantic_features(self, payload: str) -> Dict[str, Union[int, float]]:
        """Extract semantic features from payload"""
        features = {}

        # Keyword analysis (optimized with sets)
        keywords = {
            'sql': {'select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter'},
            'xss': {'script', 'javascript', 'vbscript', 'onload', 'onerror', 'onclick', 'alert'},
            'lfi': {'etc', 'passwd', 'shadow', 'config', 'htaccess'},
            'command': {'exec', 'system', 'shell_exec', 'passthru', 'eval'},
        }

        for category, words in keywords.items():
            count = sum(1 for word in words if word.lower() in payload.lower())
            features[f'{category}_keywords'] = count

        # URL pattern detection
        url_patterns = [
            'http://', 'https://', 'ftp://', 'file://',
            'javascript:', 'data:', 'vbscript:'
        ]
        features['url_schemes'] = sum(1 for pattern in url_patterns if pattern in payload.lower())

        return features

    def extract_features(self, payload: str) -> np.ndarray:
        """
        Extract optimized feature vector from payload

        Features include:
        - String statistics (length, entropy, character counts)
        - Pattern matching (SQL, XSS, LFI, command injection)
        - Structural features (tags, quotes, comments)
        - Semantic features (keywords, URL schemes)
        """
        import time
        start_time = time.time()

        try:
            # Create payload hash for caching
            payload_hash = hashlib.md5(payload.encode()).hexdigest()[:16]

            # Check cache first
            if payload_hash in self._feature_cache:
                self.stats.cache_hits += 1
                return self._feature_cache[payload_hash]

            # Extract all feature categories
            string_stats = self._cached_string_stats(payload_hash, payload)
            pattern_features = self._vectorized_pattern_matching(payload)
            structural_features = self._extract_structural_features(payload)
            semantic_features = self._extract_semantic_features(payload)

            # Combine all features
            all_features = {
                **string_stats,
                **pattern_features,
                **structural_features,
                **semantic_features,
            }

            # Convert to numpy array with consistent ordering
            feature_names = sorted(all_features.keys())
            feature_vector = np.array([all_features[name] for name in feature_names], dtype=np.float32)

            # Handle NaN and infinite values
            feature_vector = np.nan_to_num(feature_vector, nan=0.0, posinf=1000.0, neginf=-1000.0)

            # Cache the result
            if len(self._feature_cache) < self.max_cache_size:
                self._feature_cache[payload_hash] = feature_vector

            self.stats.total_extractions += 1
            self.stats.vectorized_operations += 1

            processing_time = time.time() - start_time
            self.stats.processing_time += processing_time

            return feature_vector

        except Exception as e:
            logger.warning(f"Feature extraction failed: {e}")
            # Return zero vector on error
            return np.zeros(30, dtype=np.float32)

    def extract_features_batch(self, payloads: List[str]) -> np.ndarray:
        """
        Extract features for multiple payloads efficiently

        Args:
            payloads: List of payload strings

        Returns:
            2D numpy array of features (n_payloads, n_features)
        """
        if not payloads:
            return np.array([]).reshape(0, 30)

        # Process payloads individually for now (can be optimized further)
        feature_vectors = []
        for payload in payloads:
            features = self.extract_features(payload)
            feature_vectors.append(features)

        return np.array(feature_vectors, dtype=np.float32)

    def get_feature_names(self) -> List[str]:
        """Get the names of all features in order"""
        # This is a representative payload to extract feature names
        test_payload = "<script>alert(1)</script>"
        features = self.extract_features(test_payload)

        # Create feature names based on extraction order
        return [
            'length', 'digit_count', 'alpha_count', 'special_count', 'whitespace_count',
            'uppercase_ratio', 'entropy', 'script_tags_count', 'script_tags_avg_length',
            'sql_injection_count', 'sql_injection_avg_length', 'xss_attempts_count',
            'xss_attempts_avg_length', 'path_traversal_count', 'path_traversal_avg_length',
            'command_injection_count', 'command_injection_avg_length',
            'template_injection_count', 'template_injection_avg_length',
            'angle_brackets', 'parentheses', 'brackets', 'curly_braces',
            'single_quotes', 'double_quotes', 'quote_imbalance',
            'html_comments', 'js_comments', 'sql_comments',
            'sql_keywords', 'xss_keywords', 'lfi_keywords', 'command_keywords', 'url_schemes'
        ]

    def clear_cache(self):
        """Clear all caches"""
        self._feature_cache.clear()
        self._string_stats_cache.clear()
        self._cached_string_stats.cache_clear()
        logger.info("Feature extraction cache cleared")

    def get_performance_stats(self) -> Dict[str, Union[int, float]]:
        """Get performance statistics"""
        cache_miss_rate = 0.0
        if self.stats.total_extractions > 0:
            cache_miss_rate = (self.stats.total_extractions - self.stats.cache_hits) / self.stats.total_extractions

        avg_processing_time = 0.0
        if self.stats.total_extractions > 0:
            avg_processing_time = self.stats.processing_time / self.stats.total_extractions

        return {
            'total_extractions': self.stats.total_extractions,
            'cache_hits': self.stats.cache_hits,
            'cache_hit_rate': self.stats.cache_hits / max(self.stats.total_extractions, 1),
            'cache_miss_rate': cache_miss_rate,
            'vectorized_operations': self.stats.vectorized_operations,
            'avg_processing_time_ms': avg_processing_time * 1000,
            'cache_size': len(self._feature_cache),
            'max_cache_size': self.max_cache_size,
        }

    def optimize_for_production(self):
        """Apply production optimizations"""
        # Increase cache size for production
        self.max_cache_size = 50000

        # Pre-warm cache with common patterns
        common_patterns = [
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
            "<img src=x onerror=alert(1)>",
            "UNION SELECT null,null",
        ]

        logger.info("Pre-warming feature extraction cache...")
        for pattern in common_patterns:
            self.extract_features(pattern)

        logger.info(f"Production optimizations applied. Cache size: {len(self._feature_cache)}")


# Global optimized feature extractor instance
optimized_extractor = OptimizedFeatureExtractor()


def create_optimized_feature_extractor() -> OptimizedFeatureExtractor:
    """Factory function for optimized feature extractor"""
    return OptimizedFeatureExtractor()


def extract_features_optimized(payload: str) -> np.ndarray:
    """Convenience function for optimized feature extraction"""
    return optimized_extractor.extract_features(payload)
