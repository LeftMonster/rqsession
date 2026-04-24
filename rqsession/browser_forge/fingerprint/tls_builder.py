"""
TLS configuration builder for curl_cffi
"""
import random
from typing import Optional
from ..profiles.models import TlsConfig, BrowserProfile


class TlsBuilder:
    """Build TLS configuration for curl_cffi client"""

    # TLS version mapping
    TLS_VERSION_MAP = {
        "1.0": 1,  # CURL_SSLVERSION_TLSv1_0
        "1.1": 2,  # CURL_SSLVERSION_TLSv1_1
        "1.2": 3,  # CURL_SSLVERSION_TLSv1_2
        "1.3": 4,  # CURL_SSLVERSION_TLSv1_3
    }

    @staticmethod
    def build_cipher_string(cipher_suites: list) -> str:
        """
        Build OpenSSL cipher string from cipher suite list

        Args:
            cipher_suites: List of cipher suite names

        Returns:
            Colon-separated cipher string for OpenSSL
        """
        return ":".join(cipher_suites)

    @staticmethod
    def build_curves_string(curves: list) -> str:
        """
        Build curves string for TLS

        Args:
            curves: List of curve names (e.g., ['x25519', 'secp256r1'])

        Returns:
            Colon-separated curves string
        """
        return ":".join(curves)

    @staticmethod
    def build_sigalgs_string(signature_algorithms: list) -> str:
        """
        Build signature algorithms string

        Args:
            signature_algorithms: List of signature algorithm names

        Returns:
            Colon-separated sigalgs string
        """
        return ":".join(signature_algorithms)

    @staticmethod
    def get_curl_tls_version(version: str, is_max: bool = False) -> int:
        """
        Get curl TLS version constant

        Args:
            version: TLS version string (e.g., "1.2", "1.3")
            is_max: Whether this is max version (affects constant calculation)

        Returns:
            Curl TLS version constant
        """
        base = TlsBuilder.TLS_VERSION_MAP.get(version, 0)
        if is_max and base > 0:
            # For max version, curl uses (base | (base << 16))
            # But in practice, we just use the base value
            return base
        return base

    @staticmethod
    def randomize_tls_config(config: TlsConfig,
                             shuffle_curves: bool = True,
                             shuffle_sigalgs: bool = True) -> TlsConfig:
        """
        Randomize non-critical TLS parameters to add entropy

        Args:
            config: Original TLS configuration
            shuffle_curves: Whether to shuffle curves order
            shuffle_sigalgs: Whether to shuffle signature algorithms order

        Returns:
            New TLS configuration with randomized parameters
        """
        import copy
        new_config = copy.deepcopy(config)

        if shuffle_curves and len(new_config.curves) > 1:
            random.shuffle(new_config.curves)

        if shuffle_sigalgs and len(new_config.signature_algorithms) > 1:
            random.shuffle(new_config.signature_algorithms)

        return new_config

    @staticmethod
    def apply_to_curl_options(config: TlsConfig) -> dict:
        """
        Convert TLS config to curl options dictionary

        Args:
            config: TLS configuration

        Returns:
            Dictionary of curl options
        """
        options = {}

        # Cipher suites
        if config.cipher_suites:
            options['ssl_cipher_list'] = TlsBuilder.build_cipher_string(config.cipher_suites)

        # Curves (for ECDHE)
        if config.curves:
            options['ssl_ec_curves'] = TlsBuilder.build_curves_string(config.curves)

        # Signature algorithms
        if config.signature_algorithms:
            options['ssl_sigalgs'] = TlsBuilder.build_sigalgs_string(config.signature_algorithms)

        # TLS version range
        if config.min_version:
            options['ssl_min_version'] = config.min_version
        if config.max_version:
            options['ssl_max_version'] = config.max_version

        # ALPN protocols
        if config.alpn_protocols:
            options['alpn_protocols'] = config.alpn_protocols

        return options

    @staticmethod
    def validate_config(config: TlsConfig) -> tuple[bool, Optional[str]]:
        """
        Validate TLS configuration

        Args:
            config: TLS configuration to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not config.cipher_suites:
            return False, "Cipher suites cannot be empty"

        if not config.curves:
            return False, "Curves cannot be empty"

        if config.min_version not in TlsBuilder.TLS_VERSION_MAP:
            return False, f"Invalid min_version: {config.min_version}"

        if config.max_version not in TlsBuilder.TLS_VERSION_MAP:
            return False, f"Invalid max_version: {config.max_version}"

        min_val = TlsBuilder.TLS_VERSION_MAP[config.min_version]
        max_val = TlsBuilder.TLS_VERSION_MAP[config.max_version]

        if min_val > max_val:
            return False, "min_version cannot be greater than max_version"

        return True, None


class ProfileValidator:
    """Validate browser profiles"""

    @staticmethod
    def validate_profile(profile: BrowserProfile) -> tuple[bool, list[str]]:
        """
        Validate complete browser profile

        Args:
            profile: Browser profile to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Validate name
        if not profile.name:
            errors.append("Profile name cannot be empty")

        # Validate user agent
        if not profile.user_agent:
            errors.append("User agent cannot be empty")

        # Validate TLS config
        is_valid, error = TlsBuilder.validate_config(profile.tls_config)
        if not is_valid:
            errors.append(f"TLS config error: {error}")

        # Validate H2 settings
        if profile.h2_settings.header_table_size < 0:
            errors.append("H2 header_table_size must be non-negative")

        if profile.h2_settings.initial_window_size < 0:
            errors.append("H2 initial_window_size must be non-negative")

        # Validate behavior
        if profile.behavior.connection_timeout <= 0:
            errors.append("connection_timeout must be positive")

        if profile.behavior.max_connections_per_host <= 0:
            errors.append("max_connections_per_host must be positive")

        return len(errors) == 0, errors