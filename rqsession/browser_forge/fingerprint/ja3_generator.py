"""
JA3 and JA4 fingerprint generator
"""
import hashlib
from typing import Optional
from ..profiles.models import TlsConfig


class JA3Generator:
    """Generate JA3 fingerprints from TLS configuration"""

    # TLS version to JA3 version code mapping
    TLS_VERSION_CODES = {
        "1.0": "769",
        "1.1": "770",
        "1.2": "771",
        "1.3": "772",
    }

    # Cipher suite name to code mapping (partial, commonly used)
    CIPHER_CODES = {
        "TLS_AES_128_GCM_SHA256": "4865",
        "TLS_AES_256_GCM_SHA384": "4866",
        "TLS_CHACHA20_POLY1305_SHA256": "4867",
        "ECDHE-ECDSA-AES128-GCM-SHA256": "49195",
        "ECDHE-RSA-AES128-GCM-SHA256": "49199",
        "ECDHE-ECDSA-AES256-GCM-SHA384": "49196",
        "ECDHE-RSA-AES256-GCM-SHA384": "49200",
        "ECDHE-ECDSA-CHACHA20-POLY1305": "52393",
        "ECDHE-RSA-CHACHA20-POLY1305": "52392",
        "ECDHE-ECDSA-AES128-SHA": "49169",
        "ECDHE-RSA-AES128-SHA": "49171",
        "ECDHE-ECDSA-AES256-SHA": "49170",
        "ECDHE-RSA-AES256-SHA": "49172",
        "AES128-GCM-SHA256": "156",
        "AES256-GCM-SHA384": "157",
        "AES128-SHA": "47",
        "AES256-SHA": "53",
        "ECDHE-ECDSA-AES256-SHA384": "49188",
        "ECDHE-ECDSA-AES128-SHA256": "49187",
        "ECDHE-RSA-AES256-SHA384": "49192",
        "ECDHE-RSA-AES128-SHA256": "49191",
    }

    # Curve name to code mapping
    CURVE_CODES = {
        "x25519": "29",
        "secp256r1": "23",
        "secp384r1": "24",
        "secp521r1": "25",
        "ffdhe2048": "256",
        "ffdhe3072": "257",
    }

    @staticmethod
    def generate_ja3_string(config: TlsConfig,
                            use_max_version: bool = True) -> str:
        """
        Generate JA3 fingerprint string from TLS config

        JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

        Args:
            config: TLS configuration
            use_max_version: Use max_version instead of min_version

        Returns:
            JA3 fingerprint string
        """
        # SSL/TLS Version
        version = config.max_version if use_max_version else config.min_version
        version_code = JA3Generator.TLS_VERSION_CODES.get(version, "771")

        # Cipher suites
        cipher_codes = []
        for cipher in config.cipher_suites:
            code = JA3Generator.CIPHER_CODES.get(cipher)
            if code:
                cipher_codes.append(code)
        ciphers_str = "-".join(cipher_codes) if cipher_codes else ""

        # Extensions
        extensions_str = "-".join(str(ext) for ext in config.extensions) if config.extensions else ""

        # Elliptic curves
        curve_codes = []
        for curve in config.curves:
            code = JA3Generator.CURVE_CODES.get(curve)
            if code:
                curve_codes.append(code)
        curves_str = "-".join(curve_codes) if curve_codes else ""

        # Elliptic curve point formats (usually just "0" for uncompressed)
        point_formats = "0"

        ja3_string = f"{version_code},{ciphers_str},{extensions_str},{curves_str},{point_formats}"
        return ja3_string

    @staticmethod
    def generate_ja3_hash(ja3_string: str) -> str:
        """
        Generate JA3 hash from JA3 string

        Args:
            ja3_string: JA3 fingerprint string

        Returns:
            MD5 hash of JA3 string
        """
        return hashlib.md5(ja3_string.encode()).hexdigest()

    @staticmethod
    def generate_ja3(config: TlsConfig) -> tuple[str, str]:
        """
        Generate both JA3 string and hash

        Args:
            config: TLS configuration

        Returns:
            Tuple of (ja3_string, ja3_hash)
        """
        ja3_string = JA3Generator.generate_ja3_string(config)
        ja3_hash = JA3Generator.generate_ja3_hash(ja3_string)
        return ja3_string, ja3_hash


class JA4Generator:
    """Generate JA4 fingerprints from TLS configuration"""

    @staticmethod
    def generate_ja4_string(config: TlsConfig,
                            sni: str = "d",
                            use_alpn: bool = True) -> str:
        """
        Generate JA4 fingerprint string

        JA4 format: QUIC_TLS_Version(2)_SNI(1)_CipherCount(2)_ExtensionCount(2)_ALPN(2)_
                    FirstCipherHash(12)_FirstExtensionHash(12)

        Args:
            config: TLS configuration
            sni: SNI indicator (d=domain, i=IP)
            use_alpn: Whether ALPN is used

        Returns:
            JA4 fingerprint string (simplified)
        """
        # Protocol (t=TCP, q=QUIC)
        protocol = "t"

        # TLS version
        tls_version = "13" if config.max_version == "1.3" else "12"

        # Cipher count (max 99)
        cipher_count = min(len(config.cipher_suites), 99)
        cipher_count_str = f"{cipher_count:02d}"

        # Extension count (max 99)
        ext_count = min(len(config.extensions), 99)
        ext_count_str = f"{ext_count:02d}"

        # ALPN
        alpn = "00"
        if use_alpn and config.alpn_protocols:
            if "h2" in config.alpn_protocols:
                alpn = "h2"
            elif "http/1.1" in config.alpn_protocols:
                alpn = "h1"

        # First part of JA4
        ja4_part1 = f"{protocol}{tls_version}{sni}{cipher_count_str}{ext_count_str}{alpn}"

        # For simplified version, we'll use placeholder hashes
        # In production, these would be actual hashes of cipher/extension lists
        cipher_hash = hashlib.sha256(",".join(config.cipher_suites[:10]).encode()).hexdigest()[:12]
        ext_hash = hashlib.sha256(",".join(str(e) for e in config.extensions[:10]).encode()).hexdigest()[:12]

        ja4_string = f"{ja4_part1}_{cipher_hash}_{ext_hash}"
        return ja4_string

    @staticmethod
    def generate_ja4(config: TlsConfig) -> str:
        """
        Generate JA4 fingerprint

        Args:
            config: TLS configuration

        Returns:
            JA4 fingerprint string
        """
        return JA4Generator.generate_ja4_string(config)


class FingerprintAnalyzer:
    """Analyze and compare fingerprints"""

    @staticmethod
    def compare_ja3(ja3_1: str, ja3_2: str) -> float:
        """
        Compare two JA3 hashes and return similarity score

        Args:
            ja3_1: First JA3 hash
            ja3_2: Second JA3 hash

        Returns:
            Similarity score (0.0 to 1.0)
        """
        if ja3_1 == ja3_2:
            return 1.0

        # Simple character-by-character comparison
        matches = sum(c1 == c2 for c1, c2 in zip(ja3_1, ja3_2))
        return matches / max(len(ja3_1), len(ja3_2))

    @staticmethod
    def analyze_config(config: TlsConfig) -> dict:
        """
        Analyze TLS configuration and generate all fingerprints

        Args:
            config: TLS configuration

        Returns:
            Dictionary with analysis results
        """
        ja3_string, ja3_hash = JA3Generator.generate_ja3(config)
        ja4_string = JA4Generator.generate_ja4(config)

        return {
            "ja3_string": ja3_string,
            "ja3_hash": ja3_hash,
            "ja4_string": ja4_string,
            "cipher_count": len(config.cipher_suites),
            "extension_count": len(config.extensions),
            "curve_count": len(config.curves),
            "tls_version": f"{config.min_version}-{config.max_version}",
            "alpn_protocols": config.alpn_protocols,
        }