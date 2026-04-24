"""
Browser Forge - Advanced HTTP client with browser fingerprint simulation

A powerful Python library for making HTTP requests with precise control over
TLS fingerprints, headers, and browser behavior to evade detection.
"""

__version__ = "0.2.0"  # TODO: 版本更新，添加了ja3指纹支持和tls_db_converter
__author__ = "Sherlock"

from .core import BrowserClient, AsyncBrowserClient, AsyncBrowserPool, fetch_all, HeaderBuilder, AsyncRustTLSProxyClient
from .profiles import (
    BrowserProfile,
    TlsConfig,
    H2Settings,
    HeaderProfile,
    BehaviorProfile,
    Chrome119,
    Chrome120,
    Firefox120,
    Safari17,
    Edge142
)
from .fingerprint import (
    TlsBuilder,
    ProfileValidator,
    JA3Generator,
    JA4Generator,
    FingerprintAnalyzer,
)
# TODO: 新增TLS指纹库转换器
from .tls_db_converter import (
    TlsDbConverter,
    FingerprintFilter,
    load_random_chrome_profile,
    load_random_firefox_profile,
    load_profile_by_hash,
)

__all__ = [
    # Client
    "BrowserClient",
    "AsyncBrowserClient",
    "AsyncBrowserPool",
    "fetch_all",
    "HeaderBuilder",
    "AsyncRustTLSProxyClient",

    # Profiles
    "BrowserProfile",
    "TlsConfig",
    "H2Settings",
    "HeaderProfile",
    "BehaviorProfile",

    # Presets
    "Chrome119",
    "Chrome120",
    "Firefox120",
    "Safari17",
    "Edge142",

    # Fingerprint tools
    "TlsBuilder",
    "ProfileValidator",
    "JA3Generator",
    "JA4Generator",
    "FingerprintAnalyzer",

    # TODO: TLS数据库转换器
    "TlsDbConverter",
    "FingerprintFilter",
    "load_random_chrome_profile",
    "load_random_firefox_profile",
    "load_profile_by_hash",
]