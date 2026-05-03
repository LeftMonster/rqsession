"""
rqsession — Browser TLS fingerprint impersonation library.

Primary API (Rust-powered, BoringSSL):
    from rqsession import BrowserSession, AsyncBrowserSession
    from rqsession import Chrome120, Firefox133, Safari17, Edge142, Chrome119

Legacy API (pure Python):
    from rqsession import RequestSession, EnhancedRequestSession
"""

__version__ = "0.3.2"
__author__ = "Sherlock"
__email__ = "zhzhsgg@gmail.com"

# ── Primary: Rust-powered browser-impersonating sessions ─────────────────────
from .rust_session import (
    BrowserSession,
    AsyncBrowserSession,
    Chrome120,
    Chrome119,
    Edge142,
    Firefox133,
    Safari17,
    BrowserSession,
    AsyncBrowserSession,
    AndroidChrome114,
    MacosChrome140,
    Chrome138,
    Edge141,
    Edge147,
    Tor128,
    Firefox146,
    Py37Aiohttp381
)

# ── Legacy layers (backward compatibility) ───────────────────────────────────
from .request_session import RequestSession
from .enhanced_request_session import EnhancedRequestSession
from .config_util import get_config_ini

RqSession = EnhancedRequestSession

__all__ = [
    # Primary
    "BrowserSession",
    "AsyncBrowserSession",
    "Chrome120",
    "Chrome119",
    "Edge142",
    "Firefox133",
    "Safari17",
    "BrowserSession",
    "AsyncBrowserSession",
    "AndroidChrome114",
    "MacosChrome140",
    "Chrome138",
    "Edge141",
    "Edge147",
    "Tor128",
    "Firefox146",
    "Py37Aiohttp38",
    # Legacy
    "RequestSession",
    "EnhancedRequestSession",
    "RqSession",
]