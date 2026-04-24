"""
Browser profiles package
"""
from .models import (
    BrowserProfile,
    TlsConfig,
    H2Settings,
    HeaderProfile,
    BehaviorProfile,
)
from .presets import (
    Chrome119,
    Chrome120,
    Firefox120,
    Safari17,
    Edge142,
    TorGecko128
)

__all__ = [
    "BrowserProfile",
    "TlsConfig",
    "H2Settings",
    "HeaderProfile",
    "BehaviorProfile",
    "Chrome119",
    "Chrome120",
    "Firefox120",
    "Safari17",
    "Edge142",
    "TorGecko128",
]
