"""
Browser profile data models
"""
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import json
import yaml


@dataclass
class TlsConfig:
    """TLS configuration for fingerprint control"""
    min_version: str = "1.2"
    max_version: str = "1.3"
    cipher_suites: List[str] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    curves: List[str] = field(default_factory=list)
    signature_algorithms: List[str] = field(default_factory=list)
    alpn_protocols: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TlsConfig':
        return cls(**data)


@dataclass
class H2Settings:
    """HTTP/2 settings configuration"""
    header_table_size: int = 65536
    enable_push: bool = False
    max_concurrent_streams: int = 1000
    initial_window_size: int = 6291456
    max_frame_size: int = 16777215
    max_header_list_size: Optional[int] = 262144

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'H2Settings':
        return cls(**data)


@dataclass
class HeaderProfile:
    """HTTP headers configuration"""
    accept: str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    accept_encoding: str = "gzip, deflate, br, zstd"
    accept_language: str = "en-US,en;q=0.9"
    cache_control: Optional[str] = None
    sec_ch_ua: Optional[str] = None
    sec_ch_ua_mobile: Optional[str] = None
    sec_ch_ua_platform: Optional[str] = None
    sec_fetch_dest: Optional[str] = None
    sec_fetch_mode: Optional[str] = None
    sec_fetch_site: Optional[str] = None
    sec_fetch_user: Optional[str] = None
    upgrade_insecure_requests: Optional[str] = None

    # Header order (critical for detection evasion)
    order: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HeaderProfile':
        return cls(**data)


@dataclass
class BehaviorProfile:
    """Request behavior configuration"""
    connection_timeout: int = 30
    read_timeout: int = 30
    max_connections_per_host: int = 6
    tcp_nodelay: bool = True
    tcp_keepalive: Optional[int] = 60
    gzip: bool = True
    brotli: bool = True
    deflate: bool = True
    follow_redirects: bool = True
    max_redirects: int = 10

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehaviorProfile':
        return cls(**data)


@dataclass
class BrowserProfile:
    """Complete browser fingerprint profile"""
    name: str
    user_agent: str
    tls_config: TlsConfig
    h2_settings: H2Settings
    headers: HeaderProfile
    behavior: BehaviorProfile
    ja3_fingerprint: Optional[str] = None
    ja4_fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary"""
        return {
            'name': self.name,
            'user_agent': self.user_agent,
            'tls_config': self.tls_config.to_dict(),
            'h2_settings': self.h2_settings.to_dict(),
            'headers': self.headers.to_dict(),
            'behavior': self.behavior.to_dict(),
            'ja3_fingerprint': self.ja3_fingerprint,
            'ja4_fingerprint': self.ja4_fingerprint
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BrowserProfile':
        """Create profile from dictionary"""
        return cls(
            name=data['name'],
            user_agent=data['user_agent'],
            tls_config=TlsConfig.from_dict(data['tls_config']),
            h2_settings=H2Settings.from_dict(data['h2_settings']),
            headers=HeaderProfile.from_dict(data['headers']),
            behavior=BehaviorProfile.from_dict(data['behavior']),
            ja3_fingerprint=data.get('ja3_fingerprint'),
            ja4_fingerprint=data.get('ja4_fingerprint')
        )

    def to_json(self, filepath: str) -> None:
        """Save profile to JSON file"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, filepath: str) -> 'BrowserProfile':
        """Load profile from JSON file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)

    def to_yaml(self, filepath: str) -> None:
        """Save profile to YAML file"""
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, allow_unicode=True)

    @classmethod
    def from_yaml(cls, filepath: str) -> 'BrowserProfile':
        """Load profile from YAML file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    def clone(self) -> 'BrowserProfile':
        """Create a deep copy of the profile"""
        return BrowserProfile.from_dict(self.to_dict())