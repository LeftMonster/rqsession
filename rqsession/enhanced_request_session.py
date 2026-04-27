# enhanced_request_session.py
import logging
from copy import copy

import requests
import random
import time
import json
import uuid
import os
from urllib.parse import urlparse
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass
from http.cookiejar import Cookie

_logger = logging.getLogger(__name__)

@dataclass
class BrowserFingerprint:
    """浏览器指纹信息"""
    profile_name: str
    ja3_fingerprint: str
    ja3_hash: str
    ja4_fingerprint: Optional[str]
    user_agent: str


@dataclass
class RequestTiming:
    """请求时序信息"""
    total_duration_ms: int
    tls_handshake_ms: Optional[int] = None
    dns_lookup_ms: Optional[int] = None


class EnhancedRequestSession(requests.Session):
    """增强版RequestSession，支持高级TLS指纹伪造和反检测"""

    # 预定义的浏览器配置
    BROWSER_PROFILES = {
        "chrome_119_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "sec_ch_ua": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            "sec_ch_ua_platform": '"Windows"',
        },
        "chrome_119_macos": {
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "sec_ch_ua": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            "sec_ch_ua_platform": '"macOS"',
        },
        "firefox_118_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.5",
            "sec_ch_ua": None,  # Firefox没有这些头
            "sec_ch_ua_platform": None,
        },
        "safari_17_macos": {
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.9",
            "sec_ch_ua": None,  # Safari没有这些头
            "sec_ch_ua_platform": None,
        },
        # ================= Chrome系列 =================

        "chrome_120_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "chrome_120_macos": {
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec_ch_ua_platform": '"macOS"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "chrome_118_linux": {
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
            "sec_ch_ua_platform": '"Linux"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        # ================= Firefox系列 =================

        "firefox_120_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.5",
            "accept_encoding": "gzip, deflate, br",
            "sec_ch_ua": None,  # Firefox没有这些头
            "sec_ch_ua_platform": None,
            "sec_ch_ua_mobile": None,
            "cache_control": None,
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "firefox_120_macos": {
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.5",
            "accept_encoding": "gzip, deflate, br",
            "sec_ch_ua": None,
            "sec_ch_ua_platform": None,
            "sec_ch_ua_mobile": None,
            "cache_control": None,
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "firefox_115_linux": {
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.5",
            "accept_encoding": "gzip, deflate, br",
            "sec_ch_ua": None,
            "sec_ch_ua_platform": None,
            "sec_ch_ua_mobile": None,
            "cache_control": None,
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        # ================= Safari系列 =================

        "safari_17_1_macos": {
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br",
            "sec_ch_ua": None,  # Safari没有这些头
            "sec_ch_ua_platform": None,
            "sec_ch_ua_mobile": None,
            "cache_control": "max-age=0",
            # "dnt": None,
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": None,
            "sec_fetch_mode": None,
            "sec_fetch_site": None,
            "sec_fetch_user": None,
        },

        "safari_16_6_macos": {
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br",
            "sec_ch_ua": None,
            "sec_ch_ua_platform": None,
            "sec_ch_ua_mobile": None,
            "cache_control": "max-age=0",
            # "dnt": None,
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": None,
            "sec_fetch_mode": None,
            "sec_fetch_site": None,
            "sec_fetch_user": None,
        },

        # ================= Edge系列 =================

        "edge_120_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        # ================= 移动端浏览器 =================

        "chrome_mobile_android": {
            "user_agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec_ch_ua_platform": '"Android"',
            "sec_ch_ua_mobile": "?1",  # 移动端
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "safari_mobile_ios": {
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br",
            "sec_ch_ua": None,  # iOS Safari没有这些头
            "sec_ch_ua_platform": None,
            "sec_ch_ua_mobile": None,
            "cache_control": "max-age=0",
            # "dnt": None,
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": None,
            "sec_fetch_mode": None,
            "sec_fetch_site": None,
            "sec_fetch_user": None,
        },

        # ================= 特殊版本/定制浏览器 =================

        "brave_120_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Brave隐藏身份
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Brave";v="120"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",  # Brave默认启用DNT
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "opera_105_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Opera";v="105", "Chromium";v="119", "Not?A_Brand";v="24"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        # ================= 地区/语言变体 =================

        "chrome_120_windows_de": {  # 德语版Chrome
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "de-DE,de;q=0.9,en;q=0.8",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "chrome_120_windows_fr": {  # 法语版Chrome
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "fr-FR,fr;q=0.9,en;q=0.8",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "chrome_120_windows_zh": {  # 中文版Chrome
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        # ================= 旧版本浏览器 =================

        "chrome_110_windows": {  # 较旧版本Chrome
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br",
            "sec_ch_ua": '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "firefox_102_windows": {  # 较旧版本Firefox
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.5",
            "accept_encoding": "gzip, deflate, br",
            "sec_ch_ua": None,
            "sec_ch_ua_platform": None,
            "sec_ch_ua_mobile": None,
            "cache_control": None,
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },

        "chrome_138_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="136", "Google Chrome";v="136"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
            # "dnt": "1",
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },
    }

    def __init__(self,
                 browser_profile: str = "chrome_119_windows",
                 rust_backend_url: str = "https://rust-tls-proxy-wqkdfmbbdv.cn-hongkong.fcapp.run",
                 # rust_backend_url: str = "http://127.0.0.1:5005",
                 enable_tls_fingerprinting: bool = True,
                 enable_timing_simulation: bool = True,
                 enable_header_randomization: bool = True,
                 proxy_config: Optional[Dict] = None,
                 **kwargs):
        """
        初始化增强版RequestSession

        Args:
            browser_profile: 浏览器配置名称
            rust_backend_url: Rust后端服务地址
            enable_tls_fingerprinting: 启用TLS指纹伪造
            enable_timing_simulation: 启用时序模拟
            enable_header_randomization: 启用请求头随机化
            proxy_config: 代理配置
        """
        super().__init__()

        # 基础配置
        self._id = str(uuid.uuid4()).replace("-", "")
        self.browser_profile = browser_profile
        self.rust_backend_url = rust_backend_url.rstrip('/')

        # 功能开关
        self.enable_tls_fingerprinting = enable_tls_fingerprinting
        self.enable_timing_simulation = enable_timing_simulation
        self.enable_header_randomization = enable_header_randomization
        self.enable_advanced_evasion = True

        # 代理配置
        self.proxy_config = proxy_config or {}

        # 请求历史和指纹信息
        self.request_history: List[Dict] = []
        self.fingerprint_history: List[BrowserFingerprint] = []
        self.max_history_size = 100

        # 反检测配置
        self.randomization_config = {
            "tls_randomization": True,
            "header_order_randomization": True,
            "timing_jitter": True,
            "connection_pooling": True,
        }

        # 初始化浏览器特征
        self._initialize_browser_profile()

        _logger.info(f"Enhanced RequestSession initialized with profile: {browser_profile}")

    def _initialize_browser_profile(self):
        """初始化浏览器配置"""
        if self.browser_profile not in self.BROWSER_PROFILES:
            _logger.warning(f"Unknown browser profile: {self.browser_profile}, using default")
            self.browser_profile = "chrome_119_windows"

        profile = self.BROWSER_PROFILES[self.browser_profile]

        # 设置基础头部
        base_headers = {
            "User-Agent": profile["user_agent"],
            "Accept": profile["accept"],
            "Accept-Language": profile["accept_language"],
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

        # 添加浏览器特定头部
        if profile.get("sec_ch_ua"):
            base_headers["Sec-CH-UA"] = profile["sec_ch_ua"]
            base_headers["Sec-CH-UA-Mobile"] = "?0"
            base_headers["Sec-CH-UA-Platform"] = profile["sec_ch_ua_platform"]

        self.headers.update(base_headers)

    def set_browser_profile(self, profile_name: str):
        """设置浏览器配置"""
        old_profile = self.browser_profile
        self.browser_profile = profile_name
        self._initialize_browser_profile()
        _logger.info(f"Browser profile changed from {old_profile} to {profile_name}")

    def enable_advanced_evasion_techniques(self, enabled: bool = True):
        """启用高级反检测技术"""
        self.enable_advanced_evasion = enabled
        if enabled:
            self.randomization_config.update({
                "tls_randomization": True,
                "header_order_randomization": True,
                "timing_jitter": True,
                "connection_pooling": True,
                "user_agent_rotation": False,  # 保持一致性
            })
        _logger.info(f"Advanced evasion techniques {'enabled' if enabled else 'disabled'}")

    def set_proxy_config(self, proxy_config: Dict):
        """设置代理配置"""
        self.proxy_config = proxy_config
        _logger.info(f"Proxy configuration updated")

    def _prepare_advanced_request(self, request, **kwargs):
        """准备高级请求参数"""
        # 构建请求数据
        request_data = {
            "url": request.url,
            "method": request.method,
            "headers": list(request.headers.items()) if request.headers else [],
            "body": None,
            "browser_profile": self.browser_profile,
            "randomize_tls": self.randomization_config.get("tls_randomization", True),
            "add_timing_delay": self.enable_timing_simulation,
        }

        # 处理请求体
        if request.body:
            if isinstance(request.body, bytes):
                try:
                    request_data["body"] = request.body.decode('utf-8')
                except UnicodeDecodeError:
                    # 对于二进制数据，使用base64编码
                    import base64
                    request_data["body"] = base64.b64encode(request.body).decode('ascii')
                    request_data["body_encoding"] = "base64"
            else:
                request_data["body"] = str(request.body)

        # 添加代理配置
        if self.proxy_config:
            if "url" in self.proxy_config:
                request_data["proxy"] = self.proxy_config["url"]
            elif "http" in self.proxy_config:
                request_data["proxy"] = self.proxy_config["http"]

        return request_data

    def _enhance_headers_for_request(self, request, url_obj):
        """为请求增强头部信息"""
        if not self.enable_header_randomization:
            return

        # 动态设置Referer
        if "Referer" not in request.headers:
            # 模拟真实浏览器行为，有时不设置Referer
            if random.random() < 0.8:  # 80%概率设置Referer
                request.headers["Referer"] = f"{url_obj.scheme}://{url_obj.netloc}/"

        # 动态设置Cache-Control
        if request.method == "GET" and "Cache-Control" not in request.headers:
            cache_controls = ["no-cache", "max-age=0", None]
            cache_control = random.choice(cache_controls)
            if cache_control:
                request.headers["Cache-Control"] = cache_control

        # 为POST请求添加Origin
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            if "Origin" not in request.headers:
                request.headers["Origin"] = f"{url_obj.scheme}://{url_obj.netloc}"

        # 添加随机化的DNT头
        # if "DNT" not in request.headers and random.random() < 0.6:
        #     request.headers["DNT"] = "1"

    def send(self, request, **kwargs):
        """重写send方法，使用增强的Rust后端"""
        if not self.enable_tls_fingerprinting:
            # 如果未启用TLS指纹伪造，使用标准方式
            return self._send_standard(request, **kwargs)

        return self._send_advanced(request, **kwargs)

    def _send_standard(self, request, **kwargs):
        """标准发送方式（原有逻辑）"""
        try:
            url_obj = urlparse(request.url)
            self._enhance_headers_for_request(request, url_obj)

            # 代理处理
            if self.proxy_config and "proxies" not in kwargs:
                proxies = {}
                if "http" in self.proxy_config:
                    proxies["http"] = self.proxy_config["http"]
                if "https" in self.proxy_config:
                    proxies["https"] = self.proxy_config["https"]
                if proxies:
                    kwargs["proxies"] = proxies

            start_time = time.time()
            response = super().send(request, **kwargs)
            duration = time.time() - start_time

            # 记录请求
            self._record_request(request, response, duration * 1000)

            return response

        except Exception as e:
            _logger.error(f"Standard request failed: {e}")
            raise

    def _send_advanced(self, request, **kwargs):
        """高级发送方式（通过Rust后端）"""
        try:
            url_obj = urlparse(request.url)
            self._enhance_headers_for_request(request, url_obj)

            # 准备请求数据
            request_data = self._prepare_advanced_request(request, **kwargs)

            # 发送到Rust后端
            start_time = time.time()

            # 修复：检查Rust后端是否可用
            # 因为性能效率原因、暂时停用heartbeat
            # try:
            #     health_check = requests.get(
            #         f"{self.rust_backend_url}/health",
            #         timeout=5
            #     )
            #     if health_check.status_code != 200:
            #         raise requests.exceptions.RequestException("Rust backend health check failed")
            # except requests.exceptions.RequestException as e:
            #     _logger.warning(f"Rust backend not available: {e}")
            #     _logger.info("Falling back to standard request method")
            #     return self._send_standard(request, **kwargs)

            backend_response = requests.post(
                f"{self.rust_backend_url}/advanced_fetch",
                json=request_data,
                timeout=60
            )
            backend_response.raise_for_status()

            result = backend_response.json()

            # 检查是否有错误
            if "error" in result:
                _logger.error(f"Rust backend error: {result['error']}")
                _logger.info("Falling back to standard request method")
                return self._send_standard(request, **kwargs)

            total_duration = time.time() - start_time

            # 构造Response对象
            response = self._create_response_from_result(result, request.url)

            # 记录指纹和请求信息
            self._record_fingerprint_info(result.get("fingerprint_info"))
            self._record_request(request, response, total_duration * 1000, result.get("timing"))

            return response

        except requests.exceptions.RequestException as e:
            _logger.error(f"Rust backend request failed: {e}")
            # 降级到标准方式
            _logger.info("Falling back to standard request method")
            return self._send_standard(request, **kwargs)
        except Exception as e:
            _logger.error(f"Advanced request failed: {e}")
            # 如果完全失败，尝试标准方式
            _logger.info("Falling back to standard request method")
            return self._send_standard(request, **kwargs)

    def _create_response_from_result(self, result: Dict, original_url: str):
        """从Rust后端结果创建Response对象"""
        response = requests.Response()
        response.status_code = result["status"]
        response._content = bytes(result["body"])

        # 修复：正确处理头部，特别是Set-Cookie
        response.headers = requests.structures.CaseInsensitiveDict()

        for key, value in result["headers"]:
            # 处理Set-Cookie头部可能有多个的情况
            if key.lower() == 'set-cookie':
                if key in response.headers:
                    # 如果已经存在Set-Cookie，将其转换为列表
                    existing = response.headers[key]
                    if isinstance(existing, list):
                        existing.append(value)
                    else:
                        response.headers[key] = [existing, value]
                else:
                    response.headers[key] = value
            else:
                response.headers[key] = value

        response.url = original_url
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)

        # 设置cookies
        if hasattr(response, '_cookies'):
            response._cookies = requests.cookies.extract_cookies_to_jar(
                response._cookies,
                requests.Request('GET', original_url),
                response.raw
            )
        cks = self._safe_extract_cookies(response, response.cookies)
        self.cookies.update(cks)

        return response

    def _prepare_advanced_request(self, request, **kwargs):
        """准备高级请求参数"""
        # 构建请求数据
        request_data = {
            "url": request.url,
            "method": request.method,
            "headers": list(request.headers.items()) if request.headers else [],
            "body": None,
            "browser_profile": self.browser_profile,
            "randomize_tls": self.randomization_config.get("tls_randomization", True),
            "add_timing_delay": self.enable_timing_simulation,
        }

        # 处理请求体
        if request.body:
            if isinstance(request.body, bytes):
                try:
                    request_data["body"] = request.body.decode('utf-8')
                except UnicodeDecodeError:
                    # 对于二进制数据，使用base64编码
                    import base64
                    request_data["body"] = base64.b64encode(request.body).decode('ascii')
                    request_data["body_encoding"] = "base64"
            else:
                request_data["body"] = str(request.body)

        # 修复：代理配置处理
        proxy_url = None

        # 首先检查kwargs中的代理
        if "proxies" in kwargs and kwargs["proxies"]:
            proxies = kwargs["proxies"]
            if isinstance(proxies, dict):
                # 根据URL scheme选择代理
                url_obj = urlparse(request.url)
                scheme = url_obj.scheme.lower()

                if scheme in proxies:
                    proxy_url = proxies[scheme]
                elif "https" in proxies and scheme == "https":
                    proxy_url = proxies["https"]
                elif "http" in proxies:
                    proxy_url = proxies["http"]

        # 然后检查实例的代理配置
        if not proxy_url and self.proxy_config:
            if "url" in self.proxy_config:
                proxy_url = self.proxy_config["url"]
            elif "http" in self.proxy_config:
                proxy_url = self.proxy_config["http"]
            elif "https" in self.proxy_config:
                proxy_url = self.proxy_config["https"]

        # 检查并防止循环代理
        if proxy_url:
            if "127.0.0.1:5005" in proxy_url or "localhost:5005" in proxy_url:
                _logger.warning("Detected proxy loop configuration, ignoring proxy")
                proxy_url = None
            else:
                request_data["proxy"] = proxy_url

        return request_data

    def _create_response_from_result(self, result: Dict, original_url: str):
        """从Rust后端结果创建Response对象"""
        response = requests.Response()
        response.status_code = result["status"]
        response._content = bytes(result["body"])

        # 正确设置头部，包括多个 Set-Cookie
        for key, value in result["headers"]:
            # 使用 requests 的方式添加头部，支持多个同名头部
            if key.lower() == 'set-cookie':
                # 对于 Set-Cookie，需要特别处理
                if 'Set-Cookie' not in response.headers:
                    response.headers['Set-Cookie'] = value
                else:
                    # 如果已存在，合并或创建列表
                    existing = response.headers.get('Set-Cookie')
                    if isinstance(existing, list):
                        existing.append(value)
                    else:
                        response.headers['Set-Cookie'] = [existing, value]
            else:
                response.headers[key] = value

        response.url = original_url
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)

        return response

    def _record_fingerprint_info(self, fingerprint_info: Optional[Dict]):
        """记录指纹信息"""
        if not fingerprint_info:
            return

        fingerprint = BrowserFingerprint(
            profile_name=fingerprint_info.get("browser_profile", "unknown"),
            ja3_fingerprint=fingerprint_info.get("ja3_fingerprint", ""),
            ja3_hash=fingerprint_info.get("ja3_hash", ""),
            ja4_fingerprint=fingerprint_info.get("ja4_fingerprint"),
            user_agent=fingerprint_info.get("user_agent", "")
        )

        self.fingerprint_history.append(fingerprint)

        # 限制历史记录大小
        if len(self.fingerprint_history) > self.max_history_size:
            self.fingerprint_history.pop(0)

    def _record_request(self, request, response, duration_ms: float, timing_info: Optional[Dict] = None):
        """记录请求信息"""
        parsed_url = urlparse(request.url)

        request_record = {
            "timestamp": time.time(),
            "method": request.method,
            "url": request.url,
            "path": parsed_url.path,
            "status_code": response.status_code,
            "response_url": response.url,
            "duration_ms": round(duration_ms, 3),
            "browser_profile": self.browser_profile,
            "tls_fingerprinting_enabled": self.enable_tls_fingerprinting,
            "request_headers": dict(request.headers),
            "response_headers": dict(response.headers),
        }

        # 添加时序信息
        if timing_info:
            request_record["timing"] = timing_info

        # 添加响应内容（如果启用）
        try:
            content_type = response.headers.get('content-type', '').lower()
            if 'json' in content_type:
                request_record["response_preview"] = response.text[:500]
            elif 'text' in content_type and len(response.text) < 1000:
                request_record["response_preview"] = response.text
        except Exception:
            pass

        self.request_history.append(request_record)

        # 限制历史记录大小
        if len(self.request_history) > self.max_history_size:
            self.request_history.pop(0)

        _logger.info(
            f"Request recorded: {request.method} {parsed_url.path} -> {response.status_code} ({duration_ms:.1f}ms)")

    def get_fingerprint_info(self) -> Optional[BrowserFingerprint]:
        """获取最新的指纹信息"""
        return self.fingerprint_history[-1] if self.fingerprint_history else None

    def get_fingerprint_consistency(self) -> Dict[str, Any]:
        """检查指纹一致性"""
        if not self.fingerprint_history:
            return {"status": "no_data", "message": "No fingerprint data available"}

        # 检查JA3哈希一致性
        ja3_hashes = [fp.ja3_hash for fp in self.fingerprint_history if fp.ja3_hash]
        unique_hashes = set(ja3_hashes)

        consistency_score = 1.0 if len(unique_hashes) <= 1 else len(unique_hashes) / len(ja3_hashes)

        return {
            "status": "consistent" if consistency_score > 0.9 else "inconsistent",
            "consistency_score": consistency_score,
            "total_requests": len(self.fingerprint_history),
            "unique_ja3_hashes": len(unique_hashes),
            "current_profile": self.browser_profile,
            "latest_ja3_hash": ja3_hashes[-1] if ja3_hashes else None,
        }

    def test_fingerprint_detection(self, test_urls: Optional[List[str]] = None) -> Dict[str, Any]:
        """测试指纹检测结果"""
        if test_urls is None:
            test_urls = [
                "https://tls.peet.ws/api/all",
                "https://www.nflshop.com/new-england-patriots/jerseys/t-25379296+d-2315662346+z-8-3918252576",
                # "https://www.howsmyssl.com/a/check",
            ]

        results = {}

        for url in test_urls:
            try:
                _logger.info(f"Testing fingerprint detection on {url}")
                response = self.get(url, timeout=30)

                if response.status_code == 200:
                    try:
                        data = response.json()
                        results[url] = {
                            "status": "success",
                            "data": data,
                            "detected_profile": data.get("user_agent", "unknown")
                        }
                    except ValueError:
                        results[url] = {
                            "status": "success_no_json",
                            "content_length": len(response.content),
                            "content_type": response.headers.get("content-type")
                        }
                else:
                    results[url] = {
                        "status": "http_error",
                        "status_code": response.status_code
                    }

            except Exception as e:
                results[url] = {
                    "status": "error",
                    "error": str(e)
                }
                _logger.error(f"Error testing {url}: {e}")

        return results

    def rotate_browser_profile(self):
        """随机轮换浏览器配置"""
        available_profiles = list(self.BROWSER_PROFILES.keys())
        current_idx = available_profiles.index(self.browser_profile)

        # 选择不同的配置
        new_profiles = [p for p in available_profiles if p != self.browser_profile]
        if new_profiles:
            new_profile = random.choice(new_profiles)
            self.set_browser_profile(new_profile)
            _logger.info(f"Browser profile rotated to: {new_profile}")

    def export_session_data(self, filepath: Optional[str] = None) -> str:
        """导出会话数据"""
        if not filepath:
            filepath = f"enhanced_session_{self._id}.json"

        session_data = {
            "session_id": self._id,
            "browser_profile": self.browser_profile,
            "configuration": {
                "enable_tls_fingerprinting": self.enable_tls_fingerprinting,
                "enable_timing_simulation": self.enable_timing_simulation,
                "enable_header_randomization": self.enable_header_randomization,
                "randomization_config": self.randomization_config,
                "proxy_config": self.proxy_config,
            },
            "headers": dict(self.headers),
            "cookies": self._export_cookies(),
            "request_history": self.request_history[-50:],  # 最近50个请求
            "fingerprint_history": [
                {
                    "profile_name": fp.profile_name,
                    "ja3_hash": fp.ja3_hash,
                    "ja4_fingerprint": fp.ja4_fingerprint,
                    "user_agent": fp.user_agent,
                } for fp in self.fingerprint_history[-20:]  # 最近20个指纹
            ],
            "fingerprint_consistency": self.get_fingerprint_consistency(),
            "export_time": time.time(),
        }

        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, ensure_ascii=False, indent=2)

        _logger.info(f"Session data exported to: {filepath}")
        return filepath

    def _export_cookies(self) -> List[Dict]:
        """导出Cookie数据"""
        cookies_data = []
        for cookie in self.cookies:
            cookie_data = {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "expires": cookie.expires,
                "httponly": cookie.has_nonstandard_attr('httponly'),
            }
            cookies_data.append(cookie_data)
        return cookies_data

    @classmethod
    def load_session_data(cls, filepath: str) -> 'EnhancedRequestSession':
        """从文件加载会话数据"""
        with open(filepath, 'r', encoding='utf-8') as f:
            session_data = json.load(f)

        # 创建新会话
        config = session_data.get("configuration", {})
        session = cls(
            browser_profile=session_data.get("browser_profile", "chrome_119_windows"),
            enable_tls_fingerprinting=config.get("enable_tls_fingerprinting", True),
            enable_timing_simulation=config.get("enable_timing_simulation", True),
            enable_header_randomization=config.get("enable_header_randomization", True),
            proxy_config=config.get("proxy_config", {}),
        )

        # 恢复配置
        session._id = session_data.get("session_id", session._id)
        session.randomization_config = config.get("randomization_config", session.randomization_config)

        # 恢复头部
        if "headers" in session_data:
            session.headers.update(session_data["headers"])

        # 恢复Cookie
        if "cookies" in session_data:
            for cookie_data in session_data["cookies"]:
                cookie = Cookie(
                    version=0,
                    name=cookie_data["name"],
                    value=cookie_data["value"],
                    port=None,
                    port_specified=False,
                    domain=cookie_data["domain"],
                    domain_specified=bool(cookie_data["domain"]),
                    domain_initial_dot=cookie_data["domain"].startswith('.'),
                    path=cookie_data["path"],
                    path_specified=bool(cookie_data["path"]),
                    secure=cookie_data.get("secure", False),
                    expires=cookie_data.get("expires"),
                    discard=False,
                    comment=None,
                    comment_url=None,
                    rest={'HttpOnly': cookie_data.get("httponly", False)},
                    rfc2109=False
                )
                session.cookies.set_cookie(cookie)

        _logger.info(f"Session data loaded from: {filepath}")
        return session

    def _safe_extract_cookies(self, response, cks_dict):
        """
        安全地提取cookies，避免解析错误
        将响应获得的完整的cookie数据对当前对象写入
        """
        try:
            # 方法1: 从response.cookies提取（推荐）
            if hasattr(response, 'cookies') and response.cookies:
                for cookie in response.cookies:
                    cks_dict[cookie.name] = cookie.value
                    # print(f"Cookie extracted: {cookie.name} = {cookie.value[:50]}...")

            # 方法2: 从headers提取Set-Cookie（备用）
            set_cookie_headers = response.headers.get('Set-Cookie', [])
            if isinstance(set_cookie_headers, str):
                set_cookie_headers = [set_cookie_headers]
            elif set_cookie_headers is None:
                set_cookie_headers = []

            for cookie_header in set_cookie_headers:
                if isinstance(cookie_header, str) and '=' in cookie_header:
                    # 正确的cookie解析：只在第一个=处分割
                    parts = cookie_header.split(';')[0]  # 只取cookie值部分，忽略属性
                    if '=' in parts:
                        name, value = parts.split('=', 1)  # 只分割一次
                        name = name.strip()
                        value = value.strip()
                        if name and name not in cks_dict:  # 避免重复
                            cks_dict[name] = value
                            # print(f"Set-Cookie extracted: {name} = {value[:50]}...")

        except Exception as e:
            print(f"Cookie extraction error: {e}")
            # 如果cookie提取失败，不要中断程序

        return cks_dict
