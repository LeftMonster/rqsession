"""
Core HTTP client based on curl_cffi

使用curl_cffi实现自定义TLS指纹的HTTP客户端。
支持通过ja3字符串和extra_fp参数完全自定义TLS指纹。
"""
from typing import Optional, Dict, Any, Union, List
from urllib.parse import urlparse

try:
    from curl_cffi import requests
    from curl_cffi.requests import Session, Response
except ImportError:
    raise ImportError(
        "curl_cffi is required. Install it with: pip install curl_cffi"
    )

from ..profiles.models import BrowserProfile
from ..fingerprint.tls_builder import TlsBuilder, ProfileValidator
from .header_builder import HeaderBuilder


class BrowserClient:
    """
    Advanced HTTP client with browser fingerprint simulation

    使用curl_cffi的ja3/akamai/extra_fp参数实现自定义指纹。
    """

    # TODO: 支持的curl_cffi impersonate值列表，用于fallback
    SUPPORTED_IMPERSONATE = [
        "chrome99", "chrome100", "chrome101", "chrome104", "chrome107",
        "chrome110", "chrome116", "chrome119", "chrome120", "chrome123",
        "chrome124", "chrome126", "chrome127", "chrome128", "chrome129",
        "chrome131", "chrome133",
        "safari15_3", "safari15_5", "safari17_0", "safari17_2_ios",
        "safari18_0", "safari18_0_ios",
        "firefox109", "firefox117", "firefox120", "firefox133",
        "edge99", "edge101",
    ]

    def __init__(
            self,
            profile: BrowserProfile,
            proxy: Optional[str] = None,
            randomize_tls: bool = False,
            impersonate: Optional[str] = None,
            verify: bool = True,
            timeout: Optional[int] = None,
            use_ja3: bool = True,  # TODO: 新增参数，是否使用ja3指纹模式
    ):
        """
        Initialize browser client

        Args:
            profile: Browser profile to use
            proxy: Proxy URL (e.g., "http://user:pass@host:port")
            randomize_tls: Whether to randomize TLS parameters
            impersonate: Use curl_cffi's built-in browser impersonation
                        (e.g., "chrome119", "firefox120")
                        如果指定，将忽略profile中的TLS配置
            verify: Verify SSL certificates
            timeout: Request timeout in seconds
            use_ja3: 是否使用ja3字符串模式（推荐True）
                    如果为False且没有impersonate，将使用默认TLS配置
        """
        self.profile = profile
        self.proxy = proxy
        self.randomize_tls = randomize_tls
        self.impersonate = impersonate
        self.verify = verify
        self.timeout = timeout or profile.behavior.connection_timeout
        self.use_ja3 = use_ja3

        # Validate profile
        is_valid, errors = ProfileValidator.validate_profile(profile)
        if not is_valid:
            raise ValueError(f"Invalid profile: {', '.join(errors)}")

        # Randomize TLS if requested
        if randomize_tls:
            self.profile.tls_config = TlsBuilder.randomize_tls_config(
                self.profile.tls_config
            )

        # 构建ja3和extra_fp参数
        self._ja3_string: Optional[str] = None
        self._akamai_string: Optional[str] = None
        self._extra_fp: Optional[Dict] = None
        self._ja3_has_tls13: bool = False  # TODO: 标记ja3是否包含TLS 1.3 ciphers

        if not self.impersonate and self.use_ja3:
            self._build_fingerprint_params()

        # Create session
        self._session = self._create_session()

    def _build_fingerprint_params(self) -> None:
        """
        从BrowserProfile构建curl_cffi需要的ja3/akamai/extra_fp参数

        TODO: 这是实现自定义指纹的核心方法

        注意: curl_cffi 的 ja3 自定义功能目前只支持 TLS 1.2!
              如果 ja3 包含 TLS 1.3 cipher suites (4865, 4866, 4867)，
              会触发 AssertionError，需要 fallback 到 impersonate 模式。
        """
        tls_config = self.profile.tls_config
        h2_settings = self.profile.h2_settings

        # 如果profile已经有ja3_fingerprint，直接使用
        if self.profile.ja3_fingerprint:
            ja3_candidate = self.profile.ja3_fingerprint
        else:
            # 从TLS配置生成ja3字符串
            ja3_candidate = self._generate_ja3_from_config(tls_config)

        # TODO: 检测 ja3 是否包含 TLS 1.3 cipher suites
        # curl_cffi 目前只支持 TLS 1.2 的自定义 ja3
        TLS13_CIPHERS = {"4865", "4866", "4867"}  # TLS 1.3 cipher suite IDs
        if ja3_candidate:
            # 解析 ja3 字符串中的 cipher suites 部分
            parts = ja3_candidate.split(",")
            if len(parts) >= 2:
                ciphers = set(parts[1].split("-"))
                if ciphers & TLS13_CIPHERS:
                    # 包含 TLS 1.3 ciphers，不能使用 ja3 模式
                    # 设置 fallback 标志
                    self._ja3_has_tls13 = True
                    self._ja3_string = None
                    self._akamai_string = None
                    self._extra_fp = None
                    return

        self._ja3_has_tls13 = False
        self._ja3_string = ja3_candidate

        # 构建akamai指纹 (HTTP/2 fingerprint)
        self._akamai_string = self._generate_akamai_from_h2(h2_settings)

        # 构建extra_fp (额外的TLS参数，ja3无法覆盖的部分)
        self._extra_fp = self._generate_extra_fp(tls_config)

    def _generate_ja3_from_config(self, tls_config) -> str:
        """
        从TlsConfig生成JA3字符串

        JA3格式: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

        TODO: 需要将cipher suite名称映射为数字ID
        """
        # TLS版本映射
        version_map = {
            "1.0": "769",
            "1.1": "770",
            "1.2": "771",
            "1.3": "772",
        }
        # TODO: 使用max_version作为协商版本，但record version通常是771
        tls_version = "771"  # TLS record version 通常是 771 (TLS 1.2)

        # Cipher suites -> 数字ID
        cipher_ids = self._cipher_names_to_ids(tls_config.cipher_suites)
        ciphers_str = "-".join(str(c) for c in cipher_ids)

        # Extensions -> 数字ID
        if tls_config.extensions:
            extensions_str = "-".join(str(e) for e in tls_config.extensions)
        else:
            # 默认Chrome-like extensions
            extensions_str = "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513"

        # Curves -> 数字ID
        curve_ids = self._curve_names_to_ids(tls_config.curves)
        curves_str = "-".join(str(c) for c in curve_ids)

        # EC Point Formats (通常是 0)
        ec_point_formats = "0"

        ja3 = f"{tls_version},{ciphers_str},{extensions_str},{curves_str},{ec_point_formats}"
        return ja3

    def _cipher_names_to_ids(self, cipher_names: List[str]) -> List[int]:
        """
        将cipher suite名称转换为数字ID

        TODO: 这个映射表需要更完整
        """
        # 常见cipher suite映射
        CIPHER_MAP = {
            # TLS 1.3 ciphers
            "TLS_AES_128_GCM_SHA256": 4865,
            "TLS_AES_256_GCM_SHA384": 4866,
            "TLS_CHACHA20_POLY1305_SHA256": 4867,
            # TLS 1.2 ciphers (ECDHE)
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 49195,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 49199,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 49196,
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 49200,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 52393,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 52392,
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 49171,
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 49172,
            # RSA ciphers
            "TLS_RSA_WITH_AES_128_GCM_SHA256": 156,
            "TLS_RSA_WITH_AES_256_GCM_SHA384": 157,
            "TLS_RSA_WITH_AES_128_CBC_SHA": 47,
            "TLS_RSA_WITH_AES_256_CBC_SHA": 53,
            # 兼容旧格式名称 (OpenSSL style)
            "ECDHE-ECDSA-AES128-GCM-SHA256": 49195,
            "ECDHE-RSA-AES128-GCM-SHA256": 49199,
            "ECDHE-ECDSA-AES256-GCM-SHA384": 49196,
            "ECDHE-RSA-AES256-GCM-SHA384": 49200,
            "ECDHE-ECDSA-CHACHA20-POLY1305": 52393,
            "ECDHE-RSA-CHACHA20-POLY1305": 52392,
            "ECDHE-RSA-AES128-SHA": 49171,
            "ECDHE-RSA-AES256-SHA": 49172,
            "AES128-GCM-SHA256": 156,
            "AES256-GCM-SHA384": 157,
            "AES128-SHA": 47,
            "AES256-SHA": 53,
        }

        ids = []
        for name in cipher_names:
            # 跳过GREASE值
            if "GREASE" in name:
                continue
            if name in CIPHER_MAP:
                ids.append(CIPHER_MAP[name])
            else:
                # TODO: 尝试从名称中提取ID（如果是数字格式）
                pass
        return ids

    def _curve_names_to_ids(self, curve_names: List[str]) -> List[int]:
        """将curve名称转换为数字ID"""
        CURVE_MAP = {
            "x25519": 29,
            "X25519": 29,
            "secp256r1": 23,
            "P-256": 23,
            "secp384r1": 24,
            "P-384": 24,
            "secp521r1": 25,
            "P-521": 25,
            "x448": 30,
            "X448": 30,
            "ffdhe2048": 256,
            "ffdhe3072": 257,
            "X25519MLKEM768": 4588,  # 新的混合密钥交换
        }

        ids = []
        for name in curve_names:
            if "GREASE" in name:
                continue
            if name in CURVE_MAP:
                ids.append(CURVE_MAP[name])
        return ids

    def _generate_akamai_from_h2(self, h2_settings) -> str:
        """
        生成Akamai HTTP/2指纹字符串

        格式: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
        例如: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
        """
        # SETTINGS frame
        settings_parts = []
        settings_parts.append(f"1:{h2_settings.header_table_size}")
        settings_parts.append(f"2:{1 if h2_settings.enable_push else 0}")
        settings_parts.append(f"4:{h2_settings.initial_window_size}")
        if h2_settings.max_header_list_size:
            settings_parts.append(f"6:{h2_settings.max_header_list_size}")
        settings_str = ";".join(settings_parts)

        # WINDOW_UPDATE (connection-level)
        # 通常是 initial_window_size * 某个倍数 - 1
        window_update = 15663105  # Chrome默认值

        # PRIORITY (deprecated in HTTP/2, usually 0)
        priority = 0

        # Pseudo header order: m=:method, a=:authority, s=:scheme, p=:path
        pseudo_order = "m,a,s,p"  # Chrome顺序

        return f"{settings_str}|{window_update}|{priority}|{pseudo_order}"

    def _generate_extra_fp(self, tls_config) -> Optional[Dict]:
        """
        生成extra_fp参数（JA3无法覆盖的TLS字段）

        TODO: extra_fp 只能包含 curl_cffi.ExtraFingerprints 支持的字段:
              - tls_signature_algorithms: List[str] (字符串名称，不是整数ID!)
              - tls_grease: bool (是否添加GREASE)
              - http2_stream_weight: int
              - http2_stream_exclusive: int

        注意: tls_signature_algorithms 需要的是字符串格式，如 "ecdsa_secp256r1_sha256"
        """
        # curl_cffi 支持的签名算法名称（字符串格式）
        VALID_SIGALGS = {
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "ed25519",
            "ed448",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pss_pss_sha256",
            "rsa_pss_pss_sha384",
            "rsa_pss_pss_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
            "ecdsa_sha1",
        }

        # 直接使用字符串名称，过滤掉无效的
        sig_algs = [alg for alg in tls_config.signature_algorithms if alg in VALID_SIGALGS]

        extra_fp = {}
        if sig_algs:
            extra_fp["tls_signature_algorithms"] = sig_algs

        # TODO: 可以添加其他支持的字段
        # extra_fp["tls_grease"] = True  # 如果需要GREASE

        return extra_fp if extra_fp else None

    def _create_session(self) -> Session:
        """Create and configure curl_cffi session"""
        # 优先使用impersonate（最稳定）
        if self.impersonate:
            session = Session(impersonate=self.impersonate)
        elif self._ja3_string and not self._ja3_has_tls13:
            # TODO: 使用ja3字符串创建session
            # curl_cffi在请求时传递ja3参数，而不是session初始化时
            # 注意：只有纯TLS 1.2的ja3才能使用
            session = Session()
        else:
            # Fallback: 使用impersonate模式
            # 情况1: ja3包含TLS 1.3 ciphers，curl_cffi不支持
            # 情况2: 没有ja3字符串
            fallback_impersonate = self._get_fallback_impersonate()
            if fallback_impersonate:
                # TODO: 当ja3包含TLS 1.3时自动fallback到impersonate
                if self._ja3_has_tls13:
                    import warnings
                    warnings.warn(
                        f"ja3 contains TLS 1.3 ciphers which curl_cffi doesn't support. "
                        f"Falling back to impersonate='{fallback_impersonate}'",
                        UserWarning
                    )
                session = Session(impersonate=fallback_impersonate)
            else:
                session = Session()

        # Apply proxy
        if self.proxy:
            session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }

        # Apply behavior settings
        session.timeout = self.timeout
        session.verify = self.verify

        return session

    def _get_fallback_impersonate(self) -> Optional[str]:
        """
        根据profile名称获取fallback的impersonate值

        TODO: 当自定义ja3不可用时的备选方案
        """
        name_lower = self.profile.name.lower()

        if "chrome" in name_lower:
            # 提取版本号
            import re
            match = re.search(r'(\d+)', name_lower)
            if match:
                version = match.group(1)
                impersonate = f"chrome{version}"
                if impersonate in self.SUPPORTED_IMPERSONATE:
                    return impersonate
            return "chrome120"  # 默认
        elif "firefox" in name_lower:
            return "firefox120"
        elif "safari" in name_lower:
            return "safari17_0"
        elif "edge" in name_lower:
            return "chrome120"  # Edge基于Chromium

        return "chrome120"  # 默认fallback

    def _get_request_kwargs(self) -> Dict[str, Any]:
        """
        获取请求时需要传递的额外参数（ja3等）

        TODO: curl_cffi的ja3参数是在请求时传递的
        """
        kwargs = {}

        # 如果使用ja3模式且没有impersonate
        if self._ja3_string and not self.impersonate:
            kwargs["ja3"] = self._ja3_string

            if self._akamai_string:
                kwargs["akamai"] = self._akamai_string

            if self._extra_fp:
                kwargs["extra_fp"] = self._extra_fp

        return kwargs

    def _build_headers(
            self,
            url: str,
            method: str = "GET",
            extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """Build headers for request"""
        return HeaderBuilder.build_headers(
            profile=self.profile,
            url=url,
            method=method,
            extra_headers=extra_headers
        )

    def _merge_kwargs(self, user_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """
        合并用户传入的kwargs和ja3指纹参数

        TODO: 确保ja3参数正确传递给curl_cffi
        """
        # 获取ja3相关参数
        fp_kwargs = self._get_request_kwargs()

        # 用户传入的参数优先级更高
        merged = {**fp_kwargs, **user_kwargs}
        return merged

    def get(
            self,
            url: str,
            params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ) -> Response:
        """
        Send GET request

        Args:
            url: Target URL
            params: URL parameters
            headers: Additional headers
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        request_headers = self._build_headers(url, "GET", headers)
        merged_kwargs = self._merge_kwargs(kwargs)
        return self._session.get(
            url,
            params=params,
            headers=request_headers,
            **merged_kwargs
        )

    def post(
            self,
            url: str,
            data: Optional[Union[Dict, str, bytes]] = None,
            json: Optional[Dict] = None,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ) -> Response:
        """
        Send POST request

        Args:
            url: Target URL
            data: Form data or raw body
            json: JSON data
            headers: Additional headers
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        request_headers = self._build_headers(url, "POST", headers)
        merged_kwargs = self._merge_kwargs(kwargs)
        return self._session.post(
            url,
            data=data,
            json=json,
            headers=request_headers,
            **merged_kwargs
        )

    def put(
            self,
            url: str,
            data: Optional[Union[Dict, str, bytes]] = None,
            json: Optional[Dict] = None,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ) -> Response:
        """Send PUT request"""
        request_headers = self._build_headers(url, "PUT", headers)
        merged_kwargs = self._merge_kwargs(kwargs)
        return self._session.put(
            url,
            data=data,
            json=json,
            headers=request_headers,
            **merged_kwargs
        )

    def delete(
            self,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ) -> Response:
        """Send DELETE request"""
        request_headers = self._build_headers(url, "DELETE", headers)
        merged_kwargs = self._merge_kwargs(kwargs)
        return self._session.delete(
            url,
            headers=request_headers,
            **merged_kwargs
        )

    def patch(
            self,
            url: str,
            data: Optional[Union[Dict, str, bytes]] = None,
            json: Optional[Dict] = None,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ) -> Response:
        """Send PATCH request"""
        request_headers = self._build_headers(url, "PATCH", headers)
        merged_kwargs = self._merge_kwargs(kwargs)
        return self._session.patch(
            url,
            data=data,
            json=json,
            headers=request_headers,
            **merged_kwargs
        )

    def head(
            self,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ) -> Response:
        """Send HEAD request"""
        request_headers = self._build_headers(url, "HEAD", headers)
        merged_kwargs = self._merge_kwargs(kwargs)
        return self._session.head(
            url,
            headers=request_headers,
            **merged_kwargs
        )

    def options(
            self,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ) -> Response:
        """Send OPTIONS request"""
        request_headers = self._build_headers(url, "OPTIONS", headers)
        merged_kwargs = self._merge_kwargs(kwargs)
        return self._session.options(
            url,
            headers=request_headers,
            **merged_kwargs
        )

    def close(self):
        """Close the session"""
        if self._session:
            self._session.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

    @property
    def cookies(self):
        """Get session cookies"""
        return self._session.cookies

    @cookies.setter
    def cookies(self, value):
        """Set session cookies"""
        self._session.cookies = value

    @property
    def ja3_string(self) -> Optional[str]:
        """获取当前使用的JA3字符串"""
        return self._ja3_string

    @property
    def akamai_string(self) -> Optional[str]:
        """获取当前使用的Akamai HTTP/2指纹"""
        return self._akamai_string

    def get_fingerprint_info(self) -> Dict[str, Any]:
        """
        获取当前客户端的指纹信息

        TODO: 用于调试和验证指纹配置
        """
        # 判断实际使用的模式
        if self.impersonate:
            actual_mode = f"impersonate ({self.impersonate})"
        elif self._ja3_string and not self._ja3_has_tls13:
            actual_mode = "custom ja3"
        else:
            fallback = self._get_fallback_impersonate()
            actual_mode = f"fallback impersonate ({fallback})"

        return {
            "profile_name": self.profile.name,
            "actual_mode": actual_mode,  # TODO: 显示实际使用的模式
            "impersonate": self.impersonate,
            "use_ja3": self.use_ja3,
            "ja3_has_tls13": self._ja3_has_tls13,  # TODO: 标记是否因TLS1.3而fallback
            "ja3_string": self._ja3_string,
            "akamai_string": self._akamai_string,
            "extra_fp": self._extra_fp,
            "user_agent": self.profile.user_agent,
            "tls_min_version": self.profile.tls_config.min_version,
            "tls_max_version": self.profile.tls_config.max_version,
        }