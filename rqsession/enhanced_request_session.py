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
        }
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
        if "DNT" not in request.headers and random.random() < 0.6:
            request.headers["DNT"] = "1"

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


# 使用示例
if __name__ == "__main__":
    # 创建增强版会话
    session = EnhancedRequestSession(
        browser_profile="chrome_119_windows",
        enable_tls_fingerprinting=True,
        enable_timing_simulation=True,
        enable_header_randomization=True,
    )

    # 测试基础功能
    print("Testing basic functionality...")
    # response = session.get("https://httpbin.org/get")
    # response = session.get("https://www.nflshop.com/")

    sensor_resp = session.post(
        url="https://accounts.krafton.com/W2LH1-bIl8hFyohRUQ/bmV7zpNVpwhbNXE3/HFFCUAE/G14xR/Ac5WiUB",
        json={
            "sensor_data": "3;0;1;0;3289397;61QEzmHJiF3KwzF78L5e69hhi7vAjfNvdaNduDEwkWo=;9,1,0,0,3,18;\"\"]\"7JN\"T\"`%:,z(Kx*M9+K .BiyTQH?QSI0nOirEVn:x;nYEP=s->\"_\"Luy\"y2(y.c.|\"/3\"H\"{-!Y}/\"iDY6Fyq>wurLxi`vt/Blcrc`7f~#T|kV_ILGL4+]#6@yTNF`f,7[dsrmY-4M SU-I;OLLA,dBCZE  vFDf-Nk#%ycEQqJ}}c+x.?F%/hS^xa=JBf+Mb3Pml0mG`qiFI:PJdk(w XMU}nSen5U!Jx7[PhYH`~wJYg\"v\"~7/\"O\"\"~\"-`O\"zLnHb1HX80F\"S7SG\"@glqor0\"\"_,Et$VzV0g [X\"^V-\"s_lqBNw}IC\"=4f2\"X\"\"X\"I f\"*@QRH\"A13\"uAT(GZsx\"b-l\"9\"F-!/]\"L0>\"Zu`\"C:=[w\"`u\"-r.\"W)LC\"U\"ldG4\"1iz\"&j,\"i\"\"j\"OvV\"bMR\"aa{\":sG1dVaLzBV^Jo!$\"D:`8\"k\"\"N\"!d\"Tq\"4a^\"m\"5_8PcJ3G\"pFj\"(N)\"KTrX&IU\"f<+\"B\"!~)1Gh^?$l<2N~CAfW]w)t>`A)/&Ewkq]Q5x>ZM?ZhJ{of?6^SkQm[#SkX=bY9X1q&dSn@=(L\"F\"H-%\"*X|Mb\"T D/\"=\"53U\"K\"c$Z\"}\"X\"^oD\"xn9\"(\"@Co6<!+*@AZScPM~?AOmF2Z]VWA6~s7]m!LxrRzz*2R^qS^4hcyTybHH<TA?,rIy~/mPK;IWp.McfYj9 |4hCE-~%4&3}pJ13N#mgf-9Oi-CcSWE}5R+gTM^^fqunaGx8Q9v }MU7Goy?GX> >V=wpmz$AAUNP8u;G2),3XqKpI^y&> x.W- ! @@kh%$2jQw<7}7;g$_-[xK_$i^oF*t |HMt.EGUJ5^{{i-/l,m.z<o%77.[,qls$Ec%>af n_3bZ_#1d(r32S2:fXb.N_Kiy?])A^{13|P.1&FuRui5-O4N{!(U02)IN.J Gh*54<vLUW(@1jN,wS;P*|8kEJTj0_)izfsCKGzaeuMq^6/ef@~W%,?~Zgt1U:g@lIq51E j.3d(|Se8=opC!55&o|.T|V&fD%Il!9|fq0x=F }[cOHuZn%!ly#Z2wN,nQoDishKs4sH<0B+=zsK2NldXj%g=}SR!pIx6QN4[~pB>4MCC;7uj-K:=Z|[,yU_=%`Ag*)xL]U+F1M:UOP-!K|tu9SB~j_R>8r^!I>A|E@!|}13NLc95`7?>g?ziYHI0){c7Wa]6hVXhe,+I;TBM~RYa.f[2:43+(wY(XjsS&,u12Qq4COJJ{]czL&qeoXubwVT3ixy[8E>aV&?is)4:tWkyZ/-}0-<7M7?jZh(gGUDhxPf=Flpwh@exeJEA=CUa|{lOAVrPISQ%<i|cgHI`9%RfX4?@N^ z=28+p@OF0@M}=q=~;c`%kp,P9*.<SW+5P^bV@c,!p3:r4|KxLy2Q?/R$ztv}<^)?eh{ne0UaPn&_&r6~C$?[PU&aNDNj1J#5]n-vzJ~*wLaAdM!{F{9agwDkpk+Hs.Y}Pk(!!P/:>g-w?;m`&u6njyM#)<PcGd9l6Unyu^;LC}K8rUH7rd#ZZqJ1=Ai+^4t9w7_h{K4CW-WN*|gcD1nBRoH0>Gv8$Q(`@rCE`B*B^,aS/<&$jh>v,<4&8VtI$_E}f6[{8(x}B!^cEN/B (lKb%rh}4q?2nS3vR,;]LCg+sVO:DAQHKtg*SB@T{Q2$[`90bJa}vqGaM293ED?MP;)Apkj-ZB{]EP8(`Gv;82e#v`wx3 96O:%U2.,TyZEE61&pYHsF6N&IH2I;i`*06)}^.?:y:1u}gj]XI:l;@O0jV_xu;Al`(w~W(1D$TK$D8;?C/#L#AQ,_q_-1Yn;AhYe:t2E/bP?KXd^ycV?|9<+Wqr2:t~[a):;sg#>oOQPg_qx3.*]Tmz{Sa[/C(Dt~SYrR8bpnRUAYk$,NHK*{E_L;Pa1Ow? :d}1jc4WD#51Un(/QR]KJh&*s6Fp7vH$Fxw:%7X}q^urFO(-PfqaLzGKB_gMnY%d>w.LB=cA-2LNm-h|JGq`U@lcT~; M6kQ)g%>IK.TYJf~Io?[&Dd^Y2lprD`Kpe>6fHf<4IyVbi+Cw2j,a)JQC8hovPsiG8mb@!S!51 [ba6I0Z6V5Zu#;vKsvWolJF+.gLyMp Y@_h4NBfC#Z{EXbZ@OhLxkJQ;D/zQ{DOK4HR*X5]W5yJw -&r0X/W_ON6O-0qOh#yf!;o8.iX/&P8@ZR:^voTG,M5R2E{l#I=.L`T$qNJ,&M;Lqsd)JC~,#,}C+?{p=TaXr<zNP?>unW:K&&yUqbNQIor(q0xo6cgm<Z?|$muZV..Xyv&[0!qvs;5[]nXV(_pzBr_ML>I.0xr<gp~T6$}*Biu7?T58uW[gEhhVUVY_fTN!VWpH(,-APn1U_pv$W@Ql4vl]f_$q%|mV,G]>)/2DV~7jpH;F,k8C,njbih+)C*4oTq,t^hr4U*H{$XUcT7btfFELgi2%NOP?uAk?7@Z)Dy2r/Vf|ha0A2)--IMu*GQ`G%W|jgr/_0]!u1`g|!jGhWJ[Z(3gt;A^B7s5,0>X3Z4iNpHf/~ K)m]|1_l:X)-K4Bb3>:VwP|t@|TG_~x|X(&w:I}9k,Vc/.)^8E<m4q65^h0y<_ieP!%-Ah0Z1f4GlkgNz7<s5sPL3{UAf<<M8~yxHa9lI|Xs61H,t )m,(XY@@re9rz(eXi{FcFkS)^5LfzcCZhQ}iYU4>xz[/JeN&AZ(R3sP3k/g.7~}+G1_cFL=N#y]?S+c`x&^0v[F(o?o/AL-bzd85!1 @z#aJe,.#=^7]b97xn:!.JSKu=~lo[hp#v~]Qq?05]veA0ksYP#a)SWJ(MF*+1@JVVYH>k?94j:yQYDF,{cS\"D\" `*\"HHE7NZbJ\"~\"s*{\"jsA\"gaI8~Wg\"9<rTKBSVt.CIoXW,wt~_42n~avtp]W([t8j8M@Si)6^o  0aITyR!xrxx-|)z|N/C[I0)(O]5C{s?CD%s(?,piUmq&/9)1pOm,jOhyAI}Bm,ORVC.VmX9=IZ[{+A6F!n$G;,/Gr8sze$HTsODp,%kvu9Ceb+8B( >aPIaiB_ClO\"5\"EC9\"S:o-*\"I -\")7r]!;j\"\"uc~\"rk}\"?]PY#:?-\"<V\"|*H_zdn@bTfm\"a.v@\"$_y>GG~C@2\"]#B\"Zz$H5\"l1J=\"]1h_5xR7C~q\"Hy%}\"y\"F)C{3vVf/m&G_q^K\"1\"E.Z\"fd:Ymt`\"JiU~]{MGM1~&8l=vm`IE}q-ny;weelIlPvd ]0Rav^@PkA}iSS?=$vD)1]={FL/L;jEpf2fw1{[zB}VN9D0*x#Q.Sn_;nnQ iN:a_,h 93q>]L&}myflfp;-RwhP{9z@?+tI@l[j=0~Fo_9<8IEHLS:}Fxi^5P.l[L8w+Z2e2$%GyqVXYoky+ rk9pbc4LAw$fbOQ-vGfizEnoZhe)3TBSK?uIVY+U3*.swyga@cAMV9dbann*G[[umqBw*>lI<|*u+z.le?x00gOWBbl?Hei28.tP`|Pw&p x7.6$wR=LcC#7*Ac,Hj|AGEyx~6za``aY|y*%}oU\"v\"->1\"=g4dw.=A\"QpA\"-).@>U`g\"k9/\"8 ix)RaD_\"I_!\"C\"oQQy21?sCFf[n%(Yktn~8:^d=&>m./Y[/ jaZ^>Het[$@/n4mdF}F0[9uQyON{>/h:._hZ#Gi8.WqhmKp:`)B{CN+lMy1bX_/T%+Sa6QPe;Oban$&GS<YF#_;&ZEZ\")1_\")(J\"]\"\"m\"GXp\"sGQ/aS\"r_H0\"S\"z;C\"5&80L~Y:Z9a7)9iMfjD0V<:4#o`[?kjFz]@x)u=DY/S&dL9lxbp3C$@joC=v\"}\"kEt\"u1n{eIU\"c-D8+\"fU%\"XcQ\"i`5`,;\"q|)d)~a\"M\"$k*I6+Be!_&E~mUuvQ>eB;/([xm>BttP8T:1W%q\"|gZ\"[UM\"{ZC_2#\",A9f\"slP@{ZzLAGlA/Wre\"Y~ \"2{?bP/\"l\"&(_\"DMs\"_!}1P,%nx`7#\"0>,6\"V*K\",*d\"/~lyB\"`55\":cq^qz1;ld+lkIr0}\"zn]\"(\"~.\"T6b\"m;x~\"Yn.<aS&m\"D,Y\"N\"\"V\"NNQ\"yoG+AM%df\"s|\"7{Z\"vnF\"#\"\"9=$\"z?N\"zoHqFgU\"G8g-~B{Xv+AZIln-EJPM0&!G/c>*Nfc#:LcJ~>#8kycIAPUaObgoUs#\"4\"dZr\"gIcQLoHSIQ\")C`\"!C8Wh?\"=vqNx\"3@ZFo\"N{>\"6kOqf\"O?6T5%+\">` Tf1?I8:b5?7]pItd=}I$Mt`qGupd)<n&Ys?YxsfBsyyEi=qe>-_=g,05yEGPs$_zYy`c|.&lCNU%I*f^72lNwIE_E{(#GcGgFqQc9EB&p{#P~lAN(|aGpMcpV;MM#;(K+b9`6/M1{.C#VE--naM8qJVy`PZoDiM(eJ*C+0F>y?Y?iYXTCG1~Y?SzqMp+^0{I9x`0dv73~@b=~xo~cxqe>3HbjRm,o=2cc@0bHV}}k9RA%,y$(H57{d+_H?b$hB?st^U.r.^QOwK> 5z:=JDYNAV72+RsX?D|}sc?6[$.,`,!t$s7:SUnTW(gh]6[I;9$|l}WKvAJc/^bOgi+;Y^wf`5r!2`E\"m\"IP[\"gOrVT\";if\"TP{xM@\"PI\";\"\"/\"Ay%\"tgtUZ,Wty\"3D6H2\"w\"\"h\"O$i\"jLmt]\"j#.\"OItio\"ZFN\"J\")Dx(PW^F4RiI5\".\"3OO\"8\"\"IA4\"I5\"`tNnGQ)%\"}W,\"a\"MG]r9>WWlV:Z-|p-,c&e mz[k!qm7n\"3\"5Mk\"f!%9+z;_eG\"aN\" 8~J~9THE!B0}-\"[p.K\"K\"RIqGNNev]4o@\"C75\"QB#\"w\"~7\"tRd\"7B7J\" \"\"7\"+M6\"9ZIf2t/T\"yrU\"Zj\"UlO\"TM5\"EDi;p\"/]g\""},
    )
    print(sensor_resp.status_code)
    print(sensor_resp.headers)
    print(sensor_resp.text)

    url = "https://accounts.krafton.com/auth/local"

    payload = {
        "email": "xxx@xx.com",
        "password": "dsadasdassda",
        "trusted_device": False,
        "client_id": "local",
        "activationVersion": "v2"
    }
    session.headers.update({
        "accept": "application/json, text/plain, */*",
        "origin": "https://accounts.krafton.com",
        "referer": "https://accounts.krafton.com/v2/en/web/login-main?type=last-login",
        # "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0"
    })

    cks = {
        "_abck": "8244B42B92511FA9BD77A88875D3C10A~0~YAAQXgk+F/BfvwaYAQAASXmOIQ4aFBbvPvlLQVxp9DLMxGZjtq9VF4SAWtdoy99BBR1AGu4ZGvjkORlaIotaTu+ZulgcxZs4JSu/qIc3X1egsxiy/ZGklkI46yrxYSMLhA33PZYhHD/O/fbWjkolHFWRP9V6CeKjjIbH2Z0Dn2anZNfdPgS/APG8L+aMUK3zaIkAQ6mY9OYqhNkIQgfsGkqm5fDn1vEDHuUKU/AGNidp7lDeqsBAkoXIKrL53MYXhFpUfjG5cpkamxCcBXOtVqrbsEog2vsr5my//uiiemWu2bfLmHNNpE+dg4TmNZoBq8izZVtAuXUdUCkIt34jEDDSdoxWwQpDSqLPdErUtVEoi94vEweih6oMn5O9P9G/7Djr4cY9aF1wdAkW9PN7WInTGdSxw3rL5wc/bm8sPip8OWHx6nKXCLYPOWw+alGjCjYPP21x1Xf+CxRlaZ8oFUvSJ/gS+7rj/GUc7NSChJvpJVnhLR52bGrp9tFfDkKKGV7jq5FnuAH9ylM4CmNKPmrnXIxbnS7eSg1rRxHOi2KBPWDce5OG8ITCUTKg5K/8OYfgK4aFjjWb6aKVikrHRkTAuN2VME+t4GAKIih4I0LlY7QdN6UeBhFH15ZogFGSdxTHhpZI+/CcK8Jp+bgcixWrjWgv7rgF2eNDF244FDe5GIGZWTZfmAykGKHaDUDZsq1vjIGIDzlnNvQOtp15EBBDnecGX2yegFrnf5ShDhEf70zjRTxoocgB9I05ghwaZOfl4aQwGsYrjHqOdQy0EKkufpYzyVQMGxpfmmXL1rf0XTCMdX8LS2gktVx081Wvb2DQcyLtJNcNjb2mJ3SbHjPFLT8NYBiHBVn1JRh7DtRoOSV+UKHhZj9fpI6kTw==~-1~-1~-1",
        "_dd_s": "aid=243f2954-2482-4d83-a5fa-90de2241f0dd&rum=0&expire=1752910548672",
        "bm_sz": "AA3DC2F5885CB3E820CAD8DD5B9C0051~YAAQXgk+FzpgvwaYAQAA4BOcIRy09GmP+VvR4RWMtieV5XRAUQcair3szcIRAA/ZYL3hp/hOx7GxNgs/4a+hB51PMov+mrLyCg+Ic2hfrH32tO5LxQKwVTKYS2fAbFO6NK1JmugMcmoMXLvAWzATe+KKzMk5J7ZPEpgnapWc9HzJdLchDJ6VcJgOMwV0tSnSHi8YEN7qU3kZxC/3u2i5NlQJcWWJm9aw4xDta0bRT8TL58Sht9GlcVlYr02a8SIboniPpm3NdYDyKYO56D03W7DJtAV9BdS6Ta9lucAmNQOPtBIjcgSdUJ5aW+VG9aaX1gW1EkAgDBN77FCOejWtDsPdGQ2xqcfYIAxy3k8yQuCKldtZBmj7OmjiC6eofqz9i6cL44E4t2cqHkYe6/L6IxsFRVykkmc=~3289397~3159092",
        "current_language": "en",
        "i18n_redirected": "en",
        "kid-cookie": "true",
        "KRAFTON_DID": "3e97e140-be36-4a2a-ae60-6fa32d93d27c",
        "KRAFTON_DID_UAT": "2025-03-13%3A%3A879e46f48816a3746491671c535be2ceba736c76",
        "KRAFTON_ID_LAST_LOGIN": "ejH%2BbQ2WOF02L4lbu0zefMRRBmred6jqcsSzFjX2pphWp1qozvm%2FKMcWaFAUZFczmq1cfsHtsbjZyErm%2BIjA73D1DPaIt37KnlBYfHDaFcklSJuB2UUoy79o0xIQjFD6Tak9sBWVDUwHDdjyqydP0k3EN1wT2pCq3bxwXAjy02u1oVkGL1qOQ73V14XAfsr8",
        "RT": '"z=1&dm=accounts.krafton.com&si=81a63bc1-0c31-4a20-b385-3c6e6fe03323&ss=md9ng9pr&sl=0&tt=0&bcn=%2F%2F684d0d46.akstat.io%2F"',
        "sessionId": "s%3Ayycm0yJZasSvMkiVQCQxoOYIJ-_XlUyF.0fnlcaNiW1GXVV6M%2By7yQn1pmp%2BCzESVPoS9Bpq1nv8",
        "X2RF_T0KEN": "516e32623b9d80198fe9057afd90048c3bc659639fe6892648259bfdfe3f861a",
    }
    headers = copy(session.headers)
    response = session.post(url, json=payload, headers=headers, cookies=cks, proxies={
        "http": "http://127.0.0.1:5005",
        "https": "http://127.0.0.1:5005",
    })
    print(response.status_code, response.headers, response.text)

    for key, val in response.cookies.items():
        cks.update({
            key: val
        })
    for key, val in cks.items():
        session.cookies.update({
            key: val
        })
    resp = session.get("https://accounts.krafton.com/settings/profile")

    # 测试指纹检测
    print("\nTesting fingerprint detection...")
    detection_results = session.test_fingerprint_detection()

    for url, result in detection_results.items():
        print(f"{url}: {result['status']}")

    # 获取指纹信息
    fingerprint = session.get_fingerprint_info()
    if fingerprint:
        print(f"\nFingerprint Info:")
        print(f"  Profile: {fingerprint.profile_name}")
        print(f"  JA3 Hash: {fingerprint.ja3_hash}")
        print(f"  User Agent: {fingerprint.user_agent}")

    # 测试配置切换
    print(f"\nCurrent profile: {session.browser_profile}")
    session.rotate_browser_profile()
    print(f"New profile: {session.browser_profile}")
