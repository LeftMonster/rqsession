import logging
import asyncio
import aiohttp
import random
import time
import json
import uuid
from copy import copy
from urllib.parse import urlparse
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass

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


class AsyncEnhancedRequestSession:
    """异步增强版RequestSession，支持高级TLS指纹伪造和反检测"""

    # 预定义的浏览器配置（与同步版本相同）
    BROWSER_PROFILES = {
        "chrome_119_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "sec_ch_ua": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            "sec_ch_ua_platform": '"Windows"',
        },
        "chrome_120_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br, zstd",
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "cache_control": "max-age=0",
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
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },
        "firefox_120_windows": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.5",
            "accept_encoding": "gzip, deflate, br",
            "sec_ch_ua": None,
            "sec_ch_ua_platform": None,
            "sec_ch_ua_mobile": None,
            "upgrade_insecure_requests": "1",
            "sec_fetch_dest": "document",
            "sec_fetch_mode": "navigate",
            "sec_fetch_site": "none",
            "sec_fetch_user": "?1",
        },
    }

    def __init__(
            self,
            browser_profile: str = "chrome_138_windows",
            rust_backend_url: str = "http://127.0.0.1:5005",
            enable_tls_fingerprinting: bool = True,
            enable_timing_simulation: bool = True,
            enable_header_randomization: bool = True,
            proxy_config: Optional[Dict] = None,
            connector_limit: int = 100,
            timeout: int = 30,
            **kwargs
    ):
        """
        初始化异步增强版RequestSession

        Args:
            browser_profile: 浏览器配置名称
            rust_backend_url: Rust后端服务地址
            enable_tls_fingerprinting: 启用TLS指纹伪造
            enable_timing_simulation: 启用时序模拟
            enable_header_randomization: 启用请求头随机化
            proxy_config: 代理配置
            connector_limit: 连接池大小限制
            timeout: 默认超时时间（秒）
        """
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

        # 会话配置
        self.connector_limit = connector_limit
        self.default_timeout = aiohttp.ClientTimeout(total=timeout)

        # aiohttp session（延迟初始化）
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()

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

        # 初始化请求头
        self.headers = {}
        self._initialize_browser_profile()

        # Cookie存储
        self.cookies = {}

        _logger.info(f"Async Enhanced RequestSession initialized with profile: {browser_profile}")

    def _initialize_browser_profile(self):
        """初始化浏览器配置"""
        if self.browser_profile not in self.BROWSER_PROFILES:
            _logger.warning(f"Unknown browser profile: {self.browser_profile}, using default")
            self.browser_profile = "chrome_138_windows"

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

    async def _get_session(self) -> aiohttp.ClientSession:
        """获取或创建aiohttp session（线程安全）"""
        if self._session is None or self._session.closed:
            async with self._session_lock:
                if self._session is None or self._session.closed:
                    # 创建连接器
                    connector = aiohttp.TCPConnector(
                        limit=self.connector_limit,
                        limit_per_host=30,
                        ttl_dns_cache=300,
                        ssl=False  # 通过Rust后端处理SSL
                    )

                    # 创建cookie jar
                    cookie_jar = aiohttp.CookieJar(unsafe=True)

                    self._session = aiohttp.ClientSession(
                        connector=connector,
                        cookie_jar=cookie_jar,
                        timeout=self.default_timeout,
                        headers=self.headers
                    )
                    _logger.info("Created new aiohttp session")

        return self._session

    async def close(self):
        """关闭session"""
        if self._session and not self._session.closed:
            await self._session.close()
            _logger.info("Closed aiohttp session")

    async def __aenter__(self):
        """异步上下文管理器入口"""
        await self._get_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器退出"""
        await self.close()

    def _enhance_headers_for_request(self, headers: Dict, url_obj) -> Dict:
        """为请求增强头部信息"""
        headers = copy(headers)

        if not self.enable_header_randomization:
            return headers

        # 动态设置Referer
        if "Referer" not in headers and "referer" not in headers:
            if random.random() < 0.8:
                headers["Referer"] = f"{url_obj.scheme}://{url_obj.netloc}/"

        # 动态设置Cache-Control
        if "Cache-Control" not in headers and "cache-control" not in headers:
            cache_controls = ["no-cache", "max-age=0", None]
            cache_control = random.choice(cache_controls)
            if cache_control:
                headers["Cache-Control"] = cache_control

        return headers

    async def _prepare_advanced_request(
            self,
            method: str,
            url: str,
            headers: Dict,
            data: Any = None,
            json_data: Any = None,
            **kwargs
    ) -> Dict:
        """准备高级请求参数"""

        # 过滤并转换headers - 移除null值，确保格式正确
        clean_headers = []
        for key, value in headers.items():
            if value is not None:  # 过滤null
                # 转为tuple而不是list
                clean_headers.append((str(key), str(value)))

        request_data = {
            "url": url,
            "method": method.upper(),
            "headers": clean_headers,  # 使用清理后的headers
            "body": None,
            "browser_profile": self.browser_profile,
            "randomize_tls": self.randomization_config.get("tls_randomization", True),
            "add_timing_delay": self.enable_timing_simulation,
        }

        # 处理请求体
        if json_data is not None:
            request_data["body"] = json.dumps(json_data)
            # 添加Content-Type到headers
            clean_headers.append(("Content-Type", "application/json"))
        elif data is not None:
            if isinstance(data, bytes):
                try:
                    request_data["body"] = data.decode('utf-8')
                except UnicodeDecodeError:
                    import base64
                    request_data["body"] = base64.b64encode(data).decode('ascii')
                    request_data["body_encoding"] = "base64"
            elif isinstance(data, str):
                request_data["body"] = data
            else:
                request_data["body"] = str(data)

        # 处理代理配置（保持原样）
        proxy_url = None
        if "proxy" in kwargs:
            proxy_url = kwargs["proxy"]
        elif self.proxy_config:
            if "url" in self.proxy_config:
                proxy_url = self.proxy_config["url"]
            elif "http" in self.proxy_config:
                proxy_url = self.proxy_config["http"]

        if proxy_url:
            if "127.0.0.1:5005" not in proxy_url and "localhost:5005" not in proxy_url:
                request_data["proxy"] = proxy_url

        return request_data

    async def _send_advanced(
            self,
            method: str,
            url: str,
            headers: Dict,
            **kwargs
    ) -> aiohttp.ClientResponse:
        """高级发送方式（通过Rust后端）"""
        try:
            url_obj = urlparse(url)
            headers = self._enhance_headers_for_request(headers, url_obj)

            # 准备请求数据
            request_data = await self._prepare_advanced_request(
                method, url, headers, **kwargs
            )

            # print("发送数据:", json.dumps(request_data, indent=2))

            # 发送到Rust后端
            start_time = time.time()

            session = await self._get_session()
            async with session.post(
                    f"{self.rust_backend_url}/advanced_fetch",
                    json=request_data,
                    timeout=aiohttp.ClientTimeout(total=60)
            ) as backend_response:
                result = await backend_response.json()

                # 检查错误
                if "error" in result:
                    _logger.error(f"Rust backend error: {result['error']}")
                    raise aiohttp.ClientError(f"Backend error: {result['error']}")

                total_duration = time.time() - start_time

                # 构造响应对象
                response = await self._create_response_from_result(result, url)

                # 记录指纹和请求信息
                self._record_fingerprint_info(result.get("fingerprint_info"))
                self._record_request(
                    method, url, response, total_duration * 1000, result.get("timing")
                )

                return response

        except Exception as e:
            _logger.error(f"Advanced request failed: {e}")
            raise

    async def _create_response_from_result(
            self, result: Dict, original_url: str
    ) -> 'AsyncResponse':
        """从Rust后端结果创建响应对象"""
        # 提取cookies并更新
        for key, value in result.get("headers", []):
            if key.lower() == 'set-cookie':
                self._parse_and_store_cookie(value, original_url)

        return AsyncResponse(
            status=result["status"],
            headers=dict(result.get("headers", [])),
            body=bytes(result.get("body", [])),
            url=original_url
        )

    def _parse_and_store_cookie(self, cookie_header: str, url: str):
        """解析并存储cookie"""
        try:
            parts = cookie_header.split(';')[0]
            if '=' in parts:
                name, value = parts.split('=', 1)
                self.cookies[name.strip()] = value.strip()
        except Exception as e:
            _logger.warning(f"Failed to parse cookie: {e}")

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

        if len(self.fingerprint_history) > self.max_history_size:
            self.fingerprint_history.pop(0)

    def _record_request(
            self,
            method: str,
            url: str,
            response: 'AsyncResponse',
            duration_ms: float,
            timing_info: Optional[Dict] = None
    ):
        """记录请求信息"""
        parsed_url = urlparse(url)

        request_record = {
            "timestamp": time.time(),
            "method": method,
            "url": url,
            "path": parsed_url.path,
            "status_code": response.status,
            "duration_ms": round(duration_ms, 3),
            "browser_profile": self.browser_profile,
            "tls_fingerprinting_enabled": self.enable_tls_fingerprinting,
        }

        if timing_info:
            request_record["timing"] = timing_info

        self.request_history.append(request_record)

        if len(self.request_history) > self.max_history_size:
            self.request_history.pop(0)

        _logger.info(
            f"Request recorded: {method} {parsed_url.path} -> "
            f"{response.status} ({duration_ms:.1f}ms)"
        )

    async def request(
            self,
            method: str,
            url: str,
            headers: Optional[Dict] = None,
            **kwargs
    ) -> 'AsyncResponse':
        """发送HTTP请求"""
        if headers is None:
            headers = copy(self.headers)
        else:
            merged_headers = copy(self.headers)
            merged_headers.update(headers)
            headers = merged_headers

        # 添加cookies
        if self.cookies and "cookies" not in kwargs:
            kwargs["cookies"] = self.cookies

        if self.enable_tls_fingerprinting:
            return await self._send_advanced(method, url, headers, **kwargs)
        else:
            # 标准方式（使用aiohttp）
            session = await self._get_session()
            async with session.request(method, url, headers=headers, **kwargs) as resp:
                body = await resp.read()
                return AsyncResponse(
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body,
                    url=str(resp.url)
                )

    async def get(self, url: str, **kwargs) -> 'AsyncResponse':
        """发送GET请求"""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> 'AsyncResponse':
        """发送POST请求"""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> 'AsyncResponse':
        """发送PUT请求"""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> 'AsyncResponse':
        """发送DELETE请求"""
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> 'AsyncResponse':
        """发送PATCH请求"""
        return await self.request("PATCH", url, **kwargs)

    def set_browser_profile(self, profile_name: str):
        """设置浏览器配置"""
        old_profile = self.browser_profile
        self.browser_profile = profile_name
        self._initialize_browser_profile()
        _logger.info(f"Browser profile changed from {old_profile} to {profile_name}")

    def get_fingerprint_info(self) -> Optional[BrowserFingerprint]:
        """获取最新的指纹信息"""
        return self.fingerprint_history[-1] if self.fingerprint_history else None

    async def batch_get(
            self,
            urls: List[str],
            max_concurrent: int = 10,
            **kwargs
    ) -> List['AsyncResponse']:
        """批量GET请求，支持并发控制"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def fetch_with_semaphore(url):
            async with semaphore:
                return await self.get(url, **kwargs)

        tasks = [fetch_with_semaphore(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def batch_post(
            self,
            url_data_pairs: List[tuple],
            max_concurrent: int = 10,
            **kwargs
    ) -> List['AsyncResponse']:
        """批量POST请求

        Args:
            url_data_pairs: List of (url, data) tuples
            max_concurrent: 最大并发数
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def post_with_semaphore(url, data):
            async with semaphore:
                return await self.post(url, data=data, **kwargs)

        tasks = [post_with_semaphore(url, data) for url, data in url_data_pairs]
        return await asyncio.gather(*tasks, return_exceptions=True)


class AsyncResponse:
    """异步响应包装类"""

    def __init__(self, status: int, headers: Dict, body: bytes, url: str):
        self.status = status
        self.status_code = status  # 兼容性别名
        self.headers = headers
        self._body = body
        self.url = url

    @property
    def text(self) -> str:
        """获取文本内容"""
        return self._body.decode('utf-8', errors='replace')

    @property
    def content(self) -> bytes:
        """获取二进制内容"""
        return self._body

    def json(self) -> Any:
        """解析JSON响应"""
        return json.loads(self.text)

    def __repr__(self):
        return f"<AsyncResponse [{self.status}]>"


# 使用示例
async def example_basic_usage():
    """基础使用示例"""
    async with AsyncEnhancedRequestSession(
            browser_profile="chrome_138_windows",
            enable_tls_fingerprinting=True,
            rust_backend_url="http://127.0.0.1:5005"
    ) as session:
        # 单个请求
        response = await session.get("https://httpbin.org/get")
        print(f"Status: {response.status}")
        print(f"Body: {response.text[:200]}")


async def example_concurrent_requests():
    """并发请求示例"""
    async with AsyncEnhancedRequestSession(
            browser_profile="chrome_138_windows",
            connector_limit=50
    ) as session:
        # 批量GET请求
        urls = [
                   "https://httpbin.org/get",
                   "https://httpbin.org/uuid",
                   "https://httpbin.org/user-agent",
               ] * 10

        responses = await session.batch_get(urls, max_concurrent=20)

        successful = [r for r in responses if not isinstance(r, Exception)]
        failed = [r for r in responses if isinstance(r, Exception)]

        print(f"Successful: {len(successful)}, Failed: {len(failed)}")


async def example_with_proxy():
    """使用代理示例"""
    async with AsyncEnhancedRequestSession(
            browser_profile="chrome_138_windows",
            proxy_config={"http": "http://proxy.example.com:8080"}
    ) as session:
        response = await session.get("https://httpbin.org/ip")
        print(response.json())


async def example_login_flow():
    """登录流程示例"""
    async with AsyncEnhancedRequestSession(
            browser_profile="chrome_138_windows",
            enable_tls_fingerprinting=True
    ) as session:
        # 第一步：获取登录页面
        response1 = await session.get("https://example.com/login")
        print(f"Login page: {response1.status}")

        # 第二步：提交登录表单
        login_data = {
            "username": "user@example.com",
            "password": "password123"
        }
        response2 = await session.post(
            "https://example.com/api/login",
            json_data=login_data
        )
        print(f"Login response: {response2.status}")

        # 第三步：访问受保护资源（cookies自动携带）
        response3 = await session.get("https://example.com/dashboard")
        print(f"Dashboard: {response3.status}")


async def example_error_handling():
    """错误处理示例"""
    async with AsyncEnhancedRequestSession() as session:
        try:
            response = await session.get(
                "https://httpbin.org/delay/10",
                timeout=aiohttp.ClientTimeout(total=5)
            )
        except asyncio.TimeoutError:
            print("Request timed out")
        except Exception as e:
            print(f"Error: {e}")


async def main():
    """主函数示例"""
    # 基础使用
    await example_basic_usage()

    # 并发请求
    await example_concurrent_requests()


if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 运行示例
    asyncio.run(main())