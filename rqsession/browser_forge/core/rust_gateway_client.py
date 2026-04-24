from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import json
import httpx


# ========= 数据结构：对应 Rust 的 FingerprintInfo / TimingInfo / 响应 =========

@dataclass
class FingerprintInfo:
    browser_profile: str
    ja3_fingerprint: str
    ja3_hash: str
    ja4_fingerprint: Optional[str]
    user_agent: str


@dataclass
class TimingInfo:
    total_duration_ms: int
    tls_handshake_ms: Optional[int]
    dns_lookup_ms: Optional[int]


@dataclass
class RustProxyResponse:
    """
    对应 Rust AdvancedFetchResponse 的一个高层封装：
    - status_code / headers / content: 目标网站的 HTTP 响应
    - fingerprint_info / timing: Rust 额外返回的调试信息
    """
    status_code: int
    headers: Dict[str, str]
    content: bytes
    fingerprint_info: Optional[FingerprintInfo] = None
    timing: Optional[TimingInfo] = None

    @property
    def text(self) -> str:
        try:
            return self.content.decode("utf-8", errors="replace")
        except Exception:
            return self.content.decode(errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


class RustProxyError(Exception):
    """调用 Rust 代理失败时抛出的异常"""
    pass


# ========= 构造 /advanced_fetch 请求体 =========

def build_advanced_fetch_payload(
        method: str,
        url: str,
        headers: Optional[Dict[str, str]],
        body: Any,
        browser_profile: Optional[str],
        proxy: Optional[str],
        randomize_tls: Optional[bool],
        add_timing_delay: Optional[bool],
) -> Dict[str, Any]:
    """
    精确对应 Rust 里的 AdvancedFetchRequest：
    {
        "url": String,
        "method": Option<String>,
        "headers": Option<Vec<(String, String)>>,
        "body": Option<String>,
        "browser_profile": Option<String>,
        "proxy": Option<String>,
        "randomize_tls": Option<bool>,
        "add_timing_delay": Option<bool>,
    }
    """

    # body 统一转成字符串（Rust 那边是 Option<String>）
    if body is None:
        body_str: Optional[str] = None
    elif isinstance(body, (dict, list)):
        body_str = json.dumps(body, ensure_ascii=False)
    elif isinstance(body, bytes):
        body_str = body.decode("utf-8", errors="replace")
    else:
        body_str = str(body)

    # headers: dict -> List[(k, v)]
    headers_list: Optional[List[List[str]]] = None
    if headers:
        headers_list = [[str(k), str(v)] for k, v in headers.items()]

    payload: Dict[str, Any] = {
        "url": url,
        "method": method.upper(),
        "headers": headers_list,
        "body": body_str,
        "browser_profile": browser_profile,
        "proxy": proxy,
        "randomize_tls": randomize_tls,
        "add_timing_delay": add_timing_delay,
    }
    return payload


# ========= 解析 Rust AdvancedFetchResponse =========

def parse_advanced_fetch_response(data: Dict[str, Any]) -> RustProxyResponse:
    """
    对应 Rust AdvancedFetchResponse:
    {
        "status": u16,
        "headers": Vec<(String, String)>,
        "body": Vec<u8>,
        "fingerprint_info": {...},
        "timing": {...}
    }
    """
    status = int(data.get("status", 0))

    # headers: Vec<(String, String)> -> dict[str, str]
    headers_dict: Dict[str, str] = {}
    for item in data.get("headers", []):
        # item 应该是 [key, value] 或 {"0":k,"1":v} 但 serde 默认是 list 两个元素
        if isinstance(item, (list, tuple)) and len(item) == 2:
            k, v = item
            headers_dict[str(k)] = str(v)

    # body: Vec<u8> -> bytes
    body_raw = data.get("body", [])
    if isinstance(body_raw, list):
        try:
            content = bytes(body_raw)
        except Exception:
            # 防御式处理，fallback 到空 bytes
            content = b""
    elif isinstance(body_raw, str):
        # 理论上不会是 str，这里兜底
        content = body_raw.encode("utf-8", errors="replace")
    else:
        content = b""

    # fingerprint_info
    fp_info_raw = data.get("fingerprint_info")
    fingerprint_info: Optional[FingerprintInfo] = None
    if isinstance(fp_info_raw, dict):
        fingerprint_info = FingerprintInfo(
            browser_profile=str(fp_info_raw.get("browser_profile", "")),
            ja3_fingerprint=str(fp_info_raw.get("ja3_fingerprint", "")),
            ja3_hash=str(fp_info_raw.get("ja3_hash", "")),
            ja4_fingerprint=(
                str(fp_info_raw["ja4_fingerprint"])
                if fp_info_raw.get("ja4_fingerprint") is not None
                else None
            ),
            user_agent=str(fp_info_raw.get("user_agent", "")),
        )

    # timing
    timing_raw = data.get("timing")
    timing: Optional[TimingInfo] = None
    if isinstance(timing_raw, dict):
        timing = TimingInfo(
            total_duration_ms=int(timing_raw.get("total_duration_ms", 0)),
            tls_handshake_ms=(
                int(timing_raw["tls_handshake_ms"])
                if timing_raw.get("tls_handshake_ms") is not None
                else None
            ),
            dns_lookup_ms=(
                int(timing_raw["dns_lookup_ms"])
                if timing_raw.get("dns_lookup_ms") is not None
                else None
            ),
        )

    return RustProxyResponse(
        status_code=status,
        headers=headers_dict,
        content=content,
        fingerprint_info=fingerprint_info,
        timing=timing,
    )


# ========= 异步客户端：对接 /advanced_fetch /health /profiles =========

class AsyncRustTLSProxyClient:
    """
    异步调用 Rust 高级 TLS 代理（/advanced_fetch）的客户端。

    - base_url: Rust 服务地址，默认 http://127.0.0.1:5005
    - default_profile: 默认 browser_profile，默认用你 Rust 的 chrome_138_windows
    - default_proxy: 透传给 Rust 的 data.proxy（Rust 会再往外发）
    """

    def __init__(
            self,
            *,
            base_url: str = "http://127.0.0.1:5005",
            default_profile: str = "chrome_138_windows",
            default_proxy: Optional[str] = None,
            default_randomize_tls: Optional[bool] = None,
            default_add_timing_delay: Optional[bool] = None,
            timeout: float = 30.0,
            max_connections: int = 100,
            advanced_endpoint: str = "/advanced_fetch",
            health_endpoint: str = "/health",
            profiles_endpoint: str = "/profiles",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.default_profile = default_profile
        self.default_proxy = default_proxy
        self.default_randomize_tls = default_randomize_tls
        self.default_add_timing_delay = default_add_timing_delay

        self._timeout = timeout
        self._max_connections = max_connections

        self._advanced_endpoint = advanced_endpoint
        self._health_endpoint = health_endpoint
        self._profiles_endpoint = profiles_endpoint

        self._client: Optional[httpx.AsyncClient] = None

    # --- httpx.AsyncClient 生命周期 ---

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(
                max_connections=self._max_connections,
                max_keepalive_connections=self._max_connections,
            )
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self._timeout,
                limits=limits,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> "AsyncRustTLSProxyClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # --- Rust 代理辅助接口 ---

    async def health(self) -> bool:
        """
        GET /health → True/False
        """
        client = await self._ensure_client()
        try:
            resp = await client.get(self._health_endpoint)
            return resp.status_code == 200
        except Exception:
            return False

    async def raw_health(self) -> Dict[str, Any]:
        """
        返回 /health 的完整 JSON，方便调试：
        {
          "status": "ok",
          "service": "rust_proxy_tls",
          "version": "0.2.1",
          "profiles": [...]
        }
        """
        client = await self._ensure_client()
        resp = await client.get(self._health_endpoint)
        resp.raise_for_status()
        return resp.json()

    async def list_profiles(self) -> List[Dict[str, Any]]:
        """
        调用 GET /profiles，返回类似：
        {
          "profiles": [
            {"name": "...", "user_agent": "...", "platform": "..."},
            ...
          ]
        }
        """
        client = await self._ensure_client()
        resp = await client.get(self._profiles_endpoint)
        resp.raise_for_status()
        data = resp.json()
        profiles = data.get("profiles", [])
        if isinstance(profiles, list):
            return profiles
        return []

    # --- 核心：通过 /advanced_fetch 请求目标站 ---

    async def request(
            self,
            method: str,
            url: str,
            *,
            headers: Optional[Dict[str, str]] = None,
            params: Optional[Dict[str, Any]] = None,
            json_body: Any = None,
            data: Any = None,
            browser_profile: Optional[str] = None,
            proxy: Optional[str] = None,
            randomize_tls: Optional[bool] = None,
            add_timing_delay: Optional[bool] = None,
            timeout: Optional[float] = None,
    ) -> RustProxyResponse:
        """
        通过 Rust 代理请求目标站点。
        """
        # 处理 query params，直接拼到 URL 上
        if params:
            import urllib.parse as _up
            parsed = _up.urlparse(url)
            query = _up.parse_qsl(parsed.query, keep_blank_values=True)
            for k, v in params.items():
                query.append((str(k), str(v)))
            new_query = _up.urlencode(query)
            url = _up.urlunparse(parsed._replace(query=new_query))

        # 决定最终 profile / proxy / 随机 TLS / 延迟
        profile_name = browser_profile or self.default_profile
        proxy_url = proxy or self.default_proxy
        randomize_tls_flag = (
            randomize_tls
            if randomize_tls is not None
            else self.default_randomize_tls
        )
        add_delay_flag = (
            add_timing_delay
            if add_timing_delay is not None
            else self.default_add_timing_delay
        )

        # body 优先 json_body，其次 data
        if json_body is not None:
            body_for_payload = json_body
        else:
            body_for_payload = data

        # 构造 AdvancedFetchRequest payload
        payload = build_advanced_fetch_payload(
            method=method,
            url=url,
            headers=headers,
            body=body_for_payload,
            browser_profile=profile_name,
            proxy=proxy_url,
            randomize_tls=randomize_tls_flag,
            add_timing_delay=add_delay_flag,
        )

        client = await self._ensure_client()

        try:
            resp = await client.post(
                self._advanced_endpoint,
                json=payload,
                timeout=timeout or self._timeout,
            )
        except Exception as e:
            raise RustProxyError(f"Failed to call Rust proxy: {e}") from e

        if resp.status_code != 200:
            # 这里是 Rust 服务自身的 HTTP 状态
            raise RustProxyError(
                f"Rust proxy returned {resp.status_code}: {resp.text}"
            )

        try:
            result_json = resp.json()
        except Exception as e:
            raise RustProxyError(
                f"Rust proxy response is not valid JSON: {e}"
            ) from e

        # 解析为 RustProxyResponse
        return parse_advanced_fetch_response(result_json)

    # --- 便捷方法 get/post/... ---

    async def get(
            self,
            url: str,
            *,
            headers: Optional[Dict[str, str]] = None,
            params: Optional[Dict[str, Any]] = None,
            browser_profile: Optional[str] = None,
            proxy: Optional[str] = None,
            randomize_tls: Optional[bool] = None,
            add_timing_delay: Optional[bool] = None,
            timeout: Optional[float] = None,
    ) -> RustProxyResponse:
        return await self.request(
            "GET",
            url,
            headers=headers,
            params=params,
            browser_profile=browser_profile,
            proxy=proxy,
            randomize_tls=randomize_tls,
            add_timing_delay=add_timing_delay,
            timeout=timeout,
        )

    async def post(
            self,
            url: str,
            *,
            headers: Optional[Dict[str, str]] = None,
            json: Any = None,
            data: Any = None,
            browser_profile: Optional[str] = None,
            proxy: Optional[str] = None,
            randomize_tls: Optional[bool] = None,
            add_timing_delay: Optional[bool] = None,
            timeout: Optional[float] = None,
    ) -> RustProxyResponse:
        return await self.request(
            "POST",
            url,
            headers=headers,
            json_body=json,
            data=data,
            browser_profile=browser_profile,
            proxy=proxy,
            randomize_tls=randomize_tls,
            add_timing_delay=add_timing_delay,
            timeout=timeout,
        )
