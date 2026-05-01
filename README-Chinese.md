# rqsession

通过 Rust 原生扩展（BoringSSL + hyper + tokio）精确模拟真实浏览器 TLS 指纹的 Python HTTP 库。

[![PyPI version](https://img.shields.io/pypi/v/rqsession.svg)](https://pypi.org/project/rqsession/)
[![Python versions](https://img.shields.io/pypi/pyversions/rqsession.svg)](https://pypi.org/project/rqsession/)
[![License](https://img.shields.io/github/license/LeftMonster/requestsession.svg)](https://github.com/LeftMonster/requestsession/blob/main/LICENSE)

---

## 解决的问题

Cloudflare、Akamai、DataDome 等反爬系统通过检查 TLS ClientHello 和 HTTP/2 SETTINGS 帧来识别爬虫。不管你设置了什么 `User-Agent`，标准的 `requests` 或 `httpx` 都会产生可识别的 Python 指纹。

`rqsession` 在 Rust 层面控制完整的指纹：

| 层级 | 控制内容 |
|---|---|
| TLS ClientHello | 加密套件顺序、支持的曲线（curves）、ALPN、签名算法、版本范围 |
| HTTP/2 | SETTINGS 帧参数（窗口大小、最大帧大小）、连接级 WINDOW_UPDATE |
| HTTP 请求头 | 精确的 header 顺序、浏览器特有 header（sec-ch-ua、sec-fetch-* 等） |

无需启动外部代理进程 — 编译为 `.pyd` / `.so` 扩展，直接 import 使用。

---

## 安装

```bash
pip install rqsession
```

提供 **Windows x86_64** 和 **Linux x86_64**（Python 3.9+）预编译 wheel。  
其他平台需本地安装 Rust 工具链从源码包编译。

---

## 快速开始

### 同步用法

```python
from rqsession.rust_session import BrowserSession, Chrome120

with BrowserSession(Chrome120) as s:
    resp = s.get("https://httpbin.org/get")
    print(resp.status_code)   # 200
    print(resp.json())
```

### 异步用法

```python
import asyncio
from rqsession.rust_session import AsyncBrowserSession, Chrome120

async def main():
    async with AsyncBrowserSession(Chrome120) as s:
        resp = await s.get("https://httpbin.org/get")
        print(resp.status_code)
        print(resp.json())

asyncio.run(main())
```

### 并发异步请求

```python
import asyncio
from rqsession.rust_session import AsyncBrowserSession, Chrome120

async def main():
    async with AsyncBrowserSession(Chrome120) as s:
        results = await asyncio.gather(
            s.get("https://httpbin.org/get"),
            s.get("https://httpbin.org/ip"),
            s.get("https://httpbin.org/user-agent"),
        )
    for r in results:
        print(r.status_code)

asyncio.run(main())
```

---

## 内置浏览器 Profile

| 导入名 | 浏览器 | 系统 |
|---|---|---|
| `Chrome138` | Chrome 138 | Windows |
| `Chrome120` | Chrome 120 | Windows |
| `Chrome119` | Chrome 119 | Windows |
| `Edge147` | Edge 147 | Windows |
| `Edge142` | Edge 142 | Windows |
| `Edge141` | Edge 141 | Windows |
| `Firefox146` | Firefox 146 | Windows |
| `Firefox133` | Firefox 133 | Windows |
| `Tor128` | Tor Browser 128 | Windows |
| `Safari17` | Safari 17 | macOS |
| `MacosChrome140` | Chrome 140 | macOS |
| `AndroidChrome114` | Chrome 114 | Android |
| `Py37Aiohttp381` | Python aiohttp 3.8.1 | Windows |

```python
from rqsession.rust_session import (
    BrowserSession, AsyncBrowserSession,
    Chrome138, Chrome120, Chrome119,
    Edge147, Edge142, Edge141,
    Firefox146, Firefox133,
    Tor128, Safari17, MacosChrome140,
    AndroidChrome114, Py37Aiohttp381,
)
```

每个 profile 包含对应浏览器真实的加密套件顺序、curves、签名算法、HTTP/2 参数和 header 顺序。

---

## 代理支持

同步和异步 session 均支持在构造时传入代理：

```python
# HTTP 代理
s = BrowserSession(Chrome120, proxy="http://127.0.0.1:7890")

# 带认证的代理
s = BrowserSession(Chrome120, proxy="http://user:pass@host:port")

# 异步
async with AsyncBrowserSession(Firefox133, proxy="http://127.0.0.1:7890") as s:
    resp = await s.get("https://example.com")
```

代理通过 HTTP CONNECT 在 TCP 层建立隧道，TLS 指纹在隧道内端到端生效。

---

## Session API

### 构造参数

```python
BrowserSession(
    profile,              # 内置常量或 BrowserProfile 对象
    *,
    proxy=None,           # "http://[user:pass@]host:port"
    verify=True,          # False 跳过 SSL 验证
    ca_bundle=None,       # CA 文件路径；None 时自动检测 certifi
)
# AsyncBrowserSession 参数相同
```

### 请求方法

```python
# GET
resp = s.get(url, headers={...}, params={...})

# POST — 原始数据或 JSON
resp = s.post(url, data=b"...")
resp = s.post(url, json={"key": "value"})

# 通用请求
resp = s.request("PUT", url, headers={...}, json={...})

# 异步版本 — 签名相同，加 await
resp = await s.get(url)
resp = await s.post(url, json={...})
```

### 响应对象

兼容 `requests.Response` 风格：

```python
resp.status_code    # int
resp.text           # str（自动解码）
resp.content        # bytes
resp.headers        # dict[str, str]
resp.json()         # 解析 JSON → dict / list
resp.ok             # status < 400 时为 True
resp.raise_for_status()   # 4xx/5xx 时抛出异常
resp.url            # 重定向后的最终 URL
```

响应体自动解压（gzip、deflate、br、zstd）。

### Cookie

```python
# 手动写入 cookie（后续请求自动携带）
s.update_cookies({"token": "abc123"})

# 响应中的 Set-Cookie 会自动持久化到 session，
# 下一次请求时自动带上。
```

---

## 添加自定义浏览器 Profile

用真实浏览器访问 [tls.peet.ws/api/all](https://tls.peet.ws/api/all) 采集指纹，然后转换：

```bash
# 将 tls.peet.ws 返回的 JSON 保存为 chrome136.json，然后：
python tools/tls_peet_to_profile.py chrome136.json -n chrome136_windows --install
```

`--install` 参数直接将 profile 写入 `rqsession/rust_session/profiles/builtin/`。  
也可以在运行时加载，无需重新编译：

```python
from rqsession.rust_session import BrowserSession, load_custom, load_profile_json
from rqsession._rust_core import load_profile

# 从 profiles/custom/<name>.json 加载
s = BrowserSession(load_custom("my_browser"))

# 从 JSON 字符串加载
s = BrowserSession(load_profile_json('{"name": "...", "tls": {...}, ...}'))

# 从任意文件路径加载
s = BrowserSession(load_profile("/path/to/profile.json"))

# 查看可用 profile 列表
from rqsession.rust_session import list_builtin, list_custom
print(list_builtin())   # ['chrome120_windows', 'firefox133_windows', ...]
print(list_custom())    # ['my_browser', ...]
```

---

## Windows 异步注意事项

Python 3.8+ 在 Windows 上默认使用 `ProactorEventLoop`，遇到事件循环报错时切换为 `SelectorEventLoop`：

```python
import asyncio, sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

asyncio.run(main())
```

---

## 旧版层级（兼容保留）

早期版本提供 `RequestSession` 和 `EnhancedRequestSession`，仍可使用：

```python
from rqsession import RequestSession          # 基础 requests.Session 封装
from rqsession import EnhancedRequestSession  # 通过本地 Rust 代理进程路由
```

新项目请使用 `BrowserSession` / `AsyncBrowserSession`，无需外部进程，指纹更精确。

---

## 许可证

Apache 2.0 — 详见 [LICENSE](LICENSE)。
