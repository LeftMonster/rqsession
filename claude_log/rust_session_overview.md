# rust_session — 纯 Rust PyO3 TLS 指纹模块

**版本：** 0.4.1  
**创建时间：** 2026-04-27  
**对应会话：** cd9fae2a（前半）+ 当前会话

---

## 背景与决策

### 为什么新建这个模块

旧的 TLS 指纹实现路径存在根本限制：

| 路径 | 限制 |
|---|---|
| `curl_cffi` 路径 | 不支持自定义 TLS 1.3 cipher；含 4865/4866/4867 时自动 fallback 到 impersonate |
| `Rust 代理服务` 路径 | 需要单独启动进程（`:5005`），部署复杂，且 reqwest 没有暴露完整 JA3 控制接口 |

**决定：** 新建 `rqsession/rust_session/`，用 PyO3 将 Rust 编译为 Python 扩展（`.pyd`），直接 import，无需额外进程。TLS 层用 BoringSSL（`boring` crate），是目前 Rust 生态中唯一能精确控制完整 JA3 的方案。

### 关键技术决策

- **打包工具：** maturin（从 setuptools 迁移），`pyproject.toml` 的 `build-backend` 改为 `maturin`
- **TLS：** `boring` + `tokio-boring`（BoringSSL 绑定），不用 `rustls`
- **HTTP：** `hyper 1.x` + `hyper-util`，支持 HTTP/1.1 和 HTTP/2
- **响应 API：** 兼容 `requests.Response` 风格（`status_code`、`text`、`json()`、`headers`、`content`、`ok`、`raise_for_status()`）
- **Profile 格式：** JSON 文件，放在 `rqsession/rust_session/profiles/builtin/` 或 `custom/`

---

## 模块结构

```
rqsession/rust_session/
├── __init__.py          导出 BrowserSession、AsyncBrowserSession + 内置 profile 对象 + load_*/list_* 函数
├── session.py           Python 包装层（BrowserSession 同步类）
├── async_session.py     Python 包装层（AsyncBrowserSession 异步类）
└── profiles/
    ├── __init__.py      懒加载内置 profile，_ProfileProxy 类
    ├── builtin/         内置 JSON 文件（5 个）
    │   ├── chrome120_windows.json
    │   ├── chrome119_windows.json
    │   ├── edge142_windows.json
    │   ├── firefox133_windows.json
    │   └── safari17_macos.json
    └── custom/          用户自定义（空目录，用户自己扔 JSON）

src/                     Rust 源码（PyO3 扩展）
├── lib.rs               PyBrowserProfile / PyBrowserSession / PyAsyncBrowserSession / PyResponse + pymodule
├── profile.rs           BrowserProfile / TlsConfig / Http2Config / HeaderConfig 数据结构
├── http_client.rs       execute() + send_once() + do_h1/h2 + connect_via_proxy + 重定向 + 解压
├── tls_builder.rs       build_ssl_connector()，BoringSSL TLS 配置
├── cipher_map.rs        IANA → OpenSSL cipher 名转换，curves_to_groups_list，encode_alpn
├── response.rs          RustResponse 结构体
└── error.rs             Error enum + From<Error> for PyErr

tools/
└── tls_peet_to_profile.py  将 tls.peet.ws/api/all JSON 转换为 BrowserProfile JSON（见 profile_tools.md）
```

---

## Profile JSON 格式

```json
{
  "name": "chrome120_windows",
  "user_agent": "Mozilla/5.0 ...",
  "tls": {
    "min_version": "1.2",
    "max_version": "1.3",
    "cipher_suites": [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "..."
    ],
    "curves": ["x25519", "secp256r1", "secp384r1"],
    "signature_algorithms": ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "..."],
    "alpn": ["h2", "http/1.1"]
  },
  "http2": {
    "settings": {
      "HEADER_TABLE_SIZE": 65536,
      "ENABLE_PUSH": 0,
      "INITIAL_WINDOW_SIZE": 6291456,
      "MAX_FRAME_SIZE": null,
      "MAX_CONCURRENT_STREAMS": null,
      "MAX_HEADER_LIST_SIZE": null
    },
    "window_update": 15663105,
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"]
  },
  "headers": {
    "accept": "text/html,application/xhtml+xml,...",
    "accept_language": "en-US,en;q=0.9",
    "accept_encoding": "gzip, deflate, br",
    "order": ["user-agent", "accept", "accept-language", "accept-encoding",
              "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
              "upgrade-insecure-requests", "sec-fetch-site", "sec-fetch-mode",
              "sec-fetch-user", "sec-fetch-dest"],
    "extra": {
      "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"...",
      "sec-fetch-site": "none",
      "..."
    }
  }
}
```

`extra` 字段说明：
- `order` 列表中不在 4 个基础 header（user-agent/accept/accept-language/accept-encoding）中的名字，其值从 `extra` 中查找
- 每次请求按 `order` 顺序构建请求头，保证顺序一致性（底层用 `Vec<(String, String)>` 不是 HashMap）
- Safari / Firefox 等无 sec-ch-ua 的 profile，`extra` 为空 `{}`，`order` 只含基础 4 项
```

cipher_suites 支持：
- TLS 1.3：`TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`
- TLS 1.2：IANA 格式（如 `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`），自动转换为 OpenSSL 名
- GREASE 值、未知 cipher → 自动跳过（不报错）

curves 支持：`x25519`、`secp256r1`/`prime256v1`/`P-256`、`secp384r1`/`P-384`、`secp521r1`/`P-521`、`x448`、`ffdhe2048`、`ffdhe3072`

---

## Python API

```python
from rqsession.rust_session import BrowserSession, AsyncBrowserSession
from rqsession.rust_session import Chrome120, Firefox133, Safari17, Edge142, Chrome119
from rqsession.rust_session import load_custom, load_profile_json, list_builtin, list_custom
from rqsession._rust_core import load_profile  # 按路径加载

# ── 同步用法 ──────────────────────────────────────────
s = BrowserSession(Chrome120)
s = BrowserSession(Firefox133, proxy="http://127.0.0.1:7890")
s = BrowserSession(Chrome120, verify=False)

# 请求方法
resp = s.get(url, headers={}, params={})
resp = s.post(url, headers={}, params={}, data=b"...", json={})
resp = s.request(method, url, headers={}, params={}, body=b"...", json={})

# 响应对象（兼容 requests.Response 风格）
resp.status_code   # int
resp.url           # str，最终响应的 URL（重定向后为目标 URL）
resp.text          # str
resp.content       # bytes
resp.headers       # dict[str, str]（同名 header 只保留一个值）
resp.json()        # dict/list（Python 原生类型）
resp.ok            # bool（status < 400）
resp.raise_for_status()  # status >= 400 时抛 RuntimeError
resp.cookies       # dict[str, str]，本次响应 Set-Cookie 的所有 cookies
                   # 正确处理多个 Set-Cookie header（get_all 提取，不按逗号切割）
resp.history       # list[Response]，重定向链（不含最终响应），无重定向时为空列表

# Session Cookie 管理
s.cookies                           # dict[str, str]，当前 session 累积的所有 cookies
s.update_cookies({"token": "abc"})  # 手动写入，后续请求自动带上
# 每次请求后自动将 resp.cookies 合并进 session（含重定向中间响应的 cookies）

# 上下文管理器
with BrowserSession(Chrome120) as s:
    resp = s.get("https://example.com")

# ── 异步用法 ──────────────────────────────────────────
import asyncio

async def main():
    async with AsyncBrowserSession(Chrome120) as s:
        resp = await s.get("https://example.com")
        data = resp.json()

    # 真正并发，不阻塞线程
    async with AsyncBrowserSession(Chrome120) as s:
        results = await asyncio.gather(
            s.get("https://example.com/a"),
            s.get("https://example.com/b"),
        )

asyncio.run(main())

# 构造参数（同步 / 异步相同）：proxy、verify、ca_bundle

# 加载自定义 profile
profile = load_custom("my_browser")        # 从 profiles/custom/my_browser.json
profile = load_profile_json('{"name":...}') # 从 JSON 字符串
profile = load_profile("/path/to/file.json") # 从任意路径

# 查看可用 profile
list_builtin()  # ['chrome120_windows', 'chrome119_windows', ...]
list_custom()   # ['my_browser', ...]
```

---

## Rust 核心层能力

| 功能 | 实现 |
|---|---|
| 完整 JA3（TLS 1.2 cipher suites） | `set_cipher_list`，IANA → OpenSSL 名自动转换 |
| TLS 1.3 cipher | BoringSSL 内置管理（AES-128/256-GCM、CHACHA20） |
| Supported groups（curves） | `set_curves_list` 字符串接口 |
| ALPN | `set_alpn_protos` wire 格式 |
| 签名算法 | `set_sigalgs_list` |
| TLS 版本范围 | `set_min/max_proto_version` |
| HTTP/2 设置帧 | `hyper` http2::Builder（initial_window_size、max_frame_size 等） |
| HTTP CONNECT 代理 | 手动实现 CONNECT 隧道，支持 http/https 代理，格式 `http://[user:pass@]host:port` |
| 响应体解压 | content-encoding 自动解压：gzip（flate2）、deflate（flate2）、br（brotli）、zstd（zstd crate） |
| 自动重定向 | 最多 10 跳，301/302/303 POST→GET 转换 |
| SSL 验证跳过 | `verify=False` → `SslVerifyMode::NONE` |

---

## 内置 Profile 列表

| Python 常量 | JSON 文件名 | 浏览器 |
|---|---|---|
| `Chrome138` | `chrome138_windows.json` | Chrome 138 / Windows |
| `Chrome120` | `chrome120_windows.json` | Chrome 120 / Windows |
| `Chrome119` | `chrome119_windows.json` | Chrome 119 / Windows |
| `MacosChrome140` | `macos_chrome140.json` | Chrome 140 / macOS |
| `Edge147` | `edge147_windows.json` | Edge 147 / Windows |
| `Edge142` | `edge142_windows.json` | Edge 142 / Windows |
| `Edge141` | `edge141_windows.json` | Edge 141 / Windows |
| `Firefox146` | `firefox146_windows.json` | Firefox 146 / Windows |
| `Firefox133` | `firefox133_windows.json` | Firefox 133 / Windows |
| `Safari17` | `safari17_macos.json` | Safari 17 / macOS |
| `Tor128` | `tor128_windows.json` | Tor Browser 128 / Windows |
| `AndroidChrome114` | `android_chrome114.json` | Chrome 114 / Android |
| `Py37Aiohttp381` | `py37_aiohttp381.json` | Python aiohttp 3.8.1（测试用） |

添加新 profile：在 `profiles/builtin/` 或 `profiles/custom/` 放一个符合格式的 JSON 文件即可，无需修改代码。

---

## 与旧架构的关系

- `rust_session` 是**独立新增子包**，不影响现有 `RequestSession`、`EnhancedRequestSession`、`browser_forge` 路径
- `rqsession/__init__.py` 暂未将 `BrowserSession` 加入顶层导出，从 `rqsession.rust_session` 导入
- 旧的 Rust 代理服务（`rust/` 目录，`:5005` 端口）与本模块完全独立，两者可并存
