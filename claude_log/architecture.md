# rqsession 项目架构说明

**版本：** 0.3.1  
**核心目标：** 通过控制 TLS ClientHello 参数（cipher suites、extensions、curves 等）模拟真实浏览器的 TLS 指纹（JA3/JA4），使爬虫请求在指纹层面与真实浏览器无法区分。

---

## 整体架构

```
调用方
  │
  ├─── RequestSession            基础会话层（无 TLS 伪造）
  │
  ├─── EnhancedRequestSession    增强会话层（主推接口）
  │         │
  │         ├─ 正常路径 ──────▶  Rust 代理服务（:5005）──▶ 目标网站
  │         └─ 降级路径 ──────▶  标准 requests ──────────▶ 目标网站
  │
  └─── browser_forge             精细指纹管理子系统
            ├─ BrowserClient     ──▶  curl_cffi（JA3/impersonate 模式）──▶ 目标网站
            └─ AsyncRustTLSProxyClient ──▶ Rust 代理服务（:5005）──▶ 目标网站
```

---

## 各层说明

### Layer 1 — 基础会话 `rqsession/request_session.py`

`RequestSession(requests.Session)` 是对标准 `requests.Session` 的封装，不涉及 TLS 指纹。

| 功能 | 实现方式 |
|---|---|
| 代理管理 | 支持代理列表、随机轮换、自定义获取方法（`proxy_method` 回调） |
| 自动请求头 | `auto_headers=True` 时自动补齐 Host / Referer / Origin |
| Session 持久化 | `save_session()` / `load_session()` 序列化为 JSON（含 headers、cookies、配置） |
| Cookie 管理 | 按域名分组存储，支持从字符串/字典/完整 cookie 对象导入 |
| 请求历史 | 在内存中保留最近 N 条请求记录，可导出为 JSON (`export_request_chain()`) |

配置从 `rqsession/config.ini` 读取（代理地址/端口、是否启用代理、日志开关）。

---

### Layer 2 — 增强会话 `rqsession/enhanced_request_session.py`

`EnhancedRequestSession(requests.Session)` 是**对外的主要接口**（`__init__.py` 中 `RqSession = EnhancedRequestSession`）。

#### 核心机制

重写 `send()` 方法，请求不直接发到目标网站，而是：

1. 将请求参数（url、method、headers、body、browser_profile、proxy 等）打包成 JSON
2. POST 到本地 Rust 代理服务的 `/advanced_fetch` 端点
3. Rust 服务用对应浏览器的真实指纹发出请求，返回 `{status, headers, body[], fingerprint_info, timing}`
4. Python 侧将 Rust 响应重新构造为 `requests.Response` 对象，并同步 cookies

Rust 不可用或返回错误时自动降级为标准 `requests`（`_send_standard()`）。

#### 内置 Browser Profile

20+ 个预设，覆盖：Chrome（110~138，Windows/macOS/Linux）、Firefox（102~120）、Safari（16~17，macOS/iOS）、Edge（120）、Brave（120）、Opera（105）、Chrome Mobile（Android）。  
`set_browser_profile()` / `rotate_browser_profile()` 支持运行时切换。

#### 反检测配置

- `enable_tls_fingerprinting`：是否经由 Rust 发请求（默认 True）
- `enable_header_randomization`：80% 概率自动补 Referer，随机 Cache-Control，POST 请求补 Origin
- `enable_timing_simulation`：传给 Rust 的延迟模拟开关
- `get_fingerprint_consistency()`：检查历史请求中 JA3 hash 的一致性

---

### Layer 3 — browser_forge 子系统 `rqsession/browser_forge/`

更精细的指纹管理系统，独立于 Layer 2，有两条实现路径。

#### 目录结构

```
browser_forge/
├── profiles/
│   ├── models.py        数据模型（BrowserProfile / TlsConfig / H2Settings / HeaderProfile / BehaviorProfile）
│   └── presets.py       预设实例（Chrome119/120、Firefox120、Safari17、Edge142）
├── fingerprint/
│   ├── tls_builder.py   TLS 配置构建与验证（TlsBuilder / ProfileValidator）
│   └── ja3_generator.py JA3 / JA4 生成器，指纹分析器
├── core/
│   ├── client.py        BrowserClient（curl_cffi 路径）
│   ├── async_client.py  AsyncBrowserClient / AsyncBrowserPool
│   ├── header_builder.py 请求头构建器
│   └── rust_gateway_client.py AsyncRustTLSProxyClient（异步 Rust 路径）
├── tls_fb_db/           从真实浏览器采集的 TLS 指纹数据库（JSON 格式）
├── sets/                Edge142 等实测指纹集
├── tls_db_converter.py  指纹库格式转换（TlsDbConverter / FingerprintFilter）
└── fingerprint_convert.py 指纹格式互转工具
```

#### curl_cffi 路径（`BrowserClient`）

直接调用 `curl_cffi`（底层是 libcurl + BoringSSL），通过传递 JA3 字符串、akamai（HTTP/2）指纹、extra_fp（签名算法列表）实现精确指纹控制。

**关键限制：** curl_cffi 目前只支持 TLS 1.2 的自定义 JA3。如果 JA3 中包含 TLS 1.3 cipher（4865/4866/4867），会抛 `AssertionError`，`BrowserClient` 会自动 fallback 到 `impersonate` 模式（使用 curl_cffi 内置的浏览器预设）。

```
BrowserProfile
  └─ tls_config (TlsConfig)
  │     ├─ cipher_suites / extensions / curves / signature_algorithms
  │     └─ min/max TLS version
  ├─ h2_settings (H2Settings)      → 生成 akamai HTTP/2 指纹字符串
  ├─ headers (HeaderProfile)       → HeaderBuilder 构建请求头
  └─ behavior (BehaviorProfile)    → timeout / 连接数 / 压缩等
```

#### 异步 Rust 路径（`AsyncRustTLSProxyClient`）

使用 `httpx.AsyncClient` 异步调用 Rust 服务的 `/advanced_fetch`，结构上与 Layer 2 的同步版本等价，适用于 asyncio 场景。

#### TLS 指纹数据库

`tls_fb_db/` 存储从真实浏览器（含 Tor Firefox）采集的完整 TLS 指纹，`tls_db_converter.py` 提供：
- `load_random_chrome_profile()` / `load_random_firefox_profile()`：随机加载真实指纹
- `load_profile_by_hash()`：按 JA3 hash 精确加载
- `FingerprintFilter`：按浏览器类型/版本过滤

---

### Rust 后端 `rust/src/main.rs`

Actix-web HTTP 服务，监听 `0.0.0.0:5005`。

#### 端点

| 端点 | 方法 | 作用 |
|---|---|---|
| `/advanced_fetch` | POST | 主要端点，接收 Python 代理请求，用浏览器指纹发出并返回结果 |
| `/fetch` | POST | 兼容旧接口，简化版（HTTP/1.1 only，固定 Chrome UA） |
| `/health` | GET | 健康检查，返回版本和可用 profile 列表 |
| `/profiles` | GET | 返回所有可用 browser profile 信息 |

#### 内置 Browser Profile（Rust 侧）

`chrome_119_windows`、`chrome_119_macos`、`firefox_118_windows`、`safari_17_macos`、`chrome_138_windows`，每个 profile 包含 User-Agent、JA3 字符串、JA4 字符串、Accept / Accept-Language 等浏览器特有头。

#### 请求处理流程

1. 接收 `AdvancedFetchRequest`（url / method / headers / body / browser_profile / proxy / randomize_tls / add_timing_delay）
2. 自检：拒绝指向自身（`127.0.0.1:5005`）的代理，避免循环
3. 用 `reqwest` 构建客户端（支持 gzip/brotli、重定向、外部代理）
4. 调用 `build_enhanced_headers()` 生成完整浏览器头（包含 Sec-Fetch-* / Sec-CH-UA 等）
5. 合并自定义 headers，发出请求
6. 返回 `AdvancedFetchResponse`：`{status, headers[], body[], fingerprint_info, timing}`

JA3 hash 用 SHA-256 计算（目前用 SHA-256 而非 MD5，与标准 JA3 hash 算法不同，仅作标识用途）。

---

## 关键配置文件

| 文件 | 作用 |
|---|---|
| `rqsession/config.ini` | 代理地址/端口、是否启用代理、日志开关（被 `config_util.py` 读取） |
| `rqsession/.env` | 环境变量 |
| `rqsession/static/useragents.txt` | UA 列表（`RequestSession.initialize_session()` 随机选用） |
| `rqsession/static/proxies.txt` | 代理列表（`RequestSession` 随机轮换） |
| `rqsession/static/language.txt` | Accept-Language 列表 |
| `rust/Cargo.toml` | Rust 依赖（actix-web / reqwest / serde / sha2 / hex / rand 等） |
| `pyproject.toml` | Python 包配置，依赖 `requests>=2.32.3`、`curl-cffi>=0.7.0` |

---

## 两种 TLS 指纹实现路径对比

| 维度 | Rust 代理路径 | curl_cffi 路径 |
|---|---|---|
| 入口 | `EnhancedRequestSession` / `AsyncRustTLSProxyClient` | `BrowserClient` |
| TLS 控制方式 | reqwest 内置浏览器 profile（JA3/JA4 静态配置） | curl_cffi JA3 字符串 + akamai + extra_fp |
| TLS 1.3 支持 | 是 | 否（含 TLS 1.3 ciphers 时 fallback 到 impersonate） |
| HTTP/2 指纹 | 无精确控制 | akamai 字符串精确控制 |
| 使用场景 | 同步爬虫，兼容现有 requests 用法 | 需要精确 JA3 匹配，或已有真实指纹数据 |
| 依赖 | Rust 服务需单独启动 / 部署 | 纯 Python，无需额外服务 |
| 降级 | 自动降级为标准 requests | 自动降级为 impersonate 模式 |
