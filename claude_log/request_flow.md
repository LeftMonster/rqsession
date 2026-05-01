# 请求全链路流程：Header 顺序与指纹控制

**创建时间：** 2026-04-28  
**示例：** `Chrome120` → `kick.com/api/search`，`Firefox133` → `httpbin.org/get`

---

## 总览

```
Python 调用
    │
    ▼
① Profile 加载（JSON → Rust 结构体）
    │
    ▼
② Session 构造（BrowserSession / AsyncBrowserSession）
    │
    ▼
③ build_default_headers()  ← 核心：按 profile.order 顺序组装 Vec
    │
    ▼
④ 合并用户自定义 headers（覆盖或追加）
    │
    ▼
⑤ http_client::execute()
    │
    ├─▶ TCP connect
    │
    ├─▶ TLS 握手（BoringSSL）  ← JA3/JA4 指纹在此产生
    │       cipher suites / curves / ALPN / sigalgs / version range
    │
    ├─▶ ALPN 协商：h2 → do_h2()   /   http/1.1 → do_h1()
    │
    ├─▶ [H2] 发送 SETTINGS + WINDOW_UPDATE 帧
    │
    ├─▶ 发送 HEADERS 帧（按 Vec 顺序，不经过 HashMap）
    │
    └─▶ 收到响应 → 解压（gzip/br/zstd/deflate）→ 返回 PyResponse
```

---

## Phase 1 — Profile 加载

```python
from rqsession.rust_session import BrowserSession, Chrome120
```

`Chrome120` 是 `_ProfileProxy("chrome120_windows")` 懒加载单例。  
第一次实际使用时（传入 `BrowserSession`）触发 `_inner()` 调用：

```python
# profiles/__init__.py
class _ProfileProxy:
    def _inner(self):
        if self._profile is None:
            self._profile = load_profile_json(
                (BUILTIN_DIR / f"{self._name}.json").read_text()
            )
        return self._profile
```

`load_profile_json` 是 Rust 函数（`src/lib.rs`），调用 `BrowserProfile::from_json()`：

```rust
// src/profile.rs
pub struct BrowserProfile {
    name: String,
    user_agent: String,
    tls: TlsConfig,       // cipher_suites, curves, sig_algs, alpn, version range
    http2: Http2Config,   // settings, window_update, pseudo_header_order
    headers: HeaderConfig // accept/accept_language/accept_encoding/order/extra
}
```

JSON 通过 `serde_json` 反序列化，`order` 和 `extra` 有 `#[serde(default)]`，老版本缺失也不报错。

---

## Phase 2 — Session 构造

```python
s = BrowserSession(Chrome120, proxy=None)
```

Python `session.py` 先检测 certifi CA bundle，再调用 Rust：

```rust
// src/lib.rs — PyBrowserSession::new()
Self {
    profile: Arc::new(profile.inner.clone()),
    proxy: None,
    verify: true,
    ca_bundle: Some("/path/to/certifi/cacert.pem"),
    session_cookies: Arc::new(Mutex::new(HashMap::new())),
    runtime: Arc::new(tokio::runtime::Runtime::new()),
}
```

此时还没有发出任何网络请求，TLS 连接也未建立。

---

## Phase 3 — build_default_headers()（核心）

调用 `s.get(url, headers=user_headers, params=params)` 后，Rust 侧：

```
append_params(url, params) → final_url
build_default_headers(final_url) → Vec<(String, String)>
```

`build_default_headers` 的逻辑（`src/lib.rs`）：

```rust
let resolve = |name: &str| -> Option<String> {
    match name {
        "user-agent"      => Some(p.user_agent.clone()),
        "accept"          => Some(p.headers.accept.clone()),
        "accept-language" => Some(p.headers.accept_language.clone()),
        "accept-encoding" => Some(p.headers.accept_encoding.clone()),
        other             => p.headers.extra.get(other).cloned(),  // sec-ch-ua 等
    }
};

for name in &p.headers.order {
    if let Some(value) = resolve(name) {
        out.push((name.clone(), value));   // Vec 保证顺序
    }
}
// 最后注入 session cookies（如果有）
if !cookies.is_empty() {
    out.push(("cookie".to_owned(), cookie_str));
}
```

**关键：全程用 `Vec<(String, String)>` 而非 HashMap，顺序由 profile.order 决定，不会被打乱。**

### Chrome120 实际构建结果

`chrome120_windows.json` 的 order：
```json
["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
 "upgrade-insecure-requests", "user-agent", "accept",
 "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
 "sec-fetch-dest", "accept-encoding", "accept-language"]
```

构建后的 Vec（Chrome120，请求前）：
```
1  sec-ch-ua            "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"
2  sec-ch-ua-mobile     ?0
3  sec-ch-ua-platform   "Windows"
4  upgrade-insecure-requests  1
5  user-agent           Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...Chrome/120...
6  accept               text/html,application/xhtml+xml,...
7  sec-fetch-site       none
8  sec-fetch-mode       navigate
9  sec-fetch-user       ?1
10 sec-fetch-dest       document
11 accept-encoding      gzip, deflate, br, zstd
12 accept-language      en-US,en;q=0.9
```

### Firefox133 实际构建结果

`firefox133_windows.json` 的 order（无 sec-ch-ua）：
```json
["user-agent", "accept", "accept-language",
 "accept-encoding", "upgrade-insecure-requests",
 "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user"]
```

构建后的 Vec（Firefox133，请求前）：
```
1  user-agent           Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) ...Firefox/133.0
2  accept               text/html,application/xhtml+xml,...
3  accept-language      en-US,en;q=0.5
4  accept-encoding      gzip, deflate, br, zstd
5  upgrade-insecure-requests  1
6  sec-fetch-dest       document
7  sec-fetch-mode       navigate
8  sec-fetch-site       none
9  sec-fetch-user       ?1
```

**差异一目了然：Chrome 有 sec-ch-ua 三件套且在最前，Firefox 没有；两者的字段顺序也不同。**

---

## Phase 4 — 合并用户自定义 headers

以 kick.com 示例为例：

```python
headers = {
    "accept": "application/json",
    "referer": f"https://kick.com/search/livestreams?query={keyword}",
}
```

合并逻辑（`src/lib.rs`）：
```rust
for (k, v) in extra {
    let k_lower = k.to_lowercase();
    if let Some(entry) = all_headers.iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case(&k_lower))
    {
        entry.1 = v;        // 同名 header → 原地覆盖，保持位置
    } else {
        all_headers.push((k_lower, v));   // 新 header → 追加到末尾
    }
}
```

Chrome120 合并后最终 Vec：
```
1  sec-ch-ua            ...
2  sec-ch-ua-mobile     ?0
3  sec-ch-ua-platform   "Windows"
4  upgrade-insecure-requests  1
5  user-agent           Mozilla/5.0 ...Chrome/120...
6  accept               application/json          ← 覆盖了原来的 text/html,...
7  sec-fetch-site       none
8  sec-fetch-mode       navigate
9  sec-fetch-user       ?1
10 sec-fetch-dest       document
11 accept-encoding      gzip, deflate, br, zstd
12 accept-language      en-US,en;q=0.9
13 referer              https://kick.com/search/livestreams?query=rust  ← 新增追加
```

---

## Phase 5 — TLS 握手（BoringSSL 产生 JA3/JA4）

`http_client::send_once()` → `build_ssl_connector(&profile.tls, ...)` → `tokio_boring::connect()`：

### build_ssl_connector 做了什么（src/tls_builder.rs）

```rust
// 1. TLS 版本范围
builder.set_min_proto_version(Some(SslVersion::TLS1_2));
builder.set_max_proto_version(Some(SslVersion::TLS1_3));

// 2. TLS 1.2 cipher suites（IANA 名 → OpenSSL 名，via cipher_map.rs）
//    TLS 1.3 ciphers 由 BoringSSL 内部管理，此处只设置 1.2 部分
builder.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...");

// 3. Supported groups（curves）
builder.set_curves_list("X25519:P-256:P-384");  // Chrome120
// Firefox133: "X25519:P-256:P-384:P-521"

// 4. ALPN（wire format：每个协议前缀1字节长度）
builder.set_alpn_protos(b"\x02h2\x08http/1.1");

// 5. 签名算法
builder.set_sigalgs_list("ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:...");

// 6. CA bundle
builder.set_ca_file("/path/to/certifi/cacert.pem");
```

这些参数在 TCP 握手时以 **ClientHello 扩展** 的形式发出，构成 JA3/JA4 指纹。  
TLS 1.3 下实际协商的 cipher 由服务器从支持列表中选择（通常 AES-128-GCM-SHA256）。

### Chrome120 vs Firefox133 TLS 差异

| 字段 | Chrome120 | Firefox133 |
|---|---|---|
| TLS 1.2 ciphers | 11 个，ECDHE-ECDSA-AES128 在前 | 13 个，CHACHA20 排第 2 |
| Curves | X25519, P-256, P-384（3个） | X25519, P-256, P-384, P-521（4个）|
| Sig algs | 8 个，ECDSA-SHA256 开头 | 9 个，ECDSA-SHA256 + 384 + 512 前三位 |
| ALPN | h2, http/1.1 | h2, http/1.1 |

---

## Phase 6 — HTTP/2 帧

ALPN 协商到 `h2` → `do_h2()`：

### SETTINGS 帧

```rust
// src/http_client.rs — do_h2()
let mut builder = http2::Builder::new(TokioExecutor::new());
if let Some(v) = s.initial_window_size {
    builder.initial_stream_window_size(v);
}
builder.initial_connection_window_size(profile.http2.window_update);
if let Some(v) = s.max_frame_size {
    builder.max_frame_size(v);
}
```

Chrome120 发出的 SETTINGS 帧参数：
```
INITIAL_WINDOW_SIZE = 6291456
MAX_FRAME_SIZE      = 16777215
（HEADER_TABLE_SIZE、ENABLE_PUSH 见下方"未完全落地"说明）
```

Firefox133 的 SETTINGS 帧参数：
```
INITIAL_WINDOW_SIZE = 131072      ← 明显更小
MAX_FRAME_SIZE      = 16384
```

WINDOW_UPDATE 帧（连接级）：
- Chrome120：`15663105`
- Firefox133：`12517377`

### HEADERS 帧（普通 header 顺序）

`build_request()` 将 `Vec<(String, String)>` 按顺序写入 `Request`，hyper 按此顺序编码到 HPACK HEADERS 帧。

kick.com 最终在网络上看到的 HEADERS 帧（Chrome120）：
```
:method        GET                   ← 伪头（hyper 自动产生，顺序固定）
:authority     kick.com
:scheme        https
:path          /api/search?searched_word=rust
sec-ch-ua      "Not_A Brand";v="8"...  ← 常规 header，按 Vec 顺序
sec-ch-ua-mobile  ?0
sec-ch-ua-platform  "Windows"
upgrade-insecure-requests  1
user-agent     Mozilla/5.0 ...Chrome/120...
accept         application/json
sec-fetch-site  none
sec-fetch-mode  navigate
sec-fetch-user  ?1
sec-fetch-dest  document
accept-encoding  gzip, deflate, br, zstd
accept-language  en-US,en;q=0.9
referer        https://kick.com/search/livestreams?query=rust
```

---

## Phase 7 — 响应处理

```rust
// http_client.rs — collect_response()
let encoding = headers.get("content-encoding").map(|s| s.as_str()).unwrap_or("");
let body = decompress(raw, encoding)?;
```

| content-encoding | 解压库 |
|---|---|
| gzip | flate2::read::GzDecoder |
| deflate | flate2::read::ZlibDecoder |
| br | brotli::Decompressor |
| zstd | zstd::decode_all |
| 无/其他 | 原始 bytes 直接返回 |

解压后封装为 `RustResponse { status_code, headers, body, url }` → Python `PyResponse`。

---

## 两个 Profile 完整对比

| 维度 | Chrome120 | Firefox133 |
|---|---|---|
| **Header 顺序** | sec-ch-ua → user-agent → accept → ... | user-agent → accept → accept-language → ... |
| **sec-ch-ua** | 有（3个字段，位置靠前） | 无 |
| **sec-fetch 顺序** | site/mode/user/dest（中间穿插） | dest/mode/site/user（结尾） |
| **accept 值** | 含 image/avif, image/webp, apng | 含 image/avif, image/webp（无 apng/signed-exchange） |
| **accept-language** | en-US,en;q=0.9 | en-US,en;q=0.5 |
| **TLS cipher 首位** | TLS_AES_128_GCM_SHA256 | TLS_AES_128_GCM_SHA256 |
| **TLS cipher 第二位** | TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256 |
| **Curves 数量** | 3（无 P-521） | 4（含 P-521） |
| **H2 stream window** | 6291456 (~6MB) | 131072 (~128KB) |
| **H2 max frame** | 16777215 | 16384 |
| **H2 connection window** | 15663105 | 12517377 |
| **H2 pseudo-header order** | :method :authority :scheme :path | :method :path :authority :scheme |

---

## 当前未完全落地的字段

以下字段在 profile JSON 中存在、已解析到 Rust 结构体，但目前**未实际应用**到网络层：

| 字段 | 位置 | 原因 |
|---|---|---|
| `http2.settings.ENABLE_PUSH` | `Http2Settings.enable_push` | hyper 1.x 的 `http2::Builder` 无对应方法 |
| `http2.settings.HEADER_TABLE_SIZE` | `Http2Settings.header_table_size` | hyper 1.x 的 `http2::Builder` 无对应方法 |
| `http2.settings.MAX_CONCURRENT_STREAMS` | `Http2Settings.max_concurrent_streams` | hyper 1.x 的 `http2::Builder` 无对应方法 |
| `http2.pseudo_header_order` | `Http2Config.pseudo_header_order` | hyper/h2 crate 不暴露伪头顺序控制接口 |

**影响评估：**  
- ENABLE_PUSH = 0（Chrome/Firefox 均如此）是目前 HTTP/2 的普遍行为，现代服务端也基本不用 Server Push，缺失影响可忽略。
- HEADER_TABLE_SIZE 影响 HPACK 压缩效率，不影响内容正确性，对反检测影响较小。  
- 伪头顺序（`:method :authority :scheme :path` vs `:method :path :authority :scheme`）**是 Akamai Bot Manager 重点检测字段**。目前 Chrome 和 Firefox 的伪头顺序都由 hyper 统一控制，无法区分。如果遇到专门检测伪头顺序的站点，这是当前实现的主要盲区。

---

## 小结：哪些特征已经是真实浏览器级别

| 检测维度 | 是否精确 |
|---|---|
| TLS ClientHello cipher suites 顺序 | ✓ 完整控制 |
| TLS ClientHello curves 顺序 | ✓ 完整控制 |
| TLS ALPN | ✓ |
| TLS 签名算法顺序 | ✓ |
| HTTP 常规 header 顺序 | ✓ Vec 保证顺序 |
| HTTP sec-ch-ua / sec-fetch-* 内容 | ✓ 从 profile extra 读取 |
| H2 SETTINGS INITIAL_WINDOW_SIZE | ✓ |
| H2 SETTINGS MAX_FRAME_SIZE | ✓ |
| H2 连接级 WINDOW_UPDATE | ✓ |
| H2 SETTINGS ENABLE_PUSH | ✗ 无法通过 hyper 设置 |
| H2 SETTINGS HEADER_TABLE_SIZE | ✗ 无法通过 hyper 设置 |
| H2 伪头顺序 | ✗ hyper 固定顺序，无法自定义 |
