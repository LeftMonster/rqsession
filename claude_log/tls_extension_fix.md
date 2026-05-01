# TLS 扩展缺失导致 Cloudflare 拦截 — 诊断与修复

**日期：** 2026-04-30

---

## 问题现象

Chrome120、Edge142、Edge147 向 `web.kick.com`（Cloudflare 保护）发请求返回 403，Firefox133、Safari17 正常 200。

两种 403 body 不同：

| Profile | 403 body | 层级 |
|---|---|---|
| Chrome / Edge | `{"error":"Request blocked by security policy."}` | Cloudflare Bot Management 拦截 |
| Firefox / Safari（无 token）| `{"data":{"type":"Forbidden"}}` | 应用层 auth 拒绝 |

Firefox / Safari 加 Bearer token 后正常返回 200，说明它们能通过 Cloudflare 指纹检查，只是缺认证。

---

## 根本原因

通过 `tls.browserleaks.com/json` 获取实际 JA3 后对比发现：

| | 扩展数 | 扩展列表 |
|---|---|---|
| 我们的 Chrome120 | 12 | `0-23-65281-10-11-35-16-13-51-45-43-21` |
| 真实 Chrome 120 | 16 | `0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21` |

少了 4 个扩展：

| ID | 名称 | 说明 |
|---|---|---|
| 5 | status_request | OCSP stapling，Chrome 必发 |
| 18 | signed_certificate_timestamp | SCT，Chrome 必发 |
| 27 | compress_certificate | 证书压缩，Chrome 发 zlib+brotli |
| 17513 | application_settings | ALPS，Chrome/Edge 专有 |

Cloudflare 的 JA4 对比：`t13d1512h2_...`（12 扩展）不匹配任何已知 Chrome 浏览器 JA4，直接拦截。Firefox/Safari 本身不使用这 4 个扩展，我们的实现碰巧与真实 Firefox/Safari 接近，能通过。

ALPS（17513）虽然代码已有 `SSL_add_application_settings` 调用，但因返回值未检查，静默失败（或 JA3 服务未捕获），修复后才正常出现。

---

## 修复内容

### 1. `src/profile.rs` — `TlsConfig` 新增三字段

```rust
#[serde(default)]
pub ocsp_stapling: bool,        // 控制 status_request 扩展（id 5）

#[serde(default)]
pub sct: bool,                  // 控制 SCT 扩展（id 18）

#[serde(default)]
pub cert_compression: Vec<String>,  // 证书压缩算法（id 27），如 ["zlib", "brotli"]
```

三个字段均带 `#[serde(default)]`，旧 profile JSON 不填时默认 false/空，向后兼容。

### 2. `src/tls_builder.rs` — 新增三个扩展的配置

新增两个 `CertificateCompressor` 实现：

- `ZlibCertDecompressor`：`ALGORITHM = ZLIB`，只实现 decompress（客户端只需接收压缩证书）
- `BrotliCertDecompressor`：`ALGORITHM = BROTLI`，同上

在 `build_ssl_connector` 中对应调用：

```rust
if config.ocsp_stapling { builder.enable_ocsp_stapling(); }
if config.sct           { builder.enable_signed_cert_timestamps(); }
for alg in &config.cert_compression {
    match alg.as_str() {
        "zlib"   => builder.add_certificate_compression_algorithm(ZlibCertDecompressor)?,
        "brotli" => builder.add_certificate_compression_algorithm(BrotliCertDecompressor)?,
        other    => return Err(Error::Tls(format!("unsupported cert compression: {other}"))),
    }
}
```

### 3. `src/http_client.rs` — ALPS 返回值检查

`configure_alps()` 之前不检查 `SSL_add_application_settings` 返回值，静默失败。修复为：

```rust
let ret = unsafe { boring_sys::SSL_add_application_settings(...) };
if ret != 1 {
    eprintln!("[rqsession] WARN: SSL_add_application_settings failed for {proto:?} (ret={ret})");
}
```

### 4. Chromium profile JSON — 新增三个字段

`chrome120_windows.json`、`edge142_windows.json`、`edge147_windows.json` 的 `tls` 块加入：

```json
"ocsp_stapling": true,
"sct": true,
"cert_compression": ["zlib", "brotli"]
```

Firefox133、Safari17 不加（这两个扩展本就不属于它们的指纹）。

### 5. `src/cipher_map.rs` — 静默丢弃改为 WARN

`split_cipher_lists`（密码套件）和 `curves_to_groups_list`（curves）对不支持的值原来静默跳过，现在改为打印 WARN，GREASE 值（含 `"grease"` / `"GREASE"` 字符串）仍静默跳过。

```
[rqsession] WARN: unsupported cipher suite dropped: "xxx"
[rqsession] WARN: unsupported curve dropped: "x25519mlkem768"
```

Warning 在首次请求时触发（connector 构建时），创建 `BrowserSession` 本身不触发。

---

## 修复结果

修复后 Chrome120 JA3：

```
771,4865-...,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
```

JA4：`t13d1516h2_8daaf6152771_e5627efa2ab1`（16 扩展，匹配真实 Chrome 120）

所有 5 个 profile（Chrome120、Edge142、Edge147、Firefox133、Safari17）均返回 200。

---

## x25519mlkem768 支持（已修复，2026-04-30）

Edge147 profile 中的 `"x25519mlkem768"`（Chrome 131+ / Edge 131+ 使用的后量子 KEM，curve id 4588 / 0x11EC）已完整支持。

**修复内容：**

1. **`Cargo.toml`** — 将 boring / boring-sys / tokio-boring 从 `"4"` 升级到 `"5"`。boring 5.x 新增了 `X25519MLKEM768`（id 4588）支持。

2. **`src/tls_builder.rs`** — boring 5.x 唯一 breaking change：`SslMethod::tls_client()` 重命名为 `SslMethod::tls()`，已更新。

3. **`src/cipher_map.rs`** — `curve_name_to_group` 新增两条映射：
   ```rust
   "x25519kyber768draft00" | "x25519kyber768" => Some("X25519Kyber768Draft00"),
   "x25519mlkem768" => Some("X25519MLKEM768"),
   ```

**验证结果：** Edge147 实际发出的 JA3 curves 段为 `4588-29-23-24`，其中 4588 即 x25519mlkem768，与真实 Edge 147 指纹一致。所有 5 个 profile 在 kick.com 均返回 200，无 WARN 输出。

---

## Firefox146 ffdhe 曲线问题（已修复，2026-04-30）

### 问题现象

新增 `firefox146_windows.json` profile 后请求报错：

```
ConnectionError: [UNSUPPORTED_ELLIPTIC_CURVE]
```

### 根本原因

Firefox 146 真机的 `supported_groups` 中包含 `ffdhe2048` 和 `ffdhe3072`（FFDHE 有限域 DH 组）。这两个名称在 `cipher_map.rs` 中有映射，会被传入 BoringSSL 的 `set_curves_list()`，但 **BoringSSL 从未支持 FFDHE 组**（Chrome 不用 FFDHE，BoringSSL 直接砍掉了整套 DHE），导致 `set_curves_list` 返回错误。

### 修复内容

`src/cipher_map.rs` 的 `curve_name_to_group` 中删除以下两行：

```rust
"ffdhe2048" => Some("ffdhe2048"),
"ffdhe3072" => Some("ffdhe3072"),
```

删除后这两个值走已有的 WARN-drop 路径，首次请求时会打印：

```
[rqsession] WARN: unsupported curve dropped: "ffdhe2048"
[rqsession] WARN: unsupported curve dropped: "ffdhe3072"
```

Firefox146 其余 5 个 curves（x25519mlkem768、x25519、secp256r1、secp384r1、secp521r1）均有效，不影响其他 profile。

### FFDHE 指纹差异

Firefox 真机发送 `ffdhe2048` / `ffdhe3072`，我们的实现无法复现这两个组。这是 BoringSSL 的能力边界，不可修复，只能接受。详见 `tls_fingerprint_libs.md`。

---

## py37_aiohttp381 profile 决策（2026-04-30）

新增 `py37_aiohttp381_windows.json` profile 存在两个 BoringSSL 不支持的问题：

1. `curves` 中有 `"x448"`（BoringSSL 不支持 X448）
2. `signature_algorithms` 中有 hex 格式的算法 ID（`"0x303"` 等，对应 SHA-224 和 DSA 变种，BoringSSL 不支持）

**决策：不修复，也不使用此 profile。** 原因：aiohttp 是 Python HTTP 客户端的 TLS 指纹，属于脚本流量，与本库"模拟浏览器指纹"的定位不符。如需模拟 aiohttp 行为，直接用 aiohttp 本身即可。
