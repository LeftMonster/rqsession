# Profile 工具：tls_peet_to_profile.py

**最后更新：** 2026-04-30  
**文件位置：** `tools/tls_peet_to_profile.py`

---

## 用途

将 `tls.peet.ws/api/all` 接口返回的 JSON（包含 TLS ClientHello + HTTP/2 帧数据）自动转换为 rqsession 的 BrowserProfile JSON 格式。  
解决了手动写 profile 时需要逐字段对照、容易出错的问题。

---

## 工作流程

1. 在真实浏览器里访问 `https://tls.peet.ws/api/all`（或用 API 抓取）
2. 保存返回的 JSON
3. 运行转换工具生成 profile

---

## 使用方法

```bash
# 从文件转换，输出到 stdout
python tools/tls_peet_to_profile.py input.json -n chrome136_windows

# 保存到指定路径
python tools/tls_peet_to_profile.py input.json -n chrome136_windows -o my_profile.json

# 直接安装到内置 profiles 目录（可立即使用）
python tools/tls_peet_to_profile.py input.json -n chrome136_windows --install

# 从 stdin 读取
curl https://tls.peet.ws/api/all | python tools/tls_peet_to_profile.py -n chrome136_windows --install
```

参数说明：

| 参数 | 说明 |
|---|---|
| `input` (positional, 可选) | tls.peet.ws JSON 文件路径；省略时从 stdin 读 |
| `-n/--name` | Profile 名称（必填），如 `chrome136_windows` |
| `-o/--output` | 输出文件路径；省略则输出 stdout |
| `--install` | 写入 `rqsession/rust_session/profiles/builtin/<name>.json` |

---

## 字段映射

### TLS 配置（`tls` 块）

| tls.peet.ws 字段 | → Profile 字段 | 处理 |
|---|---|---|
| `ciphers[]` | `tls.cipher_suites` | 直接用 IANA 名，无需转换 |
| `extensions[supported_groups].supported_groups` | `tls.curves` | 名称标准化（X25519→x25519，P-256→secp256r1 等） |
| `extensions[signature_algorithms].signature_algorithms` | `tls.signature_algorithms` | 直接使用 |
| `extensions[application_layer_protocol_negotiation].protocols` | `tls.alpn` | 直接使用；无此扩展时默认 `["h2", "http/1.1"]` |
| `extensions[supported_versions].versions` | `tls.min_version` / `tls.max_version` | 从版本列表取 min/max |

Curve 名称映射表（tls.peet.ws → profile）：

| 原始名 | Profile 名 |
|---|---|
| X25519 (29) | x25519 |
| P-256 (23) | secp256r1 |
| P-384 (24) | secp384r1 |
| P-521 (25) | secp521r1 |
| X448 | x448 | BoringSSL 不支持，WARN-drop |
| ffdhe2048 | ffdhe2048 | BoringSSL 不支持，WARN-drop |
| ffdhe3072 | ffdhe3072 | BoringSSL 不支持，WARN-drop |

> **注意**：GREASE 值（如 `TLS_GREASE (0x0A0A)`、`tls_grease`）静默跳过（由 `grease: true` 自动处理）。未知/不支持的值会在首次请求时打印 `[rqsession] WARN: unsupported curve dropped: "..."` 并跳过，JA3/JA4 指纹与真实浏览器会有差异。`x25519mlkem768`（Edge 147 / Chrome 131+）已在 boring 5.x 升级后完整支持，不再触发 WARN。详见 `tls_extension_fix.md`。

### HTTP/2 配置（`http2` 块）

从 `http2.sent_frames` 解析：

| 帧类型 | → Profile 字段 | 说明 |
|---|---|---|
| `SETTINGS` 帧 | `http2.settings` + `http2.settings_order` | 值和出现顺序都被记录 |
| `WINDOW_UPDATE` 帧（stream_id=0） | `http2.window_update` | 连接级窗口更新值 |
| `PRIORITY` 帧 | `http2.priority_frames` | 仅在浏览器实际发送时才出现 |
| `HEADERS` 帧（首批 `:` 头） | `http2.pseudo_header_order` | 伪头顺序 |

**`settings_order`**：记录 SETTINGS 参数在帧中的实际出现顺序，用于精确复现浏览器发送的 SETTINGS 帧字节序列。若为空列表则使用 h2 crate 默认顺序。

**`priority_frames`**：
- 仅当浏览器发送了 PRIORITY 帧时才写入
- 旧版 Chromium（约 Chrome ≤ 101）会发送，新版（Chrome 102+）已移除
- Chrome 119/120、Edge 142/147 等现代版本均**不发送** PRIORITY 帧
- Safari、Firefox 从未使用此机制

fallback：若 `sent_frames` 为空，解析 `akamai_fingerprint` 字符串（格式：`SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_ORDER`），其中 PRIORITY 段格式为 `stream_id:exclusive:dep_id:weight`（weight 为 1-256 RFC 值，工具自动减 1 转换为 0-255）。

### Headers 配置（`headers` 块）

从 HEADERS 帧的 header 列表提取（跳过 cookie、host）：

| 处理规则 | 说明 |
|---|---|
| `accept` / `accept-language` / `accept-encoding` | 提取为命名字段 |
| `user-agent` | 从 `user_agent` 顶层字段读取 |
| 其他 header | 放入 `extra` 字典 |
| `order` | 按帧中实际出现顺序记录 |

---

## Profile JSON 完整字段说明

```jsonc
{
  "name": "chrome120_windows",
  "user_agent": "...",
  "tls": {
    "min_version": "1.2",
    "max_version": "1.3",
    "cipher_suites": ["TLS_AES_128_GCM_SHA256", ...],  // GREASE 值会被跳过
    "curves": ["x25519", "secp256r1", "secp384r1"],     // GREASE/未知值会打 WARN 并跳过
    "signature_algorithms": ["ecdsa_secp256r1_sha256", ...],
    "alpn": ["h2", "http/1.1"],  // 必须用 "h2"，不能用 "http/2"
    "grease": true,              // Chrome/Edge = true，Firefox/Safari 省略或 false
    "alps": ["h2"],              // Chrome/Edge 专有；Firefox/Safari 省略
    "ocsp_stapling": true,       // Chrome/Edge = true；Firefox/Safari 省略或 false
    "sct": true,                 // Chrome/Edge = true；Firefox/Safari 省略或 false
    "cert_compression": ["zlib", "brotli"]  // Chrome/Edge；Firefox/Safari 省略
  },
  "http2": {
    "settings": { "HEADER_TABLE_SIZE": 65536, ... },
    "settings_order": ["HEADER_TABLE_SIZE", "ENABLE_PUSH", ...],  // 控制帧内字节顺序
    "window_update": 15663105,
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
    "priority_frames": [   // 可选，大多数现代浏览器无此字段
      {"stream_id": 3, "dependency": 0, "weight": 200, "exclusive": false}
    ]
  },
  "headers": {
    "accept": "...",
    "accept_language": "...",
    "accept_encoding": "...",
    "order": ["sec-ch-ua", "user-agent", ...],
    "extra": { "sec-ch-ua": "...", ... }
  }
}
```

---

## 常见错误

| 错误 | 原因 | 修复 |
|---|---|---|
| TLS 协商失败 / 400 Bad Request | `alpn` 写了 `"http/2"` 而非 `"h2"` | 改为 `"h2"`，这是 RFC 7540 规定的 ALPN 标识符 |
| Cloudflare 403 `"Request blocked by security policy."` | TLS 扩展集合与真实浏览器不符（JA4 不匹配） | Chromium profile 需要加 `ocsp_stapling`/`sct`/`cert_compression` 字段；详见 `tls_extension_fix.md` |
| Cloudflare 403 | PRIORITY frames 发送错误（如给 Chrome 102+ 加了旧版 PRIORITY 树） | 删除 `priority_frames` 字段 |
| Cloudflare 403 | kick.com 等站点还需要有效 session cookie | 需要先通过 Cloudflare Challenge 流程建立 session |

---

## 使用限制

- 需要用**真实浏览器**访问 tls.peet.ws 采集数据；用 curl 或 requests 采集到的数据反映的是 curl/requests 的指纹，不是浏览器的
- `extra` 里的 sec-ch-ua 等头含有浏览器版本信息，新版本 profile 需要手动更新这些值
- tls.peet.ws 不总是能捕获完整的 HTTP/2 SETTINGS 帧（某些网络环境下），此时 akamai_fingerprint 作为 fallback
- GREASE 值（随机化的 TLS 扩展 ID）无法通过静态 profile 复现，cipher_map.rs 会静默跳过

---

## 添加新 Profile 完整流程

```
1. 打开 Chrome/Firefox/Edge（真实浏览器）
2. 访问 https://tls.peet.ws/api/all → 保存 JSON（如 chrome136.json）
3. python tools/tls_peet_to_profile.py chrome136.json -n chrome136_windows --install
4. 在 rqsession/rust_session/profiles/__init__.py 添加：
   Chrome136 = _ProfileProxy("chrome136_windows")
5. 在 rqsession/rust_session/__init__.py 导出 Chrome136
6. 重新构建（maturin develop）后即可使用：
   from rqsession.rust_session import BrowserSession, Chrome136
```
