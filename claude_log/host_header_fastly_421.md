# Host Header 缺失导致 Fastly 421 SAN mismatch

**日期：** 2026-08-14  
**影响范围：** `BrowserSession` / `AsyncBrowserSession` Rust 核默认请求头构造

---

## 现象

请求 `https://k.twitchcdn.net/` 时，rqsession 所有 Chrome / Edge profile 稳定返回：

```
421 Requested host does not match any Subject Alternative Names (SANs) on TLS certificate
```

同一机器、同一代理或直连条件下，`curl_cffi` 的 Chrome impersonate 返回正常的 `404`。
`rqsession` 请求 `www.twitch.tv` / `gql.twitch.tv` 等其他 Fastly 域名正常。

---

## 根因

Rust 核默认 header 构造只按 profile 的 `headers.order` 发送浏览器头，没有自动注入 `Host`。

大多数目标容忍缺失或由 HTTP 栈补齐，但 `k.twitchcdn.net` 的 Fastly 边缘会根据请求 Host / 连接证书关系做严格校验。缺失 Host 时，请求被路由到不匹配该域名证书的边缘虚拟主机，返回 421 SAN mismatch。

手动传入：

```python
s.get("https://k.twitchcdn.net/", headers={"host": "k.twitchcdn.net"})
```

即可从 421 变为正常 404，确认问题不是 ECH、profile 版本、代理、连接复用或 H2 SETTINGS。

---

## 修复

`src/lib.rs` 的同步 / 异步默认 headers 构造改为从 URL authority 自动注入：

```
host: <authority>
```

用户仍可通过请求级 `headers={"host": "..."}` 覆盖，或通过 `remove_headers=["host"]` 显式移除。

---

## 验证

```powershell
D:\anaconda\python.exe -m pytest tests\test_host_header.py tests\test_remove_headers.py tests\test_allow_redirects.py -q
cargo check
D:\anaconda\python.exe E:\github\vmwatch\kasada\workspace\tests\test_rqsession_ktwitch.py
D:\anaconda\python.exe E:\github\vmwatch\kasada\workspace\tests\test_rqsession_ktwitch.py --no-proxy
```

结果：

- 本地测试：`16 passed`
- `cargo check`：通过
- `k.twitchcdn.net`：代理 / 直连下 Chrome147/138/120/119/Edge147 均从 `421` 变为 `404`
