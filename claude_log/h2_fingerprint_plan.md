# H2 精确指纹控制 — 方案决策与实施计划

**创建时间：** 2026-04-29

---

## 背景：当前 H2 的局限

现有实现用 `hyper 1.x` 的 `http2::Builder` 处理 H2，TLS 层用 BoringSSL。TLS 指纹（JA3）已精确可控，但 H2 层被 hyper 抽象屏蔽，以下关键指纹点**无法控制**：

| 指纹要素 | 当前状态 | 检测工具是否检查 |
|---|---|---|
| SETTINGS 帧参数顺序 | hyper 内部固定，profile 值部分生效但顺序不可控 | Cloudflare、Akamai 均检查 |
| 连接级 WINDOW_UPDATE 值 | 部分支持（`window_update` 字段） | 检查 |
| PRIORITY 帧（Chrome/Edge 特有） | 完全缺失 | 检查 |
| HEADERS 帧 pseudo-header 顺序 | hyper 内部固定（`:method :path :scheme :authority`） | 检查 |
| HPACK 编码细节（literal vs indexed） | 无控制 | 部分工具检查 |

---

## 方案选型

### 方案一：curl_cffi / C impersonate 路径（否决）

**否决原因：**
- 架构冲突：项目已是 BoringSSL + hyper 纯 Rust 栈，引入 libcurl C 依赖是整体退步
- curl_cffi impersonate 本质是参数配置级模拟，SETTINGS 帧顺序、PRIORITY 帧、HPACK 编码细节仍无法精确控制
- C FFI + BoringSSL patch + Python 绑定，跨平台 CI 成本高（Windows build 已经不轻松）

### 方案二：Rust 自实现 H2 帧层（采纳）

在现有 BoringSSL TLS 之上，实现可配置的 H2 帧层，绕过 hyper 的 h2 抽象，达到帧级别精确控制。

**两条实施路径：**

| | 路径 A：Fork/patch `h2` crate | 路径 B：Raw H2 framing |
|---|---|---|
| 工作量 | 中等，外科式修改关键点 | 大，需实现流量控制、多路复用 |
| 控制粒度 | SETTINGS 顺序、PRIORITY 注入、pseudo-header 顺序 | 完全控制含 HPACK 编码细节 |
| 维护成本 | 需跟随上游 h2 crate 更新 | 自主维护 |
| 推荐场景 | 应对主流检测（Cloudflare、Akamai） | 极端精确或自定义协议需要 |

**初期采用路径 A**，先覆盖主流检测场景；若路径 A 无法满足再升级至路径 B。

---

## 目标帧序列（浏览器实际行为）

以 Chrome/Edge 为例，H2 连接建立后服务端收到的帧顺序：

```
[Client Preface: PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n]
SETTINGS (HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=6291456, MAX_FRAME_SIZE=16777215)
WINDOW_UPDATE (connection-level, increment=15663105)
HEADERS (pseudo-headers 顺序: :method :authority :scheme :path, 后跟普通 headers)
[可选 PRIORITY frames，Chrome 在某些场景发送]
```

Firefox 的 SETTINGS 顺序与 Chrome 不同，是另一套参数组合，需按 profile 分别配置。

---

## Profile JSON 扩展（规划）

在现有 `http2` 字段基础上增加精确控制字段：

```json
{
  "http2": {
    "settings_order": [
      "HEADER_TABLE_SIZE",
      "ENABLE_PUSH",
      "INITIAL_WINDOW_SIZE",
      "MAX_FRAME_SIZE"
    ],
    "settings": {
      "HEADER_TABLE_SIZE": 65536,
      "ENABLE_PUSH": 0,
      "INITIAL_WINDOW_SIZE": 6291456,
      "MAX_FRAME_SIZE": 16777215
    },
    "window_update": 15663105,
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
    "priority_frames": []
  }
}
```

`settings_order` 控制 SETTINGS 帧中参数的写入顺序（当前 hyper 无此控制）。`priority_frames` 为空列表时不发送 PRIORITY 帧（Safari/Firefox 行为）。

---

## Todo List

### Phase 1 — 调研与基准

- [ ] 用 Wireshark 或 mitmproxy 抓取目标浏览器（Chrome、Firefox、Edge、Safari）的真实 H2 握手帧序列，记录每个 SETTINGS 参数顺序、WINDOW_UPDATE 值、是否有 PRIORITY 帧
- [ ] 在 [tls.peet.ws](https://tls.peet.ws) 或类似服务验证当前实现的 H2 指纹与目标浏览器的差异点，建立基准 diff
- [ ] 确认 `h2` crate 版本（hyper 1.x 依赖的 h2 版本）及其源码中 SETTINGS 帧构造位置

### Phase 2 — h2 crate Fork/Patch

- [ ] Fork `h2` crate，在本地 Cargo.toml 用 `path` 依赖替换
- [ ] 找到 SETTINGS 帧序列化位置，修改为从外部配置读取参数顺序（`settings_order`）
- [ ] 找到 pseudo-header 顺序硬编码位置，改为从 profile 读取 `pseudo_header_order`
- [ ] 实现 PRIORITY 帧发送接口（连接建立后可注入）
- [ ] 验证修改后连接级 WINDOW_UPDATE 帧值与 profile 一致

### Phase 3 — 集成到现有 http_client.rs

- [ ] `http_client.rs` 的 `do_h2()` 替换为使用 patched h2
- [ ] `BrowserProfile` / `Http2Config` 结构体增加 `settings_order` 和 `priority_frames` 字段
- [ ] Profile JSON serde 兼容旧格式（`settings_order` 缺失时保持现有行为）
- [ ] `do_h2()` 连接建立后按 profile 注入 PRIORITY 帧

### Phase 4 — Profile 更新

- [ ] 更新所有内置 profile JSON（chrome120/119、edge142、firefox133、safari17），补充 `settings_order` 字段
- [ ] 按抓包结果校正各 profile 的 SETTINGS 参数值和顺序
- [ ] Firefox/Safari profile 的 `priority_frames` 保持空列表，Chrome/Edge 按实际填写

### Phase 5 — 验证

- [ ] 用 tls.peet.ws 或同等工具验证 H2 指纹与目标浏览器吻合
- [ ] 对 Cloudflare 保护的站点做端到端请求验证
- [ ] 跑现有测试套件确认无回归
