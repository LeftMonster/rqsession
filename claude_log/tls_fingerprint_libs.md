# TLS 指纹库：BoringSSL 限制与替代方案研究计划

**创建：** 2026-04-30  
**状态：** 待研究

---

## 当前方案

本库使用 `boring` crate（BoringSSL Rust 绑定）作为 TLS 底层。BoringSSL 是 Chrome/Chromium 的 TLS 库，对复现 Chromium 系浏览器指纹效果最好。

---

## BoringSSL 已确认的能力边界

| 不支持的特性 | 影响的浏览器 | 说明 |
|---|---|---|
| FFDHE 组（ffdhe2048/3072） | Firefox | BoringSSL 砍掉了整套 DHE，Chrome 不用 |
| X448 曲线 | Python/aiohttp | BoringSSL 只实现 X25519 |
| DHE 密码套件（TLS_DHE_RSA_WITH_*） | 老式客户端 | 同上，DHE 全系删除 |
| DSA 相关签名算法 | 老式客户端 | BoringSSL 不支持 DSA |

**对 Chrome/Edge 指纹复现无影响**（Chrome 本身就用 BoringSSL，不用上述特性）。

对 Firefox 的影响：FFDHE 组无法复现，其余 Firefox 特性（cipher 顺序、sigalgs、H2 参数）均可正常复现。

---

## 潜在限制（未验证，待研究）

### 1. ClientHello 扩展顺序控制

JA4 和 Akamai 指纹会检测 TLS 扩展的排列顺序。当前 BoringSSL 内部对扩展顺序是固定的，boring crate 没有暴露控制接口。

**待验证：** boring crate / BoringSSL 是否允许自定义扩展顺序？当前实现的扩展顺序与真实 Chrome/Firefox 是否一致？

### 2. ECH（Encrypted Client Hello）

Firefox 146 开始在支持 ECH 的服务器上使用 ECH，Chrome 也在逐步推进。

**待验证：** boring crate 是否支持 ECH？现阶段 ECH 对指纹检测的影响有多大？

---

## 替代库方案（待评估）

### openssl crate（OpenSSL Rust 绑定）

- **优势**：支持 FFDHE 组、X448、DHE 套件，比 BoringSSL 覆盖面更广，复现 Firefox 更完整
- **劣势**：不支持 GREASE、ALPS（Chrome 专有扩展），扩展顺序同样无法自定义
- **适用场景**：需要精确复现 Firefox 指纹时，可考虑用 openssl crate 替换 boring 单独处理 Firefox profile
- **参考**：`openssl` crate，https://crates.io/crates/openssl

### rustls（纯 Rust TLS 实现）

- **优势**：纯 Rust，无 C 依赖，理论上控制粒度最细（可 patch）
- **劣势**：没有 GREASE、ALPS 等指纹特性，开箱即用效果差，需大量额外开发
- **参考**：https://crates.io/crates/rustls

### uTLS 思路（Go 生态）

Go 生态的 uTLS 是目前指纹复现做得最彻底的方案，核心思路：**绕过 TLS 库，逐字节构造 ClientHello**，然后把后续握手交回 TLS 库。这样可以完全控制扩展顺序、扩展值、GREASE 位置等一切字节级细节。

**Rust 侧等价方案：** 目前没有已知的成熟 Rust 库做到 uTLS 这一层。如果需要做到这一粒度，思路是手写 ClientHello 序列化，借助 BoringSSL/OpenSSL 的底层 SSL BIO 接口注入，工程量较大。

- **参考**：https://github.com/refraction-networking/utls（Go）
- **参考**：curl-impersonate（每个浏览器用各自的 TLS 库分别编译，Linux/macOS only）

### NSS（Firefox 实际 TLS 库）

Firefox 的 TLS 底层是 NSS（Network Security Services，Mozilla 维护的 C 库）。理论上用 NSS 能完整复现 Firefox 指纹，但：

- Rust 绑定质量不明，没有维护良好的 crate
- 跨平台构建复杂
- **当前不推荐**，除非有专门复现 Firefox 完整指纹的强需求

---

## 结论与建议

- **短期**：当前 BoringSSL 方案对 Chrome/Edge 指纹已足够，Firefox 差 FFDHE 两个组，实际影响有限（指纹检测能否识别这个差异，取决于目标站点）
- **中期**：若遇到 Firefox 指纹被拦截，可评估 openssl crate 路线，可能通过多后端（Chrome 用 boring，Firefox 用 openssl）的方式解决
- **长期/高精度需求**：uTLS 思路（逐字节 ClientHello 控制）是终极方案，但工程量大，目前 Rust 生态没有现成库
