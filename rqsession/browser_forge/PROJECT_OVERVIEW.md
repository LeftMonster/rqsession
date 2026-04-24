# Browser Forge - 项目概览

## 🎯 项目简介

Browser Forge是一个高级Python HTTP客户端库，专为需要精确控制浏览器指纹的场景设计。它基于curl_cffi，提供了对TLS指纹、HTTP/2设置、请求头部顺序等的完全控制，能够有效绕过Cloudflare、Akamai、Kasada等高级反爬虫系统。

## ✨ 核心特性

### 🎭 浏览器指纹模拟
- 精确的TLS指纹控制（cipher suites, curves, extensions等）
- JA3/JA4指纹生成和验证
- HTTP/2 settings精确配置
- 严格的HTTP头部顺序控制

### 🔧 灵活配置
- 4个预设浏览器配置（Chrome 119/120, Firefox 120, Safari 17）
- 完全自定义的配置系统
- JSON/YAML配置文件支持
- 配置克隆和随机化

### 🚀 强大功能
- 同步HTTP客户端（异步版本在阶段二）
- 代理支持（HTTP/HTTPS/SOCKS）
- Cookie自动管理
- 会话复用
- 上下文管理器支持

### 🛡️ 反检测能力
- TLS指纹随机化
- 头部顺序严格匹配真实浏览器
- 支持curl_cffi的impersonate模式
- 可针对特定反爬系统调优

## 📊 项目统计

```
总文件数: 15个Python文件 + 3个文档
代码行数: ~2000行
测试覆盖: 基础功能测试完成
依赖数量: 2个核心依赖
```

## 📁 项目结构

```
browser_forge/
├── 📄 README.md                    # 项目说明
├── 📄 INSTALLATION.md              # 安装指南
├── 📄 PHASE1_SUMMARY.md            # 阶段一总结
├── 📄 requirements.txt             # 依赖列表
├── 📄 test_quick.py                # 快速测试
│
├── 📦 core/                        # 核心功能模块
│   ├── __init__.py
│   ├── client.py                  # BrowserClient主类
│   └── header_builder.py          # 头部构建器
│
├── 📦 profiles/                    # 配置文件模块
│   ├── __init__.py
│   ├── models.py                  # 数据模型定义
│   └── presets.py                 # 预设浏览器配置
│
├── 📦 fingerprint/                 # 指纹工具模块
│   ├── __init__.py
│   ├── tls_builder.py             # TLS配置构建器
│   └── ja3_generator.py           # JA3/JA4生成器
│
└── 📦 examples/                    # 示例代码
    └── basic_usage.py             # 10个实用示例
```

## 🔑 核心组件

### 1. BrowserClient
主要的HTTP客户端类，提供：
- 所有HTTP方法（GET/POST/PUT/DELETE等）
- 代理支持
- Cookie管理
- TLS指纹控制
- 头部管理

### 2. BrowserProfile
浏览器配置文件，包含：
- User-Agent
- TLS配置
- HTTP/2设置
- 头部配置
- 行为配置

### 3. JA3/JA4 Generator
TLS指纹工具：
- 生成JA3字符串和哈希
- 生成JA4指纹
- 指纹分析和对比

### 4. HeaderBuilder
智能头部构建器：
- 浏览器特定的头部顺序
- 自动添加必需头部
- 支持自定义头部

## 🎓 使用示例

### 基础用法
```python
from browser_forge import BrowserClient, Chrome119

with BrowserClient(profile=Chrome119) as client:
    response = client.get("https://example.com")
    print(response.status_code)
```

### 高级用法
```python
from browser_forge import BrowserClient, Chrome119

# 自定义配置
custom = Chrome119.clone()
custom.tls_config.curves = ["x25519", "secp384r1"]

# 创建客户端
client = BrowserClient(
    profile=custom,
    proxy="http://proxy:8080",
    randomize_tls=True,
    timeout=30
)

# 发送请求
response = client.get("https://example.com")
```

### JA3指纹
```python
from browser_forge import JA3Generator, Chrome119

ja3_string, ja3_hash = JA3Generator.generate_ja3(
    Chrome119.tls_config
)
print(f"JA3: {ja3_hash}")
```

## 📈 性能特点

| 特性 | 说明 |
|------|------|
| 请求延迟 | ~50-200ms（取决于网络） |
| TLS握手 | 完全模拟真实浏览器 |
| HTTP/2 | 原生支持 |
| 连接复用 | 通过curl_cffi自动管理 |
| 内存占用 | ~10-50MB（取决于使用） |

## 🎯 适用场景

### ✅ 适合
- Web自动化测试
- 数据采集（遵守robots.txt）
- API测试
- 安全研究
- 性能测试

### ⚠️ 注意
- 必须遵守网站TOS
- 必须遵守robots.txt
- 仅用于合法用途
- 尊重速率限制

## 🛠️ 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| Python | 3.7+ | 主语言 |
| curl_cffi | 0.5.0+ | TLS/HTTP控制 |
| pyyaml | 6.0+ | YAML支持 |

## 📊 开发进度

### ✅ 已完成（阶段一）
- [x] 数据模型设计
- [x] 预设浏览器配置
- [x] TLS配置构建器
- [x] JA3/JA4生成器
- [x] 同步HTTP客户端
- [x] 头部管理器
- [x] 配置文件支持
- [x] 基础文档
- [x] 测试脚本

### 🚧 计划中（阶段二）
- [ ] 异步客户端（asyncio）
- [ ] HTTP/2 settings精确控制
- [ ] 时间延迟模拟
- [ ] 指纹随机化增强
- [ ] 连接池管理
- [ ] 检测验证工具
- [ ] 更多预设配置
- [ ] 性能优化

### 🔮 未来计划（阶段三）
- [ ] WebSocket支持
- [ ] HTTP/3 (QUIC)
- [ ] 浏览器行为模拟
- [ ] Canvas指纹
- [ ] WebGL指纹
- [ ] GUI配置工具

## 🤝 贡献指南

### 代码风格
- PEP 8规范
- 类型注解
- 文档字符串
- 单元测试

### 提交流程
1. Fork项目
2. 创建功能分支
3. 编写测试
4. 提交PR

## 📚 学习资源

### TLS指纹
- [JA3 GitHub](https://github.com/salesforce/ja3)
- [JA4 Specification](https://github.com/FoxIO-LLC/ja4)
- [TLS Fingerprinting](https://tlsfingerprint.io/)

### HTTP/2
- [HTTP/2 Specification](https://httpwg.org/specs/rfc7540.html)
- [HTTP/2 Settings](https://httpwg.org/specs/rfc7540.html#SETTINGS)

### 反爬虫
- [Cloudflare Bot Detection](https://developers.cloudflare.com/bots/)
- [Akamai Bot Manager](https://www.akamai.com/products/bot-manager)

## 🔒 安全考虑

### 建议
1. ✅ 验证SSL证书
2. ✅ 使用环境变量存储凭证
3. ✅ 限制请求频率
4. ✅ 日志脱敏
5. ✅ 定期更新依赖

### 警告
1. ⚠️ 不要在公共代码中暴露代理凭证
2. ⚠️ 不要用于非法目的
3. ⚠️ 注意GDPR等隐私法规
4. ⚠️ 遵守网站TOS

## 📞 支持

### 文档
- README.md - 项目说明
- INSTALLATION.md - 安装指南
- PHASE1_SUMMARY.md - 功能总结

### 示例
- examples/basic_usage.py - 10个实用示例
- test_quick.py - 快速测试

## 📄 许可

MIT License

## 🙏 致谢

- curl_cffi项目
- JA3/JA4规范作者
- Python社区

---

**版本**: 0.1.0 (阶段一)
**作者**: Sherlock
**最后更新**: 2024

**Browser Forge - 让HTTP请求像真实浏览器一样！** 🚀
