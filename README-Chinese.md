# RequestSession

一个功能强大的 Python requests 会话封装库，提供代理管理、会话持久化和请求日志记录等高级功能。

[![PyPI version](https://img.shields.io/pypi/v/rqsession.svg)](https://pypi.org/project/rqsession/)
[![Python versions](https://img.shields.io/pypi/pyversions/rqsession.svg)](https://pypi.org/project/rqsession/)
[![License](https://img.shields.io/github/license/yourusername/rqsession.svg)](https://github.com/yourusername/rqsession/blob/main/LICENSE)

## 特性

- 🌐 **代理管理**：简单配置代理，支持随机轮换
- 💾 **会话持久化**：保存和加载带有 cookies 和 headers 的会话
- 📝 **全面日志记录**：详细的请求和响应跟踪
- 🍪 **高级 Cookie 处理**：基于域名的 cookie 管理
- 🔄 **请求历史**：使用详细元数据跟踪所有请求
- 🔧 **自动请求头**：自动配置常见请求头，如 Host、Referer 和 Origin

## 安装

```bash
pip install rqsession
```

## 快速开始

```python
from rqsession import RequestSession

# 创建新会话
session = RequestSession()

# 使用随机请求头初始化
session.initialize_session(random_init=True)

# 启用代理
session.set_proxy(use_proxy=True, random_proxy=True)

# 发送请求
response = session.get("https://example.com")

# 保存会话以供后续使用
session.save_session(_id="my_session")

# 加载已保存的会话
loaded_session = RequestSession.load_session("tmp/http_session/my_session.json")
```

## 高级用法

### 代理配置

```python
# 使用自定义代理设置配置会话
session = RequestSession(
    config={
        "host": "127.0.0.1",
        "port": "8080",
        "enabled": True,
        "random_proxy": True,
        "proxy_file": "path/to/proxies.txt"
    }
)

# 使用自定义代理获取方法
def get_my_proxy():
    return "http://user:pass@proxy.example.com:8080"

session = RequestSession(proxy_method=get_my_proxy)
```

### 会话管理

```python
# 保存当前会话
session.save_session(_id="my_saved_session")

# 加载之前保存的会话
loaded_session = RequestSession.load_session("tmp/http_session/my_saved_session.json")

# 获取特定域名的所有 cookies
domain_cookies = session.get_cookies_for_domain("example.com")

# 导出 cookies 字符串，可用于其他工具
cookie_string = session.get_cookies_string(domain="example.com")
```

### 请求历史和日志记录

```python
# 启用详细日志记录
session.set_print_log(True)

# 发送一些请求
session.get("https://example.com/page1")
session.post("https://example.com/api", json={"key": "value"})

# 获取最近 5 个请求
recent_requests = session.get_request_history(limit=5)

# 按状态码筛选请求
successful_requests = session.get_request_history(
    filter_func=lambda r: r["status_code"] == 200
)

# 将请求历史导出到文件
session.export_request_chain(filepath="request_history.json")

# 清除请求历史
session.clear_history()
```

### Cookie 管理

```python
# 从字典设置 cookies
session.set_cookies({
    "session_id": "abc123",
    "user_preferences": "dark_mode"
})

# 使用完整详细信息设置 cookies
session.set_cookies([
    {
        "name": "session_id",
        "value": "abc123",
        "domain": "example.com",
        "path": "/",
        "secure": True,
        "httponly": True
    }
])

# 从字符串设置 cookies
session.set_cookies("name1=value1; name2=value2")
```

## 配置选项

RequestSession 可以通过以下选项进行配置：

| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| host | 代理主机 | 来自 config.ini |
| port | 代理端口 | 来自 config.ini |
| enabled | 启用代理 | 基于 config.ini |
| random_proxy | 随机轮换代理 | False |
| print_log | 启用详细日志记录 | 基于 config.ini |
| proxy_file | 代理列表文件 | "static/proxies.txt" |
| max_history_size | 历史记录保留的最大请求数 | 100 |
| auto_headers | 自动设置常见请求头 | False |
| user_agents_file | 用户代理文件 | "static/useragents.txt" |
| languages_file | Accept-Language 值文件 | "static/language.txt" |
| work_path | 保存会话和日志的路径 | "tmp/http_session" |

## 贡献

欢迎贡献！请随时提交 Pull Request。

## 许可证

本项目采用 Apache 许可证 - 详情见 LICENSE 文件。