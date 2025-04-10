# RequestSession

A powerful Python requests session wrapper with advanced features for proxy management, session persistence, and request logging.

[![PyPI version](https://img.shields.io/pypi/v/requestsession.svg)](https://pypi.org/project/requestsession/)
[![Python versions](https://img.shields.io/pypi/pyversions/requestsession.svg)](https://pypi.org/project/requestsession/)
[![License](https://img.shields.io/github/license/yourusername/requestsession.svg)](https://github.com/yourusername/requestsession/blob/main/LICENSE)

## Features

- 🌐 Proxy Management: Easy configuration of proxies with support for random rotation or fixed proxy per session
- 💾 Session Persistence: Save and load sessions with cookies and headers, eliminating repetitive setup
- 📝 Comprehensive Logging: Detailed request and response tracking with intelligent formatting and visualization
- 🍪 Advanced Cookie Handling: Automatic domain-based cookie management and updates across different domains
- 🔄 Request History: Track all requests with detailed metadata and exportable request chains for analysis
- 🔧 Auto Headers: Automatic configuration of common headers like Host, Referer, and Origin, preventing resource access issues across different domains
- 🚀 Simplified Workflow: Eliminates the hassle of manually building request signatures and managing session state

These features make RequestSession an ideal tool for web scraping, API testing, and automated browsing tasks where consistency and detailed tracking are essential.

## Installation

```bash
pip install requestsession
```

## Quick Start

- simple 1
```python
from requestsession import RequestSession

# Create a new session
session = RequestSession()
# Initialize with random base headers
session.initialize_session()
# print log
session.print_log = True

print("Current session headers:", session.headers)
session.get("https://google.com")
```

![example 1](assets/example1.png)


```python
from requestsession import RequestSession

# Create a new session
session = RequestSession()

# Initialize with random headers
session.initialize_session(random_init=True)

# Enable proxy
session.set_proxy(use_proxy=True, random_proxy=True)

# Make a request
response = session.get("https://example.com")

# Save the session for later use
session.save_session(_id="my_session")

# Load a saved session
loaded_session = RequestSession.load_session("tmp/http_session/my_session.json")
```

## Advanced Usage

### Proxy Configuration

```python
# Configure a session with custom proxy settings
session = RequestSession(
    config={
        "host": "127.0.0.1",
        "port": "8080",
        "enabled": True,
        "random_proxy": True,
        "proxy_file": "path/to/proxies.txt"
    }
)

# Use a custom proxy method
def get_my_proxy():
    return "http://user:pass@proxy.example.com:8080"

session = RequestSession(proxy_method=get_my_proxy)
```

### Session Management

```python
# Save the current session
session.save_session(_id="my_saved_session")

# Load a previously saved session
loaded_session = RequestSession.load_session("tmp/http_session/my_saved_session.json")

# Get all cookies for a specific domain
domain_cookies = session.get_cookies_for_domain("example.com")

# Export cookies as a string for use in other tools
cookie_string = session.get_cookies_string(domain="example.com")
```

### Request History and Logging

```python
# Enable detailed logging
session.set_print_log(True)

# Make some requests
session.get("https://example.com/page1")
session.post("https://example.com/api", json={"key": "value"})

# Get the last 5 requests
recent_requests = session.get_request_history(limit=5)

# Filter requests by status code
successful_requests = session.get_request_history(
    filter_func=lambda r: r["status_code"] == 200
)

# Export request history to a file
session.export_request_chain(filepath="request_history.json")

# Clear request history
session.clear_history()
```

### Cookie Management

```python
# Set cookies from a dictionary
session.set_cookies({
    "session_id": "abc123",
    "user_preferences": "dark_mode"
})

# Set cookies with full details
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

# Set cookies from a string
session.set_cookies("name1=value1; name2=value2")
```

## Configuration

The RequestSession can be configured with the following options:

| Option | Description | Default |
|--------|-------------|---------|
| host | Proxy host | From config.ini |
| port | Proxy port | From config.ini |
| enabled | Enable proxy | Based on config.ini |
| random_proxy | Rotate proxies randomly | False |
| print_log | Enable detailed logging | Based on config.ini |
| proxy_file | File with proxy list | "static/proxies.txt" |
| max_history_size | Maximum number of requests to keep in history | 100 |
| auto_headers | Automatically set common headers | False |
| user_agents_file | File with user agents | "static/useragents.txt" |
| languages_file | File with Accept-Language values | "static/language.txt" |
| work_path | Path for saving sessions and logs | "tmp/http_session" |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License - see the LICENSE file for details.