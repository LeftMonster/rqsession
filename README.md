# rqsession

A Python HTTP library that impersonates real browser TLS fingerprints, powered by a Rust native extension (BoringSSL + hyper + tokio).

[![PyPI version](https://img.shields.io/pypi/v/rqsession.svg)](https://pypi.org/project/rqsession/)
[![Python versions](https://img.shields.io/pypi/pyversions/rqsession.svg)](https://pypi.org/project/rqsession/)
[![License](https://img.shields.io/github/license/LeftMonster/requestsession.svg)](https://github.com/LeftMonster/requestsession/blob/main/LICENSE)

---

## What it does

Most anti-bot systems (Cloudflare, Akamai, DataDome, etc.) inspect the TLS ClientHello and HTTP/2 SETTINGS frame to distinguish scrapers from real browsers. Standard `requests` or `httpx` produce a recognizable Python fingerprint regardless of what `User-Agent` you set.

`rqsession` controls the full fingerprint stack at the Rust level:

| Layer | What is controlled |
|---|---|
| TLS ClientHello | Cipher suite order, supported groups (curves), ALPN, signature algorithms, version range |
| HTTP/2 | SETTINGS frame values (window size, max frame size), connection WINDOW_UPDATE |
| HTTP headers | Exact header order, browser-specific headers (sec-ch-ua, sec-fetch-*, etc.) |

No external proxy process required — it's a compiled `.pyd` / `.so` extension, imported directly.

---

## Installation

```bash
pip install rqsession
```

Pre-built wheels are available for **Windows x86_64** and **Linux x86_64** (Python 3.9+).  
Other platforms require a local Rust toolchain to build from the source distribution.

---

## Quick Start

### Synchronous

```python
from rqsession.rust_session import BrowserSession, Chrome120

with BrowserSession(Chrome120) as s:
    resp = s.get("https://httpbin.org/get")
    print(resp.status_code)   # 200
    print(resp.json())
```

### Async

```python
import asyncio
from rqsession.rust_session import AsyncBrowserSession, Chrome120

async def main():
    async with AsyncBrowserSession(Chrome120) as s:
        resp = await s.get("https://httpbin.org/get")
        print(resp.status_code)
        print(resp.json())

asyncio.run(main())
```

### Concurrent async requests

```python
import asyncio
from rqsession.rust_session import AsyncBrowserSession, Chrome120

async def main():
    async with AsyncBrowserSession(Chrome120) as s:
        results = await asyncio.gather(
            s.get("https://httpbin.org/get"),
            s.get("https://httpbin.org/ip"),
            s.get("https://httpbin.org/user-agent"),
        )
    for r in results:
        print(r.status_code)

asyncio.run(main())
```

---

## Built-in Browser Profiles

| Import name | Browser | OS |
|---|---|---|
| `Chrome138` | Chrome 138 | Windows |
| `Chrome120` | Chrome 120 | Windows |
| `Chrome119` | Chrome 119 | Windows |
| `Edge147` | Edge 147 | Windows |
| `Edge142` | Edge 142 | Windows |
| `Edge141` | Edge 141 | Windows |
| `Firefox146` | Firefox 146 | Windows |
| `Firefox133` | Firefox 133 | Windows |
| `Tor128` | Tor Browser 128 | Windows |
| `Safari17` | Safari 17 | macOS |
| `MacosChrome140` | Chrome 140 | macOS |
| `AndroidChrome114` | Chrome 114 | Android |
| `Py37Aiohttp381` | Python aiohttp 3.8.1 | Windows |

```python
from rqsession.rust_session import (
    BrowserSession, AsyncBrowserSession,
    Chrome138, Chrome120, Chrome119,
    Edge147, Edge142, Edge141,
    Firefox146, Firefox133,
    Tor128, Safari17, MacosChrome140,
    AndroidChrome114, Py37Aiohttp381,
)
```

Each profile carries its own cipher suite order, curves, signature algorithms, HTTP/2 settings, and header order — matching the real browser's wire behavior.

---

## Proxy Support

Both sync and async sessions accept a proxy URL at construction time:

```python
# HTTP proxy
s = BrowserSession(Chrome120, proxy="http://127.0.0.1:7890")

# Authenticated proxy
s = BrowserSession(Chrome120, proxy="http://user:pass@host:port")

# Async
async with AsyncBrowserSession(Firefox133, proxy="http://127.0.0.1:7890") as s:
    resp = await s.get("https://example.com")
```

The proxy tunnel is implemented as an HTTP CONNECT connection at the TCP level, so TLS fingerprinting applies end-to-end through the tunnel.

---

## Session API

### Constructor parameters

```python
BrowserSession(
    profile,              # built-in constant or BrowserProfile object
    *,
    proxy=None,           # "http://[user:pass@]host:port"
    verify=True,          # set False to skip SSL verification
    ca_bundle=None,       # path to CA bundle; auto-detects certifi when None
)
# AsyncBrowserSession takes the same parameters
```

### Request methods

```python
# GET
resp = s.get(url, headers={...}, params={...})

# POST — form data or JSON
resp = s.post(url, data=b"...", headers={...})
resp = s.post(url, json={"key": "value"})

# Generic
resp = s.request("PUT", url, headers={...}, json={...})

# Async versions — same signature, add `await`
resp = await s.get(url)
resp = await s.post(url, json={...})
```

### Response object

Compatible with `requests.Response` style:

```python
resp.status_code    # int
resp.text           # str (auto-decoded)
resp.content        # bytes
resp.headers        # dict[str, str]
resp.json()         # parsed JSON → dict / list
resp.ok             # True when status < 400
resp.raise_for_status()   # raises on 4xx/5xx
resp.url            # final URL after redirects
```

Response bodies are automatically decompressed (gzip, deflate, br, zstd).

### Cookies

```python
# Persist cookies manually
s.update_cookies({"token": "abc123"})

# Cookies from Set-Cookie response headers are automatically
# stored in the session and sent on subsequent requests.
```

---

## Adding Custom Browser Profiles

Capture a fingerprint from a real browser using [tls.peet.ws/api/all](https://tls.peet.ws/api/all), then convert it:

```bash
# Save output from tls.peet.ws as chrome136.json, then:
python tools/tls_peet_to_profile.py chrome136.json -n chrome136_windows --install
```

The `--install` flag writes the profile directly to `rqsession/rust_session/profiles/builtin/`.  
You can also load profiles at runtime without rebuilding:

```python
from rqsession.rust_session import BrowserSession, load_custom, load_profile_json
from rqsession._rust_core import load_profile

# From profiles/custom/<name>.json
s = BrowserSession(load_custom("my_browser"))

# From a JSON string
s = BrowserSession(load_profile_json('{"name": "...", "tls": {...}, ...}'))

# From an arbitrary file path
s = BrowserSession(load_profile("/path/to/profile.json"))

# List available profiles
from rqsession.rust_session import list_builtin, list_custom
print(list_builtin())   # ['chrome120_windows', 'firefox133_windows', ...]
print(list_custom())    # ['my_browser', ...]
```

---

## Windows asyncio note

Python 3.8+ on Windows uses `ProactorEventLoop` by default. If you see event-loop errors, switch to `SelectorEventLoop` before `asyncio.run()`:

```python
import asyncio, sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

asyncio.run(main())
```

---

## Legacy layers

Earlier versions of this library included `RequestSession` and `EnhancedRequestSession`. These layers are still available for backward compatibility:

```python
from rqsession import RequestSession          # basic requests.Session wrapper
from rqsession import EnhancedRequestSession  # routes through a local Rust proxy process
```

For new projects, use `BrowserSession` / `AsyncBrowserSession` instead — they are faster, require no external process, and provide more accurate fingerprinting.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
