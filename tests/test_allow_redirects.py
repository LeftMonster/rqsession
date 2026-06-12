"""
验证 allow_redirects 参数行为（使用本地 HTTP 服务器，无外部网络依赖）

服务端口：随机，通过 fixture 传入
- GET /redirect  → 302, Location: /target, Set-Cookie: foo=bar
- GET /target    → 200, body: OK
"""
import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from rqsession.rust_session import AsyncBrowserSession, BrowserSession, Chrome120

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# ── 本地测试服务器 ─────────────────────────────────────────────────────────────

class _RedirectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # 静默

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            host, port = self.server.server_address
            self.send_header("Location", f"http://{host}:{port}/target")
            self.send_header("Set-Cookie", "foo=bar; Path=/")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        else:
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)


@pytest.fixture(scope="module")
def redirect_server():
    server = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ── 同步测试 ──────────────────────────────────────────────────────────────────

def test_sync_default_follows_redirect(redirect_server):
    with BrowserSession(Chrome120, verify=False) as s:
        resp = s.get(f"{redirect_server}/redirect")
    assert resp.status_code == 200
    assert resp.history  # 中间有 302


def test_sync_allow_redirects_false(redirect_server):
    with BrowserSession(Chrome120, verify=False) as s:
        resp = s.get(f"{redirect_server}/redirect", allow_redirects=False)
    assert resp.status_code == 302
    assert "location" in {k.lower() for k in resp.headers}
    assert not resp.history


def test_sync_cookies_persisted_when_redirects_disabled(redirect_server):
    """allow_redirects=False 时，302 响应里的 Set-Cookie 仍写入 session（与 requests 一致）"""
    with BrowserSession(Chrome120, verify=False) as s:
        s.get(f"{redirect_server}/redirect", allow_redirects=False)
        assert s.cookies.get("foo") == "bar"


# ── 异步测试 ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_async_default_follows_redirect(redirect_server):
    async with AsyncBrowserSession(Chrome120, verify=False) as s:
        resp = await s.get(f"{redirect_server}/redirect")
    assert resp.status_code == 200
    assert resp.history


@pytest.mark.asyncio
async def test_async_allow_redirects_false(redirect_server):
    async with AsyncBrowserSession(Chrome120, verify=False) as s:
        resp = await s.get(f"{redirect_server}/redirect", allow_redirects=False)
    assert resp.status_code == 302
    assert "location" in {k.lower() for k in resp.headers}
    assert not resp.history


@pytest.mark.asyncio
async def test_async_cookies_persisted_when_redirects_disabled(redirect_server):
    async with AsyncBrowserSession(Chrome120, verify=False) as s:
        await s.get(f"{redirect_server}/redirect", allow_redirects=False)
        assert s.cookies.get("foo") == "bar"
