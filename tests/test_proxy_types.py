"""
验证三种代理类型 + 认证

每个 mock 服务器实现对应协议的握手，成功后直接返回固定响应，
不做真正的转发——只测我们发出的协议字节是否正确。
"""
import asyncio
import base64
import socket
import struct
import sys
import threading

import pytest

from rqsession.rust_session import AsyncBrowserSession, BrowserSession, Chrome120

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

TARGET_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n\r\n"
    b"OK"
)


# ── Mock proxy servers ────────────────────────────────────────────────────────

def _serve(sock, handler):
    """Accept connections and dispatch each to handler in its own thread."""
    while True:
        try:
            conn, _ = sock.accept()
            threading.Thread(target=handler, args=(conn,), daemon=True).start()
        except OSError:
            break


def _make_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    return s, s.getsockname()[1]


def _http_connect_handler(conn, required_auth=None):
    """Minimal HTTP CONNECT proxy. Validates Proxy-Authorization if required."""
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk

        lines = data.split(b"\r\n")
        headers = {k.lower(): v for k, v in
                   (line.split(b": ", 1) for line in lines[1:] if b": " in line)}

        if required_auth:
            auth_header = headers.get(b"proxy-authorization", b"")
            expected = b"Basic " + base64.b64encode(required_auth.encode())
            if auth_header != expected:
                conn.sendall(b"HTTP/1.1 407 Proxy Auth Required\r\n\r\n")
                return

        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        # Now act as the target: consume HTTP request and respond
        conn.recv(4096)
        conn.sendall(TARGET_RESPONSE)
    except OSError:
        pass
    finally:
        conn.close()


def _socks5_handler(conn, credentials=None):
    """SOCKS5 proxy mock (RFC 1928 + RFC 1929)."""
    try:
        # Greeting
        header = conn.recv(2)
        ver, nmethods = header[0], header[1]
        methods = conn.recv(nmethods)

        if credentials:
            # Require user/pass (0x02)
            conn.sendall(bytes([0x05, 0x02]))
            auth_ver = conn.recv(1)[0]
            ulen = conn.recv(1)[0]
            user = conn.recv(ulen).decode()
            plen = conn.recv(1)[0]
            pwd  = conn.recv(plen).decode()
            expected_user, expected_pass = credentials
            if user != expected_user or pwd != expected_pass:
                conn.sendall(bytes([0x01, 0x01]))  # auth failure
                return
            conn.sendall(bytes([0x01, 0x00]))  # auth success
        else:
            conn.sendall(bytes([0x05, 0x00]))  # no auth

        # CONNECT request
        req = conn.recv(4)
        atyp = req[3]
        if atyp == 0x03:
            dlen = conn.recv(1)[0]
            _host = conn.recv(dlen)
        elif atyp == 0x01:
            conn.recv(4)
        elif atyp == 0x04:
            conn.recv(16)
        conn.recv(2)  # port

        # Success reply
        conn.sendall(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))

        # Act as target
        conn.recv(4096)
        conn.sendall(TARGET_RESPONSE)
    except OSError:
        pass
    finally:
        conn.close()


def _socks4a_handler(conn, expected_user=None):
    """SOCKS4a proxy mock."""
    try:
        header = conn.recv(8)           # VN CD DSTPORT DSTIP
        user = b""
        while True:
            b = conn.recv(1)
            if not b or b == b"\x00":
                break
            user += b
        # Read hostname (up to null)
        while True:
            b = conn.recv(1)
            if not b or b == b"\x00":
                break

        if expected_user and user.decode() != expected_user:
            conn.sendall(bytes([0x00, 0x5B, 0, 0, 0, 0, 0, 0]))  # rejected
            return

        conn.sendall(bytes([0x00, 0x5A, 0, 0, 0, 0, 0, 0]))  # granted
        conn.recv(4096)
        conn.sendall(TARGET_RESPONSE)
    except OSError:
        pass
    finally:
        conn.close()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def http_proxy_no_auth():
    s, port = _make_server()
    threading.Thread(target=_serve, args=(s, _http_connect_handler), daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    s.close()


@pytest.fixture(scope="module")
def http_proxy_with_auth():
    s, port = _make_server()
    handler = lambda conn: _http_connect_handler(conn, required_auth="user1:secret")
    threading.Thread(target=_serve, args=(s, handler), daemon=True).start()
    yield f"http://user1:secret@127.0.0.1:{port}", port
    s.close()


@pytest.fixture(scope="module")
def socks5_no_auth():
    s, port = _make_server()
    threading.Thread(target=_serve, args=(s, _socks5_handler), daemon=True).start()
    yield f"socks5://127.0.0.1:{port}"
    s.close()


@pytest.fixture(scope="module")
def socks5_with_auth():
    s, port = _make_server()
    handler = lambda conn: _socks5_handler(conn, credentials=("alice", "p@$$w0rd"))
    threading.Thread(target=_serve, args=(s, handler), daemon=True).start()
    yield f"socks5://alice:p%40%24%24w0rd@127.0.0.1:{port}"
    s.close()


@pytest.fixture(scope="module")
def socks4a_server():
    s, port = _make_server()
    threading.Thread(target=_serve, args=(s, _socks4a_handler), daemon=True).start()
    yield f"socks4://127.0.0.1:{port}"
    s.close()


# ── Sync tests ────────────────────────────────────────────────────────────────

def test_sync_http_proxy_no_auth(http_proxy_no_auth):
    with BrowserSession(Chrome120, proxy=http_proxy_no_auth, verify=False) as s:
        r = s.get("http://fake.target/path")
    assert r.status_code == 200


def test_sync_http_proxy_with_auth(http_proxy_with_auth):
    proxy_url, _ = http_proxy_with_auth
    with BrowserSession(Chrome120, proxy=proxy_url, verify=False) as s:
        r = s.get("http://fake.target/path")
    assert r.status_code == 200


def test_sync_socks5_no_auth(socks5_no_auth):
    with BrowserSession(Chrome120, proxy=socks5_no_auth, verify=False) as s:
        r = s.get("http://fake.target/path")
    assert r.status_code == 200


def test_sync_socks5_with_auth(socks5_with_auth):
    with BrowserSession(Chrome120, proxy=socks5_with_auth, verify=False) as s:
        r = s.get("http://fake.target/path")
    assert r.status_code == 200


def test_sync_socks4a(socks4a_server):
    with BrowserSession(Chrome120, proxy=socks4a_server, verify=False) as s:
        r = s.get("http://fake.target/path")
    assert r.status_code == 200


# ── Async tests ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_async_http_proxy_no_auth(http_proxy_no_auth):
    async with AsyncBrowserSession(Chrome120, proxy=http_proxy_no_auth, verify=False) as s:
        r = await s.get("http://fake.target/path")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_async_http_proxy_with_auth(http_proxy_with_auth):
    proxy_url, _ = http_proxy_with_auth
    async with AsyncBrowserSession(Chrome120, proxy=proxy_url, verify=False) as s:
        r = await s.get("http://fake.target/path")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_async_socks5_no_auth(socks5_no_auth):
    async with AsyncBrowserSession(Chrome120, proxy=socks5_no_auth, verify=False) as s:
        r = await s.get("http://fake.target/path")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_async_socks5_with_auth(socks5_with_auth):
    async with AsyncBrowserSession(Chrome120, proxy=socks5_with_auth, verify=False) as s:
        r = await s.get("http://fake.target/path")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_async_socks4a(socks4a_server):
    async with AsyncBrowserSession(Chrome120, proxy=socks4a_server, verify=False) as s:
        r = await s.get("http://fake.target/path")
    assert r.status_code == 200
