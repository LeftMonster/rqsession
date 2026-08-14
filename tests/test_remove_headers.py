import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from rqsession.rust_session import AsyncBrowserSession, BrowserSession, Chrome120

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class _HeaderCaptureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.seen_headers.append({k.lower(): v for k, v in self.headers.items()})
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def header_server():
    server = HTTPServer(("127.0.0.1", 0), _HeaderCaptureHandler)
    server.seen_headers = []
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{port}/headers"
    server.shutdown()


def test_sync_remove_profile_headers(header_server):
    server, url = header_server
    with BrowserSession(Chrome120, verify=False) as session:
        default_response = session.get(url)
        response = session.get(
            url,
            remove_headers=["sec-fetch-user", "upgrade-insecure-requests"],
        )

    assert default_response.status_code == 200
    default_headers = server.seen_headers[-2]
    assert default_headers["sec-fetch-user"] == "?1"
    assert default_headers["upgrade-insecure-requests"] == "1"

    assert response.status_code == 200
    headers = server.seen_headers[-1]
    assert "sec-fetch-user" not in headers
    assert "upgrade-insecure-requests" not in headers
    assert "user-agent" in headers


def test_sync_removed_header_can_be_readded(header_server):
    server, url = header_server
    with BrowserSession(Chrome120, verify=False) as session:
        response = session.get(
            url,
            headers={"sec-fetch-user": "?1"},
            remove_headers=["sec-fetch-user"],
        )

    assert response.status_code == 200
    assert server.seen_headers[-1]["sec-fetch-user"] == "?1"


def test_sync_none_header_value_removes_header(header_server):
    server, url = header_server
    with BrowserSession(Chrome120, verify=False) as session:
        response = session.get(
            url,
            headers={
                "sec-fetch-user": None,
                "upgrade-insecure-requests": None,
            },
        )

    assert response.status_code == 200
    headers = server.seen_headers[-1]
    assert "sec-fetch-user" not in headers
    assert "upgrade-insecure-requests" not in headers


def test_sync_session_remove_headers(header_server):
    server, url = header_server
    with BrowserSession(Chrome120, verify=False) as session:
        session.remove_headers(["sec-fetch-user", "upgrade-insecure-requests"])
        response = session.get(url)

    assert response.status_code == 200
    headers = server.seen_headers[-1]
    assert "sec-fetch-user" not in headers
    assert "upgrade-insecure-requests" not in headers


def test_sync_update_headers_restores_removed_header(header_server):
    server, url = header_server
    with BrowserSession(Chrome120, verify=False) as session:
        session.remove_header("sec-fetch-user")
        session.update_headers({"sec-fetch-user": "?1"})
        response = session.get(url)

    assert response.status_code == 200
    assert server.seen_headers[-1]["sec-fetch-user"] == "?1"


@pytest.mark.asyncio
async def test_async_remove_profile_headers(header_server):
    server, url = header_server
    async with AsyncBrowserSession(Chrome120, verify=False) as session:
        default_response = await session.get(url)
        response = await session.get(
            url,
            remove_headers=["sec-fetch-user", "upgrade-insecure-requests"],
        )

    assert default_response.status_code == 200
    default_headers = server.seen_headers[-2]
    assert default_headers["sec-fetch-user"] == "?1"
    assert default_headers["upgrade-insecure-requests"] == "1"

    assert response.status_code == 200
    headers = server.seen_headers[-1]
    assert "sec-fetch-user" not in headers
    assert "upgrade-insecure-requests" not in headers
    assert "user-agent" in headers


@pytest.mark.asyncio
async def test_async_none_header_value_removes_header(header_server):
    server, url = header_server
    async with AsyncBrowserSession(Chrome120, verify=False) as session:
        response = await session.get(
            url,
            headers={
                "sec-fetch-user": None,
                "upgrade-insecure-requests": None,
            },
        )

    assert response.status_code == 200
    headers = server.seen_headers[-1]
    assert "sec-fetch-user" not in headers
    assert "upgrade-insecure-requests" not in headers


@pytest.mark.asyncio
async def test_async_session_remove_headers(header_server):
    server, url = header_server
    async with AsyncBrowserSession(Chrome120, verify=False) as session:
        session.remove_headers(["sec-fetch-user", "upgrade-insecure-requests"])
        response = await session.get(url)

    assert response.status_code == 200
    headers = server.seen_headers[-1]
    assert "sec-fetch-user" not in headers
    assert "upgrade-insecure-requests" not in headers
