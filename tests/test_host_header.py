import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from rqsession import BrowserSession, Chrome120


class _HostCaptureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.seen_hosts.append(self.headers.get("Host"))
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def host_server():
    server = HTTPServer(("127.0.0.1", 0), _HostCaptureHandler)
    server.seen_hosts = []
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{port}/headers"
    server.shutdown()


def test_sync_session_sends_host_header_from_url(host_server):
    server, url = host_server

    with BrowserSession(Chrome120, verify=False) as session:
        response = session.get(url)

    assert response.status_code == 200
    assert server.seen_hosts == [url.split("//", 1)[1].split("/", 1)[0]]


def test_sync_request_can_override_host_header(host_server):
    server, url = host_server

    with BrowserSession(Chrome120, verify=False) as session:
        response = session.get(url, headers={"host": "example.test"})

    assert response.status_code == 200
    assert server.seen_hosts == ["example.test"]
