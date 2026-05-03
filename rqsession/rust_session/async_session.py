from __future__ import annotations

import json as _json
from typing import Any

from rqsession._rust_core import AsyncBrowserSession as _RustAsyncSession


def _detect_ca_bundle() -> str | None:
    try:
        import certifi
        return certifi.where()
    except ImportError:
        pass
    return None


class AsyncBrowserSession:
    """
    Async browser-impersonating HTTP session backed by Rust/Tokio.

    Usage::

        from rqsession.rust_session import AsyncBrowserSession, Chrome120

        async with AsyncBrowserSession(Chrome120) as s:
            resp = await s.get("https://example.com")
            data = resp.json()

    Windows note: if you hit "Event loop is closed" errors, add this before
    asyncio.run()::

        import asyncio, sys
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    """

    def __init__(
        self,
        profile,
        *,
        proxy: str | None = None,
        verify: bool = True,
        ca_bundle: str | None = None,
    ):
        raw = profile._inner() if hasattr(profile, "_inner") else profile
        if verify and ca_bundle is None:
            ca_bundle = _detect_ca_bundle()
        self._session = _RustAsyncSession(raw, proxy=proxy, verify=verify, ca_bundle=ca_bundle)

    # ── HTTP verbs ────────────────────────────────────────────────────────────

    async def get(self, url: str, *, headers: dict | None = None, params: dict | None = None):
        return await self._session.get(url, headers=headers, params=params)

    async def post(
        self,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        data: bytes | None = None,
        json: Any = None,
    ):
        if json is not None and data is None:
            data = _json.dumps(json).encode()
            if headers is None:
                headers = {"content-type": "application/json"}
            elif "content-type" not in {k.lower() for k in headers}:
                headers = {**headers, "content-type": "application/json"}
            json = None
        return await self._session.post(url, headers=headers, params=params, data=data, json=json)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        body: bytes | None = None,
        json: Any = None,
    ):
        if json is not None and body is None:
            body = _json.dumps(json).encode()
            if headers is None:
                headers = {"content-type": "application/json"}
            elif "content-type" not in {k.lower() for k in headers}:
                headers = {**headers, "content-type": "application/json"}
            json = None
        return await self._session.request(
            method, url, headers=headers, params=params, body=body, json=json
        )

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    # ── Misc ──────────────────────────────────────────────────────────────────

    def update_cookies(self, cookies: dict[str, str]) -> None:
        self._session.update_cookies(cookies)

    def update_headers(self, headers: dict[str, str]) -> None:
        self._session.update_headers(headers)

    @property
    def cookies(self) -> dict[str, str]:
        return self._session.cookies

    @property
    def profile_name(self) -> str:
        return self._session.profile_name
