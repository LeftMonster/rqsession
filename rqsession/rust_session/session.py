from __future__ import annotations

from typing import Any

from rqsession._rust_core import BrowserSession as _RustSession, BrowserProfile


def _detect_ca_bundle() -> str | None:
    """Return a CA bundle path suitable for BoringSSL on this platform."""
    try:
        import certifi
        return certifi.where()
    except ImportError:
        pass
    return None


class BrowserSession:
    """
    Synchronous browser-impersonating HTTP session.

    Usage::

        from rqsession.rust_session import BrowserSession, Chrome120

        s = BrowserSession(Chrome120)
        resp = s.get("https://example.com")
        print(resp.status_code, resp.json())
    """

    def __init__(
        self,
        profile,
        *,
        proxy: str | None = None,
        verify: bool = True,
        ca_bundle: str | None = None,
    ):
        # Accept both _ProfileProxy and raw BrowserProfile
        raw = profile._inner() if hasattr(profile, "_inner") else profile
        # BoringSSL doesn't use the system/Python cert store automatically.
        # Auto-detect certifi when verify=True and no explicit bundle given.
        if verify and ca_bundle is None:
            ca_bundle = _detect_ca_bundle()
        self._session = _RustSession(raw, proxy=proxy, verify=verify, ca_bundle=ca_bundle)

    # ── HTTP verbs ────────────────────────────────────────────────────────────

    def get(self, url: str, *, headers: dict | None = None, params: dict | None = None):
        return self._session.get(url, headers=headers, params=params)

    def post(
        self,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        data: bytes | None = None,
        json: Any = None,
    ):
        return self._session.post(url, headers=headers, params=params, data=data, json=json)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        body: bytes | None = None,
        json: Any = None,
    ):
        return self._session.request(
            method, url, headers=headers, params=params, body=body, json=json
        )

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    # ── Misc ──────────────────────────────────────────────────────────────────

    def update_cookies(self, cookies: dict[str, str]) -> None:
        self._session.update_cookies(cookies)

    def update_headers(self, headers: dict[str, str]) -> None:
        self._session.update_headers(headers)

    @property
    def profile_name(self) -> str:
        return self._session.profile_name
