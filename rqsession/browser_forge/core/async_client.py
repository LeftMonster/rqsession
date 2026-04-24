"""
Async HTTP client based on curl_cffi
"""
from typing import Optional, Dict, Any, Union
from urllib.parse import urlparse
import asyncio

# Try to import curl_cffi async support
try:
    from curl_cffi.requests import AsyncSession

    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False
    AsyncSession = None

from ..profiles.models import BrowserProfile
from ..fingerprint.tls_builder import TlsBuilder, ProfileValidator
from .header_builder import HeaderBuilder


class AsyncBrowserClient:
    """
    Async HTTP client with browser fingerprint simulation
    """

    def __init__(
            self,
            profile: BrowserProfile,
            proxy: Optional[str] = None,
            randomize_tls: bool = False,
            impersonate: Optional[str] = None,
            verify: bool = True,
            timeout: Optional[int] = None,
    ):
        """
        Initialize async browser client

        Args:
            profile: Browser profile to use
            proxy: Proxy URL (e.g., "http://user:pass@host:port")
            randomize_tls: Whether to randomize TLS parameters
            impersonate: Use curl_cffi's built-in browser impersonation
                        (e.g., "chrome119", "firefox120")
            verify: Verify SSL certificates
            timeout: Request timeout in seconds
        """
        if not CURL_CFFI_AVAILABLE:
            raise ImportError(
                "curl_cffi is required for AsyncBrowserClient. "
                "Install it with: pip install curl_cffi"
            )

        self.profile = profile
        self.proxy = proxy
        self.randomize_tls = randomize_tls
        self.impersonate = impersonate
        self.verify = verify
        self.timeout = timeout or profile.behavior.connection_timeout

        # Validate profile
        is_valid, errors = ProfileValidator.validate_profile(profile)
        if not is_valid:
            raise ValueError(f"Invalid profile: {', '.join(errors)}")

        # Randomize TLS if requested
        if randomize_tls:
            self.profile.tls_config = TlsBuilder.randomize_tls_config(
                self.profile.tls_config
            )

        # Session will be created in async context
        self._session: Optional[AsyncSession] = None
        self._closed = False

    async def _create_session(self) -> AsyncSession:
        """Create and configure curl_cffi async session"""
        # If impersonate is specified, use it directly
        if self.impersonate:
            session = AsyncSession(impersonate=self.impersonate)
        else:
            session = AsyncSession()

        # Apply proxy
        if self.proxy:
            session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }

        # Apply TLS configuration
        if not self.impersonate:
            await self._apply_tls_config(session)

        # Apply behavior settings
        session.timeout = self.timeout
        session.verify = self.verify

        return session

    async def _apply_tls_config(self, session: AsyncSession) -> None:
        """
        Apply custom TLS configuration to session

        Note: This is a simplified version. Full TLS control requires
        deeper integration with curl options.
        """
        tls_options = TlsBuilder.apply_to_curl_options(self.profile.tls_config)

        # curl_cffi doesn't expose all curl options directly,
        # so we'll set what we can through the session
        # For full control, we might need to use session.curl directly

        # Set cipher list if available
        if hasattr(session, 'curl'):
            try:
                import pycurl

                if 'ssl_cipher_list' in tls_options:
                    session.curl.setopt(
                        pycurl.SSL_CIPHER_LIST,
                        tls_options['ssl_cipher_list']
                    )

                if 'ssl_ec_curves' in tls_options:
                    # Note: This option might not be available in all curl versions
                    try:
                        session.curl.setopt(
                            pycurl.SSL_EC_CURVES,
                            tls_options['ssl_ec_curves']
                        )
                    except:
                        pass

                # Set TLS version
                if self.profile.tls_config.max_version == "1.3":
                    session.curl.setopt(
                        pycurl.SSLVERSION,
                        pycurl.SSLVERSION_TLSv1_3
                    )
                elif self.profile.tls_config.max_version == "1.2":
                    session.curl.setopt(
                        pycurl.SSLVERSION,
                        pycurl.SSLVERSION_TLSv1_2
                    )

            except Exception as e:
                # Fallback to impersonate mode if direct TLS config fails
                print(f"Warning: Could not apply custom TLS config: {e}")

    async def _ensure_session(self):
        """Ensure session is created"""
        if self._session is None:
            self._session = await self._create_session()

    def _build_headers(
            self,
            url: str,
            method: str = "GET",
            extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """Build headers for request"""
        return HeaderBuilder.build_headers(
            profile=self.profile,
            url=url,
            method=method,
            extra_headers=extra_headers
        )

    async def get(
            self,
            url: str,
            params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ):
        """
        Send async GET request

        Args:
            url: Target URL
            params: URL parameters
            headers: Additional headers
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        await self._ensure_session()
        request_headers = self._build_headers(url, "GET", headers)
        return await self._session.get(
            url,
            params=params,
            headers=request_headers,
            **kwargs
        )

    async def post(
            self,
            url: str,
            data: Optional[Union[Dict, str, bytes]] = None,
            json: Optional[Dict] = None,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ):
        """
        Send async POST request

        Args:
            url: Target URL
            data: Form data or raw body
            json: JSON data
            headers: Additional headers
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        await self._ensure_session()
        request_headers = self._build_headers(url, "POST", headers)
        return await self._session.post(
            url,
            data=data,
            json=json,
            headers=request_headers,
            **kwargs
        )

    async def put(
            self,
            url: str,
            data: Optional[Union[Dict, str, bytes]] = None,
            json: Optional[Dict] = None,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ):
        """Send async PUT request"""
        await self._ensure_session()
        request_headers = self._build_headers(url, "PUT", headers)
        return await self._session.put(
            url,
            data=data,
            json=json,
            headers=request_headers,
            **kwargs
        )

    async def delete(
            self,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ):
        """Send async DELETE request"""
        await self._ensure_session()
        request_headers = self._build_headers(url, "DELETE", headers)
        return await self._session.delete(
            url,
            headers=request_headers,
            **kwargs
        )

    async def patch(
            self,
            url: str,
            data: Optional[Union[Dict, str, bytes]] = None,
            json: Optional[Dict] = None,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ):
        """Send async PATCH request"""
        await self._ensure_session()
        request_headers = self._build_headers(url, "PATCH", headers)
        return await self._session.patch(
            url,
            data=data,
            json=json,
            headers=request_headers,
            **kwargs
        )

    async def head(
            self,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ):
        """Send async HEAD request"""
        await self._ensure_session()
        request_headers = self._build_headers(url, "HEAD", headers)
        return await self._session.head(
            url,
            headers=request_headers,
            **kwargs
        )

    async def options(
            self,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            **kwargs
    ):
        """Send async OPTIONS request"""
        await self._ensure_session()
        request_headers = self._build_headers(url, "OPTIONS", headers)
        return await self._session.options(
            url,
            headers=request_headers,
            **kwargs
        )

    async def close(self):
        """Close the async session"""
        if self._session and not self._closed:
            await self._session.close()
            self._closed = True

    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    @property
    def cookies(self):
        """Get session cookies"""
        if self._session:
            return self._session.cookies
        return None

    @cookies.setter
    def cookies(self, value):
        """Set session cookies"""
        if self._session:
            self._session.cookies = value


class AsyncBrowserPool:
    """
    Connection pool manager for async clients
    """

    def __init__(
            self,
            profile: BrowserProfile,
            pool_size: int = 10,
            proxy: Optional[str] = None,
            randomize_tls: bool = False,
            impersonate: Optional[str] = None,
    ):
        """
        Initialize async client pool

        Args:
            profile: Browser profile to use
            pool_size: Maximum number of clients in pool
            proxy: Proxy URL
            randomize_tls: Whether to randomize TLS
            impersonate: Use curl's built-in impersonation
        """
        self.profile = profile
        self.pool_size = pool_size
        self.proxy = proxy
        self.randomize_tls = randomize_tls
        self.impersonate = impersonate

        self._pool: asyncio.Queue = asyncio.Queue(maxsize=pool_size)
        self._created_count = 0
        self._lock = asyncio.Lock()

    async def _create_client(self) -> AsyncBrowserClient:
        """Create a new client"""
        return AsyncBrowserClient(
            profile=self.profile,
            proxy=self.proxy,
            randomize_tls=self.randomize_tls,
            impersonate=self.impersonate,
        )

    async def acquire(self) -> AsyncBrowserClient:
        """
        Acquire a client from the pool

        Returns:
            AsyncBrowserClient instance
        """
        # Try to get from pool
        try:
            client = self._pool.get_nowait()
            return client
        except asyncio.QueueEmpty:
            pass

        # Create new client if pool not full
        async with self._lock:
            if self._created_count < self.pool_size:
                client = await self._create_client()
                self._created_count += 1
                return client

        # Wait for available client
        return await self._pool.get()

    async def release(self, client: AsyncBrowserClient):
        """
        Release a client back to the pool

        Args:
            client: Client to release
        """
        try:
            self._pool.put_nowait(client)
        except asyncio.QueueFull:
            # Pool is full, close the client
            await client.close()

    async def close_all(self):
        """Close all clients in the pool"""
        while not self._pool.empty():
            try:
                client = self._pool.get_nowait()
                await client.close()
            except asyncio.QueueEmpty:
                break

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close_all()


async def fetch_all(
        urls: list,
        profile: BrowserProfile,
        max_concurrent: int = 10,
        **kwargs
) -> list:
    """
    Fetch multiple URLs concurrently

    Args:
        urls: List of URLs to fetch
        profile: Browser profile to use
        max_concurrent: Maximum concurrent requests
        **kwargs: Additional arguments for AsyncBrowserClient

    Returns:
        List of responses
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def fetch_one(url: str):
        async with semaphore:
            async with AsyncBrowserClient(profile=profile, **kwargs) as client:
                return await client.get(url)

    tasks = [fetch_one(url) for url in urls]
    return await asyncio.gather(*tasks, return_exceptions=True)
