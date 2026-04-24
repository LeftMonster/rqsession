"""
HTTP header builder with proper ordering
"""
from typing import Dict, Optional
from urllib.parse import urlparse
from collections import OrderedDict
from ..profiles.models import BrowserProfile


class HeaderBuilder:
    """Build HTTP headers with correct ordering for fingerprinting"""

    # Standard header order for different browsers (HTTP/2 pseudo-headers come first)
    CHROME_HEADER_ORDER = [
        ":method",
        ":authority",
        ":scheme",
        ":path",
        "cache-control",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
        "cookie",
    ]

    FIREFOX_HEADER_ORDER = [
        ":method",
        ":path",
        ":authority",
        ":scheme",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "upgrade-insecure-requests",
        "cookie",
    ]

    SAFARI_HEADER_ORDER = [
        ":method",
        ":scheme",
        ":path",
        ":authority",
        "accept",
        "accept-encoding",
        "accept-language",
        "user-agent",
        "cookie",
    ]

    @staticmethod
    def get_header_order(profile: BrowserProfile) -> list:
        """
        Get the appropriate header order for the browser profile

        Args:
            profile: Browser profile

        Returns:
            List of header names in order
        """
        # Use custom order if specified in profile
        if profile.headers.order:
            return profile.headers.order

        # Otherwise, use browser-specific defaults
        name_lower = profile.name.lower()
        if "chrome" in name_lower or "chromium" in name_lower:
            return HeaderBuilder.CHROME_HEADER_ORDER
        elif "firefox" in name_lower:
            return HeaderBuilder.FIREFOX_HEADER_ORDER
        elif "safari" in name_lower:
            return HeaderBuilder.SAFARI_HEADER_ORDER
        else:
            return HeaderBuilder.CHROME_HEADER_ORDER  # Default to Chrome

    @staticmethod
    def build_headers(
            profile: BrowserProfile,
            url: str,
            method: str = "GET",
            extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Build headers with proper ordering

        Args:
            profile: Browser profile
            url: Target URL
            method: HTTP method
            extra_headers: Additional headers to include

        Returns:
            Ordered dictionary of headers
        """
        parsed_url = urlparse(url)
        headers = OrderedDict()
        header_profile = profile.headers

        # Collect all headers first
        all_headers = {
            "user-agent": profile.user_agent,
            "accept": header_profile.accept,
            "accept-encoding": header_profile.accept_encoding,
            "accept-language": header_profile.accept_language,
        }

        # Add optional headers
        if header_profile.cache_control:
            all_headers["cache-control"] = header_profile.cache_control

        # Chrome-specific headers
        if "chrome" in profile.name.lower():
            if header_profile.sec_ch_ua:
                all_headers["sec-ch-ua"] = header_profile.sec_ch_ua
            if header_profile.sec_ch_ua_mobile:
                all_headers["sec-ch-ua-mobile"] = header_profile.sec_ch_ua_mobile
            if header_profile.sec_ch_ua_platform:
                all_headers["sec-ch-ua-platform"] = header_profile.sec_ch_ua_platform

        # Fetch metadata headers (for HTTPS)
        if parsed_url.scheme == "https":
            if header_profile.sec_fetch_dest:
                all_headers["sec-fetch-dest"] = header_profile.sec_fetch_dest
            if header_profile.sec_fetch_mode:
                all_headers["sec-fetch-mode"] = header_profile.sec_fetch_mode
            if header_profile.sec_fetch_site:
                all_headers["sec-fetch-site"] = header_profile.sec_fetch_site

            # sec-fetch-user only for GET requests
            if method.upper() == "GET" and header_profile.sec_fetch_user:
                all_headers["sec-fetch-user"] = header_profile.sec_fetch_user

        # Upgrade insecure requests
        if header_profile.upgrade_insecure_requests:
            all_headers["upgrade-insecure-requests"] = header_profile.upgrade_insecure_requests

        # Add extra headers
        if extra_headers:
            all_headers.update({k.lower(): v for k, v in extra_headers.items()})

        # Get header order
        header_order = HeaderBuilder.get_header_order(profile)

        # Build ordered headers (skip pseudo-headers for HTTP/1.1)
        for header_name in header_order:
            if header_name.startswith(":"):
                # Skip pseudo-headers for now
                # They're handled by HTTP/2 layer in curl
                continue

            if header_name in all_headers:
                headers[header_name] = all_headers[header_name]

        # Add any remaining headers not in the order list
        for key, value in all_headers.items():
            if key not in headers and not key.startswith(":"):
                headers[key] = value

        return dict(headers)

    @staticmethod
    def build_post_headers(
            profile: BrowserProfile,
            url: str,
            content_type: Optional[str] = None,
            extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Build headers for POST request

        Args:
            profile: Browser profile
            url: Target URL
            content_type: Content-Type header value
            extra_headers: Additional headers

        Returns:
            Ordered dictionary of headers
        """
        headers = HeaderBuilder.build_headers(profile, url, "POST", extra_headers)

        # Add content-type if specified
        if content_type:
            headers["content-type"] = content_type

        # Adjust fetch metadata for POST
        if "sec-fetch-mode" in headers:
            headers["sec-fetch-mode"] = "cors"
        if "sec-fetch-dest" in headers:
            headers["sec-fetch-dest"] = "empty"

        return headers

    @staticmethod
    def normalize_header_name(name: str) -> str:
        """
        Normalize header name to lowercase

        Args:
            name: Header name

        Returns:
            Normalized header name
        """
        return name.lower()

    @staticmethod
    def is_restricted_header(name: str) -> bool:
        """
        Check if header is restricted (should not be set by user)

        Args:
            name: Header name

        Returns:
            True if restricted
        """
        restricted = [
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
        ]
        return name.lower() in restricted
