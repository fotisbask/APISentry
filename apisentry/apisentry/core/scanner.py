"""Same-origin, bounded, GET-only HTTP transport with verified TLS."""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx


def normalize_url(url: str) -> str:
    """Validate an absolute HTTP URL, reject credentials and strip fragments."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("Target must be an absolute http:// or https:// URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL credentials are not supported")
    _ = parts.port  # Validate malformed ports eagerly.
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def origin(url: str) -> tuple[str, str | None, int]:
    parts = urlsplit(normalize_url(url))
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


@dataclass(frozen=True)
class Finding:
    risk: str
    title: str
    url: str
    evidence: str
    remediation: str


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    requests: int = 0


class Scanner:
    """Own one client per assessment; never follow out-of-scope redirects."""

    USER_AGENTS = ("APISentry/1.0 (authorized assessment)",
                   "APISentry/1.0 (web security audit)")

    def __init__(self, target: str, *, timeout: float = 10, concurrency: int = 4,
                 max_requests: int = 100, max_bytes: int = 2_000_000,
                 delay: float = 0.1, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.target = normalize_url(target)
        if min(timeout, concurrency, max_requests, max_bytes) <= 0 or delay < 0:
            raise ValueError("Limits must be positive; delay must be nonnegative")
        self.max_requests, self.max_bytes, self.delay = max_requests, max_bytes, delay
        self.requests = 0
        self.errors: list[str] = []
        self._semaphore = asyncio.Semaphore(concurrency)
        self._pace = asyncio.Lock()
        self._last_start = 0.0
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout), follow_redirects=False, trust_env=False,
            limits=httpx.Limits(max_connections=concurrency), transport=transport,
        )

    async def __aenter__(self) -> Scanner:
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._client.aclose()

    def in_scope(self, url: str) -> bool:
        try:
            return origin(url) == origin(self.target)
        except ValueError:
            return False

    async def fetch(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response | None:
        """Fetch a limited body. Redirects consume budget and remain same-origin.

        Cookies are explicitly suppressed so exposure probes remain anonymous.
        HTTP errors are returned as evidence; transport failures are recorded.
        """
        for _ in range(6):
            if not self.in_scope(url):
                self.errors.append("Skipped out-of-scope URL")
                return None
            async with self._semaphore:
                async with self._pace:
                    if self.requests >= self.max_requests:
                        if "Request budget exhausted" not in self.errors:
                            self.errors.append("Request budget exhausted")
                        return None
                    loop = asyncio.get_running_loop()
                    await asyncio.sleep(max(0, self.delay - (loop.time() - self._last_start)))
                    self._last_start = loop.time()
                    self.requests += 1
                request_headers = {"User-Agent": random.choice(self.USER_AGENTS),
                                   "Cookie": "", **(headers or {})}
                try:
                    async with self._client.stream("GET", url, headers=request_headers) as response:
                        if response.status_code in {301, 302, 303, 307, 308} and "location" in response.headers:
                            url = urljoin(str(response.url), response.headers["location"])
                            continue
                        body = bytearray()
                        async for chunk in response.aiter_bytes(chunk_size=65536):
                            body.extend(chunk)
                            if len(body) > self.max_bytes:
                                self.errors.append("Response exceeded body-size limit")
                                return None
                        return httpx.Response(response.status_code, headers=response.headers,
                                              content=bytes(body), request=response.request)
                except (httpx.HTTPError, ValueError) as exc:
                    # Exception strings can contain credentials in query parameters.
                    self.errors.append(f"Request failed: {type(exc).__name__}")
                    return None
        self.errors.append("Redirect limit exceeded")
        return None
