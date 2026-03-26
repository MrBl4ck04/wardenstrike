"""
WardenStrike - HTTP Client
Async HTTP client with proxy support, rate limiting, and retry logic.
"""

import asyncio
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp


@dataclass
class HTTPResponse:
    url: str
    status: int
    headers: dict
    body: str
    elapsed: float
    size: int
    redirects: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 400

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class RateLimiter:
    """Token-bucket rate limiter."""

    def __init__(self, rate: float):
        self.rate = rate
        self.tokens = rate
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.rate, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens < 1:
                await asyncio.sleep((1 - self.tokens) / self.rate)
                self.tokens = 0
            else:
                self.tokens -= 1


class HTTPClient:
    """Async HTTP client with proxy, rate limiting, and retries."""

    def __init__(
        self,
        proxy: str | None = None,
        rate_limit: float = 10,
        timeout: int = 30,
        max_retries: int = 2,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        verify_ssl: bool = False,
        headers: dict | None = None,
    ):
        self.proxy = proxy
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.rate_limiter = RateLimiter(rate_limit)
        self.default_headers = {
            "User-Agent": user_agent,
            **(headers or {}),
        }
        self._session: aiohttp.ClientSession | None = None
        self._stats = {"requests": 0, "errors": 0, "bytes": 0}

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_ctx = False if not self.verify_ssl else None
            connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=50)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers=self.default_headers,
            )
        return self._session

    async def request(
        self,
        method: str,
        url: str,
        data: Any = None,
        json: Any = None,
        headers: dict | None = None,
        params: dict | None = None,
        follow_redirects: bool = True,
        cookies: dict | None = None,
    ) -> HTTPResponse:
        """Execute an HTTP request with rate limiting and retries."""
        await self.rate_limiter.acquire()
        session = await self._get_session()

        redirect_history = []
        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                start = time.monotonic()
                async with session.request(
                    method,
                    url,
                    data=data,
                    json=json,
                    headers=headers,
                    params=params,
                    proxy=self.proxy,
                    allow_redirects=follow_redirects,
                    cookies=cookies,
                ) as resp:
                    body = await resp.text(errors="replace")
                    elapsed = time.monotonic() - start

                    if resp.history:
                        redirect_history = [str(r.url) for r in resp.history]

                    response_headers = {k.lower(): v for k, v in resp.headers.items()}
                    self._stats["requests"] += 1
                    self._stats["bytes"] += len(body)

                    return HTTPResponse(
                        url=str(resp.url),
                        status=resp.status,
                        headers=response_headers,
                        body=body,
                        elapsed=elapsed,
                        size=len(body),
                        redirects=redirect_history,
                    )

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_error = str(e)
                self._stats["errors"] += 1
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)

        return HTTPResponse(
            url=url, status=0, headers={}, body="",
            elapsed=0, size=0, error=last_error,
        )

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("HEAD", url, **kwargs)

    async def multi_get(self, urls: list[str], concurrency: int = 10, **kwargs) -> list[HTTPResponse]:
        """Fetch multiple URLs concurrently."""
        semaphore = asyncio.Semaphore(concurrency)

        async def _fetch(url):
            async with semaphore:
                return await self.get(url, **kwargs)

        return await asyncio.gather(*[_fetch(u) for u in urls])

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
