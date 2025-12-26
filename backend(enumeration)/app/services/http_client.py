"""HTTP client wrapper with rate limiting and error handling."""

import asyncio
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
import structlog

from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class HttpClient:
    """Async HTTP client with rate limiting, retries, and timeout handling."""

    def __init__(
        self,
        base_url: str,
        rate_limit_ms: int = 500,
        timeout_seconds: int = 30,
        user_agent: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.rate_limit_seconds = rate_limit_ms / 1000
        self.timeout = timeout_seconds
        self.user_agent = user_agent or settings.user_agent
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()
        
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            headers={"User-Agent": self.user_agent},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()

    async def _rate_limit(self):
        """Enforce rate limiting between requests."""
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_request_time
            if elapsed < self.rate_limit_seconds:
                await asyncio.sleep(self.rate_limit_seconds - elapsed)
            self._last_request_time = asyncio.get_event_loop().time()

    def _resolve_url(self, url: str) -> str:
        """Resolve relative URLs against base URL."""
        if url.startswith(("http://", "https://")):
            return url
        return urljoin(self.base_url + "/", url.lstrip("/"))

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Perform a GET request with rate limiting and retries."""
        await self._rate_limit()
        
        full_url = self._resolve_url(url)
        
        try:
            response = await self._client.get(
                full_url,
                params=params,
                headers=headers,
            )
            logger.debug("GET request", url=full_url, status=response.status_code)
            return response
        except httpx.TimeoutException:
            logger.warning("Request timeout", url=full_url)
            raise
        except httpx.RequestError as e:
            logger.error("Request failed", url=full_url, error=str(e))
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Perform a POST request with rate limiting and retries."""
        await self._rate_limit()
        
        full_url = self._resolve_url(url)
        
        try:
            response = await self._client.post(
                full_url,
                data=data,
                json=json,
                headers=headers,
            )
            logger.debug("POST request", url=full_url, status=response.status_code)
            return response
        except httpx.TimeoutException:
            logger.warning("Request timeout", url=full_url)
            raise
        except httpx.RequestError as e:
            logger.error("Request failed", url=full_url, error=str(e))
            raise

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """Perform an arbitrary HTTP request."""
        await self._rate_limit()
        
        full_url = self._resolve_url(url)
        
        try:
            response = await self._client.request(method, full_url, **kwargs)
            logger.debug(f"{method} request", url=full_url, status=response.status_code)
            return response
        except Exception as e:
            logger.error(f"{method} request failed", url=full_url, error=str(e))
            raise
