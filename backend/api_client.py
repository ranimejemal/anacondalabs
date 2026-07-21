"""
AegisLab - API Client Layer
============================
A thin async HTTP client wrapper used by every test module. Centralizes:
  - Bearer token injection
  - Safe, throttled request pacing (so scans never hammer the target)
  - Timing capture (used by injection_tests for blind/time-based checks)
  - Consistent error handling so a single failed request never crashes a scan
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional, Any

import httpx


class SafeApiClient:
    """
    Wraps httpx.AsyncClient with:
      - a token-bucket-ish throttle (requests_per_second)
      - automatic backoff if the target itself starts returning 429s
        (so AegisLab never contributes to a real denial-of-service)
      - a hard cap on retries
    """

    def __init__(
        self,
        base_url: str,
        bearer_token: Optional[str] = None,
        requests_per_second: float = 5.0,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.min_interval = 1.0 / max(requests_per_second, 0.5)
        self._last_call = 0.0
        self._lock = asyncio.Lock()
        self._client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        self._consecutive_429 = 0

    def _headers(self, extra: Optional[dict] = None, token_override: Optional[str] = None) -> dict:
        headers = {"User-Agent": "AegisLab-Scanner/1.0 (+authorized-security-test)"}
        token = token_override if token_override is not None else self.bearer_token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if extra:
            headers.update(extra)
        return headers

    async def _throttle(self):
        async with self._lock:
            now = time.monotonic()
            wait = self.min_interval - (now - self._last_call)
            if self._consecutive_429 > 0:
                # back off automatically if the server is signalling it's overwhelmed
                wait = max(wait, self._consecutive_429 * 1.5)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict] = None,
        json_body: Optional[Any] = None,
        headers: Optional[dict] = None,
        token_override: Optional[str] = None,
        no_auth: bool = False,
    ) -> "ApiResponse":
        await self._throttle()
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        req_headers = self._headers(headers, token_override=None if no_auth else token_override)

        start = time.perf_counter()
        try:
            resp = await self._client.request(
                method.upper(), url, params=params, json=json_body, headers=req_headers
            )
            elapsed = time.perf_counter() - start

            if resp.status_code == 429:
                self._consecutive_429 += 1
            else:
                self._consecutive_429 = 0

            body_text = ""
            try:
                body_text = resp.text[:20000]  # cap captured body to keep memory sane
            except Exception:
                pass

            return ApiResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=body_text,
                elapsed=elapsed,
                error=None,
                url=str(resp.url),
            )
        except httpx.TimeoutException:
            return ApiResponse(status_code=0, headers={}, text="", elapsed=time.perf_counter() - start,
                                error="timeout", url=url)
        except httpx.RequestError as e:
            return ApiResponse(status_code=0, headers={}, text="", elapsed=time.perf_counter() - start,
                                error=str(e), url=url)

    async def get(self, path: str, **kwargs) -> "ApiResponse":
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs) -> "ApiResponse":
        return await self.request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs) -> "ApiResponse":
        return await self.request("PUT", path, **kwargs)

    async def delete(self, path: str, **kwargs) -> "ApiResponse":
        return await self.request("DELETE", path, **kwargs)

    async def close(self):
        await self._client.aclose()


class ApiResponse:
    """Lightweight response container so test modules don't depend on httpx directly."""

    __slots__ = ("status_code", "headers", "text", "elapsed", "error", "url")

    def __init__(self, status_code: int, headers: dict, text: str, elapsed: float,
                 error: Optional[str], url: str):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.elapsed = elapsed
        self.error = error
        self.url = url

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return self.status_code >= 500

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def json_safe(self) -> Optional[Any]:
        import json
        try:
            return json.loads(self.text)
        except Exception:
            return None
