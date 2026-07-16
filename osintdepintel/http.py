from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class HttpError(RuntimeError):
    pass


class RateLimiter:
    def __init__(self, requests_per_second: float = 4.0) -> None:
        self.interval = 1.0 / max(requests_per_second, 0.1)
        self._last_call: float = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_call
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self._last_call = time.monotonic()


class HttpClient:
    def __init__(
        self,
        timeout: int = 15,
        user_agent: str = "osintdepintel/0.2 passive-research",
        max_response_size: int = 20 * 1024 * 1024,  # 20MB default
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_response_size = max_response_size
        self._rate_limiter = rate_limiter

    def _request(self, request: urllib.request.Request) -> bytes:
        if self._rate_limiter:
            self._rate_limiter.wait()
        retries = 3
        backoff = 1.0
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    chunks = []
                    total_bytes = 0
                    while True:
                        chunk = response.read(65536)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if total_bytes > self.max_response_size:
                            raise HttpError(f"Response size exceeded maximum limit of {self.max_response_size} bytes")
                        chunks.append(chunk)
                    return b"".join(chunks)
            except Exception as exc:
                last_exc = exc
                is_transient = False
                if isinstance(exc, urllib.error.HTTPError):
                    if exc.code in (429, 502, 503, 504):
                        is_transient = True
                elif isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionResetError)):
                    is_transient = True

                if is_transient and attempt < retries - 1:
                    time.sleep(backoff)
                    backoff *= 2.0
                    continue
                break

        if isinstance(last_exc, urllib.error.HTTPError):
            raise HttpError(f"HTTP Error {last_exc.code}: {last_exc.reason}") from last_exc
        if last_exc:
            raise HttpError(str(last_exc)) from last_exc
        raise HttpError("Unknown HTTP client error")

    def fetch(self, url: str, headers: dict[str, str] | None = None) -> str:
        merged_headers = {"User-Agent": self.user_agent}
        if headers:
            merged_headers.update(headers)
        request = urllib.request.Request(url, headers=merged_headers)
        raw = self._request(request)
        return raw.decode("utf-8", errors="replace")

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> Any:
        text = self.fetch(url, headers=headers)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise HttpError(f"invalid JSON from {url}: {exc}") from exc

    def fetch_bytes(self, url: str, headers: dict[str, str] | None = None) -> bytes:
        merged_headers = {"User-Agent": self.user_agent}
        if headers:
            merged_headers.update(headers)
        request = urllib.request.Request(url, headers=merged_headers)
        return self._request(request)

    def post_json(self, url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> Any:
        body = json.dumps(payload).encode("utf-8")
        merged_headers = {
            "User-Agent": self.user_agent,
            "Content-Type": "application/json",
        }
        if headers:
            merged_headers.update(headers)
        request = urllib.request.Request(url, data=body, headers=merged_headers, method="POST")
        raw = self._request(request)
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise HttpError(f"invalid JSON from response: {exc}") from exc


def join_url(base_url: str, maybe_relative: str) -> str:
    return urllib.parse.urljoin(base_url, maybe_relative)
