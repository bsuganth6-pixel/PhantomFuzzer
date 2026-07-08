"""
PhantomFuzzer — HTTP Client
═══════════════════════════════════════════════════════════════
A thin wrapper around requests with built-in politeness: a minimum
delay between requests, a hard cap on total requests per session,
and consistent timing measurement for the timing-based detectors.

Defaults are deliberately conservative — this tool is for testing
your own applications, not for maximizing throughput against someone
else's server.
"""

import time
import requests

DEFAULT_DELAY_MS = 250
DEFAULT_TIMEOUT = 10
MAX_REQUESTS_PER_SESSION = 500  # hard safety cap


class RateLimitedClient:
    def __init__(self, delay_ms: int = DEFAULT_DELAY_MS, timeout: float = DEFAULT_TIMEOUT,
                max_requests: int = MAX_REQUESTS_PER_SESSION, headers: dict = None, cookies: dict = None):
        self.delay_seconds = max(0, delay_ms) / 1000
        self.timeout = timeout
        self.max_requests = max_requests
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update(headers or {"User-Agent": "PhantomFuzzer/1.0 (authorized security testing)"})
        if cookies:
            self.session.cookies.update(cookies)
        self._last_request_time = 0

    def _throttle(self):
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self.delay_seconds:
            time.sleep(self.delay_seconds - elapsed)

    def request(self, method: str, url: str, params: dict = None, data: dict = None,
               allow_redirects: bool = True) -> dict:
        """
        Sends one request, enforcing rate limit + session cap.
        Returns a normalized dict — never raises for network errors,
        since a fuzzing run should continue past individual failures.
        """
        if self.request_count >= self.max_requests:
            return {"success": False, "error": f"Session request cap ({self.max_requests}) reached.",
                    "capped": True}

        self._throttle()
        start = time.monotonic()
        try:
            resp = self.session.request(method.upper(), url, params=params, data=data,
                                        timeout=self.timeout, allow_redirects=allow_redirects)
            elapsed = time.monotonic() - start
            self._last_request_time = time.monotonic()
            self.request_count += 1
            return {
                "success": True, "status_code": resp.status_code, "text": resp.text,
                "headers": dict(resp.headers), "elapsed": elapsed, "final_url": resp.url,
                "content_length": len(resp.content),
            }
        except requests.exceptions.Timeout:
            self._last_request_time = time.monotonic()
            self.request_count += 1
            elapsed = time.monotonic() - start
            return {"success": False, "error": f"Request timed out after {self.timeout}s", "elapsed": elapsed}
        except requests.exceptions.RequestException as e:
            self._last_request_time = time.monotonic()
            self.request_count += 1
            return {"success": False, "error": str(e), "elapsed": time.monotonic() - start}

    def get(self, url: str, params: dict = None) -> dict:
        return self.request("GET", url, params=params)

    def post(self, url: str, data: dict = None) -> dict:
        return self.request("POST", url, data=data)
