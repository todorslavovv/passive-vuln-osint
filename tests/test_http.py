from __future__ import annotations

import json
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from osintdepintel.http import HttpClient, HttpError, RateLimiter, join_url


class HttpClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = HttpClient(timeout=5, max_response_size=1024)

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_fetch_success(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"hello world", b""]
        mock_urlopen.return_value.__enter__.return_value = mock_response
        result = self.client.fetch("https://example.test/")
        self.assertEqual(result, "hello world")

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_get_json_success(self, mock_urlopen: MagicMock) -> None:
        data = json.dumps({"key": "value"})
        mock_response = MagicMock()
        mock_response.read.side_effect = [data.encode(), b""]
        mock_urlopen.return_value.__enter__.return_value = mock_response
        result = self.client.get_json("https://example.test/data.json")
        self.assertEqual(result, {"key": "value"})

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_response_size_exceeded(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"x" * 600, b"y" * 600]
        mock_urlopen.return_value.__enter__.return_value = mock_response
        with self.assertRaises(HttpError) as ctx:
            self.client.fetch("https://example.test/")
        self.assertIn("exceeded maximum limit", str(ctx.exception))

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_fetch_bytes_returns_raw_bytes(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"\x00\x01\x02\xff\xfe", b""]
        mock_urlopen.return_value.__enter__.return_value = mock_response
        result = self.client.fetch_bytes("https://example.test/data.bin")
        self.assertEqual(result, b"\x00\x01\x02\xff\xfe")

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_no_rate_limiter_does_not_crash(self, mock_urlopen: MagicMock) -> None:
        client = HttpClient(timeout=5, rate_limiter=None)
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"no limiter", b""]
        mock_urlopen.return_value.__enter__.return_value = mock_response
        result = client.fetch("https://example.test/")
        self.assertEqual(result, "no limiter")

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_fetch_bytes_no_rate_limiter_does_not_crash(self, mock_urlopen: MagicMock) -> None:
        client = HttpClient(timeout=5, rate_limiter=None)
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"no limiter bytes", b""]
        mock_urlopen.return_value.__enter__.return_value = mock_response
        result = client.fetch_bytes("https://example.test/")
        self.assertEqual(result, b"no limiter bytes")

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_rate_limiter_wait_called(self, mock_urlopen: MagicMock) -> None:
        limiter = RateLimiter(requests_per_second=1000.0)
        limiter.wait = MagicMock()
        client = HttpClient(timeout=5, rate_limiter=limiter)
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"first", b"", b"second", b""]
        mock_urlopen.return_value.__enter__.return_value = mock_response
        result1 = client.fetch("https://example.test/1")
        self.assertEqual(result1, "first")
        result2 = client.fetch("https://example.test/2")
        self.assertEqual(result2, "second")
        self.assertEqual(limiter.wait.call_count, 2)

    # --- POST JSON ---

    @patch("osintdepintel.http.urllib.request.Request")
    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_post_json_success(self, mock_urlopen: MagicMock, mock_request: MagicMock) -> None:
        data = json.dumps({"result": "ok"})
        mock_response = MagicMock()
        mock_response.read.side_effect = [data.encode(), b""]
        mock_urlopen.return_value.__enter__.return_value = mock_response
        result = self.client.post_json("https://example.test/api", {"input": "test"})
        self.assertEqual(result, {"result": "ok"})
        mock_request.assert_called_once()

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_post_json_invalid_response(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"not json", b""]
        mock_urlopen.return_value.__enter__.return_value = mock_response
        with self.assertRaises(HttpError) as ctx:
            self.client.post_json("https://example.test/api", {"input": "test"})
        self.assertIn("invalid json from response", str(ctx.exception).lower())

    # --- Retry / transient errors ---

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_retry_on_429_then_succeeds(self, mock_urlopen: MagicMock) -> None:
        http_error = urllib.error.HTTPError("https://example.test/", 429, "Too Many Requests", MagicMock(), None)
        mock_urlopen.return_value.__enter__.return_value.read.side_effect = [b"success", b""]
        mock_urlopen.side_effect = [http_error, mock_urlopen.return_value]
        result = self.client.fetch("https://example.test/")
        self.assertEqual(result, "success")

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_retry_on_503_then_succeeds(self, mock_urlopen: MagicMock) -> None:
        http_error = urllib.error.HTTPError("https://example.test/", 503, "Service Unavailable", MagicMock(), None)
        mock_urlopen.return_value.__enter__.return_value.read.side_effect = [b"recovered", b""]
        mock_urlopen.side_effect = [http_error, mock_urlopen.return_value]
        result = self.client.fetch("https://example.test/")
        self.assertEqual(result, "recovered")

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_retry_on_urlerror_then_succeeds(self, mock_urlopen: MagicMock) -> None:
        url_error = urllib.error.URLError("connection failed")
        mock_urlopen.return_value.__enter__.return_value.read.side_effect = [b"recovered", b""]
        mock_urlopen.side_effect = [url_error, mock_urlopen.return_value]
        result = self.client.fetch("https://example.test/")
        self.assertEqual(result, "recovered")

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_retry_on_timeout_then_succeeds(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value.__enter__.return_value.read.side_effect = [b"success after timeout", b""]
        mock_urlopen.side_effect = [TimeoutError("timed out"), mock_urlopen.return_value]
        result = self.client.fetch("https://example.test/")
        self.assertEqual(result, "success after timeout")

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_retry_on_connection_reset_then_succeeds(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value.__enter__.return_value.read.side_effect = [b"recovered", b""]
        mock_urlopen.side_effect = [ConnectionResetError("connection reset"), mock_urlopen.return_value]
        result = self.client.fetch("https://example.test/")
        self.assertEqual(result, "recovered")

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_404_is_not_retried(self, mock_urlopen: MagicMock) -> None:
        http_error = urllib.error.HTTPError("https://example.test/", 404, "Not Found", MagicMock(), None)
        mock_urlopen.side_effect = http_error
        with self.assertRaises(HttpError) as ctx:
            self.client.fetch("https://example.test/")
        self.assertIn("404", str(ctx.exception))

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_persistent_429_exhausts_retries(self, mock_urlopen: MagicMock) -> None:
        http_error = urllib.error.HTTPError("https://example.test/", 429, "Too Many Requests", MagicMock(), None)
        mock_urlopen.side_effect = [http_error, http_error, http_error]
        with self.assertRaises(HttpError) as ctx:
            self.client.fetch("https://example.test/")
        self.assertIn("429", str(ctx.exception))
        self.assertEqual(mock_urlopen.call_count, 3)

    @patch("osintdepintel.http.urllib.request.urlopen")
    def test_unknown_exception_no_retry(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = ValueError("strange error")
        with self.assertRaises(HttpError) as ctx:
            self.client.fetch("https://example.test/")
        self.assertIn("strange error", str(ctx.exception))

    # --- join_url ---

    def test_join_url_absolute(self) -> None:
        result = join_url("https://example.com/base/", "https://other.com/path")
        self.assertEqual(result, "https://other.com/path")

    def test_join_url_relative(self) -> None:
        result = join_url("https://example.com/base/", "relative.js")
        self.assertEqual(result, "https://example.com/base/relative.js")

    def test_join_url_relative_no_trailing_slash(self) -> None:
        result = join_url("https://example.com/base", "relative.js")
        self.assertEqual(result, "https://example.com/relative.js")


if __name__ == "__main__":
    unittest.main()
