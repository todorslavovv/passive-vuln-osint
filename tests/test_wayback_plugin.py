from __future__ import annotations

import unittest
from typing import Any

from osintdepintel.discovery.plugins import WaybackMachinePlugin
from osintdepintel.http import HttpError
from osintdepintel.models import TargetConfig, TargetMode
from osintdepintel.registry import GlobalRegistry


class FakeHttpClientForWayback:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses

    def get_json(self, url: str) -> Any:
        if url in self.responses:
            return self.responses[url]
        raise HttpError("not found")

    def fetch(self, url: str) -> str:
        if url in self.responses:
            return self.responses[url]
        raise HttpError("not found")


class WaybackMachinePluginTests(unittest.TestCase):
    def test_offline_skip(self) -> None:
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC)
        registry = GlobalRegistry()
        plugin = WaybackMachinePlugin(offline=True)
        result = plugin.discover(target, registry)
        self.assertEqual(len(result.records), 0)
        reg_dict = registry.to_dict()
        self.assertTrue(any("offline" in str(a) for a in reg_dict.get("assumptions", [])))
        self.assertTrue(any("offline" in str(g) for g in reg_dict.get("collection_gaps", [])))

    def test_no_host_returns_empty(self) -> None:
        target = TargetConfig("test", "not-a-url", TargetMode.PUBLIC)
        plugin = WaybackMachinePlugin(offline=False)
        result = plugin.discover(target, GlobalRegistry())
        self.assertEqual(len(result.records), 0)

    def test_cdx_failure_returns_empty(self) -> None:
        class FailHttp:
            def get_json(self, url: str) -> Any:
                raise HttpError("CDX failed")

            def fetch(self, url: str) -> str:
                raise HttpError("fetch failed")

        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC)
        plugin = WaybackMachinePlugin(http=FailHttp())  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("CDX" in f for f in result.failures))

    def test_mixed_status_cdx_only_keeps_200(self) -> None:
        cdx_response = [
            ["original", "timestamp", "statuscode"],
            ["https://example.test/a.js", "20240101000000", "200"],
            ["https://example.test/b.js", "20240101000001", "404"],
            ["https://example.test/c.js", "20240101000002", "200"],
            ["https://example.test/a.js", "20240102000000", "200"],
        ]

        class MockHttp:
            def get_json(self, url: str) -> Any:
                return cdx_response

            def fetch(self, url: str) -> str:
                return "/*! jquery@3.6.0 */"

        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC)
        plugin = WaybackMachinePlugin(http=MockHttp())  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())
        self.assertGreater(len(result.records), 0)
        for record in result.records:
            self.assertTrue(record.qualifiers.get("historical_snapshot"))
            self.assertIn("archived_timestamp", record.qualifiers)
            # Confidence should be max(0.1, inferred_confidence - 0.1)
            # infer_from_js produces confidence ~0.64 → after penalty: 0.54
            self.assertAlmostEqual(record.confidence, 0.54, places=2)
            for prov in record.provenance:
                self.assertEqual(prov.source_type, "wayback_machine")
                self.assertEqual(prov.source_name, "Wayback Machine")
                self.assertEqual(prov.fetch_method, "CDX+GET")
                self.assertIn("Archived JS snapshot from", prov.evidence)
                # locator should be the full wayback archive URL
                self.assertIn("web.archive.org/web/", prov.locator)
                # evidence should contain the timestamp
                ts = record.qualifiers.get("archived_timestamp", "")
                self.assertIn(ts, prov.evidence)

    def test_empty_cdx_returns_empty(self) -> None:
        class MockHttp:
            def get_json(self, url: str) -> Any:
                return [["original", "timestamp", "statuscode"]]

            def fetch(self, url: str) -> str:
                return "var x = 1;"

        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC)
        plugin = WaybackMachinePlugin(http=MockHttp())  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())
        self.assertEqual(len(result.records), 0)

    def test_fetch_failure_records_observation(self) -> None:
        cdx_response = [
            ["original", "timestamp", "statuscode"],
            ["https://example.test/a.js", "20240101000000", "200"],
        ]

        class MockHttp:
            def get_json(self, url: str) -> Any:
                return cdx_response

            def fetch(self, url: str) -> str:
                raise HttpError("fetch failed")

        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC)
        plugin = WaybackMachinePlugin(http=MockHttp())  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())
        self.assertEqual(len(result.records), 0)

    def test_grouped_snapshots_capped_at_three(self) -> None:
        cdx_response = [
            ["original", "timestamp", "statuscode"],
            # 5 timestamps for a.js — only 3 most recent should be fetched
            ["https://example.test/a.js", "20240101000000", "200"],
            ["https://example.test/a.js", "20240201000000", "200"],
            ["https://example.test/a.js", "20240301000000", "200"],
            ["https://example.test/a.js", "20240401000000", "200"],
            ["https://example.test/a.js", "20240501000000", "200"],
            # 2 timestamps for b.js — both should be fetched
            ["https://example.test/b.js", "20240101000001", "200"],
            ["https://example.test/b.js", "20240301000001", "200"],
        ]
        fetched_urls: list[str] = []

        class RecordingHttp:
            def __init__(self) -> None:
                self.call_count = 0

            def get_json(self, url: str) -> Any:
                return cdx_response

            def fetch(self, url: str) -> str:
                fetched_urls.append(url)
                self.call_count += 1
                return "/*! jquery@3.6.0 */"

        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC)
        plugin = WaybackMachinePlugin(http=RecordingHttp())  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())
        # a.js has 5 entries → capped at 3; b.js has 2 → both fetched → total 5 fetch calls
        self.assertEqual(len(fetched_urls), 5)
        # The 3 a.js fetches should use the 3 most recent timestamps
        self.assertTrue(any("20240501000000" in u for u in fetched_urls), "latest a.js timestamp missing")
        self.assertTrue(any("20240401000000" in u for u in fetched_urls), "2nd latest a.js timestamp missing")
        self.assertTrue(any("20240301000000" in u for u in fetched_urls), "3rd latest a.js timestamp missing")
        # The oldest 2 timestamps for a.js should NOT be fetched
        self.assertFalse(any("20240101000000" in u and "a.js" in u for u in fetched_urls), "oldest a.js was fetched")
        self.assertFalse(
            any("20240201000000" in u and "a.js" in u for u in fetched_urls), "2nd oldest a.js was fetched"
        )
        # Both b.js timestamps should be fetched
        self.assertTrue(any("20240101000001" in u for u in fetched_urls), "b.js first ts missing")
        self.assertTrue(any("20240301000001" in u for u in fetched_urls), "b.js second ts missing")
        # All fetched records should have the confidence penalty applied
        for record in result.records:
            self.assertAlmostEqual(record.confidence, 0.54, places=2)


if __name__ == "__main__":
    unittest.main()
