from __future__ import annotations

import json
import unittest
from pathlib import Path

from osintdepintel.discovery.plugins import SBOMPlugin
from osintdepintel.http import HttpError
from osintdepintel.models import DependencyStatus, TargetConfig, TargetMode
from osintdepintel.registry import GlobalRegistry

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


class FakeHttp:
    def __init__(self, responses: dict[str, str]) -> None:
        self.responses = responses

    def fetch(self, url: str) -> str:
        if url in self.responses:
            return self.responses[url]
        raise HttpError(f"not found: {url}")


class SBOMPluginTests(unittest.TestCase):
    maxDiff = None

    def test_no_sbom_urls_returns_empty_and_adds_assumption_and_gap(self) -> None:
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, sbom_urls=[])
        registry = GlobalRegistry()
        plugin = SBOMPlugin(offline=False)
        result = plugin.discover(target, registry)

        self.assertEqual(len(result.records), 0)
        reg_dict = registry.to_dict()
        ass_msgs = [str(a).lower() for a in reg_dict.get("assumptions", [])]
        gap_msgs = [str(g).lower() for g in reg_dict.get("collection_gaps", [])]
        self.assertTrue(any("no public sbom url" in m for m in ass_msgs))
        self.assertTrue(any("no public sbom url" in m for m in gap_msgs))

    def test_offline_skips_and_adds_assumption_and_gap(self) -> None:
        target = TargetConfig(
            "test", "https://example.test", TargetMode.PUBLIC, sbom_urls=["https://sbom.test/cyclonedx"]
        )
        registry = GlobalRegistry()
        plugin = SBOMPlugin(offline=True)
        result = plugin.discover(target, registry)

        self.assertEqual(len(result.records), 0)
        reg_dict = registry.to_dict()
        self.assertTrue(any("offline" in str(a).lower() for a in reg_dict.get("assumptions", [])))
        self.assertTrue(any("offline" in str(g).lower() for g in reg_dict.get("collection_gaps", [])))

    def test_http_error_adds_failure(self) -> None:
        target = TargetConfig(
            "test", "https://example.test", TargetMode.PUBLIC, sbom_urls=["https://sbom.test/missing"]
        )
        plugin = SBOMPlugin(http=FakeHttp({}), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("could not load sbom" in f.lower() for f in result.failures))

    def test_malformed_json_adds_failure(self) -> None:
        responses = {"https://sbom.test/bad": "not valid json"}
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, sbom_urls=["https://sbom.test/bad"])
        plugin = SBOMPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("could not load sbom" in f.lower() for f in result.failures))

    def test_parses_cyclonedx_sbom(self) -> None:
        cyclonedx = (FIXTURE_DIR / "sbom_cyclonedx.json").read_text(encoding="utf-8")
        responses = {"https://sbom.test/cyclonedx": cyclonedx}
        target = TargetConfig(
            "test", "https://example.test", TargetMode.PUBLIC, sbom_urls=["https://sbom.test/cyclonedx"]
        )
        plugin = SBOMPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 3)
        records_by_name = {r.name: r for r in result.records}
        self.assertIn("lodash", records_by_name)
        self.assertIn("react", records_by_name)
        self.assertIn("requests", records_by_name)
        self.assertEqual(records_by_name["lodash"].version, "4.17.21")
        self.assertEqual(records_by_name["react"].version, "18.2.0")
        self.assertEqual(records_by_name["requests"].version, "2.31.0")
        for r in result.records:
            self.assertEqual(r.status, DependencyStatus.CONFIRMED)
            self.assertAlmostEqual(r.confidence, 0.9)
            self.assertEqual(r.provenance[0].source_type, "public_sbom")

    def test_parses_spdx_sbom(self) -> None:
        spdx = (FIXTURE_DIR / "sbom_spdx.json").read_text(encoding="utf-8")
        responses = {"https://sbom.test/spdx": spdx}
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, sbom_urls=["https://sbom.test/spdx"])
        plugin = SBOMPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 3)
        records_by_name = {r.name: r for r in result.records}
        self.assertIn("flask", records_by_name)
        self.assertIn("gunicorn", records_by_name)
        self.assertIn("werkzeug", records_by_name)
        for r in result.records:
            self.assertEqual(r.status, DependencyStatus.CONFIRMED)
            self.assertAlmostEqual(r.confidence, 0.9)

    def test_ecosystem_resolved_from_purl(self) -> None:
        cyclonedx = (FIXTURE_DIR / "sbom_cyclonedx.json").read_text(encoding="utf-8")
        responses = {"https://sbom.test/cyclonedx": cyclonedx}
        target = TargetConfig(
            "test", "https://example.test", TargetMode.PUBLIC, sbom_urls=["https://sbom.test/cyclonedx"]
        )
        plugin = SBOMPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        records_by_name = {r.name: r for r in result.records}
        self.assertEqual(records_by_name["lodash"].ecosystem, "npm")
        self.assertEqual(records_by_name["requests"].ecosystem, "PyPI")

    def test_inferences_and_observations_have_correct_shape(self) -> None:
        cyclonedx = (FIXTURE_DIR / "sbom_cyclonedx.json").read_text(encoding="utf-8")
        url = "https://sbom.test/cyclonedx"
        responses = {url: cyclonedx}
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, sbom_urls=[url])
        plugin = SBOMPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.observations), 1)
        obs = result.observations[0]
        self.assertEqual(obs["source_type"], "public_sbom")
        self.assertEqual(obs["locator"], url)

        self.assertEqual(len(result.inferences), 3)
        inf = result.inferences[0]
        self.assertIn("package_name", inf)
        self.assertIn("reasoning", inf)
        self.assertEqual(inf["status"], DependencyStatus.CONFIRMED.value)

    def test_multiple_sbom_urls_all_processed(self) -> None:
        cyclonedx = (FIXTURE_DIR / "sbom_cyclonedx.json").read_text(encoding="utf-8")
        spdx = (FIXTURE_DIR / "sbom_spdx.json").read_text(encoding="utf-8")
        responses = {
            "https://sbom.test/cdx": cyclonedx,
            "https://sbom.test/spdx": spdx,
        }
        target = TargetConfig(
            "test",
            "https://example.test",
            TargetMode.PUBLIC,
            sbom_urls=["https://sbom.test/cdx", "https://sbom.test/spdx"],
        )
        plugin = SBOMPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 6)
        names = {r.name for r in result.records}
        self.assertIn("lodash", names)
        self.assertIn("flask", names)

    def test_empty_sbom_no_records_no_failures(self) -> None:
        empty_cdx = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1, "components": []})
        responses = {"https://sbom.test/empty": empty_cdx}
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, sbom_urls=["https://sbom.test/empty"])
        plugin = SBOMPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 0)
        self.assertEqual(len(result.failures), 0)


if __name__ == "__main__":
    unittest.main()
