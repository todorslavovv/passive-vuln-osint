from __future__ import annotations

import unittest
from pathlib import Path

from osintdepintel.enrichment.providers import _nvd_score
from osintdepintel.models import DependencyRecord, DependencyStatus, Provenance


class NvdEnrichmentTests(unittest.TestCase):
    def test_nvd_score_returns_none_for_empty_metrics(self) -> None:
        self.assertIsNone(_nvd_score({}))

    def test_nvd_score_parses_v31(self) -> None:
        metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}
        self.assertEqual(_nvd_score(metrics), 7.5)

    def test_nvd_score_parses_v30(self) -> None:
        metrics = {"cvssMetricV30": [{"cvssData": {"baseScore": 9.1}}]}
        self.assertEqual(_nvd_score(metrics), 9.1)

    def test_nvd_score_parses_v2(self) -> None:
        metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}
        self.assertEqual(_nvd_score(metrics), 5.0)

    def test_nvd_score_prefers_v31_over_v30(self) -> None:
        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
            "cvssMetricV30": [{"cvssData": {"baseScore": 9.0}}],
        }
        self.assertEqual(_nvd_score(metrics), 7.5)

    def test_nvd_score_non_dict_cvss_data(self) -> None:
        metrics = {"cvssMetricV31": [{"cvssData": None}]}
        self.assertIsNone(_nvd_score(metrics))

    def test_nvd_score_non_list_values(self) -> None:
        metrics = {"cvssMetricV31": "not a list"}
        self.assertIsNone(_nvd_score(metrics))


class GitHubAdvisoryMappingTests(unittest.TestCase):
    def test_gh_ecosystem_mapping(self) -> None:
        from osintdepintel.enrichment.providers import GITHUB_ADVISORY_ECOSYSTEMS

        self.assertEqual(GITHUB_ADVISORY_ECOSYSTEMS.get("npm"), "NPM")
        self.assertEqual(GITHUB_ADVISORY_ECOSYSTEMS.get("PyPI"), "PIP")
        self.assertEqual(GITHUB_ADVISORY_ECOSYSTEMS.get("Maven"), "MAVEN")
        self.assertEqual(GITHUB_ADVISORY_ECOSYSTEMS.get("RubyGems"), "RUBYGEMS")
        self.assertEqual(GITHUB_ADVISORY_ECOSYSTEMS.get("Go"), "GO")
        self.assertIsNone(GITHUB_ADVISORY_ECOSYSTEMS.get("unknown"))


class OfflineEnrichmentTests(unittest.TestCase):
    def test_offline_enrichment_produces_matches(self) -> None:
        from osintdepintel.enrichment import EnrichmentEngine
        from osintdepintel.registry import GlobalRegistry

        fixtures = Path(__file__).resolve().parent / "fixtures" / "offline_intel.json"
        import json

        with open(fixtures) as f:
            data = json.load(f)

        dependency = DependencyRecord(
            "test-target",
            "lodash",
            "npm",
            "4.17.15",
            DependencyStatus.INFERRED,
            0.45,
            [Provenance("target_config", "test", "test")],
        )
        registry = GlobalRegistry()
        engine = EnrichmentEngine(offline=True, fixture_vulnerabilities=data.get("vulnerabilities", []))
        vulns = engine.enrich([dependency], registry)
        self.assertIn(dependency.key, vulns)
        self.assertEqual(vulns[dependency.key][0].vulnerability_id, "CVE-2020-8203")

    def test_offline_enrichment_no_match(self) -> None:
        from osintdepintel.enrichment import EnrichmentEngine
        from osintdepintel.registry import GlobalRegistry

        dependency = DependencyRecord(
            "test-target",
            "nonexistent-pkg",
            "npm",
            "1.0.0",
            DependencyStatus.INFERRED,
            0.5,
            [Provenance("target_config", "test", "test")],
        )
        registry = GlobalRegistry()
        engine = EnrichmentEngine(offline=True, fixture_vulnerabilities=[])
        vulns = engine.enrich([dependency], registry)
        self.assertEqual(len(vulns), 0)

    def test_offline_enrichment_false_positive_jquery_patched(self) -> None:
        from osintdepintel.enrichment import EnrichmentEngine
        from osintdepintel.registry import GlobalRegistry

        fixtures = Path(__file__).resolve().parent / "fixtures" / "offline_intel.json"
        import json

        with open(fixtures) as f:
            data = json.load(f)

        dependency = DependencyRecord(
            "evolution-of-dreams",
            "jquery",
            "npm",
            "3.5.1",
            DependencyStatus.INFERRED,
            0.42,
            [Provenance("target_config", "test", "test")],
        )
        registry = GlobalRegistry()
        engine = EnrichmentEngine(offline=True, fixture_vulnerabilities=data.get("vulnerabilities", []))
        vulns = engine.enrich([dependency], registry)
        self.assertNotIn(dependency.key, vulns, "jQuery 3.5.1 should NOT match any jQuery vulnerability (patched)")


if __name__ == "__main__":
    unittest.main()
