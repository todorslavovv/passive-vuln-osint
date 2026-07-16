import json
import unittest
from pathlib import Path

from osintdepintel.enrichment import EnrichmentEngine
from osintdepintel.exploit import correlate_exploits
from osintdepintel.models import DependencyRecord, DependencyStatus, Provenance, VulnerabilityRecord
from osintdepintel.registry import GlobalRegistry
from osintdepintel.scoring import score_findings

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "offline_intel.json"


class EnrichmentScoringTests(unittest.TestCase):
    def test_offline_enrichment_and_scoring(self):
        fixtures = json.loads(FIXTURE.read_text(encoding="utf-8"))
        dependency = DependencyRecord(
            "target",
            "lodash",
            "npm",
            "4.17.15",
            DependencyStatus.INFERRED,
            0.45,
            [Provenance("fixture", "test", "memory", evidence="test")],
        )
        registry = GlobalRegistry()
        vulns_by_dep = EnrichmentEngine(True, fixtures["vulnerabilities"]).enrich([dependency], registry)
        self.assertIn(dependency.key, vulns_by_dep)
        exploits = correlate_exploits(vulns_by_dep[dependency.key], fixtures["exploits"])
        findings = score_findings({dependency.key: dependency}, vulns_by_dep, exploits)
        self.assertEqual(findings[0].vulnerability.vulnerability_id, "CVE-2020-8203")
        self.assertGreater(findings[0].score, 0)
        self.assertTrue(findings[0].exploit_signals)

    def test_low_confidence_inferred_dependency_score_is_capped(self):
        dependency = DependencyRecord(
            "target",
            "next",
            "npm",
            "13.4.0",
            DependencyStatus.INFERRED,
            0.38,
            [Provenance("public_js_bundle", "javascript_bundles", "https://example.test/app.js", evidence="heuristic")],
        )
        vulnerability = VulnerabilityRecord(
            vulnerability_id="CVE-EXAMPLE",
            source="fixture",
            package_name="next",
            ecosystem="npm",
            affected_versions=["<13.4.20"],
            summary="example",
            severity="HIGH",
            cvss_score=8.0,
            match_confidence=0.92,
        )
        findings = score_findings({dependency.key: dependency}, {dependency.key: [vulnerability]}, {})
        self.assertLessEqual(findings[0].score, 28.0)
        self.assertTrue(findings[0].factors["low_confidence"])


if __name__ == "__main__":
    unittest.main()
