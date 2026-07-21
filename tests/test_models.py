from __future__ import annotations

import unittest

from osintdepintel.models import (
    DependencyEdge,
    DependencyRecord,
    DependencyStatus,
    DiscoveryResult,
    Provenance,
    TargetConfig,
    VulnerabilityRecord,
)


class ModelsTests(unittest.TestCase):
    def test_provenance_default_collected_at(self) -> None:
        p = Provenance("web", "test", "https://example.test/")
        self.assertIsNotNone(p.collected_at)
        self.assertIn("T", p.collected_at)

    def test_target_config_from_dict(self) -> None:
        raw = {"name": "test", "url": "https://test/", "github_repos": ["org/repo"]}
        target = TargetConfig.from_dict(raw)
        self.assertEqual(target.name, "test")
        self.assertEqual(target.github_repos, ["org/repo"])

    def test_target_config_to_dict(self) -> None:
        target = TargetConfig("test", "https://test/")
        data = target.to_dict()
        self.assertEqual(data["name"], "test")
        self.assertNotIn("mode", data)

    def test_dependency_record_key(self) -> None:
        record = DependencyRecord("t", "lodash", "npm", "4.17.15", DependencyStatus.INFERRED, 0.5, [])
        self.assertEqual(record.key, "npm:lodash@4.17.15")

    def test_dependency_record_key_no_version(self) -> None:
        record = DependencyRecord("t", "lodash", "npm", None, DependencyStatus.INFERRED, 0.5, [])
        self.assertEqual(record.key, "npm:lodash@unknown")

    def test_dependency_record_confirmed_status(self) -> None:
        record = DependencyRecord("t", "pkg", "npm", "1.0.0", DependencyStatus.CONFIRMED, 0.9, [])
        self.assertEqual(record.status, DependencyStatus.CONFIRMED)
        self.assertEqual(record.to_dict()["status"], "confirmed")

    def test_dependency_edge_to_dict(self) -> None:
        edge = DependencyEdge("t", "parent@1", "child@2", DependencyStatus.INFERRED, 0.6, [])
        data = edge.to_dict()
        self.assertEqual(data["status"], "inferred")
        self.assertEqual(data["parent_key"], "parent@1")

    def test_vulnerability_record_identity_set(self) -> None:
        vuln = VulnerabilityRecord("CVE-2024-0001", "nvd", "pkg", "npm", ["<2.0"], "test", aliases=["GHSA-xxxx"])
        ids = vuln.identity_set()
        self.assertIn("CVE-2024-0001", ids)
        self.assertIn("GHSA-xxxx", ids)

    def test_discovery_result_defaults(self) -> None:
        result = DiscoveryResult()
        self.assertEqual(result.records, [])
        self.assertEqual(result.edges, [])
        self.assertEqual(result.failures, [])

    def test_provenance_to_dict(self) -> None:
        p = Provenance("web", "plugin", "https://example.test/", evidence="found it")
        d = p.to_dict()
        self.assertEqual(d["source_type"], "web")
        self.assertEqual(d["evidence"], "found it")

    def test_vulnerability_record_to_dict(self) -> None:
        vuln = VulnerabilityRecord("CVE-2024-0001", "nvd", "pkg", "npm", ["<2.0"], "test")
        d = vuln.to_dict()
        self.assertEqual(d["vulnerability_id"], "CVE-2024-0001")
        self.assertEqual(d["severity"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
