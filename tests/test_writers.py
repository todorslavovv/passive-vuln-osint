from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from osintdepintel.reporting.writers import (
    aggregate_report,
    human_report,
    write_cyclonedx_sbom,
    write_reports,
    write_spdx_sbom,
)


class WriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_report = {
            "schema_version": "1.0",
            "target": {"name": "test-target", "url": "https://test/", "mode": "LAB TARGETS"},
            "summary": {
                "dependency_count": 3,
                "confirmed_dependencies": 2,
                "inferred_dependencies": 1,
                "vulnerability_count": 2,
                "finding_count": 1,
                "confidence_floor": 0.4,
            },
            "evidence_summary": {
                "observation_count": 5,
                "inference_count": 3,
                "dependency_evidence_chain_count": 0,
                "source_types": ["html"],
            },
            "confidence_distribution": {"high_0_8_to_1_0": 1, "medium_0_6_to_0_79": 1, "low_below_0_6": 1},
            "conflict_summary": {"count": 0, "conflicts": []},
            "source_coverage": {"observed_source_types": ["html"], "gap_categories": {}},
            "collection_gaps": [],
            "dependencies": [
                {
                    "target_name": "test-target",
                    "name": "lodash",
                    "ecosystem": "npm",
                    "version": "4.17.15",
                    "status": "inferred",
                    "confidence": 0.45,
                    "provenance": [],
                    "qualifiers": {},
                }
            ],
            "graph": {"target_name": "test-target", "nodes": {}, "edges": []},
            "vulnerabilities_by_dependency": {},
            "findings": [],
            "global_registry": {
                "assumptions": [{"timestamp": "2024-01-01T00:00:00"}],
                "failure_modes": [],
                "confidence_constraints": [],
                "conflicts": [],
                "observations": [],
                "inferences": [],
                "collection_gaps": [],
                "dependency_evidence_chains": [],
            },
        }

    def test_human_report_output(self) -> None:
        output = human_report(self.sample_report)
        self.assertIn("OSINT Dependency Vulnerability Intelligence Report", output)
        self.assertIn("test-target", output)
        self.assertIn("3", output)

    def test_human_report_no_findings(self) -> None:
        output = human_report(self.sample_report)
        self.assertIn("No vulnerable dependencies", output)

    def test_aggregate_report_single_target(self) -> None:
        result = aggregate_report([self.sample_report], self.sample_report["global_registry"])
        self.assertEqual(result["aggregate"]["target_count"], 1)
        self.assertEqual(result["aggregate"]["dependency_count"], 3)

    def test_aggregate_report_multiple_targets(self) -> None:
        reports = [self.sample_report, self.sample_report]
        result = aggregate_report(reports, self.sample_report["global_registry"])
        self.assertEqual(result["aggregate"]["target_count"], 2)
        self.assertEqual(result["aggregate"]["dependency_count"], 6)

    def test_write_reports_creates_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            paths = write_reports(output_dir, "test-target", self.sample_report, graph_dot="digraph {}")
            self.assertTrue(paths["json"].exists())
            self.assertTrue(paths["text"].exists())
            self.assertTrue(paths["graph"].exists())
            self.assertTrue(paths["cyclonedx"].exists())
            self.assertTrue(paths["spdx"].exists())

    def test_cyclonedx_sbom_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_cyclonedx_sbom(Path(tmp), "test_target", self.sample_report)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["bomFormat"], "CycloneDX")
            self.assertGreaterEqual(len(data["components"]), 1)

    def test_spdx_sbom_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_spdx_sbom(Path(tmp), "test_target", self.sample_report)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["spdxVersion"], "SPDX-2.3")
            self.assertGreaterEqual(len(data["packages"]), 1)


if __name__ == "__main__":
    unittest.main()
