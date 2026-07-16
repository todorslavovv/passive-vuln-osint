from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from osintdepintel.reporting.writers import write_cyclonedx_sbom, write_spdx_sbom


class SbomExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None
        self.report = {
            "target": {"name": "test-target", "url": "https://example.test", "mode": "LAB TARGETS"},
            "dependencies": [
                {
                    "name": "lodash",
                    "ecosystem": "npm",
                    "version": "4.17.15",
                    "status": "inferred",
                    "confidence": 0.45,
                    "relationship": "direct",
                    "scope": "runtime",
                    "provenance": [{"source_type": "target_config", "locator": "test"}],
                },
                {
                    "name": "express",
                    "ecosystem": "npm",
                    "version": "4.17.1",
                    "status": "confirmed",
                    "confidence": 0.88,
                    "relationship": "direct",
                    "scope": "runtime",
                    "provenance": [{"source_type": "github_manifest", "locator": "test"}],
                },
            ],
            "graph": {"nodes": {}, "edges": []},
            "findings": [
                {
                    "score": 6.18,
                    "dependency_key": "npm:lodash@4.17.15",
                    "dependency": {"name": "lodash", "version": "4.17.15"},
                    "vulnerability": {
                        "vulnerability_id": "CVE-2020-8203",
                        "summary": "Prototype pollution in lodash",
                        "severity": "HIGH",
                    },
                }
            ],
        }

    def test_write_cyclonedx_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_cyclonedx_sbom(Path(tmp), "test-target", self.report)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["bomFormat"], "CycloneDX")
            self.assertEqual(data["specVersion"], "1.4")
            components = data.get("components", [])
            self.assertEqual(len(components), 2)
            names = {c["name"] for c in components}
            self.assertIn("lodash", names)
            self.assertIn("express", names)
            lodash = next(c for c in components if c["name"] == "lodash")
            self.assertEqual(lodash["version"], "4.17.15")

    def test_write_spdx_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_spdx_sbom(Path(tmp), "test-target", self.report)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["spdxVersion"], "SPDX-2.3")
            self.assertEqual(data["dataLicense"], "CC0-1.0")
            packages = data.get("packages", [])
            self.assertEqual(len(packages), 2)
            names = {p["name"] for p in packages}
            self.assertIn("lodash", names)
            self.assertIn("express", names)


if __name__ == "__main__":
    unittest.main()
