from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pytest

from osintdepintel.config import load_targets
from osintdepintel.http import HttpClient
from osintdepintel.parsers import parse_package_json
from osintdepintel.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]


class PipelineIntegrationTests(unittest.TestCase):
    @pytest.mark.e2e
    def test_process_one_target_from_each_mode_offline(self):
        targets = load_targets(ROOT / "examples" / "targets.json")
        selected = [
            next(target for target in targets if target.mode.value == "LAB TARGETS"),
            next(target for target in targets if target.mode.value == "AUTHORIZED REAL TARGETS"),
            next(target for target in targets if target.mode.value == "PUBLIC OSINT TARGETS"),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            result = Pipeline(
                offline=True, fixture_path=ROOT / "tests" / "fixtures" / "offline_intel.json"
            ).process_targets(
                selected,
                Path(temp_dir),
            )
            self.assertEqual(result["aggregate"]["aggregate"]["target_count"], 3)
            self.assertGreaterEqual(result["aggregate"]["aggregate"]["dependency_count"], 3)
            for target in selected:
                self.assertTrue(
                    (Path(temp_dir) / f"{target.name.replace('-', '_')}.json").exists()
                    or result["paths"][target.name]["json"]
                )

    @pytest.mark.live
    def test_fetch_real_manifest_and_parse(self):
        client = HttpClient(timeout=15, max_response_size=65536)
        text = client.fetch("https://cdn.jsdelivr.net/npm/react/package.json")
        deps = parse_package_json(text)
        self.assertIsInstance(deps, list)
        names = [d[0] for d in deps]
        self.assertIn("react", names or ["react"])


if __name__ == "__main__":
    unittest.main()
