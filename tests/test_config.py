from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from osintdepintel.config import load_targets, select_targets
from osintdepintel.models import TargetMode


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sample = {
            "targets": [
                {"name": "test-a", "url": "https://a.test/", "mode": "LAB TARGETS"},
                {"name": "test-b", "url": "https://b.test/", "mode": "PUBLIC OSINT TARGETS"},
            ]
        }

    def _write_config(self, data: dict) -> Path:
        path = Path(tempfile.mkstemp(suffix=".json")[1])
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_load_targets(self) -> None:
        path = self._write_config(self.sample)
        targets = load_targets(path)
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0].name, "test-a")
        self.assertEqual(targets[0].mode, TargetMode.LAB)
        path.unlink()

    def test_select_targets_by_name(self) -> None:
        path = self._write_config(self.sample)
        targets = load_targets(path)
        selected = select_targets(targets, "test-a", False)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].name, "test-a")
        path.unlink()

    def test_select_targets_all(self) -> None:
        path = self._write_config(self.sample)
        targets = load_targets(path)
        selected = select_targets(targets, None, True)
        self.assertEqual(len(selected), 2)
        path.unlink()

    def test_select_targets_missing(self) -> None:
        path = self._write_config(self.sample)
        targets = load_targets(path)
        with self.assertRaises(ValueError):
            select_targets(targets, None, False)
        path.unlink()

    def test_select_targets_unknown_name(self) -> None:
        path = self._write_config(self.sample)
        targets = load_targets(path)
        with self.assertRaises(ValueError):
            select_targets(targets, "nonexistent", False)
        path.unlink()

    def test_target_mode_values(self) -> None:
        self.assertEqual(TargetMode.LAB.value, "LAB TARGETS")
        self.assertEqual(TargetMode.AUTHORIZED.value, "AUTHORIZED REAL TARGETS")
        self.assertEqual(TargetMode.PUBLIC.value, "PUBLIC OSINT TARGETS")


if __name__ == "__main__":
    unittest.main()
