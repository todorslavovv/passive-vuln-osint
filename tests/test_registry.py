from __future__ import annotations

import unittest

from osintdepintel.registry import GlobalRegistry


class RegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = GlobalRegistry()

    def test_add_assumption(self) -> None:
        self.registry.add_assumption("target-a", "test", "assumption message")
        self.assertEqual(len(self.registry.assumptions), 1)
        self.assertEqual(self.registry.assumptions[0]["target"], "target-a")
        self.assertEqual(self.registry.assumptions[0]["message"], "assumption message")

    def test_add_failure(self) -> None:
        self.registry.add_failure("target-a", "plugin-x", "something failed")
        self.assertEqual(len(self.registry.failure_modes), 1)

    def test_add_plugin_event(self) -> None:
        self.registry.add_plugin_event("target-a", "github", "loaded manifests")
        self.assertEqual(len(self.registry.plugin_events), 1)

    def test_add_observation(self) -> None:
        self.registry.add_observation({"source_type": "html", "target": "target-a"})
        self.assertEqual(len(self.registry.observations), 1)

    def test_add_inference(self) -> None:
        self.registry.add_inference({"package_name": "lodash", "confidence": 0.6})
        self.assertEqual(len(self.registry.inferences), 1)

    def test_add_gap(self) -> None:
        self.registry.add_gap("target-a", "discovery", "not_collected", "skipped offline")
        self.assertEqual(len(self.registry.collection_gaps), 1)
        self.assertEqual(self.registry.collection_gaps[0]["category"], "not_collected")

    def test_add_conflict(self) -> None:
        self.registry.add_conflict("target-a", "graph", {"key": "value"})
        self.assertEqual(len(self.registry.conflicts), 1)
        gaps = [g for g in self.registry.collection_gaps if g["category"] == "contradicted"]
        self.assertEqual(len(gaps), 1)

    def test_to_dict_structure(self) -> None:
        self.registry.add_assumption("t", "p", "msg")
        self.registry.add_observation({"source_type": "html"})
        d = self.registry.to_dict()
        self.assertIn("assumptions", d)
        self.assertIn("evidence_summary", d)
        self.assertIn("source_coverage", d)
        self.assertIn("confidence_distribution", d)
        self.assertEqual(d["evidence_summary"]["observation_count"], 1)

    def test_add_risk(self) -> None:
        self.registry.add_risk("target-a", "scoring", "low confidence", severity="warn")
        self.assertEqual(len(self.registry.risks), 1)
        self.assertEqual(self.registry.risks[0]["severity"], "warn")

    def test_add_confidence_constraint(self) -> None:
        self.registry.add_confidence_constraint("target-a", "discovery", "version not confirmed")
        self.assertEqual(len(self.registry.confidence_constraints), 1)


if __name__ == "__main__":
    unittest.main()
