import unittest

from osintdepintel.graph import build_graph
from osintdepintel.models import DependencyRecord, DependencyStatus, Provenance
from osintdepintel.registry import GlobalRegistry


class GraphRegistryTests(unittest.TestCase):
    def test_graph_merges_duplicate_records_and_tracks_status_conflict(self):
        registry = GlobalRegistry()
        provenance = Provenance("fixture", "test", "memory", "now", "evidence")
        records = [
            DependencyRecord("target", "lodash", "npm", "4.17.15", DependencyStatus.INFERRED, 0.4, [provenance]),
            DependencyRecord("target", "lodash", "npm", "4.17.15", DependencyStatus.CONFIRMED, 0.9, [provenance]),
        ]
        graph = build_graph("target", records, [], registry)
        self.assertEqual(len(graph.nodes), 1)
        self.assertEqual(graph.nodes["npm:lodash@4.17.15"].confidence, 0.9)
        self.assertEqual(len(registry.conflicts), 1)


if __name__ == "__main__":
    unittest.main()
