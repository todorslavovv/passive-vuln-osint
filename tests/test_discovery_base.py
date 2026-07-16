from __future__ import annotations

import unittest

from osintdepintel.discovery.base import DiscoveryPlugin
from osintdepintel.models import DiscoveryResult, TargetConfig, TargetMode
from osintdepintel.registry import GlobalRegistry


class ConcretePlugin(DiscoveryPlugin):
    name = "test_plugin"

    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        return DiscoveryResult()


class DiscoveryBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plugin = ConcretePlugin()
        self.target = TargetConfig("test", "https://test/", TargetMode.LAB)
        self.registry = GlobalRegistry()

    def test_plugin_name(self) -> None:
        self.assertEqual(self.plugin.name, "test_plugin")

    def test_plugin_offline_default(self) -> None:
        self.assertFalse(self.plugin.offline)

    def test_plugin_offline_set(self) -> None:
        plugin = ConcretePlugin(offline=True)
        self.assertTrue(plugin.offline)

    def test_discover_returns_discovery_result(self) -> None:
        result = self.plugin.discover(self.target, self.registry)
        self.assertIsInstance(result, DiscoveryResult)


if __name__ == "__main__":
    unittest.main()
