import json
import unittest

from osintdepintel.discovery.plugins import JavaScriptBundlePlugin
from osintdepintel.models import DependencyStatus, TargetConfig
from osintdepintel.registry import GlobalRegistry


class FakeHttpClient:
    def __init__(self, responses):
        self.responses = responses

    def fetch(self, url):
        return self.responses[url]


class JavaScriptPluginTests(unittest.TestCase):
    def test_plugin_fetches_html_js_and_source_map_into_evidence_chained_records(self):
        html_url = "https://example.test/"
        js_url = "https://example.test/_next/static/chunks/app.js"
        map_url = "https://example.test/_next/static/chunks/app.js.map"
        source_map = {
            "version": 3,
            "sources": ["webpack://./node_modules/react/package.json"],
            "sourcesContent": ['{"name": "react", "version": "18.2.0"}'],
        }
        responses = {
            html_url: f'<html><script src="{js_url}"></script></html>',
            js_url: "/*! next@13.4.0 */ /*! react@17.0.2 */\n//# sourceMappingURL=app.js.map",
            map_url: json.dumps(source_map),
        }
        target = TargetConfig("example", html_url)
        result = JavaScriptBundlePlugin(http=FakeHttpClient(responses), offline=False).discover(
            target, GlobalRegistry()
        )

        records = {(record.name, record.version): record for record in result.records}
        self.assertIn(("next", "13.4.0"), records)
        self.assertIn(("react", "18.2.0"), records)
        self.assertIn(("react", "17.0.2"), records)
        self.assertEqual(records[("next", "13.4.0")].status, DependencyStatus.INFERRED)
        self.assertEqual(records[("react", "18.2.0")].status, DependencyStatus.CONFIRMED)
        self.assertTrue(records[("react", "18.2.0")].qualifiers["evidence_chain"])
        self.assertTrue(any(item["source_type"] == "source_map" for item in result.observations))
        self.assertTrue(result.conflicts)


if __name__ == "__main__":
    unittest.main()
