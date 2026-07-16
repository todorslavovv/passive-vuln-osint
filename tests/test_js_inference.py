import json
import unittest

from osintdepintel.js_inference import (
    extract_script_urls,
    extract_source_map_urls,
    infer_from_html,
    infer_from_js,
    infer_from_source_map,
)
from osintdepintel.models import DependencyStatus


class JsInferenceTests(unittest.TestCase):
    def test_html_script_tag_extraction_and_versioned_asset_inference(self):
        html = '<html><script src="/static/jquery-3.6.0.min.js"></script></html>'
        urls = extract_script_urls("https://example.test/app/", html)
        self.assertEqual(urls, ["https://example.test/static/jquery-3.6.0.min.js"])

        candidates = infer_from_html("target", html, "https://example.test/app/", "javascript_bundles")
        jquery = next(candidate for candidate in candidates if candidate.name == "jquery")
        self.assertEqual(jquery.version, "3.6.0")
        self.assertEqual(jquery.status, DependencyStatus.INFERRED)
        self.assertIn("evidence_chain", jquery.to_record().qualifiers)
        self.assertEqual(jquery.evidence_chain[0].source_url, "https://example.test/app/")

    def test_html_script_tag_extraction_handles_whitespace(self):
        html = '<script src = "/static/vue-3.4.21.global.prod.js"></script>'
        urls = extract_script_urls("https://example.test/app/", html)
        self.assertEqual(urls, ["https://example.test/static/vue-3.4.21.global.prod.js"])

        candidates = infer_from_html("target", html, "https://example.test/app/", "javascript_bundles")
        vue = next(candidate for candidate in candidates if candidate.name == "vue")
        self.assertEqual(vue.version, "3.4.21")

    def test_inline_runtime_config_dependency_inference(self):
        html = '<script>window.__APP_CONFIG__ = {"dependencies": {"react": "18.2.0", "lodash": "^4.17.21"}};</script>'
        candidates = infer_from_html("target", html, "https://example.test/app/", "javascript_bundles")
        react = next(candidate for candidate in candidates if candidate.name == "react")
        lodash = next(candidate for candidate in candidates if candidate.name == "lodash")
        self.assertEqual(react.version, "18.2.0")
        self.assertEqual(lodash.version, "4.17.21")
        self.assertEqual(react.evidence_chain[0].source_type, "inline_runtime_config")
        self.assertGreaterEqual(react.confidence, 0.6)

    def test_next_bundle_version_token_inference(self):
        js = "/*! next@13.4.0 */ self.__BUILD_MANIFEST = {};"
        candidates = infer_from_js(
            "target", js, "https://example.test/_next/static/chunks/main.js", "javascript_bundles"
        )
        next_candidate = next(candidate for candidate in candidates if candidate.name == "next")
        self.assertEqual(next_candidate.version, "13.4.0")
        self.assertGreaterEqual(next_candidate.confidence, 0.6)
        self.assertEqual(next_candidate.status, DependencyStatus.INFERRED)
        self.assertIn("package@version", next_candidate.reasoning)

    def test_webpack_module_graph_hint_is_low_confidence_without_version(self):
        js = "webpack:///./node_modules/@scope/pkg/index.js\nwebpack:///./node_modules/react/index.js"
        candidates = infer_from_js("target", js, "https://example.test/static/app.js", "javascript_bundles")
        scoped = next(candidate for candidate in candidates if candidate.name == "@scope/pkg")
        self.assertIsNone(scoped.version)
        self.assertLess(scoped.confidence, 0.6)
        self.assertEqual(scoped.status, DependencyStatus.INFERRED)

    def test_source_map_package_metadata_promotes_confirmed_exact_version(self):
        source_map = {
            "version": 3,
            "sources": ["webpack://./node_modules/react/package.json"],
            "sourcesContent": ['{"name": "react", "version": "18.2.0"}'],
        }
        candidates = infer_from_source_map(
            "target",
            json.dumps(source_map),
            "https://example.test/static/app.js.map",
            "javascript_bundles",
        )
        react = next(
            candidate for candidate in candidates if candidate.name == "react" and candidate.version == "18.2.0"
        )
        self.assertEqual(react.status, DependencyStatus.CONFIRMED)
        self.assertGreaterEqual(react.confidence, 0.9)
        self.assertEqual(react.evidence_chain[0].directness, "direct")

    def test_source_map_url_extraction_handles_whitespace(self):
        js = "//# sourceMappingURL = chunks/app.js.map"
        urls = extract_source_map_urls("https://example.test/static/app.js", js)
        self.assertEqual(urls, ["https://example.test/static/chunks/app.js.map"])

    def test_source_map_dependency_config_block(self):
        source_map = {
            "version": 3,
            "sources": ["webpack://./src/runtime-config.js"],
            "sourcesContent": ['window.__APP_CONFIG__ = {"dependencies": {"axios": "1.6.0"}};'],
        }
        candidates = infer_from_source_map(
            "target",
            json.dumps(source_map),
            "https://example.test/static/app.js.map",
            "javascript_bundles",
        )
        axios = next(candidate for candidate in candidates if candidate.name == "axios")
        self.assertEqual(axios.version, "1.6.0")
        self.assertEqual(axios.evidence_chain[0].source_type, "source_map_content")

    def test_conflicting_versions_are_retained_with_notes(self):
        js = "/*! react@17.0.2 */ /*! react@18.2.0 */"
        candidates = infer_from_js("target", js, "https://example.test/static/app.js", "javascript_bundles")
        versions = sorted(
            candidate.version for candidate in candidates if candidate.name == "react" and candidate.version
        )
        self.assertEqual(versions, ["17.0.2", "18.2.0"])
        react_with_notes = [c for c in candidates if c.name == "react" and c.conflict_notes]
        self.assertGreaterEqual(len(react_with_notes), 1)

    def test_framework_fingerprints_in_html(self):
        html = '<html><script src="/_next/static/chunks/main.js"></script></html>'
        candidates = infer_from_html("target", html, "https://example.test/", "javascript_bundles")
        next_candidate = next((c for c in candidates if c.name == "next"), None)
        self.assertIsNotNone(next_candidate)
        self.assertIsNone(next_candidate.version)
        self.assertLess(next_candidate.confidence, 0.5)

    def test_webpack_marker_in_html(self):
        html = "<html><script>var __webpack_require__ = function(){};</script></html>"
        candidates = infer_from_html("target", html, "https://example.test/", "javascript_bundles")
        webpack = next((c for c in candidates if c.name == "webpack"), None)
        self.assertIsNotNone(webpack)
        self.assertIsNone(webpack.version)

    def test_sharepoint_marker_in_html(self):
        html = "<html><script>_spPageContextInfo = {};</script></html>"
        candidates = infer_from_html("target", html, "https://example.test/", "javascript_bundles")
        sharepoint = next((c for c in candidates if c.name == "sharepoint"), None)
        self.assertIsNotNone(sharepoint)
        self.assertIsNone(sharepoint.version)

    def test_react_version_assignment(self):
        js = 'React.version = "18.2.0"'
        candidates = infer_from_js("target", js, "https://example.test/app.js", "javascript_bundles")
        react = next((c for c in candidates if c.name == "react"), None)
        self.assertIsNotNone(react)
        self.assertEqual(react.version, "18.2.0")

    def test_extract_balanced_with_escaped_quotes(self):
        from osintdepintel.js_inference import _dependency_config_blocks, _extract_balanced

        text = '{"dependencies": {"react\\"extra": "18.0.0", "lodash": "4.17.21"}}'
        body = _extract_balanced(text, text.index("{"))
        self.assertIsNotNone(body)

        blocks = _dependency_config_blocks(text)
        self.assertGreaterEqual(len(blocks), 1)

    def test_decode_inline_source_map_base64(self):
        import base64

        from osintdepintel.js_inference import decode_inline_source_map

        data = json.dumps({"version": 3, "sources": []})
        encoded = base64.b64encode(data.encode()).decode()
        locator = f"data:application/json;base64,{encoded}"
        result = decode_inline_source_map(locator)
        self.assertIsNotNone(result)
        self.assertIn("version", result)

    def test_infer_from_source_map_invalid_json(self):
        candidates = infer_from_source_map("target", "not json", "https://example.test/map", "test")
        self.assertEqual(candidates, [])

    def test_allowed_candidate_rejects_unstable_names(self):
        from osintdepintel.js_inference import _allowed_candidate, _candidate, _evidence

        ev = _evidence("https://test", "GET", "test", "test", "token", "test", "direct", "test")
        bad = _candidate("target", "some-unstable-name", None, 0.3, "test", ev)
        self.assertFalse(_allowed_candidate(bad))

    def test_package_from_node_modules_path(self):
        from osintdepintel.js_inference import package_from_node_modules_path

        self.assertIsNone(package_from_node_modules_path("no-node-modules"))
        self.assertEqual(package_from_node_modules_path("node_modules/react"), "react")
        self.assertEqual(package_from_node_modules_path("node_modules/@scope/pkg/index.js"), "@scope/pkg")

    def test_consolidate_top_candidate_no_conflict_notes(self):
        from osintdepintel.js_inference import consolidate_candidates

        ev1 = _evidence("https://test", "GET", "test", "test", "token1", "test", "direct", "test")
        ev2 = _evidence("https://test", "GET", "test", "test", "token2", "test", "direct", "test")
        c1 = _candidate("target", "pkg", "1.0.0", 0.9, "test", ev1)
        c2 = _candidate("target", "pkg", "2.0.0", 0.8, "test", ev2)
        result = consolidate_candidates([c1, c2])
        top = next(c for c in result if c.version == "1.0.0")
        self.assertEqual(len(top.conflict_notes), 0)


def _evidence(url, method, content, plugin, token, reasoning, directness, source_type):
    from osintdepintel.js_inference import _evidence as ev_func

    return ev_func(url, method, content, plugin, token, reasoning, directness, source_type)


def _candidate(target, name, version, confidence, reasoning, evidence, ecosystem="npm"):
    from osintdepintel.js_inference import _candidate as cand_func

    return cand_func(target, name, version, confidence, reasoning, evidence, ecosystem=ecosystem)


if __name__ == "__main__":
    unittest.main()
