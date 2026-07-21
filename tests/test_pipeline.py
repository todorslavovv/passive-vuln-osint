from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from osintdepintel.discovery.base import DiscoveryPlugin
from osintdepintel.http import HttpClient
from osintdepintel.models import (
    DependencyRecord,
    DependencyStatus,
    DiscoveryResult,
    Provenance,
    TargetConfig,
    VulnerabilityRecord,
)
from osintdepintel.pipeline import (
    Pipeline,
    _confidence_distribution,
    _load_fixtures,
    _registry_for_target,
    _source_coverage,
)
from osintdepintel.registry import GlobalRegistry


def _make_plugin(records: list[DependencyRecord]) -> DiscoveryPlugin:
    plugin = MagicMock(spec=DiscoveryPlugin)
    plugin.name = "mock_plugin"
    result = DiscoveryResult(records=records)
    plugin.discover.return_value = result
    return plugin


def _make_target(name: str = "test-target") -> TargetConfig:
    return TargetConfig(name=name, url=f"https://{name}.example.com/")


def _make_record(
    name: str = "lodash",
    ecosystem: str = "npm",
    version: str = "4.17.15",
    confidence: float = 0.9,
    status: DependencyStatus = DependencyStatus.CONFIRMED,
) -> DependencyRecord:
    return DependencyRecord(
        target_name="test-target",
        name=name,
        ecosystem=ecosystem,
        version=version,
        status=status,
        confidence=confidence,
        provenance=[Provenance("test", "test", "mem", evidence="mock")],
    )


class PipelineProcessTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = _make_target()
        self.record = _make_record()
        self.mock_plugin = _make_plugin([self.record])
        self.registry = GlobalRegistry()
        self.enrich_patcher = patch(
            "osintdepintel.pipeline.EnrichmentEngine.enrich",
            return_value={},
        )
        self.mock_enrich = self.enrich_patcher.start()

    def tearDown(self) -> None:
        self.enrich_patcher.stop()

    def _run(self, plugin=None, **kw):
        pipe = Pipeline(offline=True, plugins=plugin or [self.mock_plugin], **kw)
        with tempfile.TemporaryDirectory() as tmp:
            return pipe.process_target(self.target, self.registry, Path(tmp), include_graph=False)

    def test_returns_report_with_summary(self) -> None:
        report, paths = self._run()
        self.assertIn("summary", report)
        self.assertIn("dependencies", report)
        self.assertIn("json", paths)
        self.assertEqual(report["summary"]["dependency_count"], 1)

    def test_max_enrichment_does_not_trim_graph(self) -> None:
        records = [_make_record(name=f"pkg{i}", version="1.0") for i in range(5)]
        report, paths = self._run(plugin=[_make_plugin(records)], max_enrichment_dependencies=2)
        self.assertEqual(report["summary"]["dependency_count"], 5)

    def test_with_vulnerabilities_yields_findings(self) -> None:
        vuln = VulnerabilityRecord(
            vulnerability_id="CVE-TEST-0001",
            source="test",
            package_name="lodash",
            ecosystem="npm",
            affected_versions=["<4.17.20"],
            summary="test",
        )
        self.mock_enrich.return_value = {"npm:lodash@4.17.15": [vuln]}
        report, paths = self._run()
        self.assertEqual(report["summary"]["vulnerability_count"], 1)
        self.assertEqual(report["summary"]["finding_count"], 1)

    def test_inferred_dependency_counts(self) -> None:
        inferred = _make_record(confidence=0.45, status=DependencyStatus.INFERRED)
        report, paths = self._run(plugin=[_make_plugin([inferred])])
        self.assertEqual(report["summary"]["confirmed_dependencies"], 0)
        self.assertEqual(report["summary"]["inferred_dependencies"], 1)

    def test_no_dependencies(self) -> None:
        report, paths = self._run(plugin=[_make_plugin([])])
        self.assertEqual(report["summary"]["dependency_count"], 0)

    def test_include_graph(self) -> None:
        pipe = Pipeline(offline=True, plugins=[self.mock_plugin])
        with tempfile.TemporaryDirectory() as tmp:
            report, paths = pipe.process_target(self.target, self.registry, Path(tmp), include_graph=True)
        self.assertIn("graph", report)


class PipelineProcessTargetsTests(unittest.TestCase):
    def test_multiple_targets(self) -> None:
        plugin = _make_plugin([_make_record(name="pkg-a")])
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.pipeline.EnrichmentEngine.enrich", return_value={}),
        ):
            pipe = Pipeline(offline=True, plugins=[plugin])
            result = pipe.process_targets([_make_target("target-a"), _make_target("target-b")], Path(tmp))
        self.assertEqual(len(result["reports"]), 2)
        self.assertIn("aggregate", result)
        self.assertIn("paths", result)

    def test_aggregate_report_content(self) -> None:
        plugin = _make_plugin([_make_record(name="dep-x")])
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.pipeline.EnrichmentEngine.enrich", return_value={}),
        ):
            pipe = Pipeline(offline=True, plugins=[plugin])
            result = pipe.process_targets([_make_target("single")], Path(tmp))
        self.assertEqual(result["aggregate"]["aggregate"]["target_count"], 1)

    def test_output_paths_per_target(self) -> None:
        plugin = _make_plugin([_make_record(name="alpha-pkg")])
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.pipeline.EnrichmentEngine.enrich", return_value={}),
        ):
            pipe = Pipeline(offline=True, plugins=[plugin])
            result = pipe.process_targets([_make_target("alpha")], Path(tmp))
        self.assertIn("alpha", result["paths"])
        self.assertIn("json", result["paths"]["alpha"])


class PipelineHelperTests(unittest.TestCase):
    def test_registry_for_target_filters_by_target_name(self) -> None:
        registry = {
            "observations": [
                {"target": "a", "data": 1},
                {"target": "b", "data": 2},
            ],
            "scalar_key": "shared",
        }
        filtered = _registry_for_target(registry, "a")
        self.assertEqual(len(filtered["observations"]), 1)
        self.assertEqual(filtered["scalar_key"], "shared")

    def test_confidence_distribution_all_buckets(self) -> None:
        dist = _confidence_distribution([0.9, 0.7, 0.5, 0.3])
        self.assertEqual(dist["high_0_8_to_1_0"], 1)
        self.assertEqual(dist["medium_0_6_to_0_79"], 1)
        self.assertEqual(dist["low_below_0_6"], 2)

    def test_confidence_distribution_empty(self) -> None:
        dist = _confidence_distribution([])
        for key in ("high_0_8_to_1_0", "medium_0_6_to_0_79", "low_below_0_6"):
            self.assertEqual(dist[key], 0)

    def test_source_coverage_with_observations_and_gaps(self) -> None:
        registry = {
            "observations": [
                {"source_type": "html_script", "target": "t"},
                {"source_type": "source_map", "target": "t"},
            ],
            "collection_gaps": [
                {"category": "not_collected", "target": "t"},
                {"category": "not_collected", "target": "t"},
                {"category": "skipped", "target": "t"},
            ],
        }
        coverage = _source_coverage(registry)
        self.assertIn("html_script", coverage["observed_source_types"])
        self.assertEqual(coverage["gap_categories"]["not_collected"], 2)
        self.assertEqual(coverage["gap_categories"]["skipped"], 1)

    def test_source_coverage_empty(self) -> None:
        coverage = _source_coverage({})
        self.assertEqual(coverage["observed_source_types"], [])
        self.assertEqual(coverage["gap_categories"], {})

    @patch("pathlib.Path.exists", return_value=False)
    def test_load_fixtures_no_path_default_not_found(self, _mock_exists: MagicMock) -> None:
        fixtures = _load_fixtures(None)
        self.assertEqual(fixtures["vulnerabilities"], [])
        self.assertEqual(fixtures["exploits"], [])
        self.assertEqual(fixtures["transitives"], {})

    def test_load_fixtures_with_path(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"vulnerabilities": [{"id": "CVE-TEST"}], "exploits": [], "transitives": {}}')
            path = Path(f.name)
        try:
            fixtures = _load_fixtures(path)
            self.assertEqual(len(fixtures["vulnerabilities"]), 1)
        finally:
            path.unlink(missing_ok=True)


class PipelinePluginsTests(unittest.TestCase):
    @patch("osintdepintel.pipeline.default_plugins")
    def test_default_plugins_when_none_given(self, mock_default: MagicMock) -> None:
        mock_plugin = MagicMock(spec=DiscoveryPlugin)
        mock_plugin.name = "default_mock"
        mock_plugin.discover.return_value = DiscoveryResult()
        mock_default.return_value = [mock_plugin]
        pipe = Pipeline(offline=True)
        self.assertEqual(len(pipe.plugins), 1)

    def test_custom_plugins_used(self) -> None:
        plugin = _make_plugin([])
        pipe = Pipeline(offline=True, plugins=[plugin])
        self.assertIs(pipe.plugins[0], plugin)


class PipelineHttpSetupTests(unittest.TestCase):
    def test_pipeline_creates_http_client_with_rate_limiter(self) -> None:
        pipe = Pipeline(offline=True)
        self.assertIsInstance(pipe.http, HttpClient)


if __name__ == "__main__":
    unittest.main()
