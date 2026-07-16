from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .discovery import DiscoveryPlugin, default_plugins
from .enrichment import EnrichmentEngine
from .exploit import correlate_exploits
from .graph import add_fixture_transitives, build_graph
from .http import HttpClient, RateLimiter
from .logger import logger
from .models import DependencyRecord, DependencyStatus, TargetConfig
from .registry import GlobalRegistry
from .reporting.writers import aggregate_report, write_reports
from .scoring import score_findings


class Pipeline:
    def __init__(
        self,
        offline: bool = False,
        fixture_path: Path | None = None,
        plugins: list[DiscoveryPlugin] | None = None,
        max_enrichment_dependencies: int | None = None,
        enable_nvd: bool = True,
        rate_limit_rps: float = 4.0,
    ) -> None:
        self.offline = offline
        self.fixtures = _load_fixtures(fixture_path)
        rate_limiter = RateLimiter(rate_limit_rps)
        self.http = HttpClient(rate_limiter=rate_limiter)
        self.plugins = plugins if plugins is not None else default_plugins(offline=offline, http=self.http)
        self.max_enrichment_dependencies = max_enrichment_dependencies
        self.enable_nvd = enable_nvd

    def process_targets(
        self, targets: Iterable[TargetConfig], output_dir: Path, include_graph: bool = True
    ) -> dict[str, Any]:
        registry = GlobalRegistry()
        reports = []
        output_paths: dict[str, dict[str, str]] = {}
        for target in targets:
            report, paths = self.process_target(target, registry, output_dir, include_graph=include_graph)
            reports.append(report)
            output_paths[target.name] = {kind: str(path) for kind, path in paths.items()}
        aggregate = aggregate_report(reports, registry.to_dict())
        output_dir.mkdir(parents=True, exist_ok=True)
        aggregate_path = output_dir / "aggregate_report.json"
        aggregate_path.write_text(json.dumps(aggregate, indent=2, sort_keys=True), encoding="utf-8")
        output_paths["aggregate"] = {"json": str(aggregate_path)}
        return {"reports": reports, "aggregate": aggregate, "paths": output_paths}

    def process_target(
        self,
        target: TargetConfig,
        registry: GlobalRegistry,
        output_dir: Path,
        include_graph: bool = True,
    ) -> tuple[dict[str, Any], dict[str, Path]]:
        registry.add_plugin_event(target.name, "orchestrator", f"processing target in mode {target.mode.value}")
        discovery_records: list[DependencyRecord] = []
        discovery_edges = []
        for plugin in self.plugins:
            result = plugin.discover(target, registry)
            discovery_records.extend(result.records)
            discovery_edges.extend(result.edges)
            for observation in result.observations:
                registry.add_observation(observation)
            for inference in result.inferences:
                registry.add_inference(inference)
            for record in result.records:
                evidence_chain = record.qualifiers.get("evidence_chain")
                if evidence_chain:
                    registry.add_dependency_evidence_chain(target.name, record.key, evidence_chain)
            for assumption in result.assumptions:
                registry.add_assumption(target.name, plugin.name, assumption)
            for failure in result.failures:
                registry.add_failure(target.name, plugin.name, failure)
            for conflict in result.conflicts:
                registry.add_conflict(target.name, plugin.name, conflict)

        graph = build_graph(target.name, discovery_records, discovery_edges, registry)
        add_fixture_transitives(graph, self.fixtures.get("transitives", {}), registry)
        enrichment_nodes = list(graph.nodes.values())
        if self.max_enrichment_dependencies is not None and len(enrichment_nodes) > self.max_enrichment_dependencies:
            registry.add_gap(
                target.name,
                "enrichment",
                "not_collected",
                f"enrichment capped at {self.max_enrichment_dependencies} of {len(enrichment_nodes)} dependencies for this run",
            )
            enrichment_nodes = enrichment_nodes[: self.max_enrichment_dependencies]
        vulnerabilities_by_dependency = EnrichmentEngine(
            offline=self.offline,
            fixture_vulnerabilities=self.fixtures.get("vulnerabilities", []),
            http=self.http,
            enable_nvd=self.enable_nvd,
        ).enrich(enrichment_nodes, registry)
        all_vulnerabilities = [vuln for vulns in vulnerabilities_by_dependency.values() for vuln in vulns]
        exploits_by_vulnerability = correlate_exploits(all_vulnerabilities, self.fixtures.get("exploits", []))
        findings = score_findings(graph.nodes, vulnerabilities_by_dependency, exploits_by_vulnerability)
        report = _target_report(target, graph, vulnerabilities_by_dependency, findings, registry.to_dict())
        paths = write_reports(output_dir, target.name, report, graph.to_dot() if include_graph else "")
        logger.info(
            "Target %s: %d dependencies, %d vulnerabilities, %d findings",
            target.name,
            len(graph.nodes),
            len(all_vulnerabilities),
            len(findings),
        )
        return report, paths


def _target_report(
    target: TargetConfig,
    graph: Any,
    vulnerabilities_by_dependency: dict[str, Any],
    findings: list[Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    dependencies = list(graph.nodes.values())
    confirmed = [item for item in dependencies if item.status == DependencyStatus.CONFIRMED]
    inferred = [item for item in dependencies if item.status == DependencyStatus.INFERRED]
    vulnerabilities = [vuln for vulns in vulnerabilities_by_dependency.values() for vuln in vulns]
    registry_for_target = _registry_for_target(registry, target.name)
    source_types = sorted({prov.source_type for item in dependencies for prov in item.provenance})
    confidence_values = [item.confidence for item in dependencies]
    return {
        "schema_version": "1.0",
        "target": target.to_dict(),
        "summary": {
            "dependency_count": len(dependencies),
            "confirmed_dependencies": len(confirmed),
            "inferred_dependencies": len(inferred),
            "vulnerability_count": len(vulnerabilities),
            "finding_count": len(findings),
            "confirmed_sources": sorted({prov.source_type for item in confirmed for prov in item.provenance}),
            "inferred_sources": sorted({prov.source_type for item in inferred for prov in item.provenance}),
            "conflicting_sources": sorted(
                {
                    claim.get("ecosystem", "")
                    for claim in registry_for_target.get("conflicts", [])
                    if claim.get("ecosystem")
                }
            ),
            "confidence_floor": min(confidence_values) if confidence_values else None,
        },
        "evidence_summary": {
            "observation_count": len(registry_for_target.get("observations", [])),
            "inference_count": len(registry_for_target.get("inferences", [])),
            "dependency_evidence_chain_count": len(registry_for_target.get("dependency_evidence_chains", [])),
            "source_types": source_types,
        },
        "confidence_distribution": _confidence_distribution(confidence_values),
        "conflict_summary": {
            "count": len(registry_for_target.get("conflicts", [])),
            "conflicts": registry_for_target.get("conflicts", []),
        },
        "source_coverage": _source_coverage(registry_for_target),
        "collection_gaps": registry_for_target.get("collection_gaps", []),
        "dependencies": [item.to_dict() for item in dependencies],
        "graph": graph.to_dict(),
        "vulnerabilities_by_dependency": {
            key: [item.to_dict() for item in value] for key, value in vulnerabilities_by_dependency.items()
        },
        "findings": [finding.to_dict() for finding in findings],
        "global_registry": registry,
    }


def _registry_for_target(registry: dict[str, Any], target_name: str) -> dict[str, Any]:
    filtered: dict[str, Any] = {}
    for key, value in registry.items():
        if isinstance(value, list):
            filtered[key] = [item for item in value if item.get("target") == target_name]
        else:
            filtered[key] = value
    return filtered


def _confidence_distribution(values: list[float]) -> dict[str, int]:
    return {
        "high_0_8_to_1_0": sum(1 for value in values if value >= 0.8),
        "medium_0_6_to_0_79": sum(1 for value in values if 0.6 <= value < 0.8),
        "low_below_0_6": sum(1 for value in values if value < 0.6),
    }


def _source_coverage(registry_for_target: dict[str, Any]) -> dict[str, Any]:
    observations = registry_for_target.get("observations", [])
    gaps = registry_for_target.get("collection_gaps", [])
    return {
        "observed_source_types": sorted({item.get("source_type", "unknown") for item in observations}),
        "gap_categories": {
            category: sum(1 for item in gaps if item.get("category") == category)
            for category in sorted({item.get("category", "unknown") for item in gaps})
        },
    }


def _load_fixtures(path: Path | None) -> dict[str, Any]:
    if path is None:
        default = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "offline_intel.json"
        path = default if default.exists() else None
    if path is None:
        return {"vulnerabilities": [], "exploits": [], "transitives": {}}
    with path.open("r", encoding="utf-8") as handle:
        result: Any = json.load(handle)
        return result if isinstance(result, dict) else {"vulnerabilities": [], "exploits": [], "transitives": {}}
