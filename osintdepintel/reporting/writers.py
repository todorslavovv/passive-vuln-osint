from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_reports(output_dir: Path, target_name: str, report: dict[str, Any], graph_dot: str = "") -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _safe_filename(target_name)
    json_path = output_dir / f"{safe_name}.json"
    text_path = output_dir / f"{safe_name}.txt"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    text_path.write_text(human_report(report), encoding="utf-8")
    paths: dict[str, Path] = {"json": json_path, "text": text_path}
    if graph_dot:
        dot_path = output_dir / f"{safe_name}.dot"
        dot_path.write_text(graph_dot, encoding="utf-8")
        paths["graph"] = dot_path
    cyclonedx_path = write_cyclonedx_sbom(output_dir, safe_name, report)
    spdx_path = write_spdx_sbom(output_dir, safe_name, report)
    paths["cyclonedx"] = cyclonedx_path
    paths["spdx"] = spdx_path
    return paths


def human_report(report: dict[str, Any]) -> str:
    target = report["target"]
    summary = report["summary"]
    lines = [
        "OSINT Dependency Vulnerability Intelligence Report",
        f"Target: {target['name']}",
        f"URL: {target['url']}",
        "",
        "Summary",
        f"- Dependencies: {summary['dependency_count']}",
        f"- Confirmed dependencies: {summary['confirmed_dependencies']}",
        f"- Inferred dependencies: {summary['inferred_dependencies']}",
        f"- Vulnerabilities: {summary['vulnerability_count']}",
        f"- Ranked findings: {summary['finding_count']}",
        f"- Confidence floor: {summary.get('confidence_floor')}",
        "",
        "Top Findings",
    ]
    for finding in report.get("findings", [])[:10]:
        vuln = finding["vulnerability"]
        dep = finding["dependency"]
        lines.extend(
            [
                f"- {finding['score']:.2f} | {vuln['vulnerability_id']} | {dep['ecosystem']} {dep['name']} {dep.get('version') or 'unknown'}",
                f"  {finding['rank_reason']}",
                f"  Dependency evidence: status={dep.get('status')} confidence={dep.get('confidence')}",
                f"  Reasoning: {dep.get('qualifiers', {}).get('reasoning', 'not recorded')}",
                "  Exploitability: not proven by OSINT; treat as an intelligence lead unless authorized validation confirms exposure.",
            ]
        )
        evidence_chain = dep.get("qualifiers", {}).get("evidence_chain", [])
        if evidence_chain:
            first = evidence_chain[0]
            lines.append(
                f"  Evidence: {first.get('source_type')} from {first.get('source_url')} token={first.get('extracted_token')}"
            )
        conflict_notes = dep.get("qualifiers", {}).get("conflict_notes", [])
        if conflict_notes:
            lines.append(f"  Conflicts: {'; '.join(conflict_notes)}")
    if not report.get("findings"):
        lines.append("- No vulnerable dependencies were identified from available passive evidence.")
    lines.extend(["", "Global Registry Notes"])
    registry = report.get("global_registry", {})
    for field in (
        "assumptions",
        "failure_modes",
        "confidence_constraints",
        "conflicts",
        "collection_gaps",
        "observations",
        "inferences",
    ):
        lines.append(f"- {field}: {len(registry.get(field, []))}")
    return "\n".join(lines) + "\n"


def aggregate_report(target_reports: list[dict[str, Any]], registry: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "aggregate": {
            "target_count": len(target_reports),
            "dependency_count": sum(r["summary"]["dependency_count"] for r in target_reports),
            "vulnerability_count": sum(r["summary"]["vulnerability_count"] for r in target_reports),
            "finding_count": sum(r["summary"]["finding_count"] for r in target_reports),
        },
        "evidence_summary": {
            "observation_count": sum(r.get("evidence_summary", {}).get("observation_count", 0) for r in target_reports),
            "inference_count": sum(r.get("evidence_summary", {}).get("inference_count", 0) for r in target_reports),
            "dependency_evidence_chain_count": sum(
                r.get("evidence_summary", {}).get("dependency_evidence_chain_count", 0) for r in target_reports
            ),
            "source_types": sorted(
                {source for r in target_reports for source in r.get("evidence_summary", {}).get("source_types", [])}
            ),
        },
        "confidence_distribution": {
            "high_0_8_to_1_0": sum(
                r.get("confidence_distribution", {}).get("high_0_8_to_1_0", 0) for r in target_reports
            ),
            "medium_0_6_to_0_79": sum(
                r.get("confidence_distribution", {}).get("medium_0_6_to_0_79", 0) for r in target_reports
            ),
            "low_below_0_6": sum(r.get("confidence_distribution", {}).get("low_below_0_6", 0) for r in target_reports),
        },
        "conflict_summary": {
            "count": len(registry.get("conflicts", [])),
            "conflicts": registry.get("conflicts", []),
        },
        "source_coverage": {
            "observed_source_types": sorted(
                {
                    source
                    for r in target_reports
                    for source in r.get("source_coverage", {}).get("observed_source_types", [])
                }
            ),
            "gap_categories": _aggregate_gap_categories(target_reports),
        },
        "collection_gaps": registry.get("collection_gaps", []),
        "targets": [
            {
                "name": report["target"]["name"],
                "summary": report["summary"],
                "top_findings": report["findings"][:3],
            }
            for report in target_reports
        ],
        "global_registry": registry,
    }


def _aggregate_gap_categories(target_reports: list[dict[str, Any]]) -> dict[str, int]:
    categories: dict[str, int] = {}
    for report in target_reports:
        for category, count in report.get("source_coverage", {}).get("gap_categories", {}).items():
            categories[category] = categories.get(category, 0) + count
    return categories


def _safe_filename(value: str) -> str:
    # Sanitize only; keep the name stable so re-scanning the same target overwrites the previous report.
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value).strip("_").lower()
    return safe or "target"


def write_cyclonedx_sbom(output_dir: Path, target_name: str, report: dict[str, Any]) -> Path:
    vulnerabilities_by_dep: dict[str, list[dict[str, Any]]] = {}
    for finding in report.get("findings", []):
        dep_key = finding.get("dependency_key", "")
        vulnerabilities_by_dep.setdefault(dep_key, []).append(finding["vulnerability"])
    components: list[dict[str, Any]] = []
    key_to_bomref: dict[str, str] = {}
    for dep in report.get("dependencies", []):
        dep_name = dep.get("name", "")
        dep_version = dep.get("version") or ""
        ecosystem = dep.get("ecosystem", "")
        raw_key = f"{ecosystem.lower()}:{dep_name.lower()}@{dep_version or 'unknown'}"
        bom_ref = f"{dep_name}@{dep_version}" if dep_version else dep_name
        key_to_bomref[raw_key] = bom_ref
        component: dict[str, Any] = {
            "type": "library",
            "name": dep_name,
            "version": dep_version,
            "bom-ref": bom_ref,
        }

        vulns = vulnerabilities_by_dep.get(raw_key, [])
        if vulns:
            advisories: list[dict[str, str]] = []
            for vuln in vulns:
                advisory: dict[str, str] = {"id": vuln.get("vulnerability_id", "")}
                refs = vuln.get("references", [])
                if refs:
                    advisory["url"] = refs[0]
                advisories.append(advisory)
            component["advisories"] = advisories
        components.append(component)
    dependencies_list: list[dict[str, Any]] = []
    parent_deps: dict[str, list[str]] = {}
    graph_data = report.get("graph", {})
    for edge in graph_data.get("edges", []):
        parent_key = edge.get("parent_key", "")
        child_key = edge.get("child_key", "")
        parent_bom = key_to_bomref.get(parent_key, parent_key)
        child_bom = key_to_bomref.get(child_key, child_key)
        if parent_bom and child_bom:
            parent_deps.setdefault(parent_bom, []).append(child_bom)
    for parent_ref, child_refs in parent_deps.items():
        dependencies_list.append({"ref": parent_ref, "dependsOn": sorted(set(child_refs))})
    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": report.get("target", {}).get("name", target_name),
            },
            "timestamp": _get_timestamp(report),
        },
        "components": components,
    }
    if dependencies_list:
        sbom["dependencies"] = dependencies_list
    out_path = output_dir / f"{target_name}_cyclonedx.json"
    out_path.write_text(json.dumps(sbom, indent=2, sort_keys=True), encoding="utf-8")
    return out_path


def write_spdx_sbom(output_dir: Path, target_name: str, report: dict[str, Any]) -> Path:
    packages: list[dict[str, Any]] = []
    key_to_spdxid: dict[str, str] = {}
    for dep in report.get("dependencies", []):
        dep_name = dep.get("name", "")
        dep_version = dep.get("version") or ""
        ecosystem = dep.get("ecosystem", "").lower()
        raw_key = f"{ecosystem}:{dep_name.lower()}@{dep_version or 'unknown'}"
        spdx_id = _spdx_id(dep_name, dep_version)
        key_to_spdxid[raw_key] = spdx_id
        pkg: dict[str, Any] = {
            "name": dep_name,
            "versionInfo": dep_version,
            "SPDXID": spdx_id,
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }
        packages.append(pkg)
    relationships: list[dict[str, str]] = []
    graph_data = report.get("graph", {})
    edges = graph_data.get("edges", [])
    for edge in edges:
        parent_key = edge.get("parent_key", "")
        child_key = edge.get("child_key", "")
        parent_spdxid = key_to_spdxid.get(parent_key)
        child_spdxid = key_to_spdxid.get(child_key)
        if parent_spdxid and child_spdxid:
            relationships.append(
                {
                    "spdxElementId": parent_spdxid,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": child_spdxid,
                }
            )
    spdx_doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{report.get('target', {}).get('name', target_name)}-sbom",
        "creationInfo": {
            "creators": ["Tool: osintdepintel"],
            "created": _get_timestamp(report),
        },
        "packages": packages,
    }
    if edges:
        spdx_doc["relationships"] = relationships
    else:
        spdx_doc["comment"] = "Relationship data was unavailable \u2014 no dependency edges were discovered."
    out_path = output_dir / f"{target_name}_spdx.json"
    out_path.write_text(json.dumps(spdx_doc, indent=2, sort_keys=True), encoding="utf-8")
    return out_path


def _get_timestamp(report: dict[str, Any]) -> str:
    assumptions = report.get("global_registry", {}).get("assumptions", [])
    if isinstance(assumptions, list) and assumptions:
        first = assumptions[0]
        if isinstance(first, dict):
            ts = first.get("timestamp")
            if ts:
                return str(ts)
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _spdx_id(name: str, version: str) -> str:
    safe = "".join(ch if ch.isalnum() else "-" for ch in f"{name}-{version}").strip("-")
    return f"SPDXRef-Package-{safe}"
