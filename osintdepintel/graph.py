from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .models import DependencyEdge, DependencyRecord, DependencyStatus, Provenance
from .registry import GlobalRegistry


@dataclass
class DependencyGraph:
    target_name: str
    nodes: dict[str, DependencyRecord] = field(default_factory=dict)
    edges: list[DependencyEdge] = field(default_factory=list)

    def add_record(self, record: DependencyRecord, registry: GlobalRegistry) -> None:
        existing = self.nodes.get(record.key)
        if existing is None:
            self.nodes[record.key] = record
            return
        if existing.status != record.status:
            registry.add_conflict(
                self.target_name,
                "graph",
                {
                    "dependency_key": record.key,
                    "existing_status": existing.status.value,
                    "new_status": record.status.value,
                },
            )
        if record.confidence > existing.confidence:
            existing.confidence = record.confidence
        if existing.version != record.version:
            registry.add_conflict(
                self.target_name,
                "graph",
                {
                    "dependency_name": record.name,
                    "ecosystem": record.ecosystem,
                    "existing_version": existing.version,
                    "new_version": record.version,
                    "resolution": "both records retained by version-specific key when versions differ",
                },
            )
        existing.provenance.extend(record.provenance)

    def add_edge(self, edge: DependencyEdge) -> None:
        if not any(e.parent_key == edge.parent_key and e.child_key == edge.child_key for e in self.edges):
            self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "nodes": {key: value.to_dict() for key, value in self.nodes.items()},
            "edges": [edge.to_dict() for edge in self.edges],
        }

    def to_dot(self) -> str:
        def escape_str(s: str) -> str:
            s = s.replace("\\", "\\\\").replace('"', '\\"')
            for ch in ("<", ">", "|", "{", "}"):
                s = s.replace(ch, f"\\{ch}")
            return s

        lines = ["digraph dependencies {"]
        lines.append('  rankdir="LR";')
        for key, record in self.nodes.items():
            escaped_key = escape_str(key)
            label = f"{escape_str(record.ecosystem)}\\n{escape_str(record.name)}\\n{escape_str(record.version or 'unknown')}"
            style = "solid" if record.status == DependencyStatus.CONFIRMED else "dashed"
            lines.append(f'  "{escaped_key}" [label="{label}", style="{style}"];')
        for edge in self.edges:
            parent = escape_str(edge.parent_key)
            child = escape_str(edge.child_key)
            style = "solid" if edge.status == DependencyStatus.CONFIRMED else "dashed"
            lines.append(f'  "{parent}" -> "{child}" [style="{style}", label="{edge.confidence:.2f}"];')
        lines.append("}")
        return "\n".join(lines)


def build_graph(
    target_name: str, records: Iterable[DependencyRecord], edges: Iterable[DependencyEdge], registry: GlobalRegistry
) -> DependencyGraph:
    graph = DependencyGraph(target_name=target_name)
    claims: dict[tuple[str, str], list[DependencyRecord]] = {}
    for record in records:
        claims.setdefault((record.ecosystem.lower(), record.name.lower()), []).append(record)
    for (ecosystem, name), claim_records in claims.items():
        versions = sorted({record.version or "unknown" for record in claim_records})
        if len(versions) > 1:
            winner = max(
                claim_records, key=lambda item: (item.status.value == DependencyStatus.CONFIRMED.value, item.confidence)
            )
            for record in claim_records:
                if record.key != winner.key:
                    record.confidence = max(0.1, round(record.confidence - 0.15, 3))
            registry.add_conflict(
                target_name,
                "graph",
                {
                    "conflict_type": "dependency_version_claim",
                    "package": name,
                    "ecosystem": ecosystem,
                    "winner": winner.key,
                    "why_winner": "highest confidence, with confirmed evidence preferred over inferred evidence",
                    "conflicting_claims": [
                        {
                            "dependency_key": record.key,
                            "status": record.status.value,
                            "confidence": record.confidence,
                            "sources": [prov.source_type for prov in record.provenance],
                        }
                        for record in claim_records
                    ],
                    "confidence_penalty": 0.15,
                },
            )
    for record in records:
        graph.add_record(record, registry)
    for edge in edges:
        graph.add_edge(edge)
    return graph


def add_fixture_transitives(
    graph: DependencyGraph, transitives: dict[str, list[dict[str, Any]]], registry: GlobalRegistry
) -> None:
    for parent_key, children in transitives.items():
        if parent_key not in graph.nodes:
            continue
        for child in children:
            record = DependencyRecord(
                target_name=graph.target_name,
                name=child["name"],
                ecosystem=child["ecosystem"],
                version=child.get("version"),
                status=DependencyStatus.INFERRED,
                confidence=float(child.get("confidence", 0.4)),
                provenance=[
                    Provenance(
                        source_type="package_metadata_fixture",
                        source_name="offline_transitives",
                        locator=parent_key,
                        evidence="transitive dependency from offline package metadata fixture",
                    )
                ],
                relationship="transitive",
            )
            graph.add_record(record, registry)
            graph.add_edge(
                DependencyEdge(
                    target_name=graph.target_name,
                    parent_key=parent_key,
                    child_key=record.key,
                    status=DependencyStatus.INFERRED,
                    confidence=record.confidence,
                    provenance=record.provenance,
                )
            )
