from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import utc_now


@dataclass
class GlobalRegistry:
    """Shared state used to keep uncertainty visible across pipeline phases."""

    assumptions: list[dict[str, Any]] = field(default_factory=list)
    risks: list[dict[str, Any]] = field(default_factory=list)
    failure_modes: list[dict[str, Any]] = field(default_factory=list)
    confidence_constraints: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    plugin_events: list[dict[str, Any]] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    inferences: list[dict[str, Any]] = field(default_factory=list)
    collection_gaps: list[dict[str, Any]] = field(default_factory=list)
    dependency_evidence_chains: list[dict[str, Any]] = field(default_factory=list)

    def add_assumption(self, target: str, phase: str, message: str) -> None:
        self.assumptions.append(self._entry(target, phase, message))

    def add_risk(self, target: str, phase: str, message: str, severity: str = "info") -> None:
        entry = self._entry(target, phase, message)
        entry["severity"] = severity
        self.risks.append(entry)

    def add_failure(self, target: str, phase: str, message: str) -> None:
        self.failure_modes.append(self._entry(target, phase, message))

    def add_confidence_constraint(self, target: str, phase: str, message: str) -> None:
        self.confidence_constraints.append(self._entry(target, phase, message))

    def add_conflict(self, target: str, phase: str, conflict: dict[str, Any]) -> None:
        entry = self._entry(target, phase, "conflicting source data")
        entry.update(conflict)
        self.conflicts.append(entry)
        self.add_gap(target, phase, "contradicted", "competing claims were observed")

    def add_plugin_event(self, target: str, plugin: str, message: str, status: str = "ok") -> None:
        entry = self._entry(target, plugin, message)
        entry["status"] = status
        self.plugin_events.append(entry)

    def add_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(observation)

    def add_inference(self, inference: dict[str, Any]) -> None:
        self.inferences.append(inference)

    def add_dependency_evidence_chain(
        self, target: str, dependency_key: str, evidence_chain: list[dict[str, Any]]
    ) -> None:
        self.dependency_evidence_chains.append(
            {
                "target": target,
                "dependency_key": dependency_key,
                "evidence_chain": evidence_chain,
                "timestamp": utc_now(),
            }
        )

    def add_gap(self, target: str, phase: str, category: str, message: str) -> None:
        entry = self._entry(target, phase, message)
        entry["category"] = category
        self.collection_gaps.append(entry)

    def to_dict(self) -> dict[str, Any]:
        return {
            "assumptions": self.assumptions,
            "risks": self.risks,
            "failure_modes": self.failure_modes,
            "confidence_constraints": self.confidence_constraints,
            "conflicts": self.conflicts,
            "plugin_events": self.plugin_events,
            "observations": self.observations,
            "inferences": self.inferences,
            "collection_gaps": self.collection_gaps,
            "dependency_evidence_chains": self.dependency_evidence_chains,
            "evidence_summary": {
                "observation_count": len(self.observations),
                "inference_count": len(self.inferences),
                "dependency_evidence_chain_count": len(self.dependency_evidence_chains),
                "source_types": sorted({item.get("source_type", "unknown") for item in self.observations}),
            },
            "source_coverage": {
                "observed_source_types": sorted({item.get("source_type", "unknown") for item in self.observations}),
                "gap_categories": {
                    category: sum(1 for item in self.collection_gaps if item.get("category") == category)
                    for category in sorted({item.get("category", "unknown") for item in self.collection_gaps})
                },
            },
            "confidence_distribution": self._confidence_distribution(),
            "conflict_summary": {
                "count": len(self.conflicts),
                "conflicts": self.conflicts,
            },
        }

    @staticmethod
    def _entry(target: str, phase: str, message: str) -> dict[str, Any]:
        return {
            "target": target,
            "phase": phase,
            "message": message,
            "timestamp": utc_now(),
        }

    def _confidence_distribution(self) -> dict[str, int]:
        values = [
            float(item.get("confidence", 0.0))
            for item in self.inferences
            if isinstance(item.get("confidence"), (int, float))
        ]
        return {
            "high_0_8_to_1_0": sum(1 for value in values if value >= 0.8),
            "medium_0_6_to_0_79": sum(1 for value in values if 0.6 <= value < 0.8),
            "low_below_0_6": sum(1 for value in values if value < 0.6),
        }
