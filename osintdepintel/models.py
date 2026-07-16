from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class TargetMode(str, Enum):
    LAB = "LAB TARGETS"
    AUTHORIZED = "AUTHORIZED REAL TARGETS"
    PUBLIC = "PUBLIC OSINT TARGETS"


class DependencyStatus(str, Enum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"


@dataclass
class Provenance:
    source_type: str
    source_name: str
    locator: str
    collected_at: str = field(default_factory=utc_now)
    evidence: str = ""
    fetch_method: str = "GET"
    content_sha256: str | None = None
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TargetConfig:
    name: str
    url: str
    mode: TargetMode
    github_repos: list[str] = field(default_factory=list)
    sbom_urls: list[str] = field(default_factory=list)
    container_images: list[str] = field(default_factory=list)
    mobile_artifacts: list[str] = field(default_factory=list)
    package_hints: list[dict[str, str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> TargetConfig:
        return cls(
            name=raw["name"],
            url=raw["url"],
            mode=TargetMode(raw["mode"]),
            github_repos=list(raw.get("github_repos", [])),
            sbom_urls=list(raw.get("sbom_urls", [])),
            container_images=list(raw.get("container_images", [])),
            mobile_artifacts=list(raw.get("mobile_artifacts", [])),
            package_hints=list(raw.get("package_hints", [])),
            metadata=dict(raw.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["mode"] = self.mode.value
        return data


@dataclass
class DependencyRecord:
    target_name: str
    name: str
    ecosystem: str
    version: str | None
    status: DependencyStatus
    confidence: float
    provenance: list[Provenance]
    relationship: str = "direct"
    scope: str = "runtime"
    qualifiers: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        version = self.version or "unknown"
        return f"{self.ecosystem.lower()}:{self.name.lower()}@{version}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["provenance"] = [p.to_dict() for p in self.provenance]
        return data


@dataclass
class DependencyEdge:
    target_name: str
    parent_key: str
    child_key: str
    status: DependencyStatus
    confidence: float
    provenance: list[Provenance]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["provenance"] = [p.to_dict() for p in self.provenance]
        return data


@dataclass
class DiscoveryResult:
    records: list[DependencyRecord] = field(default_factory=list)
    edges: list[DependencyEdge] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    inferences: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)


@dataclass
class VulnerabilityRecord:
    vulnerability_id: str
    source: str
    package_name: str
    ecosystem: str
    affected_versions: list[str]
    summary: str
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    published: str | None = None
    modified: str | None = None
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    matched_version: str | None = None
    match_confidence: float = 0.0

    def identity_set(self) -> set[str]:
        return {self.vulnerability_id, *self.aliases}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExploitSignal:
    vulnerability_id: str
    source: str
    reference: str
    description: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskFinding:
    dependency_key: str
    dependency: DependencyRecord
    vulnerability: VulnerabilityRecord
    exploit_signals: list[ExploitSignal]
    score: float
    rank_reason: str
    factors: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency_key": self.dependency_key,
            "dependency": self.dependency.to_dict(),
            "vulnerability": self.vulnerability.to_dict(),
            "exploit_signals": [s.to_dict() for s in self.exploit_signals],
            "score": self.score,
            "rank_reason": self.rank_reason,
            "factors": self.factors,
        }
