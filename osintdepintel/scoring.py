from __future__ import annotations

from datetime import datetime, timezone

from .models import (
    DependencyRecord,
    DependencyStatus,
    ExploitSignal,
    RiskFinding,
    VulnerabilityRecord,
)

SEVERITY_BASE = {
    "CRITICAL": 40.0,
    "HIGH": 30.0,
    "MEDIUM": 18.0,
    "LOW": 8.0,
    "UNKNOWN": 10.0,
}


def score_findings(
    dependencies: dict[str, DependencyRecord],
    vulnerabilities_by_dependency: dict[str, list[VulnerabilityRecord]],
    exploits_by_vulnerability: dict[str, list[ExploitSignal]],
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for dependency_key, vulnerabilities in vulnerabilities_by_dependency.items():
        dependency = dependencies[dependency_key]
        for vulnerability in vulnerabilities:
            signals = exploits_by_vulnerability.get(vulnerability.vulnerability_id, [])
            score, factors = _score(dependency, vulnerability, signals)
            findings.append(
                RiskFinding(
                    dependency_key=dependency_key,
                    dependency=dependency,
                    vulnerability=vulnerability,
                    exploit_signals=signals,
                    score=score,
                    rank_reason=_reason(dependency, vulnerability, signals, score),
                    factors=factors,
                )
            )
    return sorted(findings, key=lambda item: item.score, reverse=True)


def _score(
    dependency: DependencyRecord, vulnerability: VulnerabilityRecord, exploit_signals: list[ExploitSignal]
) -> tuple[float, dict[str, float]]:
    severity = SEVERITY_BASE.get(vulnerability.severity.upper(), SEVERITY_BASE["UNKNOWN"])
    if vulnerability.cvss_score is not None:
        severity = max(severity, vulnerability.cvss_score * 4.0)
    exploit = min(12.0, sum(_exploit_weight(signal) for signal in exploit_signals))
    patch_lag = _patch_lag(vulnerability)
    provenance_quality = min(1.0, 0.35 + (len(dependency.provenance) * 0.2))
    confidence_factor = dependency.confidence * max(vulnerability.match_confidence, 0.1) * provenance_quality
    status_factor = 1.0 if dependency.status == DependencyStatus.CONFIRMED else 0.7
    base = severity + exploit + patch_lag
    score = base * confidence_factor * status_factor
    low_confidence = dependency.confidence < 0.6 or vulnerability.match_confidence < 0.6
    if low_confidence:
        score = min(score, 28.0)
    if _fixture_only(dependency, exploit_signals):
        score = min(score, 35.0)
    score = max(0.0, min(100.0, score))
    return round(score, 2), {
        "severity": round(severity, 2),
        "exploit_availability": round(exploit, 2),
        "dependency_confidence": round(dependency.confidence, 3),
        "version_match_confidence": round(vulnerability.match_confidence, 3),
        "confidence_factor": round(confidence_factor, 3),
        "provenance_quality": round(provenance_quality, 3),
        "patch_lag": round(patch_lag, 2),
        "status_factor": status_factor,
        "low_confidence": low_confidence,
        "fixture_only": _fixture_only(dependency, exploit_signals),
    }


def _patch_lag(vulnerability: VulnerabilityRecord) -> float:
    if not vulnerability.published:
        return 3.0
    try:
        published = datetime.fromisoformat(vulnerability.published.replace("Z", "+00:00"))
    except ValueError:
        return 3.0
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    days = (datetime.now(timezone.utc) - published).days
    if days > 365:
        return 8.0
    if days > 90:
        return 5.0
    if days > 30:
        return 3.0
    return 1.0


def _reason(
    dependency: DependencyRecord, vulnerability: VulnerabilityRecord, exploit_signals: list[ExploitSignal], score: float
) -> str:
    status = "confirmed" if dependency.status == DependencyStatus.CONFIRMED else "inferred"
    exploit_text = " with exploit-intelligence signal" if exploit_signals else ""
    confidence_text = (
        "low-confidence lead, not an exploit path"
        if dependency.confidence < 0.6 or vulnerability.match_confidence < 0.6
        else "supported lead"
    )
    return f"{vulnerability.severity} vulnerability match in {status} {dependency.ecosystem} dependency{exploit_text}; {confidence_text}; score {score:.2f}"


def _exploit_weight(signal: ExploitSignal) -> float:
    if "fixture" in signal.source.lower():
        return signal.confidence * 3.0
    return signal.confidence * 8.0


def _fixture_only(dependency: DependencyRecord, exploit_signals: list[ExploitSignal]) -> bool:
    provenance_fixture = all(
        "fixture" in prov.source_type.lower() or "config" in prov.source_type.lower() for prov in dependency.provenance
    )
    exploit_fixture = bool(exploit_signals) and all("fixture" in signal.source.lower() for signal in exploit_signals)
    return provenance_fixture or exploit_fixture
