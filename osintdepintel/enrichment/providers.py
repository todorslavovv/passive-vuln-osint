from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..http import HttpClient, HttpError
from ..models import DependencyRecord, VulnerabilityRecord
from ..registry import GlobalRegistry
from ..versioning import satisfies

OSV_ECOSYSTEMS = {
    "npm": "npm",
    "PyPI": "PyPI",
    "Maven": "Maven",
    "RubyGems": "RubyGems",
    "Go": "Go",
}

GITHUB_ADVISORY_ECOSYSTEMS = {
    "npm": "NPM",
    "PyPI": "PIP",
    "Maven": "MAVEN",
    "RubyGems": "RUBYGEMS",
    "Go": "GO",
    "NuGet": "NUGET",
    "Composer": "COMPOSER",
}


class EnrichmentEngine:
    def __init__(
        self,
        offline: bool = False,
        fixture_vulnerabilities: list[dict[str, Any]] | None = None,
        http: HttpClient | None = None,
        enable_nvd: bool = True,
    ) -> None:
        self.offline = offline
        self.fixture_vulnerabilities = fixture_vulnerabilities or []
        self.http = http or HttpClient()
        self.enable_nvd = enable_nvd

    def enrich(
        self, dependencies: Iterable[DependencyRecord], registry: GlobalRegistry
    ) -> dict[str, list[VulnerabilityRecord]]:
        output: dict[str, list[VulnerabilityRecord]] = {}
        for dependency in dependencies:
            records = self._offline_records(dependency)
            if not self.offline:
                records.extend(self._osv_records(dependency, registry))
                if self.enable_nvd:
                    records.extend(self._nvd_records(dependency, registry))
                else:
                    registry.add_gap(
                        dependency.target_name,
                        "nvd_enrichment",
                        "not_collected",
                        "NVD enrichment was skipped for this run",
                    )
                records.extend(self._github_advisory_records(dependency, registry))
            deduped = dedupe_vulnerabilities(records)
            if deduped:
                output[dependency.key] = deduped
        return output

    def _offline_records(self, dependency: DependencyRecord) -> list[VulnerabilityRecord]:
        records = []
        for raw in self.fixture_vulnerabilities:
            if raw.get("package_name", "").lower() != dependency.name.lower():
                continue
            raw_eco = (raw.get("ecosystem") or "").lower()
            dep_eco = (dependency.ecosystem or "").lower()
            if raw_eco != dep_eco:
                continue
            affected = list(raw.get("affected_versions", []))
            dep_version = dependency.version.strip() if dependency.version else None
            if affected and dep_version and not satisfies(dep_version, affected):
                continue
            records.append(
                VulnerabilityRecord(
                    vulnerability_id=raw["vulnerability_id"],
                    source=raw.get("source", "fixture"),
                    package_name=dependency.name,
                    ecosystem=dependency.ecosystem,
                    affected_versions=affected,
                    summary=raw.get("summary", ""),
                    severity=raw.get("severity", "UNKNOWN"),
                    cvss_score=raw.get("cvss_score"),
                    published=raw.get("published"),
                    modified=raw.get("modified"),
                    aliases=list(raw.get("aliases", [])),
                    references=list(raw.get("references", [])),
                    matched_version=dep_version or dependency.version,
                    match_confidence=float(raw.get("match_confidence", 0.85)),
                )
            )
        return records

    def _osv_records(self, dependency: DependencyRecord, registry: GlobalRegistry) -> list[VulnerabilityRecord]:
        ecosystem = OSV_ECOSYSTEMS.get(dependency.ecosystem)
        if not ecosystem or not dependency.version:
            return []
        payload = {"version": dependency.version, "package": {"name": dependency.name, "ecosystem": ecosystem}}
        try:
            raw = self.http.post_json("https://api.osv.dev/v1/query", payload)
        except HttpError as exc:
            registry.add_failure(
                dependency.target_name, "osv_enrichment", f"OSV query failed for {dependency.key}: {exc}"
            )
            return []
        records = []
        for vuln in raw.get("vulns", []):
            ranges = _affected_ranges_from_osv(vuln)
            records.append(
                VulnerabilityRecord(
                    vulnerability_id=vuln.get("id", "OSV-UNKNOWN"),
                    source="OSV.dev",
                    package_name=dependency.name,
                    ecosystem=dependency.ecosystem,
                    affected_versions=ranges or ["*"],
                    summary=vuln.get("summary", ""),
                    severity=_severity_from_osv(vuln),
                    cvss_score=_cvss_from_osv(vuln),
                    published=vuln.get("published"),
                    modified=vuln.get("modified"),
                    aliases=list(vuln.get("aliases", [])),
                    references=[item.get("url", "") for item in vuln.get("references", []) if item.get("url")],
                    matched_version=dependency.version,
                    match_confidence=0.92,
                )
            )
        return records

    def _nvd_records(self, dependency: DependencyRecord, registry: GlobalRegistry) -> list[VulnerabilityRecord]:
        if not dependency.version:
            return []
        import urllib.parse

        encoded_keyword = urllib.parse.quote(f"{dependency.name} {dependency.version}")
        query = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_keyword}"
        try:
            raw = self.http.get_json(query)
        except HttpError as exc:
            registry.add_failure(
                dependency.target_name, "nvd_enrichment", f"NVD query failed for {dependency.key}: {exc}"
            )
            return []
        records = []
        had_results = False
        cpe_confirmed = False
        dep_name_lower = dependency.name.lower()
        for item in raw.get("vulnerabilities", [])[:10]:
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            score = _nvd_score(metrics)
            cpe_match = False
            cpe_match_confidence = 0.85
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match_entry in node.get("cpeMatch", []):
                        cpe_uri = match_entry.get("criteria", "")
                        parts = cpe_uri.split(":")
                        if len(parts) > 4:
                            cpe_product = parts[4].lower()
                            if cpe_product == dep_name_lower:
                                cpe_match = True
                                cpe_match_confidence = 0.85
                                break
                            prefixes = ("python-", "lib", "node-", "py-", "perl-")
                            dep_stripped = dep_name_lower
                            cpe_stripped = cpe_product
                            for pfx in prefixes:
                                if dep_stripped.startswith(pfx):
                                    dep_stripped = dep_stripped[len(pfx) :]
                                if cpe_stripped.startswith(pfx):
                                    cpe_stripped = cpe_stripped[len(pfx) :]
                            if dep_stripped and cpe_stripped and dep_stripped == cpe_stripped:
                                cpe_match = True
                                cpe_match_confidence = 0.5
                                break
                        else:
                            if dep_name_lower in cpe_uri.lower():
                                cpe_match = True
                                cpe_match_confidence = 0.3
                                break
                    if cpe_match:
                        break
                if cpe_match:
                    break

            had_results = True
            if cpe_match:
                cpe_confirmed = True

            records.append(
                VulnerabilityRecord(
                    vulnerability_id=cve.get("id", "CVE-UNKNOWN"),
                    source="NVD",
                    package_name=dependency.name,
                    ecosystem=dependency.ecosystem,
                    affected_versions=[dependency.version],
                    summary=_nvd_summary(cve),
                    severity=_severity_from_score(score),
                    cvss_score=score,
                    published=cve.get("published"),
                    modified=cve.get("lastModified"),
                    aliases=[],
                    references=_nvd_references(cve.get("references", [])),
                    matched_version=dependency.version,
                    match_confidence=cpe_match_confidence if cpe_match else 0.45,
                )
            )
        if had_results and not cpe_confirmed:
            registry.add_gap(
                dependency.target_name,
                "nvd_enrichment",
                "cpe_mismatch",
                f"Keyword search returned results but no CPE product matched dependency '{dependency.name}'",
            )
        return records

    def _github_advisory_records(
        self, dependency: DependencyRecord, registry: GlobalRegistry
    ) -> list[VulnerabilityRecord]:
        ecosystem = GITHUB_ADVISORY_ECOSYSTEMS.get(dependency.ecosystem)
        if not ecosystem or not dependency.name:
            return []
        import os

        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            registry.add_gap(
                dependency.target_name,
                "github_advisory",
                "missing_credentials",
                f"GitHub Advisory enrichment skipped for '{dependency.name}' because GITHUB_TOKEN environment variable is not set",
            )
            return []

        query_str = (
            "query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {"
            " securityAdvisories(first: 10, ecosystem: $ecosystem, package: $package) {"
            " nodes { ghsaId summary severity cvss { score }"
            " identifiers { value } publishedAt updatedAt references { url } } } }"
        )
        variables = {"ecosystem": ecosystem, "package": dependency.name}
        headers = {"Authorization": f"Bearer {token}"}
        try:
            raw = self.http.post_json(
                "https://api.github.com/graphql", {"query": query_str, "variables": variables}, headers=headers
            )
        except HttpError as exc:
            registry.add_failure(
                dependency.target_name, "github_advisory", f"GitHub Advisory query failed for {dependency.key}: {exc}"
            )
            return []
        if not raw or "errors" in raw:
            return []
        data = raw.get("data", {})
        advisories = data.get("securityAdvisories", {})
        nodes = advisories.get("nodes", [])
        records = []
        for node in nodes:
            ghsa_id = node.get("ghsaId", "") or ""
            summary = node.get("summary", "") or ""
            severity_raw = node.get("severity", "UNKNOWN") or "UNKNOWN"
            cvss_data = node.get("cvss")
            cvss_score = None
            if isinstance(cvss_data, dict):
                cvss_score = cvss_data.get("score")
            identifiers = node.get("identifiers", []) or []
            cve_id = ""
            aliases: list[str] = []
            for ident in identifiers:
                value = ident.get("value", "") or ""
                if value.startswith("CVE-"):
                    cve_id = value
                else:
                    aliases.append(value)
            vulnerability_id = ghsa_id or cve_id or "GHSA-UNKNOWN"
            published = node.get("publishedAt") or None
            modified = node.get("updatedAt") or None
            refs = [
                ref.get("url", "") for ref in (node.get("references") or []) if isinstance(ref, dict) and ref.get("url")
            ]
            records.append(
                VulnerabilityRecord(
                    vulnerability_id=vulnerability_id,
                    source="GitHub Advisory Database",
                    package_name=dependency.name,
                    ecosystem=dependency.ecosystem,
                    affected_versions=[dependency.version] if dependency.version else [],
                    summary=summary,
                    severity=_severity_from_gh(severity_raw),
                    cvss_score=cvss_score if isinstance(cvss_score, (int, float)) else None,
                    published=published,
                    modified=modified,
                    aliases=aliases,
                    references=refs,
                    matched_version=dependency.version,
                    match_confidence=0.75,
                )
            )
        return records


def dedupe_vulnerabilities(records: Iterable[VulnerabilityRecord]) -> list[VulnerabilityRecord]:
    merged: list[VulnerabilityRecord] = []
    for record in records:
        existing = next((item for item in merged if item.identity_set() & record.identity_set()), None)
        if not existing:
            merged.append(record)
            continue
        existing.aliases = sorted(
            set(existing.aliases + record.aliases + [record.vulnerability_id]) - {existing.vulnerability_id}
        )
        existing.references = sorted(set(existing.references + record.references))
        if (record.cvss_score or 0) > (existing.cvss_score or 0):
            existing.cvss_score = record.cvss_score
            existing.severity = record.severity
        existing.match_confidence = max(existing.match_confidence, record.match_confidence)
        existing_sources = [s.strip() for s in existing.source.split(",")]
        if record.source not in existing_sources:
            existing.source = f"{existing.source}, {record.source}"
    return merged


def _affected_ranges_from_osv(vuln: dict[str, Any]) -> list[str]:
    ranges: list[str] = []
    for affected in vuln.get("affected", []):
        for range_item in affected.get("ranges", []):
            introduced = "0"
            for event in range_item.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    ranges.append(f">={introduced} <{event['fixed']}")
    return ranges


def _severity_from_osv(vuln: dict[str, Any]) -> str:
    score = _cvss_from_osv(vuln)
    return _severity_from_score(score)


def _cvss_from_osv(vuln: dict[str, Any]) -> float | None:
    db_specific = vuln.get("database_specific")
    if isinstance(db_specific, dict):
        cvss = db_specific.get("cvss")
        if isinstance(cvss, dict):
            score = cvss.get("score")
            if isinstance(score, (int, float)):
                return float(score)

    for severity in vuln.get("severity", []):
        if not isinstance(severity, dict):
            continue
        score = severity.get("score", "")
        if not isinstance(score, str):
            if isinstance(score, (int, float)):
                return float(score)
            continue
        if "/AV:" in score:
            continue
        try:
            return float(score)
        except ValueError:
            continue
    return None


def _nvd_score(metrics: dict[str, Any]) -> float | None:
    for field in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(field)
        if values and isinstance(values, list) and len(values) > 0:
            cvss_data = values[0].get("cvssData", {})
            score = cvss_data.get("baseScore") if isinstance(cvss_data, dict) else None
            if isinstance(score, (int, float)):
                return float(score)
    return None


def _nvd_references(raw: Any) -> list[str]:
    if isinstance(raw, dict):
        refs = raw.get("referenceData", [])
    elif isinstance(raw, list):
        refs = raw
    else:
        refs = []
    return [ref.get("url", "") for ref in refs if isinstance(ref, dict) and ref.get("url")]


def _severity_from_gh(severity: str) -> str:
    normalized = severity.upper().strip()
    if normalized in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        return normalized
    return "UNKNOWN"


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def _nvd_summary(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list) or not descriptions:
        return ""
    for desc in descriptions:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            result: str = desc.get("value", "")
            return result
    first = descriptions[0]
    if isinstance(first, dict):
        return str(first.get("value", ""))
    return ""
