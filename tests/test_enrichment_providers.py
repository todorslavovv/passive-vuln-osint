from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from osintdepintel.enrichment.providers import EnrichmentEngine, dedupe_vulnerabilities
from osintdepintel.http import HttpError
from osintdepintel.models import DependencyRecord, DependencyStatus, Provenance, VulnerabilityRecord
from osintdepintel.registry import GlobalRegistry


@pytest.fixture
def registry() -> GlobalRegistry:
    return GlobalRegistry()


@pytest.fixture
def sample_provenance() -> Provenance:
    return Provenance("fixture", "test", "memory", evidence="test fixture")


@pytest.fixture
def dep_record(sample_provenance: Provenance) -> DependencyRecord:
    return DependencyRecord("target", "lodash", "npm", "4.17.15", DependencyStatus.CONFIRMED, 0.9, [sample_provenance])


@pytest.fixture
def engine() -> EnrichmentEngine:
    return EnrichmentEngine(offline=False, enable_nvd=True, http=MagicMock())


class OsvProviderTests:
    def test_valid_response(
        self, engine: EnrichmentEngine, dep_record: DependencyRecord, registry: GlobalRegistry
    ) -> None:
        mock_response = {
            "vulns": [
                {
                    "id": "CVE-2020-8203",
                    "summary": "Prototype pollution in lodash",
                    "aliases": ["GHSA-p6mc-m468-83gw"],
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"}],
                    "published": "2020-07-15T00:00:00Z",
                    "modified": "2020-07-16T00:00:00Z",
                    "database_specific": {"cvss": {"score": 7.4}},
                    "severity": [{"type": "CVSS_V3", "score": 7.4}],
                    "affected": [
                        {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}
                    ],
                }
            ]
        }
        engine.http.post_json.return_value = mock_response
        records = engine._osv_records(dep_record, registry)
        assert len(records) == 1
        r = records[0]
        assert r.vulnerability_id == "CVE-2020-8203"
        assert r.source == "OSV.dev"
        assert r.severity == "HIGH"
        assert r.cvss_score == 7.4
        assert "GHSA-p6mc-m468-83gw" in r.aliases

    def test_http_error_returns_empty(
        self, engine: EnrichmentEngine, dep_record: DependencyRecord, registry: GlobalRegistry
    ) -> None:
        engine.http.post_json.side_effect = HttpError("500 Server Error")
        records = engine._osv_records(dep_record, registry)
        assert records == []

    def test_malformed_json_returns_empty(
        self, engine: EnrichmentEngine, dep_record: DependencyRecord, registry: GlobalRegistry
    ) -> None:
        engine.http.post_json.side_effect = HttpError("invalid JSON from response")
        records = engine._osv_records(dep_record, registry)
        assert records == []


class NvdProviderTests:
    def test_valid_response(
        self, engine: EnrichmentEngine, dep_record: DependencyRecord, registry: GlobalRegistry
    ) -> None:
        mock_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2020-8203",
                        "published": "2020-07-15T00:00:00Z",
                        "lastModified": "2020-07-16T00:00:00Z",
                        "descriptions": [{"lang": "en", "value": "Prototype pollution in lodash"}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 7.4, "baseSeverity": "HIGH"}}],
                        },
                        "configurations": [
                            {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:lodash:lodash:4.17.15:*:*:*:*:*:*:*"}]}]}
                        ],
                        "references": {"referenceData": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"}]},
                    }
                }
            ]
        }
        engine.http.get_json.return_value = mock_response
        records = engine._nvd_records(dep_record, registry)
        assert len(records) == 1
        r = records[0]
        assert r.cvss_score == 7.4
        assert r.severity == "HIGH"
        assert r.vulnerability_id == "CVE-2020-8203"

    def test_empty_results(
        self, engine: EnrichmentEngine, dep_record: DependencyRecord, registry: GlobalRegistry
    ) -> None:
        engine.http.get_json.return_value = {"totalResults": 0, "vulnerabilities": []}
        records = engine._nvd_records(dep_record, registry)
        assert records == []

    def test_cpe_false_positive_prevention(self, engine: EnrichmentEngine, registry: GlobalRegistry) -> None:
        ssh_dep = DependencyRecord(
            "target", "ssh", "npm", "1.0.0", DependencyStatus.CONFIRMED, 0.9, [Provenance("fixture", "test", "memory")]
        )
        mock_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "published": "2024-01-01T00:00:00Z",
                        "lastModified": "2024-01-02T00:00:00Z",
                        "descriptions": [{"lang": "en", "value": "Test vuln"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]},
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {"criteria": "cpe:2.3:a:libssh2_project:libssh2:1.9.0:*:*:*:*:*:*:*"}
                                        ]
                                    }
                                ]
                            }
                        ],
                        "references": {"referenceData": []},
                    }
                }
            ]
        }
        engine.http.get_json.return_value = mock_response
        records = engine._nvd_records(ssh_dep, registry)
        # The CPE contains "libssh2" not "ssh", so cpe_match should be False
        assert len(records) == 1
        # match_confidence should be 0.45 (keyword match only), not 0.85 (CPE confirmed)
        assert records[0].match_confidence < 0.85


class GithubAdvisoryProviderTests:
    def test_valid_graphql_response(
        self, engine: EnrichmentEngine, dep_record: DependencyRecord, registry: GlobalRegistry
    ) -> None:
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "nodes": [
                        {
                            "ghsaId": "GHSA-p6mc-m468-83gw",
                            "summary": "Prototype pollution in lodash",
                            "severity": "HIGH",
                            "cvss": {"score": 7.4},
                            "identifiers": [{"value": "CVE-2020-8203"}, {"value": "GHSA-p6mc-m468-83gw"}],
                            "publishedAt": "2020-07-15T00:00:00Z",
                            "updatedAt": "2020-07-16T00:00:00Z",
                            "references": [{"url": "https://github.com/advisories/GHSA-p6mc-m468-83gw"}],
                        }
                    ]
                }
            }
        }
        engine.http.post_json.return_value = mock_response
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}):
            records = engine._github_advisory_records(dep_record, registry)
        assert len(records) == 1
        r = records[0]
        assert r.vulnerability_id == "GHSA-p6mc-m468-83gw"
        assert r.source == "GitHub Advisory Database"
        assert r.cvss_score == 7.4

    def test_missing_github_token(
        self, engine: EnrichmentEngine, dep_record: DependencyRecord, registry: GlobalRegistry
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            records = engine._github_advisory_records(dep_record, registry)
        assert records == []


class FixtureProviderTests:
    def test_known_package_match(self, dep_record: DependencyRecord) -> None:
        fixture_vulns = [
            {
                "vulnerability_id": "CVE-2020-8203",
                "source": "fixture/NVD",
                "package_name": "lodash",
                "ecosystem": "npm",
                "affected_versions": ["<4.17.19"],
                "summary": "Prototype pollution in lodash",
                "severity": "HIGH",
                "cvss_score": 7.4,
                "aliases": ["GHSA-p6mc-m468-83gw"],
                "references": ["https://github.com/lodash/lodash/wiki/Security"],
                "match_confidence": 0.9,
            }
        ]
        offline_engine = EnrichmentEngine(offline=True, fixture_vulnerabilities=fixture_vulns)
        records = offline_engine._offline_records(dep_record)
        assert len(records) == 1
        r = records[0]
        assert r.vulnerability_id == "CVE-2020-8203"
        assert r.match_confidence == 0.9
        assert r.severity == "HIGH"

    def test_known_package_from_fixture_file(self) -> None:
        fixture_dir = Path(__file__).resolve().parent / "fixtures"
        path = fixture_dir / "offline_intel.json"
        fixture_data = json.loads(path.read_text(encoding="utf-8"))
        engine = EnrichmentEngine(offline=True, fixture_vulnerabilities=fixture_data.get("vulnerabilities", []))
        jquery_dep = DependencyRecord(
            "target",
            "jquery",
            "npm",
            "3.3.1",
            DependencyStatus.CONFIRMED,
            0.9,
            [Provenance("fixture", "test", "memory")],
        )
        records = engine._offline_records(jquery_dep)
        assert len(records) >= 1
        ids = {r.vulnerability_id for r in records}
        assert "CVE-2019-11358" in ids


class DeduplicationTests:
    def test_deduplicates_identical_vulnerability(self, engine: EnrichmentEngine) -> None:
        records = [
            VulnerabilityRecord(
                vulnerability_id="CVE-2020-8203",
                source="OSV.dev",
                package_name="lodash",
                ecosystem="npm",
                affected_versions=["<4.17.19"],
                summary="Prototype pollution",
                severity="HIGH",
                cvss_score=7.4,
                aliases=["GHSA-p6mc-m468-83gw"],
                match_confidence=0.92,
            ),
            VulnerabilityRecord(
                vulnerability_id="GHSA-p6mc-m468-83gw",
                source="GitHub Advisory Database",
                package_name="lodash",
                ecosystem="npm",
                affected_versions=["<4.17.19"],
                summary="Prototype pollution in lodash",
                severity="HIGH",
                cvss_score=7.5,
                aliases=["CVE-2020-8203"],
                match_confidence=0.75,
            ),
        ]
        deduped = dedupe_vulnerabilities(records)
        assert len(deduped) == 1
        # Should keep the highest CVSS score
        assert deduped[0].cvss_score == 7.5
        # Should combine sources
        assert "OSV.dev" in deduped[0].source
        assert "GitHub Advisory Database" in deduped[0].source
        # Should keep max confidence
        assert deduped[0].match_confidence == 0.92
