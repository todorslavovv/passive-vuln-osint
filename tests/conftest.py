from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from osintdepintel.models import DependencyRecord, DependencyStatus, Provenance, VulnerabilityRecord

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
ROOT_DIR = FIXTURE_DIR.parent.parent


@pytest.fixture(scope="session")
def offline_intel() -> dict[str, Any]:
    path = FIXTURE_DIR / "offline_intel.json"
    return (
        json.loads(path.read_text(encoding="utf-8"))
        if path.exists()
        else {"vulnerabilities": [], "exploits": [], "transitives": {}}
    )


@pytest.fixture(scope="session")
def targets_config() -> list[dict[str, Any]]:
    path = ROOT_DIR / "examples" / "targets.json"
    return json.loads(path.read_text(encoding="utf-8"))["targets"]


@pytest.fixture
def sample_provenance() -> Provenance:
    return Provenance("fixture", "test", "memory", evidence="test fixture")


@pytest.fixture
def inferred_record(sample_provenance: Provenance) -> DependencyRecord:
    return DependencyRecord("target", "lodash", "npm", "4.17.15", DependencyStatus.INFERRED, 0.45, [sample_provenance])


@pytest.fixture
def confirmed_record(sample_provenance: Provenance) -> DependencyRecord:
    return DependencyRecord("target", "lodash", "npm", "4.17.15", DependencyStatus.CONFIRMED, 0.9, [sample_provenance])


@pytest.fixture
def sample_vulnerability() -> VulnerabilityRecord:
    return VulnerabilityRecord(
        vulnerability_id="CVE-TEST-2024-0001",
        source="test",
        package_name="lodash",
        ecosystem="npm",
        affected_versions=["<4.17.20"],
        summary="test vulnerability",
        severity="HIGH",
        cvss_score=7.5,
        match_confidence=0.9,
    )
