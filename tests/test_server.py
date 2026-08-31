from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from osintdepintel.server import main
from osintdepintel.server.main import app

_TEST_TARGET = {
    "name": "test-target",
    "url": "https://test.example.com",
    "github_repos": [],
    "sbom_urls": [],
    "container_images": [],
    "mobile_artifacts": [],
    "package_hints": [],
    "metadata": {},
}


@pytest.fixture
def demo(tmp_path):
    """Point the server at a temp baseline (one target, empty seed reports) and a fresh
    per-test session store, then hand back a client plus the baseline reports dir so a
    test can pre-seed reports before its first request (sessions seed lazily from it)."""
    config = tmp_path / "targets.json"
    config.write_text(json.dumps({"targets": [_TEST_TARGET]}), encoding="utf-8")
    baseline_reports = tmp_path / "baseline"
    baseline_reports.mkdir()

    saved = (
        main.BASELINE_CONFIG,
        main.SESSIONS_ROOT,
        main.BASELINE_REPORTS,
        main.BASELINE_REPORT_TARGETS,
        main.store,
        main._baseline_built,
    )
    main.BASELINE_CONFIG = config
    main.SESSIONS_ROOT = tmp_path / "sessions"
    main.BASELINE_REPORTS = baseline_reports
    main.BASELINE_REPORT_TARGETS = []  # don't run the pipeline during tests
    main._baseline_built = True
    main.store = main.SessionStore()

    with TestClient(app) as client:
        yield client, baseline_reports

    (
        main.BASELINE_CONFIG,
        main.SESSIONS_ROOT,
        main.BASELINE_REPORTS,
        main.BASELINE_REPORT_TARGETS,
        main.store,
        main._baseline_built,
    ) = saved


def _seed_report(baseline_reports, stem, data):
    (baseline_reports / f"{stem}.json").write_text(json.dumps(data), encoding="utf-8")


def test_get_targets(demo):
    client, _ = demo
    response = client.get("/api/targets")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["name"] == "test-target"
    assert data[0]["url"] == "https://test.example.com"


def test_add_target(demo):
    client, _ = demo
    assert client.post("/api/targets", json={"url": "https://new.example.com"}).json()["status"] == "success"
    data = client.get("/api/targets").json()
    assert len(data) == 2
    assert any(t["name"] == "new" for t in data)


def test_add_duplicate_target(demo):
    client, _ = demo
    response = client.post("/api/targets", json={"url": "https://test-target.example.com"})
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]


def test_update_target(demo):
    client, _ = demo
    assert client.put("/api/targets/test-target", json={"url": "https://updated.example.com"}).status_code == 200
    data = client.get("/api/targets").json()
    assert len(data) == 1
    assert data[0]["url"] == "https://updated.example.com"
    assert data[0]["name"] == "updated"


def test_update_nonexistent_target(demo):
    client, _ = demo
    assert client.put("/api/targets/nonexistent", json={"url": "https://none.example.com"}).status_code == 404


def test_delete_target(demo):
    client, _ = demo
    assert client.delete("/api/targets/test-target").status_code == 200
    assert len(client.get("/api/targets").json()) == 0


def test_delete_nonexistent_target(demo):
    client, _ = demo
    assert client.delete("/api/targets/nonexistent").status_code == 404


def test_get_scan_status(demo):
    client, _ = demo
    data = client.get("/api/scans/status").json()
    assert data["running"] is False


@patch("threading.Thread")
def test_start_scan(mock_thread, demo):
    client, _ = demo
    payload = {"targets": ["test-target"], "options": {"offline": True, "skip_nvd": True}}
    assert client.post("/api/scans/run", json=payload).json()["status"] == "started"
    assert client.get("/api/scans/status").json()["running"] is True
    mock_thread.assert_called_once()


def test_list_reports_empty(demo):
    client, _ = demo
    assert client.get("/api/reports").json() == []


def test_get_report_details_and_list(demo):
    client, baseline = demo
    _seed_report(
        baseline,
        "test-target",
        {
            "target": {"name": "test-target"},
            "summary": {"dependency_count": 5, "vulnerability_count": 2, "finding_count": 2},
        },
    )
    data = client.get("/api/reports").json()
    assert len(data) == 1
    assert data[0]["target_name"] == "test-target"
    assert data[0]["dependency_count"] == 5

    detail = client.get("/api/reports/detail/test-target").json()
    assert detail["summary"]["dependency_count"] == 5


def test_get_nonexistent_report_details(demo):
    client, _ = demo
    assert client.get("/api/reports/detail/nonexistent").status_code == 404


def test_get_aggregate_report(demo):
    client, baseline = demo
    (baseline / "aggregate_report.json").write_text(
        json.dumps({"aggregate": {"target_count": 1, "dependency_count": 5}}), encoding="utf-8"
    )
    response = client.get("/api/reports/aggregate")
    assert response.status_code == 200
    assert response.json()["aggregate"]["dependency_count"] == 5


def test_get_nonexistent_aggregate_report(demo):
    client, _ = demo
    assert client.get("/api/reports/aggregate").status_code == 404


def test_get_opencode_summary(demo):
    client, baseline = demo
    (baseline / "test-target_opencode_summary.txt").write_text("Mock summary content", encoding="utf-8")
    response = client.get("/api/reports/opencode-summary/test-target")
    assert response.status_code == 200
    assert response.json()["summary"] == "Mock summary content"


def test_get_nonexistent_opencode_summary(demo):
    client, _ = demo
    assert client.get("/api/reports/opencode-summary/test-target").status_code == 404


def test_delete_report_removes_all_artifacts(demo):
    client, baseline = demo
    for suffix in (".json", ".txt", ".dot", "_cyclonedx.json", "_spdx.json", "_opencode_summary.txt"):
        (baseline / f"test-target{suffix}").write_text("x", encoding="utf-8")
    _seed_report(baseline, "test-target", {"target": {"name": "test-target"}, "summary": {}})

    assert client.delete("/api/reports/test-target").status_code == 200
    # Report is gone from this sandbox (verified via the API, not the filesystem).
    assert client.get("/api/reports/detail/test-target").status_code == 404
    assert client.get("/api/reports/artifacts/test-target").json() == []


def test_delete_nonexistent_report(demo):
    client, _ = demo
    assert client.delete("/api/reports/nonexistent").status_code == 404


def test_report_detail_path_traversal_is_neutralized(demo):
    client, _ = demo
    # Encoded traversal that, if used verbatim as a stem, would escape the reports dir.
    # The stem is sanitized, so it can never resolve to ../secret.json.
    assert client.get("/api/reports/detail/..%2Fsecret").status_code == 404


def test_download_artifact_unknown_kind(demo):
    client, baseline = demo
    _seed_report(baseline, "test-target", {"target": {"name": "test-target"}, "summary": {}})
    assert client.get("/api/reports/artifact/test-target/evil-kind").status_code == 400


def test_sessions_are_isolated_between_visitors(demo):
    """A delete by one visitor must not affect another visitor's sandbox."""
    _client_a, baseline = demo
    _seed_report(baseline, "test-target", {"target": {"name": "test-target"}, "summary": {}})

    # Two independent visitors (separate cookie jars => separate sandboxes).
    with TestClient(app) as visitor_a, TestClient(app) as visitor_b:
        # Both start from the same baseline: one target, one seeded report.
        assert len(visitor_a.get("/api/targets").json()) == 1
        assert len(visitor_b.get("/api/targets").json()) == 1
        assert len(visitor_a.get("/api/reports").json()) == 1
        assert len(visitor_b.get("/api/reports").json()) == 1

        # Visitor A deletes both a target and a report.
        assert visitor_a.delete("/api/targets/test-target").status_code == 200
        assert visitor_a.delete("/api/reports/test-target").status_code == 200
        assert len(visitor_a.get("/api/targets").json()) == 0
        assert len(visitor_a.get("/api/reports").json()) == 0

        # Visitor B is completely unaffected.
        assert len(visitor_b.get("/api/targets").json()) == 1
        assert len(visitor_b.get("/api/reports").json()) == 1
