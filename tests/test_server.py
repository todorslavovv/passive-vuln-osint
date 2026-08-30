from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from osintdepintel.server import main
from osintdepintel.server.main import app

client = TestClient(app)


@pytest.fixture
def mock_config_and_output(tmp_path):
    # Setup temporary targets.json file
    temp_config = tmp_path / "targets.json"
    temp_config.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "name": "test-target",
                        "url": "https://test.example.com",
                        "github_repos": [],
                        "sbom_urls": [],
                        "container_images": [],
                        "mobile_artifacts": [],
                        "package_hints": [],
                        "metadata": {},
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # Setup temporary reports folder
    temp_output_dir = tmp_path / "reports"
    temp_output_dir.mkdir()

    # Mock global variables in main
    old_config = main.CONFIG_PATH_GLOBAL
    old_output = main.OUTPUT_DIR_GLOBAL
    main.CONFIG_PATH_GLOBAL = temp_config
    main.OUTPUT_DIR_GLOBAL = temp_output_dir

    yield temp_config, temp_output_dir

    main.CONFIG_PATH_GLOBAL = old_config
    main.OUTPUT_DIR_GLOBAL = old_output


def test_get_targets(mock_config_and_output):
    response = client.get("/api/targets")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["name"] == "test-target"
    assert data[0]["url"] == "https://test.example.com"


def test_add_target(mock_config_and_output):
    payload = {"url": "https://new.example.com"}
    response = client.post("/api/targets", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify target was saved to file with auto-derived name
    response = client.get("/api/targets")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert any(t["name"] == "new" for t in data)


def test_add_duplicate_target(mock_config_and_output):
    # URL that auto-derives the same name as an existing target
    payload = {"url": "https://test-target.example.com"}
    response = client.post("/api/targets", json=payload)
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]


def test_update_target(mock_config_and_output):
    payload = {"url": "https://updated.example.com"}
    response = client.put("/api/targets/test-target", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify it updated in file (name auto-derived from URL)
    response = client.get("/api/targets")
    data = response.json()
    assert len(data) == 1
    assert data[0]["url"] == "https://updated.example.com"
    assert data[0]["name"] == "updated"


def test_update_nonexistent_target(mock_config_and_output):
    payload = {"url": "https://none.example.com"}
    response = client.put("/api/targets/nonexistent", json=payload)
    assert response.status_code == 404


def test_delete_target(mock_config_and_output):
    response = client.delete("/api/targets/test-target")
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify deleted
    response = client.get("/api/targets")
    assert len(response.json()) == 0


def test_delete_nonexistent_target(mock_config_and_output):
    response = client.delete("/api/targets/nonexistent")
    assert response.status_code == 404


def test_get_scan_status():
    response = client.get("/api/scans/status")
    assert response.status_code == 200
    data = response.json()
    assert "running" in data
    assert data["running"] is False


@patch("threading.Thread")
def test_start_scan(mock_thread, mock_config_and_output):
    payload = {"targets": ["test-target"], "options": {"offline": True, "skip_nvd": True, "rate_limit": 4.0}}
    response = client.post("/api/scans/run", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "started"

    # Verify status is running
    status_response = client.get("/api/scans/status")
    assert status_response.json()["running"] is True

    # Reset status manually for subsequent tests
    with main.scan_state.lock:
        main.scan_state.running = False
    mock_thread.assert_called_once()


def test_list_reports_empty(mock_config_and_output):
    response = client.get("/api/reports")
    assert response.status_code == 200
    assert len(response.json()) == 0


def test_get_report_details_and_list(mock_config_and_output):
    _, temp_output_dir = mock_config_and_output

    # Write mock report file
    report_data = {
        "target": {"name": "test-target"},
        "summary": {"dependency_count": 5, "vulnerability_count": 2, "finding_count": 2},
    }
    report_file = temp_output_dir / "test-target.json"
    report_file.write_text(json.dumps(report_data), encoding="utf-8")

    # Test listing reports
    response = client.get("/api/reports")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["target_name"] == "test-target"
    assert data[0]["dependency_count"] == 5

    # Test getting report details
    detail_response = client.get("/api/reports/detail/test-target")
    assert detail_response.status_code == 200
    assert detail_response.json()["summary"]["dependency_count"] == 5


def test_get_nonexistent_report_details(mock_config_and_output):
    response = client.get("/api/reports/detail/nonexistent")
    assert response.status_code == 404


def test_get_aggregate_report(mock_config_and_output):
    _, temp_output_dir = mock_config_and_output

    # Write mock aggregate report
    aggregate_data = {"aggregate": {"target_count": 1, "dependency_count": 5}}
    aggregate_file = temp_output_dir / "aggregate_report.json"
    aggregate_file.write_text(json.dumps(aggregate_data), encoding="utf-8")

    response = client.get("/api/reports/aggregate")
    assert response.status_code == 200
    assert response.json()["aggregate"]["dependency_count"] == 5


def test_get_nonexistent_aggregate_report(mock_config_and_output):
    response = client.get("/api/reports/aggregate")
    assert response.status_code == 404


def test_get_opencode_summary(mock_config_and_output):
    _, temp_output_dir = mock_config_and_output

    summary_file = temp_output_dir / "test-target_opencode_summary.txt"
    summary_file.write_text("Mock summary content", encoding="utf-8")

    response = client.get("/api/reports/opencode-summary/test-target")
    assert response.status_code == 200
    assert response.json()["summary"] == "Mock summary content"


def test_get_nonexistent_opencode_summary(mock_config_and_output):
    response = client.get("/api/reports/opencode-summary/test-target")
    assert response.status_code == 404


def test_delete_report_removes_all_artifacts(mock_config_and_output):
    _, temp_output_dir = mock_config_and_output

    for suffix in (".json", ".txt", ".dot", "_cyclonedx.json", "_spdx.json", "_opencode_summary.txt"):
        (temp_output_dir / f"test-target{suffix}").write_text("x", encoding="utf-8")

    response = client.delete("/api/reports/test-target")
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    # Every generated artifact for the stem should be gone.
    assert not any(temp_output_dir.glob("test-target*"))


def test_delete_nonexistent_report(mock_config_and_output):
    response = client.delete("/api/reports/nonexistent")
    assert response.status_code == 404


def test_report_detail_path_traversal_is_neutralized(mock_config_and_output):
    _, temp_output_dir = mock_config_and_output

    # A secret file one directory above the reports output dir.
    secret = temp_output_dir.parent / "secret.json"
    secret.write_text(json.dumps({"target": {}, "summary": {}}), encoding="utf-8")

    # Encoded traversal that, if used verbatim as a stem, would escape the output dir.
    response = client.get("/api/reports/detail/..%2Fsecret")
    # The stem is sanitized, so the traversal cannot reach ../secret.json.
    assert response.status_code == 404


def test_download_artifact_unknown_kind(mock_config_and_output):
    _, temp_output_dir = mock_config_and_output
    (temp_output_dir / "test-target.json").write_text("{}", encoding="utf-8")
    response = client.get("/api/reports/artifact/test-target/evil-kind")
    assert response.status_code == 400
