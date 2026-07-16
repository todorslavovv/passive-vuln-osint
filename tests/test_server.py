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
                        "mode": "LAB TARGETS",
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
    assert data[0]["mode"] == "LAB TARGETS"


def test_add_target(mock_config_and_output):
    payload = {"name": "new-target", "url": "https://new.example.com", "mode": "PUBLIC OSINT TARGETS"}
    response = client.post("/api/targets", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify target was saved to file
    response = client.get("/api/targets")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert any(t["name"] == "new-target" for t in data)


def test_add_duplicate_target(mock_config_and_output):
    payload = {"name": "test-target", "url": "https://different.example.com", "mode": "LAB TARGETS"}
    response = client.post("/api/targets", json=payload)
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]


def test_update_target(mock_config_and_output):
    payload = {"name": "test-target", "url": "https://updated.example.com", "mode": "AUTHORIZED REAL TARGETS"}
    response = client.put("/api/targets/test-target", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify it updated in file
    response = client.get("/api/targets")
    data = response.json()
    assert len(data) == 1
    assert data[0]["url"] == "https://updated.example.com"
    assert data[0]["mode"] == "AUTHORIZED REAL TARGETS"


def test_update_nonexistent_target(mock_config_and_output):
    payload = {"name": "nonexistent", "url": "https://none.example.com", "mode": "LAB TARGETS"}
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
    report_data = {"summary": {"dependency_count": 5, "vulnerability_count": 2, "finding_count": 2}}
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


def test_get_nvidia_summary(mock_config_and_output):
    _, temp_output_dir = mock_config_and_output

    summary_file = temp_output_dir / "nvidia_human_summary.txt"
    summary_file.write_text("Mock summary content", encoding="utf-8")

    response = client.get("/api/reports/nvidia-summary")
    assert response.status_code == 200
    assert response.json()["summary"] == "Mock summary content"


def test_get_nonexistent_nvidia_summary(mock_config_and_output):
    response = client.get("/api/reports/nvidia-summary")
    assert response.status_code == 404
