from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from osintdepintel.ai_summary import (
    _clean_text,
    _local_fallback_summary,
    _looks_readable,
    _summary_prompt,
    write_nvidia_summary,
)
from osintdepintel.http import HttpError

SAMPLE_AGGREGATE_NO_EXPLOIT: dict = {
    "aggregate": {"target_count": 1, "dependency_count": 3, "vulnerability_count": 1, "finding_count": 1},
    "evidence_summary": {"observation_count": 2},
    "confidence_distribution": {"high": 0, "medium": 1, "low": 2},
    "source_coverage": {"observed_source_types": ["html"]},
    "targets": [
        {
            "name": "notarget.test",
            "summary": {"dependency_count": 3, "vulnerability_count": 1},
            "top_findings": [
                {
                    "score": 6.0,
                    "dependency": {"ecosystem": "pypi", "name": "requests", "version": "2.25.0"},
                    "vulnerability": {"vulnerability_id": "CVE-2025-0001", "summary": "HTTP走私"},
                    "exploit_signals": [],
                    "rank_reason": "Medium CVSS",
                }
            ],
        }
    ],
}

SAMPLE_AGGREGATE: dict = {
    "aggregate": {"target_count": 2, "dependency_count": 15, "vulnerability_count": 4, "finding_count": 8},
    "evidence_summary": {"observation_count": 12, "inference_count": 5},
    "confidence_distribution": {"high": 5, "medium": 7, "low": 3},
    "source_coverage": {"observed_source_types": ["html", "webpack"]},
    "targets": [
        {
            "name": "example.com",
            "summary": {"dependency_count": 8, "vulnerability_count": 3},
            "top_findings": [
                {
                    "score": 8.5,
                    "dependency": {"ecosystem": "npm", "name": "lodash", "version": "4.17.15"},
                    "vulnerability": {"vulnerability_id": "CVE-2024-0001", "summary": "Prototype pollution"},
                    "exploit_signals": [{"source": "ExploitDB", "reference": "https://exploit-db.com/12345"}],
                    "rank_reason": "High CVSS + known exploit",
                }
            ],
        }
    ],
}


class CleanTextTests:
    def test_replaces_bad_unicode_sequences(self) -> None:
        result = _clean_text("Hello\u00e2\u20ac\u2122World\u00e2\u20ac\u0153Test\u00e2\u20ac\u009dEnd")
        assert "'" in result
        assert result.isascii()

    def test_normalizes_and_strips_non_ascii(self) -> None:
        result = _clean_text("caf\u00e9")
        assert result == "cafe"

    def test_empty_string(self) -> None:
        assert _clean_text("") == ""

    def test_clean_ascii_passthrough(self) -> None:
        assert _clean_text("hello world") == "hello world"


class LooksReadableTests:
    def test_returns_false_for_short_text(self) -> None:
        assert not _looks_readable("short")

    def test_returns_false_for_low_printable_ratio(self) -> None:
        text = "website " + "\x00\x01\x02" * 20 + " dependencies"
        assert not _looks_readable(text)

    def test_returns_false_without_common_words(self) -> None:
        text = "abc def ghi jkl mno pqr stu vwx yz" * 5
        assert not _looks_readable(text)

    def test_returns_false_with_many_unk_tokens(self) -> None:
        text = "website <unk> <unk> <unk> <unk> dependencies vulnerabilities"
        assert not _looks_readable(text)

    def test_returns_true_for_readable_text(self) -> None:
        text = "The website example.com has 15 dependencies and 4 vulnerabilities."
        assert _looks_readable(text)

    def test_boundary_40_chars(self) -> None:
        assert not _looks_readable("x" * 39)


class SummaryPromptTests:
    def test_includes_aggregate_data(self) -> None:
        prompt = _summary_prompt(SAMPLE_AGGREGATE)
        assert "15" in prompt
        assert "4" in prompt

    def test_includes_target_info(self) -> None:
        prompt = _summary_prompt(SAMPLE_AGGREGATE)
        assert "example.com" in prompt
        assert "lodash" in prompt

    def test_includes_exploit_signals(self) -> None:
        prompt = _summary_prompt(SAMPLE_AGGREGATE)
        assert "ExploitDB" in prompt

    def test_returns_non_empty_string(self) -> None:
        prompt = _summary_prompt(SAMPLE_AGGREGATE)
        assert isinstance(prompt, str)
        assert len(prompt) > 100


class LocalFallbackSummaryTests:
    def test_with_warning(self) -> None:
        result = _local_fallback_summary(SAMPLE_AGGREGATE, "NVIDIA API error")
        assert "NVIDIA API error" in result
        assert "2 websites" in result
        assert "15 dependencies" in result

    def test_without_warning(self) -> None:
        result = _local_fallback_summary(SAMPLE_AGGREGATE)
        assert "NVIDIA" not in result
        assert "Processed 2 websites" in result

    def test_includes_target_details(self) -> None:
        result = _local_fallback_summary(SAMPLE_AGGREGATE)
        assert "example.com" in result

    def test_includes_finding_and_exploit_signal(self) -> None:
        result = _local_fallback_summary(SAMPLE_AGGREGATE)
        assert "CVE-2024-0001" in result
        assert "ExploitDB" in result

    def test_empty_aggregate(self) -> None:
        result = _local_fallback_summary({})
        assert "0 websites" in result

    def test_finding_without_exploit_signals(self) -> None:
        result = _local_fallback_summary(SAMPLE_AGGREGATE_NO_EXPLOIT)
        assert "none found" in result
        assert "CVE-2025-0001" in result


class NvidiaSummaryTests:
    def test_successful_call_writes_summary_file(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.return_value = {
            "choices": [{"message": {"content": "The website example.com has 15 dependencies and 4 vulnerabilities."}}]
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            output_dir = Path(tmp)
            result_path = write_nvidia_summary(SAMPLE_AGGREGATE, output_dir, "test-key", "test-model")
            assert result_path.exists()
            content = result_path.read_text(encoding="utf-8")
            assert "15 dependencies" in content

    def test_http_error_triggers_fallback(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.side_effect = HttpError("API unreachable")
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            output_dir = Path(tmp)
            result_path = write_nvidia_summary(SAMPLE_AGGREGATE, output_dir, "test-key", "test-model")
            content = result_path.read_text(encoding="utf-8")
            assert "API unreachable" in content
            assert "15 dependencies" in content

    def test_bad_response_format_triggers_fallback(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.return_value = {"unexpected": "response"}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            output_dir = Path(tmp)
            result_path = write_nvidia_summary(SAMPLE_AGGREGATE, output_dir, "test-key", "test-model")
            content = result_path.read_text(encoding="utf-8")
            assert "NVIDIA summary failed" in content

    def test_unreadable_response_triggers_local_fallback(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.return_value = {"choices": [{"message": {"content": "short"}}]}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            output_dir = Path(tmp)
            result_path = write_nvidia_summary(SAMPLE_AGGREGATE, output_dir, "test-key", "test-model")
            content = result_path.read_text(encoding="utf-8")
            assert "not readable" in content

    def test_creates_output_directory_recursively(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.return_value = {
            "choices": [{"message": {"content": "The website example.com has 15 dependencies."}}]
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            nested_dir = Path(tmp) / "deep" / "nested"
            result_path = write_nvidia_summary(SAMPLE_AGGREGATE, nested_dir, "test-key", "test-model")
            assert result_path.exists()

    def test_passes_model_name_to_api(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.return_value = {"choices": [{"message": {"content": "Valid summary content here."}}]}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            output_dir = Path(tmp)
            write_nvidia_summary(SAMPLE_AGGREGATE, output_dir, "test-key", "nemotron-3-ultra")
            args, kwargs = mock_http.post_json.call_args
            payload = args[1]
            assert payload["model"] == "nemotron-3-ultra"

    def test_sends_authorization_header(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.return_value = {"choices": [{"message": {"content": "Valid summary content here."}}]}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            output_dir = Path(tmp)
            write_nvidia_summary(SAMPLE_AGGREGATE, output_dir, "secret-key-12345", "test-model")
            args, kwargs = mock_http.post_json.call_args
            headers = kwargs.get("headers")
            assert headers is not None
            assert headers["Authorization"] == "Bearer secret-key-12345"


@pytest.mark.live
class LiveNvidiaSummaryTests:
    def test_live_api_call(self) -> None:
        api_key = os.environ.get("NVIDIA_API_KEY")
        if not api_key:
            pytest.skip("NVIDIA_API_KEY not set")
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            model = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")
            result_path = write_nvidia_summary(SAMPLE_AGGREGATE, output_dir, api_key, model)
            assert result_path.exists()
            content = result_path.read_text(encoding="utf-8")
            assert len(content) > 40
