from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from osintdepintel.ai_summary import (
    OPENCODE_DEFAULT_MODEL,
    _clean_text,
    _local_fallback_summary,
    _looks_readable,
    _summary_prompt,
    write_opencode_summary,
    write_opencode_target_summary,
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
        result = _local_fallback_summary(SAMPLE_AGGREGATE, "OpenCode API error")
        assert "OpenCode API error" in result
        assert "2 websites" in result
        assert "15 dependencies" in result

    def test_without_warning(self) -> None:
        result = _local_fallback_summary(SAMPLE_AGGREGATE)
        assert "API error" not in result
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


class OpenCodeSummaryTests:
    def test_successful_call_writes_summary_file(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.return_value = {
            "choices": [{"message": {"content": "The website example.com has 15 dependencies and 4 vulnerabilities."}}]
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            result_path = write_opencode_summary(SAMPLE_AGGREGATE, Path(tmp), "test-key")
            assert result_path.name == "opencode_human_summary.txt"
            assert "15 dependencies" in result_path.read_text(encoding="utf-8")

    def test_default_model_and_bearer_auth(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.return_value = {
            "choices": [{"message": {"content": "Valid readable summary content here."}}]
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            write_opencode_summary(SAMPLE_AGGREGATE, Path(tmp), "secret-key-999")
            _, kwargs = mock_http.post_json.call_args
            assert kwargs["headers"]["Authorization"] == "Bearer secret-key-999"
            # model defaults to OPENCODE_DEFAULT_MODEL when not overridden
            payload = mock_http.post_json.call_args.args[1]
            assert payload["model"] == OPENCODE_DEFAULT_MODEL

    def test_http_error_triggers_fallback(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.side_effect = HttpError("Internal server error")
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            content = write_opencode_summary(SAMPLE_AGGREGATE, Path(tmp), "test-key").read_text(encoding="utf-8")
            assert "OpenCode summary failed" in content
            assert "15 dependencies" in content

    def test_target_summary_writes_stemmed_file(self) -> None:
        mock_http = MagicMock()
        mock_http.post_json.return_value = {"choices": [{"message": {"content": "Readable target summary content."}}]}
        target_report = {
            "target": {"name": "Example Site", "url": "https://example.test"},
            "summary": {"dependency_count": 2, "vulnerability_count": 1, "finding_count": 1},
            "findings": [],
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("osintdepintel.ai_summary.HttpClient", return_value=mock_http),
        ):
            path = write_opencode_target_summary(target_report, Path(tmp), "k", "laguna-s-2.1-free", "Example Site")
            assert path.name == "example_site_opencode_summary.txt"
            assert path.exists()
