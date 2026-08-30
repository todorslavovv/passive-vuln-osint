from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any

from .http import HttpClient, HttpError
from .reporting.writers import _safe_filename

# OpenCode Zen is an OpenAI-compatible chat-completions gateway (Bearer auth).
OPENCODE_BASE_URL = "https://opencode.ai/zen/v1/chat/completions"
OPENCODE_DEFAULT_MODEL = "muse-spark-1.2-contributor-free"

_OPENCODE_SYSTEM = (
    "You explain passive OSINT dependency intelligence reports in simple human language. "
    "Do not claim exploitability unless the report proves it. Say exploit signals are suggested leads."
)


def _opencode_chat(prompt: str, api_key: str, model: str, timeout: int) -> str:
    """Call the OpenCode Zen OpenAI-compatible endpoint and return the message text.

    max_tokens is kept modest to limit output-token spend; no reasoning/thinking
    parameters are sent so the model answers directly (cheaper, and plenty for a
    plain-language summary).
    """
    client = HttpClient(timeout=timeout)
    response = client.post_json(
        OPENCODE_BASE_URL,
        {
            "model": model,
            "messages": [
                {"role": "system", "content": _OPENCODE_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "top_p": 0.95,
            "max_tokens": 2048,
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return str(response["choices"][0]["message"]["content"]).strip()


def write_opencode_summary(
    aggregate_report: dict[str, Any],
    output_dir: Path,
    api_key: str,
    model: str = OPENCODE_DEFAULT_MODEL,
    timeout: int = 120,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "opencode_human_summary.txt"
    prompt = _summary_prompt(aggregate_report)
    try:
        text = _clean_text(_opencode_chat(prompt, api_key, model, timeout))
        if not _looks_readable(text):
            text = _local_fallback_summary(
                aggregate_report,
                "OpenCode summary response was not readable, so a deterministic local summary was written.",
            )
    except (HttpError, KeyError, IndexError, TypeError) as exc:
        text = _local_fallback_summary(aggregate_report, f"OpenCode summary failed: {exc}")
    summary_path.write_text(_clean_text(text) + "\n", encoding="utf-8")
    return summary_path


def write_opencode_target_summary(
    target_report: dict[str, Any],
    output_dir: Path,
    api_key: str,
    model: str,
    target_name: str,
    timeout: int = 120,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_stem = _safe_filename(target_name)
    summary_path = output_dir / f"{safe_stem}_opencode_summary.txt"
    prompt = _target_summary_prompt(target_report)
    try:
        text = _clean_text(_opencode_chat(prompt, api_key, model, timeout))
        if not _looks_readable(text):
            text = _local_fallback_target_summary(
                target_report,
                "OpenCode summary response was not readable, so a deterministic local summary was written.",
            )
    except (HttpError, KeyError, IndexError, TypeError) as exc:
        text = _local_fallback_target_summary(target_report, f"OpenCode summary failed: {exc}")
    summary_path.write_text(_clean_text(text) + "\n", encoding="utf-8")
    return summary_path


def _summary_prompt(aggregate_report: dict[str, Any]) -> str:
    compact = {
        "aggregate": aggregate_report.get("aggregate", {}),
        "evidence_summary": aggregate_report.get("evidence_summary", {}),
        "confidence_distribution": aggregate_report.get("confidence_distribution", {}),
        "source_coverage": aggregate_report.get("source_coverage", {}),
        "targets": [
            {
                "name": target.get("name"),
                "summary": target.get("summary"),
                "top_findings": [
                    {
                        "score": finding.get("score"),
                        "dependency": finding.get("dependency", {}),
                        "vulnerability": finding.get("vulnerability", {}),
                        "exploit_signals": finding.get("exploit_signals", []),
                        "rank_reason": finding.get("rank_reason"),
                    }
                    for finding in target.get("top_findings", [])
                ],
            }
            for target in aggregate_report.get("targets", [])
        ],
    }
    return (
        "Write a normal, simple human explanation of this passive OSINT run. "
        "Use only plain ASCII punctuation. "
        "Include: the websites, how many dependencies were found, how many vulnerabilities were found, "
        "which items are exploitable if any, and suggested exploit references for each vulnerability if any. "
        "Be careful: version matches and exploit references are leads, not proof of exploitability.\n\n"
        + json.dumps(compact, indent=2)
    )


def _target_summary_prompt(target_report: dict[str, Any]) -> str:
    target = target_report.get("target", {})
    summary = target_report.get("summary", {})
    findings = target_report.get("findings", [])[:10]
    compact = {
        "target": {"name": target.get("name"), "url": target.get("url")},
        "summary": summary,
        "findings": [
            {
                "score": finding.get("score"),
                "dependency": finding.get("dependency", {}),
                "vulnerability": finding.get("vulnerability", {}),
                "exploit_signals": finding.get("exploit_signals", []),
                "rank_reason": finding.get("rank_reason"),
            }
            for finding in findings
        ],
    }
    return (
        "Write a normal, simple human explanation of this single-website passive OSINT run. "
        "Use only plain ASCII punctuation. "
        "Include: the website URL, how many dependencies were found, how many vulnerabilities were found, "
        "which items are exploitable if any, and suggested exploit references for each vulnerability if any. "
        "Be careful: version matches and exploit references are leads, not proof of exploitability.\n\n"
        + json.dumps(compact, indent=2)
    )


def _local_fallback_summary(aggregate_report: dict[str, Any], warning: str | None = None) -> str:
    lines = []
    if warning:
        lines.append(warning)
        lines.append("")
    aggregate = aggregate_report.get("aggregate", {})
    lines.append(
        f"Processed {aggregate.get('target_count', 0)} websites. "
        f"Found {aggregate.get('dependency_count', 0)} dependencies, "
        f"{aggregate.get('vulnerability_count', 0)} vulnerability matches, and "
        f"{aggregate.get('finding_count', 0)} ranked findings."
    )
    for target in aggregate_report.get("targets", []):
        summary = target.get("summary", {})
        lines.append("")
        lines.append(
            f"{target.get('name')}: {summary.get('dependency_count', 0)} dependencies, {summary.get('vulnerability_count', 0)} vulnerabilities."
        )
        for finding in target.get("top_findings", []):
            dep = finding.get("dependency", {})
            vuln = finding.get("vulnerability", {})
            signals = finding.get("exploit_signals", [])
            lines.append(
                f"- {vuln.get('vulnerability_id')} matched {dep.get('ecosystem')} {dep.get('name')} {dep.get('version') or 'unknown'} "
                f"with score {finding.get('score')}. Exploitability is not proven by passive OSINT."
            )
            if signals:
                for signal in signals:
                    lines.append(f"  Suggested exploit lead: {signal.get('source')} - {signal.get('reference')}")
            else:
                lines.append("  Suggested exploit lead: none found.")
    return "\n".join(lines)


def _local_fallback_target_summary(target_report: dict[str, Any], warning: str | None = None) -> str:
    lines = []
    if warning:
        lines.append(warning)
        lines.append("")
    target = target_report.get("target", {})
    summary = target_report.get("summary", {})
    lines.append(
        f"Target: {target.get('name')} ({target.get('url')}). "
        f"Found {summary.get('dependency_count', 0)} dependencies, "
        f"{summary.get('vulnerability_count', 0)} vulnerability matches, and "
        f"{summary.get('finding_count', 0)} ranked findings."
    )
    for finding in target_report.get("findings", [])[:10]:
        dep = finding.get("dependency", {})
        vuln = finding.get("vulnerability", {})
        signals = finding.get("exploit_signals", [])
        lines.append("")
        lines.append(
            f"- {vuln.get('vulnerability_id')} matched {dep.get('ecosystem')} {dep.get('name')} {dep.get('version') or 'unknown'} "
            f"with score {finding.get('score')}. Exploitability is not proven by passive OSINT."
        )
        if signals:
            for signal in signals:
                lines.append(f"  Suggested exploit lead: {signal.get('source')} - {signal.get('reference')}")
        else:
            lines.append("  Suggested exploit lead: none found.")
    return "\n".join(lines)


def _looks_readable(text: str) -> bool:
    if len(text) < 40:
        return False
    printable = sum(1 for char in text if char.isprintable() or char.isspace())
    if printable / max(len(text), 1) < 0.95:
        return False
    common_words = ("website", "dependencies", "vulnerabilities", "exploit", "target", "found")
    if sum(1 for word in common_words if word in text.lower()) < 2:
        return False
    return not text.count("<unk>") > 3


def _clean_text(text: str) -> str:
    replacements = {
        "â€™": "'",
        "â€˜": "'",
        "â€œ": '"',
        "â€": '"',
        "â€“": "-",
        "â€”": "-",
        "â€‘": "-",
        "â€¯": " ",
        "â€¦": "...",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    text = unicodedata.normalize("NFKD", text)
    return text.encode("ascii", errors="ignore").decode("ascii")
