from __future__ import annotations

import json
import os
import unicodedata
from pathlib import Path
from typing import Any

from .http import HttpClient, HttpError
from .reporting.writers import _safe_filename

# The AI summary talks to any OpenAI-compatible chat-completions endpoint. The
# default is NVIDIA NIM, which -- unlike OpenCode Zen -- serves its models to a
# plain API key. OPENCODE_* env names are kept for backwards compatibility with
# existing deployments; they are provider-neutral in everything but the name.
#
# Do not go back to OpenCode Zen: its entire "-free" tier is gated to the
# interactive OpenCode CLI and answers a server request with
#   HTTP 400 {"type":"MissingSessionID","message":"OpenCode's free tier can only
#   be used in OpenCode"}
# (verified 2026-09-14 for every free id), while its paid ids need a billed
# workspace and laguna-s-2.1-free was deleted outright.
OPENCODE_DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
OPENCODE_DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"

_OPENCODE_SYSTEM = (
    "You explain passive OSINT dependency intelligence reports in simple human language. "
    "Do not claim exploitability unless the report proves it. Say exploit signals are suggested leads."
)


def _opencode_chat(prompt: str, api_key: str, model: str, timeout: int) -> str:
    """Call an OpenAI-compatible chat-completions endpoint and return the message text.

    Two payload keys matter for the default NVIDIA Nemotron model and are harmless
    elsewhere:

    * ``stream`` is false because HttpClient reads whole responses, not SSE deltas.
    * ``enable_thinking`` is false because Nemotron is reasoning-capable and ships
      with thinking ON. Left on, reasoning tokens are billed against max_tokens and
      the answer comes back truncated into ``reasoning_content``, leaving ``content``
      short enough that _looks_readable rejects it -- an AI failure that looks
      exactly like a working fallback.

    max_tokens is deliberately small: a plain-language summary of one report measured
    ~115 output tokens, so 600 is headroom, not a budget, and it caps how long a
    runaway response can block a scan.
    """
    client = HttpClient(timeout=timeout)
    base_url = os.environ.get("OPENCODE_BASE_URL", OPENCODE_DEFAULT_BASE_URL)
    response = client.post_json(
        base_url,
        {
            "model": model,
            "messages": [
                {"role": "system", "content": _OPENCODE_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "top_p": 0.95,
            "max_tokens": 600,
            "stream": False,
            "chat_template_kwargs": {"enable_thinking": False},
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
