from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .ai_summary import OPENCODE_DEFAULT_MODEL, write_nvidia_summary, write_opencode_summary
from .config import AppConfig, load_targets, select_targets
from .logger import configure_logging, logger
from .pipeline import Pipeline

_shutdown_requested = False

# Exit code returned when --fail-on trips the severity gate. Kept distinct from
# argparse's usage error (2) so CI can tell "risky finding" apart from "bad invocation".
SEVERITY_GATE_EXIT_CODE = 3

_SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _gate_breaches(reports: list[dict[str, Any]], threshold: str) -> list[dict[str, str]]:
    """Return findings whose vulnerability severity meets or exceeds the threshold."""
    threshold_rank = _SEVERITY_RANK[threshold.upper()]
    breaches: list[dict[str, str]] = []
    for report in reports:
        target_name = report.get("target", {}).get("name", "unknown")
        for finding in report.get("findings", []):
            vuln = finding.get("vulnerability", {})
            severity = str(vuln.get("severity", "UNKNOWN")).upper()
            if _SEVERITY_RANK.get(severity, 0) >= threshold_rank:
                breaches.append(
                    {
                        "target": target_name,
                        "severity": severity,
                        "vulnerability_id": str(vuln.get("vulnerability_id", "UNKNOWN")),
                        "package": str(vuln.get("package_name", "")),
                    }
                )
    return breaches


def _handle_signal(signum: int, _frame: Any) -> None:
    global _shutdown_requested
    if _shutdown_requested:
        sys.stderr.write("\nForced exit.\n")
        sys.exit(1)
    _shutdown_requested = True
    sig_name = signal.Signals(signum).name
    sys.stderr.write(f"\n{sig_name} received — shutting down gracefully...\n")
    logger.warning("%s received, initiating graceful shutdown", sig_name)


def _register_signals() -> None:
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _handle_signal)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osintdepintel",
        description="Passive OSINT supply-chain dependency vulnerability intelligence CLI.",
    )
    parser.add_argument("--config", default="examples/targets.json", help="Path to target configuration JSON.")
    parser.add_argument("--target", help="Target name to process.")
    parser.add_argument("--all", action="store_true", help="Process every target from the configuration.")
    parser.add_argument(
        "--offline", action="store_true", help="Use local fixtures and skip live passive HTTP collection."
    )
    parser.add_argument("--fixtures", help="Optional offline intelligence fixture JSON.")
    parser.add_argument("--output-dir", default="reports", help="Directory for per-target and aggregate reports.")
    parser.add_argument("--no-graph", action="store_true", help="Do not write DOT graph exports.")
    parser.add_argument(
        "--max-enrich-dependencies",
        type=int,
        help="Cap advisory enrichment to the first N discovered dependencies for practical live runs.",
    )
    parser.add_argument(
        "--skip-nvd",
        action="store_true",
        help="Skip live NVD enrichment while keeping other online passive collection enabled.",
    )
    parser.add_argument(
        "--nvidia-summary",
        action="store_true",
        help="Send the aggregate report to NVIDIA NIM for a simple human explanation.",
    )
    parser.add_argument(
        "--nvidia-model", default="nvidia/nemotron-3-ultra-550b-a55b", help="NVIDIA model name for --nvidia-summary."
    )
    parser.add_argument(
        "--opencode-summary",
        action="store_true",
        help="Send the aggregate report to OpenCode Zen (OpenAI-compatible) for a plain-language summary. Uses OPENCODE_API_KEY.",
    )
    parser.add_argument(
        "--opencode-model",
        default=OPENCODE_DEFAULT_MODEL,
        help=f"OpenCode Zen model for --opencode-summary (default: {OPENCODE_DEFAULT_MODEL}).",
    )
    parser.add_argument("--log-file", help="Path to log file (default: stderr only).")
    parser.add_argument("--log-json", action="store_true", help="Output logs in JSON format.")
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: OSINTDEPINTEL_LOG_LEVEL env or INFO).",
    )
    parser.add_argument("--rate-limit", type=float, default=4.0, help="Maximum HTTP requests per second.")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help=(
            "Exit with a non-zero status (3) if any finding has a vulnerability at or above this "
            "severity. Use in CI/CD to block releases on risky dependencies."
        ),
    )
    parser.add_argument("--server", action="store_true", help="Start the web dashboard server.")
    parser.add_argument("--host", default="127.0.0.1", help="Host address for the server.")
    parser.add_argument("--port", type=int, default=8000, help="Port for the server.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    _register_signals()
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "server", False):
        from .server.main import run_server

        run_server(args.host, args.port, args.config)
        return 0

    app_config = AppConfig.from_cli_args(args)

    configure_logging(
        level=getattr(logging, app_config.log_level.upper(), logging.INFO),
        log_file=app_config.log_file,
        json_output=app_config.log_json,
    )

    logger.info("Starting OSINT dependency vulnerability intelligence run")
    logger.info(
        "Config: targets=%s offline=%s output=%s", app_config.config_path, app_config.offline, app_config.output_dir
    )

    config_path = Path(app_config.config_path)
    fixture_path = Path(app_config.fixtures) if app_config.fixtures else None

    try:
        targets = select_targets(load_targets(config_path), app_config.target, app_config.all_targets)
    except (ValueError, FileNotFoundError) as exc:
        logger.error("Configuration error: %s", exc)
        parser.exit(2, f"error: {exc}\n")

    if _shutdown_requested:
        parser.exit(1, "Shutdown before processing started.\n")

    try:
        result = Pipeline(
            offline=app_config.offline,
            fixture_path=fixture_path,
            max_enrichment_dependencies=app_config.max_enrich_dependencies,
            enable_nvd=not app_config.skip_nvd,
            rate_limit_rps=app_config.rate_limit_rps,
        ).process_targets(
            targets,
            output_dir=Path(app_config.output_dir),
            include_graph=not app_config.no_graph,
        )
    except Exception as exc:
        logger.error("Execution failed: %s", exc)
        parser.exit(2, f"error: {exc}\n")

    if _shutdown_requested:
        logger.warning("Run completed after shutdown signal — results may be partial")

    if app_config.nvidia_summary:
        api_key = os.environ.get("NVIDIA_API_KEY")
        if not api_key:
            logger.warning("--nvidia-summary requires NVIDIA_API_KEY in the environment — skipping")
        else:
            summary_path = write_nvidia_summary(
                result["aggregate"], Path(app_config.output_dir), api_key, app_config.nvidia_model
            )
            result["paths"]["nvidia_summary"] = {"text": str(summary_path)}
            logger.info("NVIDIA summary written to %s", summary_path)

    if getattr(args, "opencode_summary", False):
        api_key = os.environ.get("OPENCODE_API_KEY")
        if not api_key:
            logger.warning("--opencode-summary requires OPENCODE_API_KEY in the environment — skipping")
        else:
            summary_path = write_opencode_summary(
                result["aggregate"], Path(app_config.output_dir), api_key, args.opencode_model
            )
            result["paths"]["opencode_summary"] = {"text": str(summary_path)}
            logger.info("OpenCode summary written to %s", summary_path)

    aggregate = result["aggregate"]["aggregate"]
    print("OSINT dependency intelligence run complete")
    print(f"Targets processed: {aggregate['target_count']}")
    print(f"Dependencies: {aggregate['dependency_count']}")
    print(f"Vulnerabilities: {aggregate['vulnerability_count']}")
    print(f"Findings: {aggregate['finding_count']}")
    print("Outputs:")
    for target_name, paths in result["paths"].items():
        for kind, path in paths.items():
            print(f"- {target_name} {kind}: {path}")

    logger.info(
        "Run complete: %d targets, %d dependencies, %d findings",
        aggregate["target_count"],
        aggregate["dependency_count"],
        aggregate["finding_count"],
    )

    fail_on = getattr(args, "fail_on", None)
    if fail_on:
        breaches = _gate_breaches(result["reports"], fail_on)
        if breaches:
            print(f"\nSeverity gate: FAILED — {len(breaches)} finding(s) at or above {fail_on.upper()}:")
            for breach in breaches:
                print(
                    f"- [{breach['severity']}] {breach['vulnerability_id']} in {breach['package']} ({breach['target']})"
                )
            logger.error("Severity gate tripped: %d finding(s) at or above %s", len(breaches), fail_on.upper())
            return SEVERITY_GATE_EXIT_CODE
        print(f"\nSeverity gate: PASSED — no findings at or above {fail_on.upper()}.")

    return 0
