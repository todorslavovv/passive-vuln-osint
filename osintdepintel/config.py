from __future__ import annotations

import argparse
import json
import os
from collections.abc import Iterable
from pathlib import Path

from .models import TargetConfig


def load_targets(path: Path) -> list[TargetConfig]:
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    targets = raw.get("targets", raw if isinstance(raw, list) else [])
    return [TargetConfig.from_dict(item) for item in targets]


def select_targets(targets: Iterable[TargetConfig], name: str | None, all_targets: bool) -> list[TargetConfig]:
    available = list(targets)
    if all_targets:
        return available
    if not name:
        raise ValueError("Provide --target NAME or --all.")
    selected = [target for target in available if target.name == name]
    if not selected:
        known = ", ".join(target.name for target in available)
        raise ValueError(f"Unknown target {name!r}. Known targets: {known}")
    return selected


class AppConfig:
    def __init__(
        self,
        config_path: str = "examples/targets.json",
        target: str | None = None,
        all_targets: bool = False,
        offline: bool = False,
        fixtures: str | None = None,
        output_dir: str = "reports",
        no_graph: bool = False,
        max_enrich_dependencies: int | None = None,
        skip_nvd: bool = False,
        nvidia_summary: bool = False,
        nvidia_model: str = "nvidia/nemotron-3-ultra-550b-a55b",
        log_file: str | None = None,
        log_json: bool = False,
        log_level: str = "INFO",
        rate_limit_rps: float = 4.0,
    ) -> None:
        self.config_path = config_path
        self.target = target
        self.all_targets = all_targets
        self.offline = offline
        self.fixtures = fixtures
        self.output_dir = output_dir
        self.no_graph = no_graph
        self.max_enrich_dependencies = max_enrich_dependencies
        self.skip_nvd = skip_nvd
        self.nvidia_summary = nvidia_summary
        self.nvidia_model = nvidia_model
        self.log_file = log_file or os.environ.get("OSINTDEPINTEL_LOG_FILE")
        self.log_json = log_json or os.environ.get("OSINTDEPINTEL_LOG_JSON", "").lower() in ("1", "true", "yes")
        self.log_level = log_level or os.environ.get("OSINTDEPINTEL_LOG_LEVEL", "INFO")
        self.rate_limit_rps = rate_limit_rps

    @classmethod
    def from_cli_args(cls, args: argparse.Namespace) -> AppConfig:
        return cls(
            config_path=args.config,
            target=args.target,
            all_targets=args.all,
            offline=args.offline,
            fixtures=args.fixtures,
            output_dir=args.output_dir,
            no_graph=args.no_graph,
            max_enrich_dependencies=args.max_enrich_dependencies,
            skip_nvd=args.skip_nvd,
            nvidia_summary=args.nvidia_summary,
            nvidia_model=args.nvidia_model,
            log_file=getattr(args, "log_file", None),
            log_json=getattr(args, "log_json", False),
            log_level=getattr(args, "log_level", "INFO"),
            rate_limit_rps=float(getattr(args, "rate_limit", 4.0)),
        )
