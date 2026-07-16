from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from osintdepintel.cli import _handle_signal, build_parser, main


@pytest.fixture(autouse=True)
def _reset_shutdown_flag() -> None:
    import osintdepintel.cli as cli_mod

    cli_mod._shutdown_requested = False


_BUILDER_RESULT: dict = {
    "reports": [],
    "aggregate": {
        "aggregate": {"target_count": 0, "dependency_count": 0, "vulnerability_count": 0, "finding_count": 0}
    },
    "paths": {},
}
_BUILDER_RESULT_PATHS: dict = {
    "reports": [],
    "aggregate": {
        "aggregate": {"target_count": 1, "dependency_count": 2, "vulnerability_count": 0, "finding_count": 0}
    },
    "paths": {"test": {"json": "/tmp/report.json"}},
}


class BuildParserTests:
    def test_help_output(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--help"])
        assert exc.value.code == 0

    def test_version_output(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0

    def test_missing_target_or_all_exits_nonzero(self) -> None:
        with patch(
            "osintdepintel.cli.sys.argv",
            ["osintdepintel", "--config", str(Path(__file__).parent.parent / "examples" / "targets.json")],
        ):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 2

    def test_nonexistent_config_file(self) -> None:
        with patch(
            "osintdepintel.cli.sys.argv", ["osintdepintel", "--config", "/nonexistent/path.json", "--target", "test"]
        ):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 2

    def test_valid_targets_invokes_pipeline(self) -> None:
        mock_pipeline = MagicMock()
        mock_pipeline.process_targets.return_value = {
            "reports": [],
            "aggregate": {
                "aggregate": {"target_count": 0, "dependency_count": 0, "vulnerability_count": 0, "finding_count": 0}
            },
            "paths": {},
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            with (
                patch("osintdepintel.cli.Pipeline", return_value=mock_pipeline),
                patch(
                    "osintdepintel.cli.sys.argv",
                    [
                        "osintdepintel",
                        "--config",
                        str(Path(__file__).parent.parent / "examples" / "targets.json"),
                        "--all",
                        "--output-dir",
                        str(out_dir),
                    ],
                ),
            ):
                ret = main()
            assert ret == 0
            mock_pipeline.process_targets.assert_called_once()

    def test_offline_flag_forwarded(self) -> None:
        mock_pipeline = MagicMock()
        mock_pipeline.process_targets.return_value = {
            "reports": [],
            "aggregate": {
                "aggregate": {"target_count": 0, "dependency_count": 0, "vulnerability_count": 0, "finding_count": 0}
            },
            "paths": {},
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            with (
                patch("osintdepintel.cli.Pipeline", return_value=mock_pipeline) as mock_pipeline_cls,
                patch(
                    "osintdepintel.cli.sys.argv",
                    [
                        "osintdepintel",
                        "--config",
                        str(Path(__file__).parent.parent / "examples" / "targets.json"),
                        "--all",
                        "--output-dir",
                        str(out_dir),
                        "--offline",
                    ],
                ),
            ):
                ret = main()
            assert ret == 0
            _call_kwargs = mock_pipeline_cls.call_args.kwargs
            assert _call_kwargs.get("offline") is True

    def test_no_enrich_flag_skips_nvd(self) -> None:
        mock_pipeline = MagicMock()
        mock_pipeline.process_targets.return_value = {
            "reports": [],
            "aggregate": {
                "aggregate": {"target_count": 0, "dependency_count": 0, "vulnerability_count": 0, "finding_count": 0}
            },
            "paths": {},
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            with (
                patch("osintdepintel.cli.Pipeline", return_value=mock_pipeline) as mock_pipeline_cls,
                patch(
                    "osintdepintel.cli.sys.argv",
                    [
                        "osintdepintel",
                        "--config",
                        str(Path(__file__).parent.parent / "examples" / "targets.json"),
                        "--all",
                        "--output-dir",
                        str(out_dir),
                        "--skip-nvd",
                    ],
                ),
            ):
                ret = main()
            assert ret == 0
            _call_kwargs = mock_pipeline_cls.call_args.kwargs
            assert _call_kwargs.get("enable_nvd") is False

    def test_signal_handler_sets_shutdown_flag(self) -> None:
        import osintdepintel.cli as cli_mod

        cli_mod._shutdown_requested = False
        _handle_signal(signal.SIGINT, None)
        assert cli_mod._shutdown_requested is True

    def test_double_signal_force_exits(self) -> None:
        import osintdepintel.cli as cli_mod

        cli_mod._shutdown_requested = True
        with pytest.raises(SystemExit) as exc:
            _handle_signal(signal.SIGINT, None)
        assert exc.value.code == 1

    def test_pipeline_failure_exits_nonzero(self) -> None:
        mock_pipeline = MagicMock()
        mock_pipeline.process_targets.side_effect = RuntimeError("pipeline failure")
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            with (
                patch("osintdepintel.cli.Pipeline", return_value=mock_pipeline),
                patch(
                    "osintdepintel.cli.sys.argv",
                    [
                        "osintdepintel",
                        "--config",
                        str(Path(__file__).parent.parent / "examples" / "targets.json"),
                        "--all",
                        "--output-dir",
                        str(out_dir),
                    ],
                ),
            ):
                with pytest.raises(SystemExit) as exc:
                    main()
                assert exc.value.code == 2

    def test_nvidia_summary_without_api_key_skips(self) -> None:
        mock_pipeline = MagicMock()
        mock_pipeline.process_targets.return_value = dict(_BUILDER_RESULT)
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("osintdepintel.cli.Pipeline", return_value=mock_pipeline),
            patch(
                "osintdepintel.cli.sys.argv",
                [
                    "osintdepintel",
                    "--config",
                    str(Path(__file__).parent.parent / "examples" / "targets.json"),
                    "--all",
                    "--nvidia-summary",
                ],
            ),
        ):
            ret = main()
            assert ret == 0

    def test_output_paths_printed(self) -> None:
        mock_pipeline = MagicMock()
        mock_pipeline.process_targets.return_value = dict(_BUILDER_RESULT_PATHS)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            with (
                patch("osintdepintel.cli.Pipeline", return_value=mock_pipeline),
                patch(
                    "osintdepintel.cli.sys.argv",
                    [
                        "osintdepintel",
                        "--config",
                        str(Path(__file__).parent.parent / "examples" / "targets.json"),
                        "--all",
                        "--output-dir",
                        str(out_dir),
                    ],
                ),
            ):
                ret = main()
            assert ret == 0

    def test_args_log_level_rate_limit_fixtures_no_graph_forwarded(self) -> None:
        mock_pipeline = MagicMock()
        mock_pipeline.process_targets.return_value = dict(_BUILDER_RESULT)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            with (
                patch("osintdepintel.cli.Pipeline", return_value=mock_pipeline) as mock_pipeline_cls,
                patch(
                    "osintdepintel.cli.sys.argv",
                    [
                        "osintdepintel",
                        "--config",
                        str(Path(__file__).parent.parent / "examples" / "targets.json"),
                        "--all",
                        "--output-dir",
                        str(out_dir),
                        "--log-level",
                        "DEBUG",
                        "--rate-limit",
                        "2.0",
                        "--fixtures",
                        "/tmp/fixtures.json",
                        "--no-graph",
                    ],
                ),
            ):
                ret = main()
            assert ret == 0
            kwargs = mock_pipeline_cls.call_args.kwargs
            assert kwargs.get("rate_limit_rps") == 2.0


class CliEntryPointTests:
    def test_help_exits_zero(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "osintdepintel", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "usage" in result.stdout.lower()

    def test_version_outputs_version(self) -> None:
        from osintdepintel import __version__

        result = subprocess.run(
            [sys.executable, "-m", "osintdepintel", "--version"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert __version__ in result.stdout

    def test_missing_target_exits_nonzero(self) -> None:
        config_path = Path(__file__).parent.parent / "examples" / "targets.json"
        result = subprocess.run(
            [sys.executable, "-m", "osintdepintel", "--config", str(config_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0

    def test_nonexistent_config_errors(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "osintdepintel", "--config", "/nonexistent/path.json", "--target", "test"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "error" in result.stderr.lower()
