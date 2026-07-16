from __future__ import annotations

import importlib
import sys


def test_main_module_importable() -> None:
    mod = importlib.import_module("osintdepintel.__main__")
    assert hasattr(mod, "__name__")


def test_main_module_import_has_main_function() -> None:
    from osintdepintel.__main__ import main as main_ref
    from osintdepintel.cli import main

    assert main_ref is main


def test_main_module_executes_via_subprocess() -> None:
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "osintdepintel", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "usage" in result.stdout.lower()
