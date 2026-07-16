from __future__ import annotations

import json
import logging
import sys
import tempfile
from pathlib import Path

from osintdepintel.logger import JSONFormatter, configure_logging, get_logger, logger, setup_logger


def test_setup_logger_returns_logger() -> None:
    log = setup_logger("test_default")
    assert isinstance(log, logging.Logger)
    assert log.name == "test_default"
    assert log.level == logging.INFO


def test_get_logger_singleton() -> None:
    log1 = get_logger("test_singleton")
    log2 = get_logger("test_singleton")
    assert log1 is log2


def test_get_logger_default_name() -> None:
    log = get_logger()
    assert log.name == "osintdepintel"


def test_logger_module_level() -> None:
    assert isinstance(logger, logging.Logger)


def test_json_formatter_basic() -> None:
    fmt = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello world",
        args=(),
        exc_info=None,
    )
    output = fmt.format(record)
    parsed = json.loads(output)
    assert parsed["level"] == "INFO"
    assert parsed["message"] == "hello world"
    assert parsed["logger"] == "test"
    assert "timestamp" in parsed
    assert "exception" not in parsed


def test_json_formatter_with_exception() -> None:
    fmt = JSONFormatter()
    try:
        raise ValueError("test error")
    except ValueError:
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="failed",
            args=(),
            exc_info=sys.exc_info(),
        )
    output = fmt.format(record)
    parsed = json.loads(output)
    assert parsed["level"] == "ERROR"
    assert "exception" in parsed
    assert "ValueError" in parsed["exception"]


def test_json_formatter_with_extra_fields() -> None:
    fmt = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="with extra",
        args=(),
        exc_info=None,
    )
    record.extra_fields = {"target": "juice-shop", "confidence": 0.85}
    output = fmt.format(record)
    parsed = json.loads(output)
    assert parsed["target"] == "juice-shop"
    assert parsed["confidence"] == 0.85


def test_configure_logging_json_output() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        log_file = Path(tmp) / "test.json"
        configure_logging(level=logging.DEBUG, log_file=str(log_file), json_output=True)
        log = get_logger("test_json_output")
        log.info('{"json": "test"}')
        log.handlers.clear()
        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        parsed = json.loads(content.strip().split("\n")[0])
        assert "level" in parsed
        assert "message" in parsed


def test_configure_logging_text_file() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        log_file = Path(tmp) / "test.log"
        configure_logging(level=logging.INFO, log_file=str(log_file), json_output=False)
        log = get_logger("test_text_file")
        log.info("file log test")
        log.handlers.clear()
        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "file log test" in content


def test_configure_logging_stdout() -> None:
    configure_logging(level=logging.INFO, log_file=None, json_output=False)
    log = get_logger("test_stdout")
    assert log.level == logging.INFO


def test_setup_logger_file_handler_rotation_params() -> None:
    from logging.handlers import RotatingFileHandler

    with tempfile.TemporaryDirectory() as tmp:
        log_file = Path(tmp) / "rotate.log"
        log = setup_logger("test_rotation", level=logging.INFO, log_file=str(log_file), max_bytes=1024, backup_count=2)
        for handler in log.handlers:
            if isinstance(handler, RotatingFileHandler):
                assert handler.maxBytes == 1024
                assert handler.backupCount == 2
