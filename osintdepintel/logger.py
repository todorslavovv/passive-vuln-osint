from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            payload["exception"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, default=str)


def setup_logger(
    name: str = "osintdepintel",
    level: int = logging.INFO,
    log_file: str | Path | None = None,
    json_output: bool = False,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 3,
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()

    if json_output:
        fmt: logging.Formatter = JSONFormatter()
    else:
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    handler: logging.Handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(str(log_path), maxBytes=max_bytes, backupCount=backup_count)
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(fmt)
    logger.addHandler(handler)

    if not json_output and not log_file:
        handler.setLevel(level)

    return logger


_logger_instance: logging.Logger | None = None


def get_logger(name: str = "osintdepintel") -> logging.Logger:
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = setup_logger(name)
    return _logger_instance


def configure_logging(
    *,
    level: int = logging.INFO,
    log_file: str | Path | None = None,
    json_output: bool = False,
) -> None:
    global _logger_instance
    _logger_instance = setup_logger(level=level, log_file=log_file, json_output=json_output)


logger = get_logger()
