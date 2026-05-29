from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path


LOGS_DIR = Path("logs")
LOGGER_NAME = "GlitchReconAI"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_LOGGER: logging.Logger | None = None


def log_info(message: str) -> None:
    """
    Write an informational message to the daily log file.
    """
    _get_logger().info(_normalize_message(message))


def log_warning(message: str) -> None:
    """
    Write a warning message to the daily log file.
    """
    _get_logger().warning(_normalize_message(message))


def log_error(message: str) -> None:
    """
    Write an error message to the daily log file.
    """
    _get_logger().error(_normalize_message(message))


def _get_logger() -> logging.Logger:
    global _LOGGER

    if _LOGGER is None:
        _LOGGER = logging.getLogger(LOGGER_NAME)
        _LOGGER.setLevel(logging.INFO)
        _LOGGER.propagate = False

    _ensure_daily_file_handler(_LOGGER)
    return _LOGGER


def _ensure_daily_file_handler(logger: logging.Logger) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = _daily_log_path()

    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            handler_path = Path(handler.baseFilename)
            if handler_path == log_path.resolve():
                return

    for handler in list(logger.handlers):
        if isinstance(handler, logging.FileHandler):
            logger.removeHandler(handler)
            handler.close()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(file_handler)


def _daily_log_path() -> Path:
    today = datetime.now().strftime("%Y-%m-%d")
    return LOGS_DIR / f"{today}.log"


def _normalize_message(message: str) -> str:
    if isinstance(message, str):
        return message.strip()

    return str(message)
