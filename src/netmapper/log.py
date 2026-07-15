"""Per-project logging setup writing to ``logs/netmapper.log``."""

from __future__ import annotations

import logging
from pathlib import Path


def get_logger(log_file: Path) -> logging.Logger:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"netmapper.{log_file.parent.parent.name}")
    logger.setLevel(logging.INFO)
    # Avoid duplicate handlers for the same file across repeated calls.
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler) and getattr(
            handler, "baseFilename", None
        ) == str(log_file.resolve()):
            return logger
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    logger.addHandler(handler)
    logger.propagate = False
    return logger
