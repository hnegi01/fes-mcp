"""Logging setup shared by both services: stderr plus a rotating file.

stderr remains the primary stream (container-native, stdio-transport safe);
the file copy in the log directory is what local monitoring tails. Each
service writes its own file (fes-mcp.log / fes-auth.log), rotated at 5 MB
with three backups. Override the directory with FES_MCP_LOG_DIR.
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .settings import REPO_ROOT

_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def setup_logging(level: str, service: str) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level, logging.INFO))

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(logging.Formatter(_FORMAT))
    root.addHandler(stream)

    log_dir = Path(os.getenv("FES_MCP_LOG_DIR") or REPO_ROOT / "logs")
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / f"{service}.log", maxBytes=5 * 1024 * 1024, backupCount=3
        )
        file_handler.setFormatter(logging.Formatter(_FORMAT))
        root.addHandler(file_handler)
    except OSError as exc:  # unwritable dir must never stop the server
        root.warning("file logging disabled (%s): %s", log_dir, exc)
