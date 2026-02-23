#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.core.logging  –  Application logging
=============================================================================
Centralised loggers for activity and error recording.

Two log files under AppPaths:
  * NTFSecur.log   – general activity  (DEBUG and above)
  * error.log      – warnings and errors only

Import anywhere::

    from ntfsecur.core.logging import log_info, log_debug, log_warn, log_error
=============================================================================
"""

from __future__ import annotations

import logging as _logging
import traceback as _traceback
from typing import Optional

__all__ = ["log_info", "log_debug", "log_warn", "log_error", "app_log", "error_log"]

# ---------------------------------------------------------------------------
#  Formatter
# ---------------------------------------------------------------------------
_FMT = _logging.Formatter(
    "%(asctime)s  [%(levelname)-8s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def _setup() -> tuple[_logging.Logger, _logging.Logger]:
    """Initialise and return (app_log, error_log)."""
    # Lazy import to avoid circular dependencies at module-load time
    from ntfsecur.core.paths import AppPaths  # noqa: PLC0415

    act = _logging.getLogger("ntfsecur")
    act.setLevel(_logging.DEBUG)
    if not act.handlers:
        fh = _logging.FileHandler(AppPaths.LOG, encoding="utf-8")
        fh.setFormatter(_FMT)
        act.addHandler(fh)

    err = _logging.getLogger("ntfsecur.error")
    err.setLevel(_logging.WARNING)
    if not err.handlers:
        eh = _logging.FileHandler(AppPaths.ERROR_LOG, encoding="utf-8")
        eh.setFormatter(_FMT)
        err.addHandler(eh)

    return act, err


try:
    app_log, error_log = _setup()
except Exception:
    # Fallback to null loggers if paths are unavailable (e.g. during tests)
    app_log   = _logging.getLogger("ntfsecur")
    error_log = _logging.getLogger("ntfsecur.error")


# ---------------------------------------------------------------------------
#  Public helpers
# ---------------------------------------------------------------------------

def log_info(msg: str) -> None:
    """Log an informational message."""
    app_log.info(msg)


def log_debug(msg: str) -> None:
    """Log a debug message."""
    app_log.debug(msg)


def log_warn(msg: str) -> None:
    """Log a warning (written to both loggers)."""
    app_log.warning(msg)
    error_log.warning(msg)


def log_error(msg: str, exc: Optional[Exception] = None) -> None:
    """
    Log an error message.

    Parameters
    ----------
    msg : Human-readable description of the error.
    exc : Optional exception instance; when provided its traceback is included
          in error.log for full post-mortem analysis.
    """
    app_log.error(msg)
    if exc is not None:
        error_log.error(f"{msg}\n{_traceback.format_exc()}")
    else:
        error_log.error(msg)
