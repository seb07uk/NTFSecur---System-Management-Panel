#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.core.settings  –  Application settings (JSON persistence)
=============================================================================
Priorities:
  1. FACTORY_SETTINGS  – built-in defaults
  2. settings.json     – saved user preferences (overrides factory)

Usage::

    from ntfsecur.core.settings import get_settings

    cfg = get_settings()
    cfg.get("theme", "dark")
    cfg.set("theme", "light")
    cfg.save()
    cfg.reset_to_factory()
=============================================================================
"""

from __future__ import annotations

import json
import os
from typing import Any

__all__ = ["Settings", "get_settings", "FACTORY_SETTINGS"]

# ---------------------------------------------------------------------------
#  Metadata (populated at import by the package __init__)
# ---------------------------------------------------------------------------
_VERSION   = "2.1.0"
_AUTHOR    = "Sebastian Januchowski"
_PRODUCT   = "PolSoft System Management Panel"

FACTORY_SETTINGS: dict[str, Any] = {
    # Interface
    "theme":              "dark",
    "last_module":        "ntfsecur",
    "window_geometry":    "1280x780",
    "window_locked":      False,
    "window_topmost":     False,
    # Behaviour
    "log_level":          "INFO",
    "scan_interval_sec":  0,
    "confirm_dangerous":  True,
    "show_watermark":     True,
    # Drives
    "drives_default_tab": "overview",
    "bench_size_mb":      256,
    # Read-only metadata
    "version":            _VERSION,
    "build_date":         "2026-02-21",
    "author":             _AUTHOR,
    "product":            _PRODUCT,
}


class Settings:
    """
    Read/write application settings persisted to ``settings.json``.

    The class merges factory defaults with stored values so that new keys
    introduced in later versions always have a safe default.
    """

    def __init__(self) -> None:
        from ntfsecur.core.paths import AppPaths
        self._path: str = AppPaths.SETTINGS
        self._data: dict[str, Any] = dict(FACTORY_SETTINGS)
        self._load()

    # ------------------------------------------------------------------
    #  Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        try:
            from ntfsecur.core.logging import log_info, log_error
        except ImportError:
            log_info = log_error = lambda *a, **k: None  # type: ignore

        try:
            if os.path.exists(self._path):
                with open(self._path, "r", encoding="utf-8") as f:
                    stored: dict = json.load(f)
                # Merge – stored values override factory defaults
                for key, value in stored.items():
                    self._data[key] = value
                log_info(f"Settings loaded from {self._path}")
            else:
                # First run – persist factory defaults
                self.save()
                log_info("First run – factory settings written to disk.")
        except Exception as exc:
            log_error(f"Failed to load settings: {exc}", exc)

    # ------------------------------------------------------------------
    #  Public API
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Persist the current settings to ``settings.json``."""
        try:
            from ntfsecur.core.logging import log_debug, log_error
        except ImportError:
            log_debug = log_error = lambda *a, **k: None  # type: ignore

        try:
            self._data["version"] = _VERSION
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=4, ensure_ascii=False)
            log_debug(f"Settings saved to {self._path}")
        except Exception as exc:
            log_error(f"Failed to save settings: {exc}", exc)

    def reset_to_factory(self) -> None:
        """Restore factory defaults and save to disk."""
        try:
            from ntfsecur.core.logging import log_info
        except ImportError:
            log_info = lambda *a, **k: None  # type: ignore

        self._data = dict(FACTORY_SETTINGS)
        self.save()
        log_info("Settings reset to factory defaults.")

    def get(self, key: str, default: Any = None) -> Any:
        """Return the value for *key*, or *default* if not present."""
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set *key* to *value* (in-memory; call :meth:`save` to persist)."""
        self._data[key] = value

    def as_dict(self) -> dict[str, Any]:
        """Return a shallow copy of the settings dictionary."""
        return dict(self._data)

    # Allow dict-style access for backward compatibility
    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value


# ---------------------------------------------------------------------------
#  Singleton
# ---------------------------------------------------------------------------
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the application-wide :class:`Settings` singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
