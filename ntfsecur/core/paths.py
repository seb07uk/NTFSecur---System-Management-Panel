#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.core.paths  –  Centralised application paths
=============================================================================
Single source of truth for every file and directory the application uses.

Layout::

    %USERPROFILE%\\.polsoft\\software\\NTFSecur\\   (Windows)
    ~/.polsoft/software/NTFSecur/                    (Linux / macOS)
        settings.json       – user preferences / theme
        NTFSecur.log        – general activity log
        error.log           – error / exception log
        usb_history.db      – SQLite USB history database
        report/             – generated HTML reports
=============================================================================
"""

from __future__ import annotations

import os
import sys

__all__ = ["AppPaths"]


class AppPaths:
    """Filesystem paths used throughout the application."""

    if sys.platform == "win32":
        _BASE: str = os.path.join(
            os.environ.get("USERPROFILE", os.path.expanduser("~")),
            ".polsoft", "software", "NTFSecur",
        )
    else:
        _BASE: str = os.path.join(
            os.path.expanduser("~"),
            ".polsoft", "software", "NTFSecur",
        )

    BASE:         str = _BASE
    SETTINGS:     str = os.path.join(_BASE, "settings.json")
    LOG:          str = os.path.join(_BASE, "NTFSecur.log")
    ERROR_LOG:    str = os.path.join(_BASE, "error.log")
    DB:           str = os.path.join(_BASE, "usb_history.db")
    DISKPART_TMP: str = os.path.join(_BASE, "diskpart_tmp.txt")
    REPORT_DIR:   str = os.path.join(_BASE, "report")
    BACKUP_DIR:   str = r"C:\.polsoft\backup\windows"

    @classmethod
    def ensure_dirs(cls) -> None:
        """Create all required directories if they do not already exist."""
        for directory in (cls.BASE, cls.REPORT_DIR, cls.BACKUP_DIR):
            os.makedirs(directory, exist_ok=True)

    @classmethod
    def report_path(cls, filename: str) -> str:
        """Return the full path for a report file inside the report sub-folder."""
        return os.path.join(cls.REPORT_DIR, filename)


# Ensure directories exist at import time
AppPaths.ensure_dirs()
