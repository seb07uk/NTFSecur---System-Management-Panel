#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.core.backup  –  System backup operations
=============================================================================
Provides three independent backup tasks:

  * :func:`backup_file_history`   – uruchamia File History (fhmanagew.exe)
                                    i opcjonalnie otwiera panel konfiguracji
  * :func:`backup_registry`       – eksportuje HKLM i HKCU do plików .reg
  * :func:`backup_bcd`            – eksportuje magazyn BCD przez bcdedit

Każda funkcja zwraca ``(ok: bool, message: str)``.

Katalog docelowy jest pobierany z :attr:`~ntfsecur.core.paths.AppPaths.BACKUP_DIR`
i tworzony automatycznie przed pierwszym zapisem.
=============================================================================
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Tuple

from ntfsecur.core.paths import AppPaths

__all__ = [
    "backup_file_history",
    "backup_file_history_location",
    "backup_registry",
    "backup_bcd",
    "run_all_backups",
]

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _ensure_backup_dir() -> str:
    """Create and return the backup destination directory."""
    d = AppPaths.BACKUP_DIR
    os.makedirs(d, exist_ok=True)
    return d


def _run(
    cmd: list[str],
    timeout: int = 120,
) -> Tuple[bool, str]:
    """
    Execute *cmd* via subprocess and return ``(ok, message)``.

    stdout + stderr are captured and merged into the returned message.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        out = (result.stdout + result.stderr).strip()
        ok  = result.returncode == 0
        return ok, out or ("OK" if ok else f"exit code {result.returncode}")
    except FileNotFoundError as exc:
        return False, f"Command not found: {exc.filename}"
    except subprocess.TimeoutExpired:
        return False, f"Timeout ({timeout}s) – operation may still be running."
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------

def backup_file_history() -> Tuple[bool, str]:
    """
    Uruchamia natychmiastowy backup File History.

    Komenda: ``fhmanagew.exe -backupnow``

    Returns
    -------
    (True, message)  – jeśli fhmanagew zakończył się kodem 0
    (False, message) – w przypadku błędu
    """
    return _run(["fhmanagew.exe", "-backupnow"], timeout=300)


def backup_file_history_location() -> Tuple[bool, str]:
    """
    Otwiera panel konfiguracji lokalizacji File History (tylko UI, nie blokuje).

    Komenda: ``control /name Microsoft.FileHistory``

    Returns
    -------
    (True, "Panel opened")  – zawsze, jeśli control.exe uruchomił się poprawnie
    """
    try:
        subprocess.Popen(
            ["control", "/name", "Microsoft.FileHistory"],
            shell=False,
        )
        return True, "File History configuration panel opened."
    except Exception as exc:
        return False, str(exc)


def backup_registry() -> Tuple[bool, str]:
    """
    Eksportuje HKLM i HKCU do plików .reg w katalogu backupu.

    Pliki wyjściowe:
      * ``<BACKUP_DIR>\\HKLM.reg``
      * ``<BACKUP_DIR>\\HKCU.reg``

    Wymaga uprawnień administratora (HKLM).

    Returns
    -------
    (True, message)   – jeśli oba eksporty zakończyły się sukcesem
    (False, message)  – jeśli którykolwiek eksport się nie powiódł
    """
    d = _ensure_backup_dir()
    results: list[str] = []
    all_ok = True

    for hive, filename in (("HKLM", "HKLM.reg"), ("HKCU", "HKCU.reg")):
        path = os.path.join(d, filename)
        ok, msg = _run(
            ["reg", "export", hive, path, "/y"],
            timeout=180,
        )
        status = "✔" if ok else "✘"
        results.append(f"{status} {hive} → {path}: {msg}")
        if not ok:
            all_ok = False

    return all_ok, "\n".join(results)


def backup_bcd() -> Tuple[bool, str]:
    """
    Eksportuje magazyn BCD (bootloader) przez ``bcdedit /export``.

    Plik wyjściowy: ``<BACKUP_DIR>\\bcd_backup``

    Wymaga uprawnień administratora.

    Returns
    -------
    (True, message)   – eksport zakończony sukcesem
    (False, message)  – błąd
    """
    d    = _ensure_backup_dir()
    path = os.path.join(d, "bcd_backup")
    return _run(["bcdedit", "/export", path], timeout=60)


def run_all_backups() -> list[Tuple[str, bool, str]]:
    """
    Uruchamia wszystkie trzy zadania backupu sekwencyjnie.

    Returns
    -------
    list of (task_name, ok, message)
    """
    tasks = [
        ("File History",      backup_file_history),
        ("Registry (HKLM+HKCU)", backup_registry),
        ("BCD (bootloader)",  backup_bcd),
    ]
    results = []
    for name, func in tasks:
        ok, msg = func()
        results.append((name, ok, msg))
    return results
