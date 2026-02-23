#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.core.security  –  Security primitives
=============================================================================
Provides:
  * is_admin()            – check for elevated privileges
  * require_admin()       – decorator that blocks execution without privileges
  * validate_drive()      – validate drive letter / path to prevent injection
  * safe_run()            – subprocess wrapper: shell=False, no console, logged
  * SecureString          – in-memory string that can be zeroed after use
=============================================================================
"""

from __future__ import annotations

import ctypes
import functools
import os
import re
import subprocess
import sys
from typing import Callable, Any

from ntfsecur.i18n import t

__all__ = [
    "is_admin",
    "require_admin",
    "validate_drive",
    "safe_run",
    "SecureString",
    "no_window_kwargs",
]

# ---------------------------------------------------------------------------
#  Admin check
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    """Return True if the current process has administrator / root privileges."""
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
#  Admin decorator
# ---------------------------------------------------------------------------

def require_admin(func: Callable) -> Callable:
    """
    Decorator for tkinter widget methods that require administrator privileges.

    Shows a warning messagebox and returns early when the user does not have
    admin rights.  The decorated method must be an instance method of a
    ``tk.Widget`` subclass (so that ``messagebox`` can find a parent window).

    Example::

        class BitLockerPanel(tk.Frame):

            @require_admin
            def _action_enable(self):
                self._run_async("Enabling BitLocker", bl_enable, self.drive)
    """
    @functools.wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        if not is_admin():
            # Import here to avoid circular dependency at module load time
            from tkinter import messagebox
            messagebox.showwarning(
                t("common.permissions"),
                t("common.admin_required"),
            )
            return None
        return func(self, *args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
#  Drive / path validation
# ---------------------------------------------------------------------------

# Windows drive letter pattern: single letter + colon, e.g. "C:"
_WIN_DRIVE_RE  = re.compile(r'^[A-Za-z]:$')
# Linux/macOS device path pattern: /dev/sd*, /dev/nvme*, /dev/disk* …
_UNIX_PATH_RE  = re.compile(r'^/dev/[a-zA-Z0-9/_-]{1,64}$')


def validate_drive(drive: str) -> str:
    """
    Validate and normalise a drive identifier.

    Parameters
    ----------
    drive : str
        On Windows: a drive letter + colon, e.g. ``"C:"`` or ``"c:"``.
        On Linux/macOS: a device path, e.g. ``"/dev/sda1"``.

    Returns
    -------
    str
        Normalised drive string (Windows drive letters are uppercased).

    Raises
    ------
    ValueError
        If the string does not match the expected pattern.
    """
    drive = drive.strip()

    # Accept Windows-style drive letters on all platforms so that
    # BitLocker functions work correctly when called on Windows
    # even if the test/validation runs from a Linux host.
    if _WIN_DRIVE_RE.match(drive):
        return drive[0].upper() + ":"

    if sys.platform != "win32":
        if _UNIX_PATH_RE.match(drive):
            return drive
        raise ValueError(
            f"Invalid device path: {drive!r}. "
            "Expected a path under /dev/, e.g. '/dev/sda1'."
        )

    # Windows but not a drive letter
    raise ValueError(
        f"Invalid drive identifier: {drive!r}. "
        "Expected a drive letter followed by a colon, e.g. 'C:'."
    )


# ---------------------------------------------------------------------------
#  Subprocess helpers
# ---------------------------------------------------------------------------

def no_window_kwargs() -> dict:
    """
    Return subprocess keyword arguments that suppress the console window on
    Windows.  Returns an empty dict on other platforms.
    """
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        return {
            "startupinfo":  si,
            "creationflags": subprocess.CREATE_NO_WINDOW,
        }
    return {}


def safe_run(
    cmd: list[str],
    timeout: int = 10,
    encoding: str = "utf-8",
) -> tuple[bool, str]:
    """
    Run *cmd* safely (``shell=False``, no console window) and return
    ``(success, output)``.

    Logging is performed via the application logger if available; the function
    is self-contained otherwise.

    Parameters
    ----------
    cmd     : List of command tokens – never a shell string.
    timeout : Maximum execution time in seconds.
    encoding: Output encoding (use "cp1250" for manage-bde on Polish Windows).

    Returns
    -------
    (True,  stdout)  on success (returncode == 0).
    (False, message) on failure, timeout, or missing command.
    """
    # Lazy import to avoid circular imports
    try:
        from ntfsecur.core.logging import log_debug, log_warn, log_error
    except ImportError:
        log_debug = log_warn = log_error = lambda *a, **k: None  # type: ignore

    log_debug(f"safe_run: {' '.join(str(c) for c in cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding=encoding,
            errors="replace",
            shell=False,          # NEVER shell=True
            **no_window_kwargs(),
        )
        output = result.stdout.strip() or result.stderr.strip()
        if result.returncode != 0:
            log_warn(
                f"safe_run rc={result.returncode}: "
                f"{' '.join(str(c) for c in cmd)} → {output[:200]}"
            )
        return result.returncode == 0, output

    except FileNotFoundError:
        msg = f"Command not found: '{cmd[0]}'"
        log_error(msg)
        return False, msg

    except subprocess.TimeoutExpired:
        msg = t("common.op_timeout")
        log_warn(f"safe_run timeout: {' '.join(str(c) for c in cmd)}")
        return False, msg

    except Exception as exc:
        msg = str(exc)
        log_error(f"safe_run exception: {msg}")
        return False, msg


# ---------------------------------------------------------------------------
#  SecureString – password / key holder that can be zeroed from memory
# ---------------------------------------------------------------------------

class SecureString:
    """
    Holds a sensitive string (password, recovery key) and provides a
    ``zero()`` method that overwrites the value in memory.

    Usage::

        with SecureString(password_entry.get()) as pwd:
            bl_unlock_password(drive, pwd.value)
        # pwd.value is now zeroed

        # Alternatively:
        pwd = SecureString(raw)
        try:
            do_something(pwd.value)
        finally:
            pwd.zero()

    Notes
    -----
    CPython's string objects are immutable and interned; overwriting the
    character buffer via :mod:`ctypes` is best-effort, not guaranteed.
    This class provides a clear signal of intent and removes the reference
    from the Python object graph as quickly as possible.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        # Store a private copy so the caller's reference can be cleared
        self._value: str | None = str(value)

    @property
    def value(self) -> str:
        if self._value is None:
            raise RuntimeError("SecureString has already been zeroed.")
        return self._value

    def zero(self) -> None:
        """Overwrite the internal string buffer and release the reference."""
        if self._value is not None:
            try:
                # Best-effort: overwrite CPython string buffer via ctypes
                buf = (ctypes.c_char * (len(self._value) * 4)).from_address(
                    id(self._value) + ctypes.sizeof(ctypes.c_ssize_t) * 4
                )
                ctypes.memset(buf, 0, len(buf))
            except Exception:
                pass  # Zeroing is best-effort
            finally:
                self._value = None

    def __enter__(self) -> "SecureString":
        return self

    def __exit__(self, *_: Any) -> None:
        self.zero()

    def __repr__(self) -> str:
        return "SecureString(***)"

    def __del__(self) -> None:
        self.zero()
