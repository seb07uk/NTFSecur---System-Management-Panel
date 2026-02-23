#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.ui.helpers  –  Shared UI utilities
=============================================================================
Provides:
  * thread_worker()   – decorator that runs a method body in a daemon thread
                        with automatic exception capture and UI callback
  * AdminMixin        – mixin that provides require_admin_ui() for Widgets
=============================================================================
"""

from __future__ import annotations

import functools
import threading
import traceback
from typing import Any, Callable, Optional

__all__ = ["thread_worker", "AdminMixin"]


# ---------------------------------------------------------------------------
#  thread_worker decorator
# ---------------------------------------------------------------------------

def thread_worker(
    on_error: Optional[Callable[[str], None]] = None,
) -> Callable:
    """
    Decorator factory that runs the decorated instance method in a daemon
    thread.

    Any unhandled exception in the worker is caught, logged, and — if the
    widget provides a ``_set_status(msg)`` method — surfaced to the user.

    Usage::

        class MyPanel(tk.Frame):

            @thread_worker()
            def _load_data(self) -> None:
                # Runs in a background thread
                data = expensive_operation()
                # Schedule UI update back on the main thread
                self.after(0, lambda: self._show(data))

    Notes
    -----
    *  The decorated method must be an instance method of a ``tk.Widget``
       subclass so that ``self.after()`` is available.
    *  The daemon thread will be killed when the main window exits.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> None:
            def run() -> None:
                try:
                    func(self, *args, **kwargs)
                except Exception as exc:
                    tb = traceback.format_exc()
                    # Log if logger is available
                    try:
                        from ntfsecur.core.logging import log_error
                        log_error(f"thread_worker exception in {func.__qualname__}: {exc}")
                    except ImportError:
                        pass

                    msg = f"✘ Error: {exc}"
                    # Surface error to the widget if possible
                    def _notify() -> None:
                        if on_error:
                            on_error(msg)
                        elif hasattr(self, "_set_status"):
                            self._set_status(msg)  # type: ignore[attr-defined]
                        elif hasattr(self, "_set_bot"):
                            self._set_bot(msg)     # type: ignore[attr-defined]

                    try:
                        self.after(0, _notify)
                    except Exception:
                        pass

            t = threading.Thread(target=run, daemon=True)
            t.start()
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
#  AdminMixin
# ---------------------------------------------------------------------------

class AdminMixin:
    """
    Mixin for tkinter widgets that provides a reusable admin-check helper.

    Usage::

        class BitLockerPanel(AdminMixin, tk.Frame):

            def _action_lock(self):
                if not self.require_admin_ui():
                    return
                # … proceed with privileged operation …
    """

    def require_admin_ui(self) -> bool:
        """
        Return True if the application is running with admin privileges.

        If not, display a messagebox warning and return False.
        """
        from ntfsecur.core.security import is_admin  # noqa: PLC0415
        from ntfsecur.i18n import t                  # noqa: PLC0415

        if is_admin():
            return True

        from tkinter import messagebox                # noqa: PLC0415
        messagebox.showwarning(
            t("common.permissions"),
            t("common.admin_required"),
        )
        return False
