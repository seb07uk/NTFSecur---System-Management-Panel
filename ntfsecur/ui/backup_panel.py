#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.ui.backup_panel  –  Panel kopii zapasowej systemu
=============================================================================
Panel UI wzorowany na BitLockerPanel.  Zawiera trzy sekcje:

  * Backup plików użytkownika (File History)
  * Backup rejestru Windows (HKLM + HKCU)
  * Backup BCD (bootloader)

Każde zadanie uruchamiane jest w osobnym wątku roboczym przez
:func:`~ntfsecur.ui.helpers.thread_worker`.  Wyniki trafiają do
wbudowanego okna logu i paska statusu.
=============================================================================
"""

from __future__ import annotations

import os
import subprocess
import time
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox

from ntfsecur.core.backup import (
    backup_file_history,
    backup_file_history_location,
    backup_registry,
    backup_bcd,
    run_all_backups,
)
from ntfsecur.core.paths import AppPaths
from ntfsecur.core.security import require_admin
from ntfsecur.i18n import t
from ntfsecur.ui.helpers import thread_worker, AdminMixin

__all__ = ["BackupPanel"]


class BackupPanel(AdminMixin, tk.Frame):
    """
    Panel zarządzania kopiami zapasowymi systemu.

    Parameters
    ----------
    parent  : tk.Widget
        Widget nadrzędny.
    colours : dict
        Paleta kolorów z SystemManagementPanel.
    """

    def __init__(
        self,
        parent: tk.Widget,
        colours: dict,
        **kwargs,
    ) -> None:
        super().__init__(parent, bg=colours["BG"], **kwargs)
        self._clr: dict = colours

        self.CLR_BG      = colours["BG"]
        self.CLR_SURFACE = colours["SURFACE"]
        self.CLR_ACCENT  = colours["ACCENT"]
        self.CLR_TEXT    = colours["TEXT"]
        self.CLR_TEXT2   = colours["TEXT2"]
        self.CLR_DANGER  = colours["DANGER"]
        self.CLR_SUCCESS = colours["SUCCESS"]
        self.CLR_WARN    = colours["WARN"]
        self.CLR_HEADER  = colours.get("HEADER_BG", "#000")

        self._build_ui()

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Zbuduj układ panelu."""
        # Nagłówek
        top = tk.Frame(self, bg=self.CLR_SURFACE)
        top.pack(fill=tk.X, padx=8, pady=(6, 2))

        tk.Label(
            top,
            text=t("backup.section_title"),
            font=("Segoe UI", 13, "bold"),
            fg=self.CLR_ACCENT,
            bg=self.CLR_SURFACE,
        ).pack(side=tk.LEFT, padx=10, pady=6)

        self._lbl_dir = tk.Label(
            top,
            text=AppPaths.BACKUP_DIR,
            font=("Segoe UI", 9),
            fg=self.CLR_TEXT2,
            bg=self.CLR_SURFACE,
        )
        self._lbl_dir.pack(side=tk.LEFT, padx=16)

        # Zakładki
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        self._make_actions_tab(nb)
        self._txt_log = self._make_log_tab(nb)

        # Pasek statusu
        bot = tk.Frame(self, bg=self.CLR_SURFACE, height=24)
        bot.pack(fill=tk.X, side=tk.BOTTOM)
        self._bot_status = tk.Label(
            bot,
            text=t("common.ready"),
            anchor=tk.W,
            font=("Segoe UI", 9),
            fg=self.CLR_TEXT2,
            bg=self.CLR_SURFACE,
        )
        self._bot_status.pack(side=tk.LEFT, padx=10)

    def _make_actions_tab(self, nb: ttk.Notebook) -> None:
        """Zakładka z przyciskami akcji backup."""
        frm = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(frm, text="Backup")

        btn_cfg = dict(
            font=("Segoe UI", 9, "bold"),
            fg=self.CLR_HEADER,
            relief=tk.FLAT,
            padx=12, pady=5,
            cursor="hand2",
        )

        def btn(row: int, col: int, text: str, cmd, color: str) -> None:
            tk.Button(
                frm, text=text, command=cmd, bg=color, **btn_cfg
            ).grid(row=row, column=col, padx=6, pady=5, sticky=tk.W)

        def lbl(row: int, text: str) -> None:
            tk.Label(
                frm,
                text=text,
                font=("Segoe UI", 9, "bold"),
                fg=self.CLR_TEXT,
                bg=self.CLR_BG,
                anchor=tk.W,
            ).grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=8, pady=(12, 0))

        def sublbl(row: int, text: str) -> None:
            tk.Label(
                frm,
                text=text,
                font=("Segoe UI", 8),
                fg=self.CLR_TEXT2,
                bg=self.CLR_BG,
                anchor=tk.W,
            ).grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=24, pady=(0, 2))

        # ── File History ────────────────────────────────────────────────────
        lbl(0, t("backup.file_history"))
        sublbl(1, "fhmanagew.exe -backupnow   |   control /name Microsoft.FileHistory")
        btn(2, 0, t("backup.file_history_run"),      self._action_fh_backup,   self.CLR_SUCCESS)
        btn(2, 1, t("backup.file_history_location"), self._action_fh_location, self.CLR_SURFACE)

        # ── Rejestr Windows ─────────────────────────────────────────────────
        lbl(3, t("backup.registry"))
        sublbl(4, r"reg export HKLM <BACKUP_DIR>\HKLM.reg /y   |   reg export HKCU <BACKUP_DIR>\HKCU.reg /y")
        btn(5, 0, t("backup.registry_hklm") + " + HKCU", self._action_registry, self.CLR_ACCENT)

        # ── BCD ─────────────────────────────────────────────────────────────
        lbl(6, t("backup.bcd"))
        sublbl(7, r"bcdedit /export <BACKUP_DIR>\bcd_backup")
        btn(8, 0, t("backup.bcd_export"), self._action_bcd, self.CLR_ACCENT)

        # ── Pełny backup ─────────────────────────────────────────────────────
        sep = tk.Frame(frm, bg=self.CLR_SURFACE, height=1)
        sep.grid(row=9, column=0, columnspan=3, sticky=tk.EW, padx=8, pady=(14, 6))

        btn(10, 0, t("backup.run_all"),    self._action_all,         self.CLR_SUCCESS)
        btn(10, 1, t("backup.open_folder"), self._action_open_folder, self.CLR_SURFACE)

        # Ścieżka docelowa
        dir_frm = tk.Frame(frm, bg=self.CLR_BG)
        dir_frm.grid(row=11, column=0, columnspan=3, sticky=tk.W, padx=8, pady=(10, 4))
        tk.Label(
            dir_frm,
            text=f"{t('backup.output_dir')}:  ",
            font=("Segoe UI", 9),
            fg=self.CLR_TEXT2,
            bg=self.CLR_BG,
        ).pack(side=tk.LEFT)
        tk.Label(
            dir_frm,
            text=AppPaths.BACKUP_DIR,
            font=("Consolas", 9),
            fg=self.CLR_ACCENT,
            bg=self.CLR_BG,
        ).pack(side=tk.LEFT)

    def _make_log_tab(self, nb: ttk.Notebook) -> tk.Text:
        """Zakładka z oknem logu operacji."""
        frm = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(frm, text="Log")

        btn_row = tk.Frame(frm, bg=self.CLR_BG)
        btn_row.pack(fill=tk.X, padx=4, pady=4)
        for text, cmd in [
            ("Wyczyść log", self._clear_log),
        ]:
            tk.Button(
                btn_row, text=text, command=cmd,
                bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                font=("Segoe UI", 9), relief=tk.FLAT,
                padx=8, pady=4, cursor="hand2",
            ).pack(side=tk.LEFT, padx=3)

        txt = tk.Text(
            frm,
            bg=self.CLR_BG,
            fg=self.CLR_TEXT,
            font=("Consolas", 9),
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        sb = tk.Scrollbar(frm, command=txt.yview, bg=self.CLR_SURFACE)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        txt.pack(fill=tk.BOTH, expand=True)
        return txt

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self._txt_log.configure(state=tk.NORMAL)
        self._txt_log.insert(tk.END, f"[{ts}]  {msg}\n")
        self._txt_log.see(tk.END)
        self._txt_log.configure(state=tk.DISABLED)

    def _set_status(self, text: str) -> None:
        self._bot_status.configure(text=text)

    _set_bot = _set_status

    def _clear_log(self) -> None:
        self._txt_log.configure(state=tk.NORMAL)
        self._txt_log.delete("1.0", tk.END)
        self._txt_log.configure(state=tk.DISABLED)

    def _run_task(self, name: str, func) -> None:
        """Uruchom jedno zadanie backup w wątku roboczym."""
        self._set_status(t("backup.running").format(name=name))
        self._log(f"▶ {t('backup.running').format(name=name)}")

        def worker() -> None:
            try:
                ok, msg = func()
            except Exception as exc:
                ok, msg = False, str(exc)

            def done() -> None:
                key   = "backup.done" if ok else "backup.error"
                icon  = "✔" if ok else "✘"
                entry = t(key).format(name=name, msg=msg[:200]) if not ok else \
                        t(key).format(name=name)
                self._set_status(f"{icon} {entry}")
                self._log(f"{icon} {entry}")
                if msg and msg not in ("OK",):
                    self._log(f"   {msg[:500]}")

            self.after(0, done)

        import threading
        threading.Thread(target=worker, daemon=True).start()

    # ── Actions ───────────────────────────────────────────────────────────────

    def _action_fh_backup(self) -> None:
        self._run_task(t("backup.file_history"), backup_file_history)

    def _action_fh_location(self) -> None:
        """Otwórz panel konfiguracji File History (nie wymaga admina)."""
        ok, msg = backup_file_history_location()
        icon = "✔" if ok else "✘"
        self._set_status(f"{icon} {msg}")
        self._log(f"{icon} {t('backup.file_history_location')}: {msg}")

    @require_admin
    def _action_registry(self) -> None:
        self._run_task(t("backup.registry"), backup_registry)

    @require_admin
    def _action_bcd(self) -> None:
        self._run_task(t("backup.bcd"), backup_bcd)

    @require_admin
    def _action_all(self) -> None:
        """Uruchom wszystkie trzy zadania sekwencyjnie w jednym wątku."""
        self._set_status(t("backup.running").format(name="…"))
        self._log(f"▶ {t('backup.run_all')}")

        def worker() -> None:
            results = run_all_backups()
            lines   = []
            all_ok  = True
            for name, ok, msg in results:
                icon = "✔" if ok else "✘"
                lines.append(f"{icon} {name}: {msg[:200]}")
                if not ok:
                    all_ok = False

            def done() -> None:
                for line in lines:
                    self._log(f"   {line}")
                final = t("backup.all_done") if all_ok else "✘ Niektóre zadania zakończyły się błędem – sprawdź log."
                self._set_status(final)
                self._log(final)

            self.after(0, done)

        import threading
        threading.Thread(target=worker, daemon=True).start()

    def _action_open_folder(self) -> None:
        """Otwórz folder docelowy backupu w Eksploratorze."""
        d = AppPaths.BACKUP_DIR
        try:
            os.makedirs(d, exist_ok=True)
            subprocess.Popen(["explorer", d])
            self._set_status(f"✔ {t('backup.open_folder')}: {d}")
        except Exception as exc:
            self._set_status(f"✘ {exc}")
            self._log(f"✘ open_folder: {exc}")
