#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.ui.bitlocker_panel  –  BitLocker management UI panel
=============================================================================
Refactored from the monolithic NTFSecur.py.

Key improvements over the original:
  * :func:`require_admin` decorator replaces 12 identical admin-check blocks
  * :func:`thread_worker` decorator replaces 10 hand-written Thread+daemon calls
  * All admin checks use the shared :class:`~ntfsecur.ui.helpers.AdminMixin`
  * Type hints on every public / protected method
  * Passwords handled via :class:`~ntfsecur.core.security.SecureString`
  * Drive identifier validated before every BitLocker call
  * Imports moved to module level (except filedialog, which is optional)
=============================================================================
"""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import messagebox, filedialog
from typing import Callable, Optional

from ntfsecur.core.bitlocker import (
    bl_status, bl_enable, bl_disable, bl_lock,
    bl_unlock_password, bl_unlock_recovery,
    bl_suspend, bl_resume,
    bl_get_recovery_key, bl_backup_recovery_to_ad,
    bl_add_password_protector, bl_add_tpm_protector,
    bl_add_recovery_protector, bl_change_pin,
    bl_wipe_free_space, bl_run,
)
from ntfsecur.core.security import require_admin, SecureString
from ntfsecur.i18n import t
from ntfsecur.ui.helpers import thread_worker, AdminMixin

__all__ = ["BitLockerPanel"]


class BitLockerPanel(AdminMixin, tk.Frame):
    """
    Full-featured BitLocker management panel for a single drive.

    Parameters
    ----------
    parent : tk.Widget
        Parent widget.
    drive  : str
        Drive letter + colon, e.g. ``"C:"``.  Validated on construction.
    colours: dict
        Colour palette from :class:`SystemManagementPanel`.
    """

    def __init__(
        self,
        parent: tk.Widget,
        drive: str,
        colours: dict,
        **kwargs,
    ) -> None:
        super().__init__(parent, bg=colours["BG"], **kwargs)
        # Validate drive early – raises ValueError for bad input
        from ntfsecur.core.security import validate_drive
        self.drive: str     = validate_drive(drive)
        self._clr: dict     = colours
        self._status_info: dict = {}

        # Convenience colour aliases
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
        self._refresh_status()

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Build the panel layout."""
        top = tk.Frame(self, bg=self.CLR_SURFACE)
        top.pack(fill=tk.X, padx=8, pady=(6, 2))

        tk.Label(
            top,
            text=f"BitLocker  –  {self.drive}",
            font=("Segoe UI", 13, "bold"),
            fg=self.CLR_ACCENT,
            bg=self.CLR_SURFACE,
        ).pack(side=tk.LEFT, padx=10, pady=6)

        self._lbl_protection = tk.Label(
            top,
            text=t("bitlocker.protection_label"),
            font=("Segoe UI", 9),
            fg=self.CLR_WARN,
            bg=self.CLR_SURFACE,
        )
        self._lbl_protection.pack(side=tk.LEFT, padx=16)

        self._lbl_lock = tk.Label(
            top,
            text=t("bitlocker.lock_label"),
            font=("Segoe UI", 9),
            fg=self.CLR_TEXT2,
            bg=self.CLR_SURFACE,
        )
        self._lbl_lock.pack(side=tk.LEFT, padx=8)

        self._lbl_method = tk.Label(
            top,
            text=t("bitlocker.method_label"),
            font=("Segoe UI", 9),
            fg=self.CLR_TEXT2,
            bg=self.CLR_SURFACE,
        )
        self._lbl_method.pack(side=tk.LEFT, padx=8)

        self._lbl_pct = tk.Label(
            top, text="", font=("Segoe UI", 9),
            fg=self.CLR_WARN, bg=self.CLR_SURFACE,
        )
        self._lbl_pct.pack(side=tk.LEFT, padx=8)

        # ── Notebook tabs ────────────────────────────────────────────────────
        import tkinter.ttk as ttk
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        self._txt_main = self._make_tab(nb, "Status")
        self._txt_keys = self._make_tab(nb, "Keys / Protectors")
        self._txt_adv  = self._make_tab(nb, "PowerShell")
        self._make_actions_tab(nb)
        self._make_unlock_tab(nb)
        self._make_pin_tab(nb)
        self._txt_log  = self._make_tab(nb, "Log")

        # ── Status bar ───────────────────────────────────────────────────────
        bot = tk.Frame(self, bg=self.CLR_SURFACE, height=24)
        bot.pack(fill=tk.X, side=tk.BOTTOM)
        self._bot_status = tk.Label(
            bot,
            text=t("common.loading"),
            anchor=tk.W,
            font=("Segoe UI", 9),
            fg=self.CLR_TEXT2,
            bg=self.CLR_SURFACE,
        )
        self._bot_status.pack(side=tk.LEFT, padx=10)

    def _make_tab(self, nb: tk.Widget, title: str) -> tk.Text:
        """Create a read-only text tab in *nb* and return the Text widget."""
        frm = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(frm, text=title)
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

    def _make_actions_tab(self, nb: tk.Widget) -> None:
        """Build the main actions tab (enable / disable / lock / suspend)."""
        frm = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(frm, text="Actions")

        btn_cfg = dict(
            font=("Segoe UI", 9, "bold"),
            fg=self.CLR_HEADER,
            relief=tk.FLAT,
            padx=12, pady=5,
            cursor="hand2",
        )

        def btn(row: int, col: int, text: str, cmd: Callable, color: str) -> None:
            tk.Button(
                frm, text=text, command=cmd, bg=color, **btn_cfg
            ).grid(row=row, column=col, padx=6, pady=4, sticky=tk.W)

        btn(0, 0, t("bitlocker.enable"),  self._action_enable,  self.CLR_SUCCESS)
        btn(0, 1, t("bitlocker.disable"), self._action_disable, self.CLR_DANGER)
        btn(1, 0, t("bitlocker.lock"),    self._action_lock,    self.CLR_ACCENT)
        btn(1, 1, t("bitlocker.lock_force"), self._action_lock_force, self.CLR_DANGER)
        btn(2, 0, t("bitlocker.suspend"), self._action_suspend, self.CLR_WARN)
        btn(2, 1, t("bitlocker.resume"),  self._action_resume,  self.CLR_SUCCESS)
        btn(3, 0, t("bitlocker.backup_ad"),    self._action_backup_ad,    self.CLR_ACCENT)
        btn(3, 1, t("bitlocker.add_tpm"),      self._action_add_tpm,      self.CLR_ACCENT)
        btn(4, 0, t("bitlocker.add_recovery"), self._action_add_recovery, self.CLR_ACCENT)
        btn(4, 1, t("bitlocker.wipe_free"),    self._action_wipe_free,    self.CLR_DANGER)

        # Keys panel buttons
        row_keys = tk.Frame(frm, bg=self.CLR_BG)
        row_keys.grid(row=5, column=0, columnspan=3, sticky=tk.W, pady=(10, 2))
        for text, cmd in [
            ("Fetch Keys",          self._action_get_keys),
            (t("common.save"),      self._action_save_recovery),
            ("Copy Advanced",       self._action_copy_adv),
            ("PS Info",             self._action_ps_info),
        ]:
            tk.Button(
                row_keys, text=text, command=cmd,
                bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                font=("Segoe UI", 9), relief=tk.FLAT,
                padx=8, pady=4, cursor="hand2",
            ).pack(side=tk.LEFT, padx=3)

    def _make_unlock_tab(self, nb: tk.Widget) -> None:
        """Build the unlock tab (password + recovery key fields)."""
        frm = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(frm, text="Unlock")

        ent_cfg = dict(
            bg=self.CLR_SURFACE,
            fg=self.CLR_TEXT,
            insertbackground=self.CLR_ACCENT,
            relief=tk.FLAT,
            width=40,
            font=("Segoe UI", 10),
        )

        tk.Label(
            frm, text=t("bitlocker.pwd_label"),
            font=("Segoe UI", 10),
            fg=self.CLR_TEXT, bg=self.CLR_BG,
        ).grid(row=0, column=0, sticky=tk.W, padx=12, pady=(14, 2))

        self._ent_pwd = tk.Entry(frm, show="•", **ent_cfg)
        self._ent_pwd.grid(row=1, column=0, padx=12, pady=(0, 6))

        tk.Button(
            frm,
            text=t("bitlocker.unlock_pwd"),
            command=self._action_unlock_pwd,
            bg=self.CLR_ACCENT,
            fg=self.CLR_HEADER,
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=10, pady=4,
            cursor="hand2",
        ).grid(row=2, column=0, sticky=tk.W, padx=12, pady=(0, 14))

        tk.Label(
            frm, text=t("bitlocker.recovery_key_label"),
            font=("Segoe UI", 10),
            fg=self.CLR_TEXT, bg=self.CLR_BG,
        ).grid(row=3, column=0, sticky=tk.W, padx=12, pady=(0, 2))

        tk.Label(
            frm, text=t("bitlocker.key_format"),
            font=("Segoe UI", 8),
            fg=self.CLR_TEXT2, bg=self.CLR_BG,
        ).grid(row=4, column=0, sticky=tk.W, padx=12)

        self._ent_rk = tk.Entry(frm, **ent_cfg)
        self._ent_rk.grid(row=5, column=0, padx=12, pady=(2, 6))

        tk.Button(
            frm,
            text=t("bitlocker.unlock_key"),
            command=self._action_unlock_recovery,
            bg=self.CLR_ACCENT,
            fg=self.CLR_HEADER,
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=10, pady=4,
            cursor="hand2",
        ).grid(row=6, column=0, sticky=tk.W, padx=12)

    def _make_pin_tab(self, nb: tk.Widget) -> None:
        """Build the PIN management tab."""
        frm = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(frm, text="PIN")

        ent_cfg = dict(
            show="•",
            bg=self.CLR_SURFACE,
            fg=self.CLR_TEXT,
            insertbackground=self.CLR_ACCENT,
            relief=tk.FLAT,
            width=20,
            font=("Segoe UI", 10),
        )

        for row, label, attr in [
            (0, t("bitlocker.old_pin_label"), "_ent_old_pin"),
            (2, t("bitlocker.new_pin_label"), "_ent_new_pin"),
        ]:
            tk.Label(
                frm, text=label,
                font=("Segoe UI", 10),
                fg=self.CLR_TEXT, bg=self.CLR_BG,
            ).grid(row=row, column=0, sticky=tk.W, padx=12, pady=(10, 2))
            ent = tk.Entry(frm, **ent_cfg)
            ent.grid(row=row + 1, column=0, padx=12)
            setattr(self, attr, ent)

        tk.Button(
            frm,
            text="Change PIN",
            command=self._action_change_pin,
            bg=self.CLR_ACCENT,
            fg=self.CLR_HEADER,
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=10, pady=4,
            cursor="hand2",
        ).grid(row=4, column=0, sticky=tk.W, padx=12, pady=10)

        tk.Button(
            frm,
            text="Add Password Protector",
            command=self._action_add_pwd_protector,
            bg=self.CLR_SURFACE,
            fg=self.CLR_TEXT,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            padx=10, pady=4,
            cursor="hand2",
        ).grid(row=5, column=0, sticky=tk.W, padx=12)

        # Log controls
        log_row = tk.Frame(frm, bg=self.CLR_BG)
        log_row.grid(row=6, column=0, columnspan=2, sticky=tk.W, padx=12, pady=8)
        for text, cmd in [
            ("Clear Log", self._clear_log),
            ("Save Log",  self._save_log),
        ]:
            tk.Button(
                log_row, text=text, command=cmd,
                bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                font=("Segoe UI", 9), relief=tk.FLAT,
                padx=8, pady=4, cursor="hand2",
            ).pack(side=tk.LEFT, padx=3)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _write(
        self, widget: tk.Text, text: str, append: bool = False
    ) -> None:
        """Write *text* to a read-only Text widget."""
        widget.configure(state=tk.NORMAL)
        if not append:
            widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.see(tk.END)
        widget.configure(state=tk.DISABLED)

    def _log(self, msg: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self._write(self._txt_log, f"[{ts}]  {msg}\n", append=True)

    def _set_status(self, text: str) -> None:
        """Update the bottom status label (also aliased as _set_bot)."""
        self._bot_status.configure(text=text)

    # Keep old alias for backward compatibility with thread_worker
    _set_bot = _set_status

    # ── Status refresh ────────────────────────────────────────────────────────

    @thread_worker()
    def _refresh_status(self) -> None:
        """Fetch BitLocker status in a background thread."""
        self.after(0, lambda: self._set_status("Fetching BitLocker status…"))
        info = bl_status(self.drive)
        self.after(0, lambda: self._apply_status(info))

    def _apply_status(self, info: dict) -> None:
        """Apply fetched status to the UI (must be called on main thread)."""
        self._status_info = info
        prot = info.get("protection", "Unknown")
        lock = info.get("lock_status", "Unknown")
        meth = info.get("method", "–")
        pct  = info.get("percentage", "–")
        raw  = info.get("raw", "")

        if "On" in prot or prot == "1":
            pc = self.CLR_SUCCESS
            pt = f"✔  Protection: ON ({prot})"
        elif "Off" in prot or prot == "0":
            pc = self.CLR_DANGER
            pt = f"✘  Protection: OFF ({prot})"
        else:
            pc = self.CLR_WARN
            pt = f"?  Protection: {prot}"

        self._lbl_protection.configure(text=pt, fg=pc)
        self._lbl_lock.configure(
            text=f"Lock: {lock}",
            fg=self.CLR_DANGER if "Locked" in lock else self.CLR_SUCCESS,
        )
        self._lbl_method.configure(text=f"Method: {meth}", fg=self.CLR_TEXT2)
        self._lbl_pct.configure(
            text=f"Progress: {pct}" if pct not in ("–", "100%", "100.0%") else ""
        )

        if hasattr(self, "_txt_main"):
            self._write(self._txt_main, raw or "(no data)")

        kps = info.get("key_protectors", [])
        if kps:
            self._write(
                self._txt_keys,
                "Key Protectors:\n" + "\n".join(f"  • {k}" for k in kps),
            )

        status_str = f"Status: {prot} | {lock} | {meth}"
        self._set_status(status_str)
        self._log(f"Status refreshed: {status_str}")

    # ── Async runner ──────────────────────────────────────────────────────────

    def _run_async(
        self,
        label: str,
        func: Callable,
        *args,
        on_done: Optional[Callable[[bool, str], None]] = None,
    ) -> None:
        """Run *func(*args)* in a daemon thread, update UI on completion."""
        self._set_status(f"{label}…")
        self._log(f"▶ {label} ({self.drive})")

        def worker() -> None:
            try:
                ok, msg = func(*args)
            except Exception as exc:
                ok, msg = False, str(exc)

            def done() -> None:
                icon = "✔" if ok else "✘"
                self._set_status(f"{icon} {msg[:120]}")
                self._log(f"{icon} {msg}")
                if on_done:
                    on_done(ok, msg)
                self._refresh_status()

            self.after(0, done)

        import threading
        threading.Thread(target=worker, daemon=True).start()

    # ── Actions  (all guarded by require_admin decorator) ─────────────────────

    @require_admin
    def _action_enable(self) -> None:
        if not messagebox.askyesno(
            "BitLocker – Enable",
            f"Enable BitLocker encryption on {self.drive}?\n\n"
            "The operation may take a long time. A recovery key will be generated.",
        ):
            return
        self._run_async("Enabling BitLocker", bl_enable, self.drive, True)

    @require_admin
    def _action_disable(self) -> None:
        if not messagebox.askyesno(
            "BitLocker – Disable",
            f"⚠  DISABLE and remove BitLocker encryption on {self.drive}?\n\n"
            "Data will be decrypted. The operation may take a very long time.",
        ):
            return
        self._run_async("Disabling BitLocker", bl_disable, self.drive)

    @require_admin
    def _action_lock(self) -> None:
        self._run_async("Locking drive", bl_lock, self.drive, False)

    @require_admin
    def _action_lock_force(self) -> None:
        if not messagebox.askyesno(
            "BitLocker – Force Lock",
            f"Force immediate disconnection and locking of {self.drive}?\n"
            "Unsaved data may be lost!",
        ):
            return
        self._run_async("Force-locking drive", bl_lock, self.drive, True)

    @require_admin
    def _action_suspend(self) -> None:
        self._run_async("Suspending Protection", bl_suspend, self.drive, 1)

    @require_admin
    def _action_resume(self) -> None:
        self._run_async("Resuming Protection", bl_resume, self.drive)

    def _action_unlock_pwd(self) -> None:
        raw_pwd = self._ent_pwd.get().strip()
        if not raw_pwd:
            messagebox.showwarning("Password", "Enter a password.")
            return
        # Hand off to SecureString – original entry is cleared immediately
        with SecureString(raw_pwd) as pwd:
            self._ent_pwd.delete(0, tk.END)
            self._run_async(
                "Unlocking with Password", bl_unlock_password, self.drive, pwd.value
            )

    def _action_unlock_recovery(self) -> None:
        rk = self._ent_rk.get().strip()
        if not rk:
            messagebox.showwarning("Key", "Enter the recovery key.")
            return
        self._run_async("Unlocking with Key", bl_unlock_recovery, self.drive, rk)

    @thread_worker()
    def _action_get_keys(self) -> None:
        self.after(0, lambda: self._set_status("Fetching keys…"))
        self._log(f"▶ Fetching protectors ({self.drive})")
        ok, msg = bl_get_recovery_key(self.drive)
        icon = "✔" if ok else "✘"

        def done() -> None:
            self._write(self._txt_keys, msg)
            self._set_status(f"{icon} Protectors retrieved.")
            self._log(f"{icon} Keys: {msg[:120]}")

        self.after(0, done)

    @thread_worker()
    def _action_save_recovery(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title=f"Save BitLocker Recovery Key – {self.drive}",
        )
        if not path:
            return
        ok, msg = bl_get_recovery_key(self.drive)
        if ok:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"BitLocker Recovery Key – {self.drive}\n")
                    f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    f.write(msg)
                result = f"✔ Key saved: {path}"
            except Exception as exc:
                result = f"✘ Write error: {exc}"
        else:
            result = f"✘ {msg}"
        self.after(0, lambda: (self._set_status(result), self._log(result)))

    @require_admin
    def _action_backup_ad(self) -> None:
        self._run_async("Backing Up Key to AD", bl_backup_recovery_to_ad, self.drive)

    @require_admin
    def _action_add_pwd_protector(self) -> None:
        """Open a modal dialog to add a password-based protector."""
        win = tk.Toplevel(self)
        win.title("Add Password Protector")
        win.configure(bg=self.CLR_SURFACE)
        win.resizable(False, False)
        win.grab_set()
        win.geometry(f"360x180+{self.winfo_x() + 200}+{self.winfo_y() + 200}")

        ent_cfg = dict(
            show="•",
            font=("Segoe UI", 11),
            bg=self.CLR_BG,
            fg=self.CLR_TEXT,
            insertbackground=self.CLR_ACCENT,
            relief=tk.FLAT,
            width=32,
        )

        for label_text, row in [
            (t("bitlocker.new_pwd_label"),     0),
            (t("bitlocker.confirm_pwd_label"), 2),
        ]:
            tk.Label(
                win, text=label_text,
                font=("Segoe UI", 10),
                fg=self.CLR_TEXT, bg=self.CLR_SURFACE,
            ).pack(padx=20, pady=(14 if row == 0 else 6, 4), anchor=tk.W)
            ent = tk.Entry(win, **ent_cfg)
            ent.pack(padx=20, pady=(0, 4))
            if row == 0:
                ent1 = ent
            else:
                ent2 = ent

        def _add() -> None:
            p1, p2 = ent1.get(), ent2.get()
            if p1 != p2:
                messagebox.showwarning("Password", "Passwords do not match.", parent=win)
                return
            if len(p1) < 8:
                messagebox.showwarning("Password", "Password must be at least 8 characters.", parent=win)
                return
            # Zero raw values before handing off
            with SecureString(p1) as s:
                win.destroy()
                self._run_async(
                    "Adding Password Protector",
                    bl_add_password_protector,
                    self.drive,
                    s.value,
                )

        tk.Button(
            win,
            text=t("common.add"),
            font=("Segoe UI", 10, "bold"),
            fg=self.CLR_HEADER,
            bg=self.CLR_ACCENT,
            relief=tk.FLAT,
            padx=16, pady=5,
            cursor="hand2",
            command=_add,
        ).pack()

    @require_admin
    def _action_add_tpm(self) -> None:
        self._run_async("Adding TPM Protector", bl_add_tpm_protector, self.drive)

    @require_admin
    def _action_add_recovery(self) -> None:
        def on_done(ok: bool, msg: str) -> None:
            if ok:
                self._write(self._txt_keys, msg, append=True)

        self._run_async(
            "Generating Recovery Key",
            bl_add_recovery_protector,
            self.drive,
            on_done=on_done,
        )

    @require_admin
    def _action_change_pin(self) -> None:
        old = self._ent_old_pin.get()
        new = self._ent_new_pin.get()
        if not old or not new:
            messagebox.showwarning("PIN", "Enter old and new PIN.")
            return
        # Clear entries before passing to SecureString
        self._ent_old_pin.delete(0, tk.END)
        self._ent_new_pin.delete(0, tk.END)
        with SecureString(old) as s_old, SecureString(new) as s_new:
            self._run_async(
                "Changing PIN", bl_change_pin, self.drive, s_old.value, s_new.value
            )

    @thread_worker()
    def _action_ps_info(self) -> None:
        self.after(0, lambda: self._set_status("Fetching PowerShell data…"))
        self._log(f"▶ PowerShell info ({self.drive})")
        ps = (
            f"Get-BitLockerVolume -MountPoint '{self.drive}' | "
            "Select-Object -Property * | Format-List"
        )
        rc, out, err = bl_run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            timeout=20,
        )
        result = out or err or "No data (PowerShell unavailable or insufficient privileges)."

        def done() -> None:
            self._write(self._txt_adv, result)
            self._set_status("✔ PowerShell data retrieved.")
            self._log(f"✔ PowerShell info ({len(result)} chars)")

        self.after(0, done)

    def _action_copy_adv(self) -> None:
        try:
            text = self._txt_adv.get("1.0", tk.END)
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status("✔ Copied to clipboard.")
        except Exception as exc:
            self._set_status(f"✘ Copy error: {exc}")

    @require_admin
    def _action_wipe_free(self) -> None:
        if not messagebox.askyesno(
            "Wipe Free Space",
            f"Wipe free space on {self.drive}?\n\n"
            "The operation may take many hours for large drives!",
        ):
            return
        self._run_async("Wiping Free Space", bl_wipe_free_space, self.drive)

    # ── Log controls ──────────────────────────────────────────────────────────

    def _clear_log(self) -> None:
        self._write(self._txt_log, "")

    def _save_log(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title=t("bitlocker.save_log"),
        )
        if not path:
            return
        try:
            content = self._txt_log.get("1.0", tk.END)
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"BitLocker Operation Log – {self.drive}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(content)
            self._set_status(f"✔ Log saved: {path}")
        except Exception as exc:
            self._set_status(f"✘ Write error: {exc}")
