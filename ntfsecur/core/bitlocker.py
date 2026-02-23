#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.core.bitlocker  –  BitLocker management helpers
=============================================================================
All manage-bde / PowerShell calls are centralised here.
Every public function returns ``(success: bool, message: str)``.

Security notes
--------------
* Passwords are never passed to :func:`~ntfsecur.core.security.safe_run`
  (which would log the command).  Functions that accept passwords call
  subprocess directly and are clearly annotated.
* Drive identifiers are validated with :func:`~ntfsecur.core.security.validate_drive`
  before any subprocess call, preventing command injection.
* Recovery keys saved to disk are placed in the user's chosen location;
  callers should warn users about the sensitivity of the file.
=============================================================================
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Optional

from ntfsecur.core.security import validate_drive, no_window_kwargs, SecureString
from ntfsecur.core.logging import log_debug, log_warn, log_error

__all__ = [
    "bl_run",
    "bl_status",
    "bl_enable",
    "bl_disable",
    "bl_lock",
    "bl_unlock_password",
    "bl_unlock_recovery",
    "bl_suspend",
    "bl_resume",
    "bl_get_recovery_key",
    "bl_backup_recovery_to_ad",
    "bl_add_password_protector",
    "bl_add_tpm_protector",
    "bl_add_recovery_protector",
    "bl_change_pin",
    "bl_wipe_free_space",
]

# ---------------------------------------------------------------------------
#  Low-level runner
# ---------------------------------------------------------------------------

def bl_run(
    args: list[str],
    timeout: int = 30,
) -> tuple[int, str, str]:
    """
    Run a manage-bde or PowerShell command.

    Returns
    -------
    (returncode, stdout, stderr)
        ``returncode == 0`` signals success.
    """
    log_debug(f"bl_run: {' '.join(args)}")
    try:
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="cp1250",
            errors="replace",
            shell=False,
            **no_window_kwargs(),
        )
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError as exc:
        return -1, "", str(exc)
    except subprocess.TimeoutExpired:
        log_warn(f"bl_run timeout: {' '.join(args)}")
        return -2, "", "Timeout"
    except Exception as exc:
        log_error(f"bl_run exception: {exc}")
        return -99, "", str(exc)


# ---------------------------------------------------------------------------
#  Status query
# ---------------------------------------------------------------------------

def bl_status(drive: str) -> dict:
    """
    Return a dict with BitLocker status for *drive* (e.g. ``"C:"``).

    Keys
    ----
    drive, protection, conversion, percentage, method,
    lock_status, key_protectors, raw, error
    """
    drive = validate_drive(drive)
    rc, out, err = bl_run(["manage-bde", "-status", drive])

    info: dict = {
        "drive":          drive,
        "protection":     "Unknown",
        "conversion":     "Unknown",
        "percentage":     "–",
        "method":         "–",
        "lock_status":    "Unknown",
        "key_protectors": [],
        "raw":            out or err,
        "error":          rc != 0,
    }

    if rc != 0:
        # Fallback to PowerShell
        ps = (
            f"Get-BitLockerVolume -MountPoint '{drive}' | "
            "Select-Object -Property MountPoint,ProtectionStatus,"
            "EncryptionMethod,EncryptionPercentage,LockStatus,"
            "KeyProtector | ConvertTo-Json"
        )
        rc2, out2, _ = bl_run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            timeout=20,
        )
        if rc2 == 0 and out2.strip():
            try:
                j = json.loads(out2.strip())
                kp = j.get("KeyProtector") or []
                info.update({
                    "protection":     str(j.get("ProtectionStatus", "Unknown")),
                    "conversion":     f"{j.get('EncryptionPercentage', 0)}%",
                    "percentage":     f"{j.get('EncryptionPercentage', 0)}%",
                    "method":         str(j.get("EncryptionMethod", "–")),
                    "lock_status":    str(j.get("LockStatus", "Unknown")),
                    "key_protectors": [str(k.get("KeyProtectorType", k)) for k in kp],
                    "error":          False,
                })
                return info
            except Exception:
                pass
        info["raw"] = err or out or "manage-bde not available"
        return info

    for line in out.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key_lower = key.strip().lower()
        val = val.strip()
        if "protection" in key_lower and "status" in key_lower:
            info["protection"] = val
        elif "conversion" in key_lower and "status" in key_lower:
            info["conversion"] = val
        elif "percentage" in key_lower:
            info["percentage"] = val
        elif "encryption method" in key_lower:
            info["method"] = val
        elif "lock status" in key_lower:
            info["lock_status"] = val
        elif "key protector" in key_lower or "protectors" in key_lower:
            info["key_protectors"].append(val)

    return info


# ---------------------------------------------------------------------------
#  Enable / Disable
# ---------------------------------------------------------------------------

def bl_enable(
    drive: str,
    recovery_password: bool = True,
) -> tuple[bool, str]:
    """Start BitLocker encryption on *drive*."""
    drive = validate_drive(drive)
    args = ["manage-bde", "-on", drive]
    if recovery_password:
        args += ["-RecoveryPassword"]
    rc, out, err = bl_run(args, timeout=60)
    if rc == 0:
        return True, out.strip() or "BitLocker encryption started."
    return False, err.strip() or out.strip() or "Error enabling BitLocker."


def bl_disable(drive: str) -> tuple[bool, str]:
    """Decrypt and remove BitLocker from *drive*."""
    drive = validate_drive(drive)
    rc, out, err = bl_run(["manage-bde", "-off", drive], timeout=60)
    if rc == 0:
        return True, out.strip() or "BitLocker disabled."
    return False, err.strip() or out.strip() or "Error disabling BitLocker."


# ---------------------------------------------------------------------------
#  Lock / Unlock
# ---------------------------------------------------------------------------

def bl_lock(drive: str, force: bool = False) -> tuple[bool, str]:
    """Lock *drive*.  Pass ``force=True`` to force-dismount first."""
    drive = validate_drive(drive)
    args = ["manage-bde", "-lock", drive]
    if force:
        args.append("-ForceDismount")
    rc, out, err = bl_run(args, timeout=20)
    if rc == 0:
        return True, out.strip() or "Drive locked."
    return False, err.strip() or out.strip() or "Error locking drive."


def bl_unlock_password(drive: str, password: str) -> tuple[bool, str]:
    """
    Unlock *drive* using *password*.

    Security note
    -------------
    ``manage-bde`` requires the password as a CLI argument.  This function
    does **not** pass the command through :func:`bl_run` (which logs args)
    to avoid leaking the password to the log file.
    """
    drive = validate_drive(drive)
    with SecureString(password) as pwd:
        cmd = ["manage-bde", "-unlock", drive, "-Password", pwd.value]
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=20,
                encoding="cp1250",
                errors="replace",
                shell=False,
                **no_window_kwargs(),
            )
            if r.returncode == 0:
                return True, r.stdout.strip() or "Unlocked with password."
            return False, r.stderr.strip() or r.stdout.strip() or "Error unlocking drive."
        except Exception as exc:
            return False, str(exc)


def bl_unlock_recovery(
    drive: str,
    recovery_key: str,
) -> tuple[bool, str]:
    """Unlock *drive* using a 48-digit recovery key."""
    drive = validate_drive(drive)
    rc, out, err = bl_run(
        ["manage-bde", "-unlock", drive, "-RecoveryPassword", recovery_key],
        timeout=20,
    )
    if rc == 0:
        return True, out.strip() or "Unlocked with recovery key."
    return False, err.strip() or out.strip() or "Error unlocking drive."


# ---------------------------------------------------------------------------
#  Suspend / Resume
# ---------------------------------------------------------------------------

def bl_suspend(drive: str, count: int = 1) -> tuple[bool, str]:
    """Temporarily suspend BitLocker protection for *count* reboots."""
    drive = validate_drive(drive)
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-disable", drive, "-RebootCount", str(count)],
        timeout=30,
    )
    if rc == 0:
        return True, out.strip() or "Protection suspended."
    return False, err.strip() or out.strip() or "Error suspending protection."


def bl_resume(drive: str) -> tuple[bool, str]:
    """Resume BitLocker protection on *drive*."""
    drive = validate_drive(drive)
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-enable", drive],
        timeout=30,
    )
    if rc == 0:
        return True, out.strip() or "Protection resumed."
    return False, err.strip() or out.strip() or "Error resuming protection."


# ---------------------------------------------------------------------------
#  Key / protector management
# ---------------------------------------------------------------------------

def bl_get_recovery_key(drive: str) -> tuple[bool, str]:
    """Return the recovery key / password ID for *drive*."""
    drive = validate_drive(drive)
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-get", drive, "-Type", "RecoveryPassword"],
        timeout=20,
    )
    if rc == 0:
        return True, out.strip()
    # Fallback: list all protectors
    rc2, out2, err2 = bl_run(["manage-bde", "-protectors", "-get", drive], timeout=20)
    if rc2 == 0:
        return True, out2.strip()
    return False, err.strip() or err2.strip() or "No recovery key data."


def bl_backup_recovery_to_ad(drive: str) -> tuple[bool, str]:
    """Backup the recovery key to Active Directory via PowerShell."""
    drive = validate_drive(drive)
    ps = (
        f"$vol = Get-BitLockerVolume -MountPoint '{drive}';"
        f"$kp = $vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq 'RecoveryPassword' }};"
        f"if ($kp) {{ Backup-BitLockerKeyProtector -MountPoint '{drive}' "
        f"-KeyProtectorId $kp[0].KeyProtectorId; Write-Output 'OK' }}"
        f" else {{ Write-Output 'NoKey' }}"
    )
    rc, out, err = bl_run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        timeout=20,
    )
    if rc == 0 and "OK" in out:
        return True, "Recovery key archived in Active Directory."
    return False, err.strip() or out.strip() or "AD backup error."


def bl_add_password_protector(drive: str, password: str) -> tuple[bool, str]:
    """
    Add a password-based protector to *drive*.

    Security note
    -------------
    Password is never logged (see :func:`bl_unlock_password`).
    """
    drive = validate_drive(drive)
    with SecureString(password) as pwd:
        try:
            r = subprocess.run(
                ["manage-bde", "-protectors", "-add", drive, "-Password", pwd.value],
                capture_output=True,
                text=True,
                timeout=20,
                encoding="cp1250",
                errors="replace",
                shell=False,
                **no_window_kwargs(),
            )
            if r.returncode == 0:
                return True, r.stdout.strip() or "Password protector added."
            return False, r.stderr.strip() or r.stdout.strip() or "Error adding protector."
        except Exception as exc:
            return False, str(exc)


def bl_add_tpm_protector(drive: str) -> tuple[bool, str]:
    """Add a TPM protector to *drive*."""
    drive = validate_drive(drive)
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-add", drive, "-Tpm"],
        timeout=20,
    )
    if rc == 0:
        return True, out.strip() or "TPM protector added."
    return False, err.strip() or out.strip() or "Error adding TPM protector."


def bl_add_recovery_protector(drive: str) -> tuple[bool, str]:
    """Generate and add a new 48-digit recovery password for *drive*."""
    drive = validate_drive(drive)
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-add", drive, "-RecoveryPassword"],
        timeout=20,
    )
    if rc == 0:
        return True, out.strip() or "Recovery password protector added."
    return False, err.strip() or out.strip() or "Error adding recovery protector."


def bl_change_pin(drive: str, old_pin: str, new_pin: str) -> tuple[bool, str]:
    """
    Change the TPM+PIN protector PIN on *drive*.

    Security note
    -------------
    PINs are not logged.
    """
    drive = validate_drive(drive)
    with SecureString(old_pin) as old, SecureString(new_pin) as new_:
        try:
            r = subprocess.run(
                ["manage-bde", "-changepin", drive],
                input=f"{old.value}\n{new_.value}\n{new_.value}\n",
                capture_output=True,
                text=True,
                timeout=20,
                encoding="cp1250",
                errors="replace",
                shell=False,
                **no_window_kwargs(),
            )
            if r.returncode == 0:
                return True, r.stdout.strip() or "PIN changed."
            return False, r.stderr.strip() or r.stdout.strip() or "Error changing PIN."
        except Exception as exc:
            return False, str(exc)


def bl_wipe_free_space(drive: str) -> tuple[bool, str]:
    """Securely wipe the free space on *drive*."""
    drive = validate_drive(drive)
    rc, out, err = bl_run(
        ["manage-bde", "-wipefreespace", drive],
        timeout=3600,  # can take hours on large drives
    )
    if rc == 0:
        return True, out.strip() or "Free space wiped."
    return False, err.strip() or out.strip() or "Error wiping free space."
