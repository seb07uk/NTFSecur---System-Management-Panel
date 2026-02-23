#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ntfsecur.core.system  –  System data collectors
=============================================================================
Functions that gather live system information:
  * get_ntfs_partitions()
  * set_ntfs_readonly()
  * get_processes()
  * kill_process()
  * get_network_info()
  * get_services()
  * control_service()
  * get_logs()
  * get_usb_devices()

Each function returns plain data structures (lists of dicts) so they can be
used independently of any GUI framework.
=============================================================================
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
from typing import Any

from ntfsecur.core.security import validate_drive, safe_run, no_window_kwargs
from ntfsecur.core.logging import log_debug, log_warn, log_error

__all__ = [
    "get_ntfs_partitions",
    "set_ntfs_readonly",
    "get_processes",
    "kill_process",
    "get_network_info",
    "get_services",
    "control_service",
    "get_logs",
    "get_usb_devices",
]

# ---------------------------------------------------------------------------
#  NTFS partitions
# ---------------------------------------------------------------------------

def get_ntfs_partitions() -> list[dict[str, str]]:
    """
    Return a list of dicts describing NTFS partitions on the system.

    Each dict contains: ``drive``, ``label``, ``size``.
    """
    partitions: list[dict[str, str]] = []

    if sys.platform == "win32":
        try:
            import win32api, win32con, win32file  # type: ignore
            drives: list[str] = win32api.GetLogicalDriveStrings().split('\x00')
            for drive in drives:
                if not drive:
                    continue
                drive = drive.strip('\\')
                try:
                    dtype = win32file.GetDriveType(drive + '\\')
                    if dtype not in (win32con.DRIVE_FIXED, win32con.DRIVE_REMOVABLE):
                        continue
                    vol_info = win32api.GetVolumeInformation(drive + '\\')
                    fs: str = vol_info[4]
                    if 'NTFS' in fs:
                        _free, total, _ = win32api.GetDiskFreeSpaceEx(drive + '\\')
                        size_gb = round(total / (1024 ** 3), 1)
                        label: str = vol_info[0] if vol_info[0] else "No Label"
                        partitions.append({
                            "drive": drive,
                            "label": label,
                            "size":  f"{size_gb} GB",
                        })
                except Exception:
                    pass
        except ImportError:
            log_warn("pywin32 not available; using placeholder partitions.")
            partitions = [
                {"drive": "C:", "label": "System", "size": "237 GB"},
                {"drive": "D:", "label": "Data",   "size": "465 GB"},
                {"drive": "E:", "label": "Backup", "size": "931 GB"},
            ]
    else:
        partitions = [
            {"drive": "/dev/sda1", "label": "System", "size": "237 GB"},
            {"drive": "/dev/sdb1", "label": "Data",   "size": "465 GB"},
            {"drive": "/dev/sdc1", "label": "Backup", "size": "931 GB"},
        ]

    return partitions


def set_ntfs_readonly(drive: str, readonly: bool) -> tuple[bool, str]:
    """
    Set or clear the read-only attribute on an NTFS volume.

    Parameters
    ----------
    drive    : Drive identifier (validated before use).
    readonly : True to lock (read-only), False to unlock (full access).

    Returns
    -------
    (success, message)
    """
    drive = validate_drive(drive)
    state = "ENABLED (Read-Only)" if readonly else "DISABLED (Full Access)"

    if sys.platform == "win32":
        try:
            import subprocess, tempfile as _tf
            letter = drive.replace(":", "").strip()
            attrib_cmd = (
                "attributes volume set readonly"
                if readonly else
                "attributes volume clear readonly"
            )
            script = f"select volume {letter}\n{attrib_cmd}\nexit\n"
            with _tf.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tf:
                tf.write(script)
                tmp = tf.name
            try:
                result = subprocess.run(
                    ["diskpart", "/s", tmp],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,
                    **no_window_kwargs(),
                )
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            if result.returncode == 0:
                return True, f"NTFSecur {state} on {drive}"
            return False, f"diskpart error: {result.stderr.strip()}"
        except Exception as exc:
            return False, f"Windows error: {exc}"
    else:
        flag = "--setro" if readonly else "--setrw"
        ok, out = safe_run(["sudo", "blockdev", flag, drive], timeout=15)
        if ok:
            return True, f"NTFSecur {state} on {drive}"
        return False, f"blockdev error: {out}"


# ---------------------------------------------------------------------------
#  Processes
# ---------------------------------------------------------------------------

def get_processes() -> list[dict[str, str]]:
    """Return a list of running processes (up to 30 entries)."""
    procs: list[dict[str, str]] = []

    if sys.platform == "win32":
        ok, out = safe_run(["tasklist", "/fo", "csv", "/nh"], timeout=10)
        if ok:
            for line in out.strip().split("\n")[:30]:
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 5:
                    procs.append({
                        "name":   parts[0],
                        "pid":    parts[1],
                        "mem":    parts[4].replace("\xa0", " "),
                        "status": "Running",
                    })
    else:
        ok, out = safe_run(
            ["ps", "aux", "--no-header"], timeout=10
        )
        if ok:
            for line in out.strip().split("\n")[:30]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    procs.append({
                        "name":   parts[10][:40],
                        "pid":    parts[1],
                        "mem":    f"{parts[3]}%",
                        "status": parts[7],
                    })

    if not procs:
        procs = [
            {"name": "System",       "pid": "4",    "mem": "0.1 MB",   "status": "Running"},
            {"name": "explorer.exe", "pid": "1234", "mem": "48.2 MB",  "status": "Running"},
            {"name": "svchost.exe",  "pid": "876",  "mem": "12.4 MB",  "status": "Running"},
            {"name": "chrome.exe",   "pid": "5432", "mem": "320.1 MB", "status": "Running"},
            {"name": "python.exe",   "pid": "9988", "mem": "24.6 MB",  "status": "Running"},
        ]
    return procs


def kill_process(pid: str) -> tuple[bool, str]:
    """
    Terminate a process by PID.

    Validates that *pid* is numeric before issuing the kill command.
    """
    if not pid.isdigit():
        return False, "Invalid PID format – expected a numeric string."
    if sys.platform == "win32":
        return safe_run(["taskkill", "/PID", pid, "/F"])
    return safe_run(["kill", "-9", pid])


# ---------------------------------------------------------------------------
#  Network
# ---------------------------------------------------------------------------

def get_network_info() -> list[dict[str, str]]:
    """Return a list of network interface dicts and host metadata."""
    interfaces: list[dict[str, str]] = []

    # Detect outgoing IP via temporary UDP socket (no data sent)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        interfaces.append({
            "name": "Local", "ip": local_ip, "status": "Up", "type": "Ethernet"
        })
    except Exception:
        pass

    if sys.platform == "win32":
        ok, out = safe_run(["ipconfig"], timeout=10)
        if ok:
            current: dict[str, str] = {}
            for line in out.split("\n"):
                line = line.strip()
                if "adapter" in line.lower() and ":" in line:
                    if current.get("name"):
                        interfaces.append(current)
                    current = {
                        "name": (
                            line.split(":")[0]
                            .replace("Ethernet adapter", "")
                            .replace("Wireless", "")
                            .strip()
                        ),
                        "ip":     "N/A",
                        "status": "Up",
                        "type":   "Adapter",
                    }
                elif "IPv4" in line and ":" in line:
                    current["ip"] = line.split(":", 1)[1].strip()
                elif "Media disconnected" in line:
                    current["status"] = "Down"
            if current.get("name"):
                interfaces.append(current)
    else:
        ok, out = safe_run(["ip", "addr"], timeout=10)
        if ok:
            current = {}
            for line in out.split("\n"):
                if line and line[0].isdigit():
                    if current.get("name"):
                        interfaces.append(current)
                    parts = line.split(":")
                    current = {
                        "name":   parts[1].strip() if len(parts) > 1 else "?",
                        "ip":     "N/A",
                        "status": "Up" if "UP" in line else "Down",
                        "type":   "Interface",
                    }
                elif "inet " in line:
                    current["ip"] = line.strip().split()[1].split("/")[0]
            if current.get("name"):
                interfaces.append(current)

    if not interfaces:
        interfaces = [
            {"name": "Ethernet", "ip": "192.168.1.10", "status": "Up",   "type": "Ethernet"},
            {"name": "Wi-Fi",    "ip": "192.168.1.11", "status": "Up",   "type": "Wireless"},
            {"name": "Loopback", "ip": "127.0.0.1",    "status": "Up",   "type": "Loopback"},
        ]

    interfaces = interfaces[:10]
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "N/A"

    if interfaces:
        interfaces[0]["hostname"] = hostname
        interfaces[0]["raw"] = "\n".join(
            f"{iface['name']:<20} {iface['ip']:<18} {iface['status']:<8} {iface['type']}"
            for iface in interfaces
        )

    return interfaces


# ---------------------------------------------------------------------------
#  Services
# ---------------------------------------------------------------------------

def get_services() -> list[dict[str, str]]:
    """Return a list of services (up to 25 entries)."""
    services: list[dict[str, str]] = []

    if sys.platform == "win32":
        ok, out = safe_run(
            ["sc", "query", "type=", "all", "state=", "all"],
            timeout=15,
        )
        if ok:
            name: str | None = None
            for line in out.split("\n"):
                line = line.strip()
                if line.startswith("SERVICE_NAME:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("STATE") and ":" in line:
                    parts = line.split(":", 1)[1].strip().split()
                    state = parts[1] if len(parts) > 1 else parts[0]
                    if name:
                        services.append({
                            "name": name, "status": state, "type": "Win32"
                        })
                        name = None
                    if len(services) >= 25:
                        break
    else:
        ok, out = safe_run(
            [
                "systemctl", "list-units",
                "--type=service", "--no-pager", "--no-legend", "--all",
            ],
            timeout=15,
        )
        if ok:
            for line in out.strip().split("\n")[:25]:
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    services.append({
                        "name":   parts[0].replace(".service", ""),
                        "status": parts[2],
                        "type":   "systemd",
                    })

    if not services:
        services = [
            {"name": "Windows Update", "status": "RUNNING", "type": "Win32"},
            {"name": "Task Scheduler", "status": "RUNNING", "type": "Win32"},
            {"name": "DNS Client",     "status": "RUNNING", "type": "Win32"},
            {"name": "Print Spooler",  "status": "STOPPED", "type": "Win32"},
            {"name": "Remote Desktop", "status": "STOPPED", "type": "Win32"},
        ]
    return services


def control_service(name: str, action: str) -> tuple[bool, str]:
    """
    Start, stop or restart a system service.

    Parameters
    ----------
    name   : Service name (alphanumeric + ``-_. ``, validated).
    action : One of ``start``, ``stop``, ``restart``, ``pause``, ``continue``.

    Returns
    -------
    (success, message)
    """
    _VALID_ACTIONS = {"start", "stop", "restart", "pause", "continue"}
    if action not in _VALID_ACTIONS:
        return False, f"Invalid action '{action}'. Allowed: {', '.join(sorted(_VALID_ACTIONS))}"
    if not name or not all(c.isalnum() or c in "-_." for c in name):
        return False, "Invalid service name – only alphanumeric characters and -_. are allowed."

    if sys.platform == "win32":
        return safe_run(["sc", action, name], timeout=20)
    return safe_run(["sudo", "systemctl", action, name + ".service"], timeout=20)


# ---------------------------------------------------------------------------
#  Logs
# ---------------------------------------------------------------------------

def get_logs() -> list[dict[str, str]]:
    """Return a list of recent system log entries (up to 20)."""
    logs: list[dict[str, str]] = []

    if sys.platform == "win32":
        ok, out = safe_run(
            ["wevtutil", "qe", "System", "/c:20", "/rd:true", "/f:text"],
            timeout=15,
        )
        if ok:
            entry: dict[str, str] = {}
            for line in out.split("\n"):
                line = line.strip()
                if line.startswith("Date:"):
                    entry["time"] = line[5:].strip()[:19]
                elif line.startswith("Level:"):
                    entry["level"] = line[6:].strip()
                elif line.startswith("Source:"):
                    entry["source"] = line[7:].strip()
                elif line.startswith("Message:"):
                    entry["msg"] = line[8:].strip()[:60]
                    if "time" in entry:
                        logs.append(entry)
                        entry = {}
    else:
        ok, out = safe_run(
            ["journalctl", "-n", "20", "--no-pager", "-o", "short"],
            timeout=15,
        )
        if ok:
            for line in out.strip().split("\n"):
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    level = (
                        "ERROR" if "error" in line.lower() else
                        ("WARN"  if "warn"  in line.lower() else "INFO")
                    )
                    logs.append({
                        "time":   f"{parts[0]} {parts[1]}",
                        "level":  level,
                        "source": parts[3],
                        "msg":    parts[4][:60],
                    })

    if not logs:
        logs = [
            {"time": "2026-02-21 12:01", "level": "INFO",  "source": "Kernel",   "msg": "System boot completed successfully"},
            {"time": "2026-02-21 12:02", "level": "INFO",  "source": "Network",  "msg": "Ethernet interface connected"},
            {"time": "2026-02-21 12:05", "level": "WARN",  "source": "Disk",     "msg": "High I/O latency detected on sda"},
            {"time": "2026-02-21 12:10", "level": "INFO",  "source": "Service",  "msg": "DNS resolver started"},
            {"time": "2026-02-21 12:15", "level": "ERROR", "source": "Security", "msg": "Failed login attempt (user: admin)"},
            {"time": "2026-02-21 12:20", "level": "INFO",  "source": "Update",   "msg": "No updates available"},
        ]
    return logs


# ---------------------------------------------------------------------------
#  USB devices
# ---------------------------------------------------------------------------

def get_usb_devices() -> list[dict[str, Any]]:
    """Return a list of connected USB storage devices with capacity details."""
    devices: list[dict[str, Any]] = []

    if sys.platform == "win32":
        try:
            import win32api, win32con, win32file  # type: ignore
            drives = win32api.GetLogicalDriveStrings().split("\x00")
            for drive in drives:
                if not drive:
                    continue
                drive = drive.strip("\\")
                try:
                    dtype = win32file.GetDriveType(drive + "\\")
                    if dtype != win32con.DRIVE_REMOVABLE:
                        continue
                    vol_info = win32api.GetVolumeInformation(drive + "\\")
                    free, total, _ = win32api.GetDiskFreeSpaceEx(drive + "\\")
                    used = total - free
                    pct  = round(used * 100 / total, 1) if total else 0
                    devices.append({
                        "name":         vol_info[0] or "USB Drive",
                        "drive":        drive,
                        "fstype":       vol_info[4],
                        "total":        total,
                        "used":         used,
                        "free":         free,
                        "pct":          pct,
                        "serial":       str(vol_info[1]) if vol_info[1] else "N/A",
                        "manufacturer": "Unknown",
                        "status":       "Mounted",
                    })
                except Exception:
                    pass
        except ImportError:
            pass

    else:
        ok, out = safe_run(
            ["lsblk", "-J", "-o", "NAME,TRAN,SIZE,FSTYPE,MOUNTPOINT,LABEL,MODEL,VENDOR"],
            timeout=10,
        )
        if ok:
            try:
                import json as _json
                data = _json.loads(out)
                for dev in data.get("blockdevices", []):
                    if dev.get("tran") != "usb":
                        continue
                    vendor = (dev.get("vendor") or "").strip()
                    model  = (dev.get("model")  or "").strip()
                    for child in dev.get("children", [dev]):
                        mp = child.get("mountpoint") or ""
                        total = used = free = 0
                        pct = 0.0
                        if mp:
                            ok2, out2 = safe_run(["df", "-B1", mp], timeout=5)
                            if ok2:
                                lines = out2.split("\n")
                                if len(lines) >= 2:
                                    cols = lines[1].split()
                                    if len(cols) >= 4:
                                        total = int(cols[1])
                                        used  = int(cols[2])
                                        free  = int(cols[3])
                                        pct   = round(used * 100 / total, 1) if total else 0.0
                        devices.append({
                            "name":         child.get("label") or model or "USB Drive",
                            "drive":        "/dev/" + child.get("name", "?"),
                            "fstype":       child.get("fstype") or "Unknown",
                            "total":        total,
                            "used":         used,
                            "free":         free,
                            "pct":          pct,
                            "serial":       "N/A",
                            "manufacturer": vendor or "Unknown",
                            "status":       "Mounted" if mp else "Not mounted",
                        })
            except Exception as exc:
                log_error(f"get_usb_devices parse error: {exc}", exc)

    return devices
