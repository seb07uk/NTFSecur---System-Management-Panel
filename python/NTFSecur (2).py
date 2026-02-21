#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
PolSoft System Management Panel
=============================================================================
Author      : Sebastian Januchowski
Email       : polsoft.its@fastservice.com
GitHub      : https://github.com/seb07uk
Copyright   : 2026© polsoft.ITS™. All rights reserved.
Version     : 2.0.0
Description : System Management Panel – NTFSecur + Processes + Network +
              Services + Logs modules
=============================================================================
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import ctypes
import sys

def _no_window_kwargs():
    """Zwraca kwargs dla subprocess.run ukrywające okno konsoli na Windows."""
    if sys.platform != "win32":
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags    |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return {
        "startupinfo":   si,
        "creationflags": subprocess.CREATE_NO_WINDOW,
    }
import os
import threading
import platform
import socket
import sqlite3
import json
import csv
import datetime

__author__    = "Sebastian Januchowski"
__email__     = "polsoft.its@fastservice.com"
__github__    = "https://github.com/seb07uk"
__copyright__ = "2026© polsoft.ITS™. All rights reserved."
__version__   = "2.0.0"
__product__   = "PolSoft System Management Panel"


# ─────────────────────────────────────────────────────────────────────────────
#  Application paths – centralised, cross-platform
# ─────────────────────────────────────────────────────────────────────────────
class AppPaths:
    """
    Single source of truth for every file / directory the application uses.

    Layout:
        %USERPROFILE%\\.polsoft\\software\\NTFSecur\\
            settings.json       – user preferences / theme
            NTFSecur.log        – general activity log
            error.log           – error / exception log
            usb_history.db      – SQLite USB history database
            diskpart_tmp.txt    – temporary diskpart script (auto-deleted)
            report\\            – generated HTML reports
    """

    # Root: %USERPROFILE%\.polsoft\software\NTFSecur  (Win)
    #       ~/.polsoft/software/NTFSecur               (Linux/macOS)
    if sys.platform == "win32":
        _BASE = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")),
                             ".polsoft", "software", "NTFSecur")
    else:
        _BASE = os.path.join(os.path.expanduser("~"),
                             ".polsoft", "software", "NTFSecur")

    BASE        = _BASE
    SETTINGS    = os.path.join(_BASE, "settings.json")
    LOG         = os.path.join(_BASE, "NTFSecur.log")
    ERROR_LOG   = os.path.join(_BASE, "error.log")
    DB          = os.path.join(_BASE, "usb_history.db")
    DISKPART_TMP= os.path.join(_BASE, "diskpart_tmp.txt")
    REPORT_DIR  = os.path.join(_BASE, "report")

    @classmethod
    def ensure_dirs(cls):
        """Create all required directories if they don't exist."""
        for d in (cls.BASE, cls.REPORT_DIR):
            os.makedirs(d, exist_ok=True)

    @classmethod
    def report_path(cls, filename: str) -> str:
        """Return full path for a report file inside the report sub-folder."""
        return os.path.join(cls.REPORT_DIR, filename)


# Ensure directories exist at import time
AppPaths.ensure_dirs()


# ─────────────────────────────────────────────────────────────────────────────
#  Logging helpers
# ─────────────────────────────────────────────────────────────────────────────
import logging as _logging
import traceback as _traceback

def _setup_logging():
    fmt = _logging.Formatter(
        "%(asctime)s  [%(levelname)-8s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Activity logger
    _act = _logging.getLogger("ntfsecur")
    _act.setLevel(_logging.DEBUG)
    if not _act.handlers:
        fh = _logging.FileHandler(AppPaths.LOG, encoding="utf-8")
        fh.setFormatter(fmt)
        _act.addHandler(fh)

    # Error logger
    _err = _logging.getLogger("ntfsecur.error")
    _err.setLevel(_logging.WARNING)
    if not _err.handlers:
        eh = _logging.FileHandler(AppPaths.ERROR_LOG, encoding="utf-8")
        eh.setFormatter(fmt)
        _err.addHandler(eh)

_setup_logging()
app_log   = _logging.getLogger("ntfsecur")
error_log = _logging.getLogger("ntfsecur.error")


def log_info(msg: str):
    app_log.info(msg)

def log_debug(msg: str):
    app_log.debug(msg)

def log_warn(msg: str):
    app_log.warning(msg)
    error_log.warning(msg)

def log_error(msg: str, exc: Exception = None):
    app_log.error(msg)
    if exc:
        error_log.error(f"{msg}\n{_traceback.format_exc()}")
    else:
        error_log.error(msg)


# ─────────────────────────────────────────────────────────────────────────────
#  Factory / Default settings  –  wzorzec producenta
#  Edytuj FACTORY_SETTINGS aby zmienic domyslne ustawienia po kompilacji.
# ─────────────────────────────────────────────────────────────────────────────
FACTORY_SETTINGS: dict = {
    # Interfejs
    "theme":              "dark",
    "last_module":        "NTFSecur",
    "window_geometry":    "960x640",
    "window_locked":      False,
    # Zachowanie
    "log_level":          "INFO",
    "scan_interval_sec":  0,
    "confirm_dangerous":  True,
    "show_watermark":     True,
    # Drives
    "drives_default_tab": "overview",
    "bench_size_mb":      256,
    # Metadane (tylko do odczytu)
    "version":            __version__,
    "build_date":         "2026-02-17",
    "author":             __author__,
    "product":            __product__,
}

# Alias dla kompatybilnosci wstecznej
_DEFAULT_SETTINGS: dict = FACTORY_SETTINGS


class Settings:
    """Read/write application settings to settings.json.

    Priorytety:
      1. FACTORY_SETTINGS  – wbudowane wartosci domyslne
      2. settings.json     – zapisane preferencje uzytkownika  (nadpisuje factory)
    Przy pierwszym uruchomieniu plik jest tworzony z wartosciami fabrycznymi.
    """

    def __init__(self):
        self._path = AppPaths.SETTINGS
        self._data: dict = dict(FACTORY_SETTINGS)
        self._load()

    def _load(self):
        try:
            if os.path.exists(self._path):
                with open(self._path, "r", encoding="utf-8") as f:
                    stored = json.load(f)
                for k, v in stored.items():
                    self._data[k] = v
                log_info(f"Settings loaded from {self._path}")
            else:
                # Pierwsze uruchomienie – zapisz ustawienia fabryczne
                self.save()
                log_info("First run – factory settings written to disk.")
        except Exception as e:
            log_error(f"Failed to load settings: {e}", e)

    def save(self):
        try:
            self._data["version"] = __version__
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=4, ensure_ascii=False)
            log_debug(f"Settings saved to {self._path}")
        except Exception as e:
            log_error(f"Failed to save settings: {e}", e)

    def reset_to_factory(self):
        """Przywroc ustawienia fabryczne i zapisz na dysk."""
        self._data = dict(FACTORY_SETTINGS)
        self.save()
        log_info("Settings reset to factory defaults.")

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value):
        self._data[key] = value

    def as_dict(self) -> dict:
        return dict(self._data)

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value


# Singleton
_settings: Settings = None

def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────
def is_admin() -> bool:
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def run_cmd(cmd: list, timeout: int = 10) -> tuple:
    try:
        log_debug(f"run_cmd: {' '.join(str(c) for c in cmd)}")

        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, **_no_window_kwargs())
        out = r.stdout.strip() or r.stderr.strip()
        if r.returncode != 0:
            log_warn(f"run_cmd failed (rc={r.returncode}): {' '.join(str(c) for c in cmd)} → {out[:120]}")
        return r.returncode == 0, out
    except FileNotFoundError:
        msg = f"Polecenie '{cmd[0]}' nie znalezione."
        log_error(msg)
        return False, msg
    except subprocess.TimeoutExpired:
        msg = "Przekroczono czas oczekiwania."
        log_warn(f"run_cmd timeout: {' '.join(str(c) for c in cmd)}")
        return False, msg
    except Exception as e:
        log_error(f"run_cmd exception: {e}", e)
        return False, str(e)


# ─────────────────────────────────────────────────────────────────────────────
#  USB Database – SQLite persistent storage for USB device history
# ─────────────────────────────────────────────────────────────────────────────
class USBDatabase:
    """Persistent SQLite database for USB device history tracking."""

    DB_FILE = AppPaths.DB

    def __init__(self):
        self._conn = sqlite3.connect(self.DB_FILE, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS usb_devices (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                connect_count INTEGER DEFAULT 1,
                name          TEXT,
                drive         TEXT,
                fstype        TEXT,
                total_bytes   INTEGER DEFAULT 0,
                used_bytes    INTEGER DEFAULT 0,
                free_bytes    INTEGER DEFAULT 0,
                serial        TEXT,
                manufacturer  TEXT,
                status        TEXT
            );

            CREATE TABLE IF NOT EXISTS usb_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT NOT NULL,
                event_type   TEXT NOT NULL,
                device_id    INTEGER,
                name         TEXT,
                drive        TEXT,
                fstype       TEXT,
                serial       TEXT,
                manufacturer TEXT,
                total_bytes  INTEGER DEFAULT 0,
                notes        TEXT,
                FOREIGN KEY (device_id) REFERENCES usb_devices(id)
            );

            CREATE INDEX IF NOT EXISTS idx_events_ts      ON usb_events(ts);
            CREATE INDEX IF NOT EXISTS idx_devices_serial ON usb_devices(serial);
        """)
        self._conn.commit()

    def _now(self) -> str:
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def record_scan(self, devices: list):
        """Called after each USB scan – upserts device records and logs events."""
        now = self._now()
        cur = self._conn.cursor()

        for dev in devices:
            serial = dev.get('serial') or 'N/A'
            name   = dev.get('name', 'USB Drive')
            drive  = dev.get('drive', '?')

            # Try to find existing record by serial (or name+fstype if serial unknown)
            if serial != 'N/A':
                cur.execute("SELECT id, connect_count FROM usb_devices WHERE serial = ?", (serial,))
            else:
                cur.execute(
                    "SELECT id, connect_count FROM usb_devices WHERE name = ? AND fstype = ?",
                    (name, dev.get('fstype', '')))
            row = cur.fetchone()

            if row:
                dev_id = row['id']
                cur.execute("""
                    UPDATE usb_devices
                    SET last_seen = ?, connect_count = ?, name = ?, drive = ?,
                        fstype = ?, total_bytes = ?, used_bytes = ?, free_bytes = ?,
                        manufacturer = ?, status = ?
                    WHERE id = ?
                """, (now, row['connect_count'] + 1, name, drive,
                      dev.get('fstype', ''), dev.get('total', 0), dev.get('used', 0),
                      dev.get('free', 0), dev.get('manufacturer', 'Unknown'),
                      dev.get('status', 'OK'), dev_id))
            else:
                cur.execute("""
                    INSERT INTO usb_devices
                        (first_seen, last_seen, connect_count, name, drive, fstype,
                         total_bytes, used_bytes, free_bytes, serial, manufacturer, status)
                    VALUES (?,?,1,?,?,?,?,?,?,?,?,?)
                """, (now, now, name, drive, dev.get('fstype', ''),
                      dev.get('total', 0), dev.get('used', 0), dev.get('free', 0),
                      serial, dev.get('manufacturer', 'Unknown'), dev.get('status', 'OK')))
                dev_id = cur.lastrowid

            # Log event
            cur.execute("""
                INSERT INTO usb_events
                    (ts, event_type, device_id, name, drive, fstype, serial,
                     manufacturer, total_bytes, notes)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (now, 'DETECTED', dev_id, name, drive, dev.get('fstype', ''),
                  serial, dev.get('manufacturer', 'Unknown'), dev.get('total', 0), ''))

        self._conn.commit()

    def get_all_devices(self, search: str = "", order: str = "last_seen DESC") -> list:
        """Return all known USB devices from history."""
        safe_order = order if order in (
            "last_seen DESC", "last_seen ASC", "first_seen DESC",
            "connect_count DESC", "name ASC", "total_bytes DESC"
        ) else "last_seen DESC"

        q = f"%{search}%"
        sql = """
            SELECT * FROM usb_devices
            WHERE name LIKE ? OR serial LIKE ? OR manufacturer LIKE ? OR fstype LIKE ?
            ORDER BY {}
        """.format(safe_order)
        cur = self._conn.execute(sql, (q, q, q, q))
        return [dict(r) for r in cur.fetchall()]

    def get_events(self, device_id: int = None, limit: int = 200) -> list:
        """Return recent USB events, optionally filtered by device."""
        if device_id:
            cur = self._conn.execute(
                "SELECT * FROM usb_events WHERE device_id = ? ORDER BY ts DESC LIMIT ?",
                (device_id, limit))
        else:
            cur = self._conn.execute(
                "SELECT * FROM usb_events ORDER BY ts DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]

    def delete_device(self, device_id: int):
        """Remove a device and its events from history."""
        self._conn.execute("DELETE FROM usb_events WHERE device_id = ?", (device_id,))
        self._conn.execute("DELETE FROM usb_devices WHERE id = ?", (device_id,))
        self._conn.commit()

    def clear_all(self):
        """Wipe entire history."""
        self._conn.executescript("DELETE FROM usb_events; DELETE FROM usb_devices;")
        self._conn.commit()

    def export_csv(self, filepath: str):
        """Export device history to CSV."""
        devices = self.get_all_devices()
        if not devices:
            return False, "No data to export."
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=devices[0].keys())
                writer.writeheader()
                writer.writerows(devices)
            return True, f"Export completed: {filepath}"
        except Exception as e:
            return False, str(e)

    def get_stats(self) -> dict:
        """Return aggregate statistics."""
        cur = self._conn.execute("SELECT COUNT(*) as cnt FROM usb_devices")
        total = cur.fetchone()['cnt']
        cur = self._conn.execute("SELECT COUNT(*) as cnt FROM usb_events")
        events = cur.fetchone()['cnt']
        cur = self._conn.execute(
            "SELECT name, connect_count FROM usb_devices ORDER BY connect_count DESC LIMIT 1")
        most = cur.fetchone()
        cur = self._conn.execute(
            "SELECT name, total_bytes FROM usb_devices ORDER BY total_bytes DESC LIMIT 1")
        biggest = cur.fetchone()
        return {
            'total_devices': total,
            'total_events':  events,
            'most_connected': dict(most) if most else {},
            'biggest_device': dict(biggest) if biggest else {},
        }

    def close(self):
        self._conn.close()


# Singleton instance (created lazily)
_usb_db: USBDatabase = None

def get_usb_db() -> USBDatabase:
    global _usb_db
    if _usb_db is None:
        _usb_db = USBDatabase()
    return _usb_db


# ─── NTFSecur ────────────────────────────────────────────────────────────────
def get_ntfs_partitions() -> list:
    if sys.platform == "win32":
        try:
            import win32api, win32con, win32file
            partitions = []
            drives = win32api.GetLogicalDriveStrings().split('\x00')
            for drive in drives:
                if not drive:
                    continue
                drive = drive.strip('\\')
                try:
                    dtype = win32file.GetDriveType(drive + '\\')
                    if dtype not in (win32con.DRIVE_FIXED, win32con.DRIVE_REMOVABLE):
                        continue
                    vol_info = win32api.GetVolumeInformation(drive + '\\')
                    if 'NTFS' in vol_info[4]:
                        _, total, _ = win32api.GetDiskFreeSpaceEx(drive + '\\')
                        partitions.append({
                            'drive': drive,
                            'label': vol_info[0] or "No Label",
                            'size': f"{round(total/(1024**3),1)} GB"
                        })
                except Exception:
                    pass
            return partitions
        except ImportError:
            # Fallback: use PowerShell to get actual NTFS drives
            ok, out = run_cmd(['powershell', '-NoProfile', '-Command',
                              'Get-Volume | Where-Object {$_.FileSystem -eq "NTFS"} | '
                              'Select-Object DriveLetter, Label, Size | ConvertTo-Csv -NoTypeInformation'],
                             timeout=15)
            if ok:
                partitions = []
                lines = out.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    parts = [p.strip('"').strip() for p in line.split(',')]
                    if len(parts) >= 3 and parts[0]:
                        try:
                            size_gb = round(int(parts[2]) / (1024**3), 1)
                            partitions.append({
                                'drive': parts[0] + ':' if parts[0] else '?:',
                                'label': parts[1] or "No Label",
                                'size': f"{size_gb} GB"
                            })
                        except ValueError:
                            pass
                return partitions
            return []
    else:
        # Linux: Use lsblk to find NTFS partitions
        ok, out = run_cmd(['lsblk', '-o', 'NAME,FSTYPE,SIZE,LABEL', '-J'], timeout=10)
        partitions = []
        if ok:
            try:
                import json
                data = json.loads(out)
                for dev in data.get('blockdevices', []):
                    for child in dev.get('children', []):
                        if child.get('fstype') == 'ntfs':
                            partitions.append({
                                'drive': '/dev/' + child.get('name', '?'),
                                'label': child.get('label', 'No Label'),
                                'size': child.get('size', '0 B')
                            })
            except Exception:
                pass
        return partitions


def set_ntfs_readonly(drive: str, readonly: bool) -> tuple:
    action_str = "READ-ONLY" if readonly else "READ-WRITE"
    log_info(f"set_ntfs_readonly: drive={drive} mode={action_str}")
    if sys.platform == "win32":
        try:
            letter = drive.replace(':', '').strip()
            cmd = "attributes volume set readonly" if readonly else "attributes volume clear readonly"
            script = f"select volume {letter}\n{cmd}\nexit\n"
            tmp = AppPaths.DISKPART_TMP
            with open(tmp, 'w') as f:
                f.write(script)
            result = subprocess.run(['diskpart', '/s', tmp], capture_output=True, text=True, timeout=30, **_no_window_kwargs())
            try:
                os.remove(tmp)
            except Exception:
                pass
            if result.returncode == 0:
                state = "ENABLED (Read-Only)" if readonly else "DISABLED (Full Access)"
                msg = f"NTFSecur {state} on {drive}"
                log_info(msg)
                return True, msg
            err = f"diskpart error: {result.stderr.strip()}"
            log_error(err)
            return False, err
        except Exception as e:
            log_error(f"set_ntfs_readonly Windows error: {e}", e)
            return False, f"Windows error: {e}"
    else:
        try:
            flag = '--setro' if readonly else '--setrw'
            result = subprocess.run(['sudo', 'blockdev', flag, drive],
                                    capture_output=True, text=True, timeout=15,
                                    **_no_window_kwargs())
            if result.returncode == 0:
                state = "ENABLED (Read-Only)" if readonly else "DISABLED (Full Access)"
                msg = f"NTFSecur {state} on {drive}"
                log_info(msg)
                return True, msg
            err = f"blockdev error: {result.stderr.strip()}"
            log_error(err)
            return False, err
        except Exception as e:
            log_error(f"set_ntfs_readonly Linux error: {e}", e)
            return False, f"Linux error: {e}"


# ─── BitLocker ───────────────────────────────────────────────────────────────
def get_bitlocker_status(drive: str) -> dict:
    """Get BitLocker status for a drive (Windows only)"""
    if sys.platform != "win32":
        return {'status': 'N/A', 'protection': 'N/A', 'percent': 0, 'error': 'Linux system'}
    
    try:
        letter = drive.replace(':', '').strip().upper()
        result = subprocess.run(['manage-bde', '-status', f'{letter}:'],
                              capture_output=True, text=True, timeout=10,
              **_no_window_kwargs())
        if result.returncode == 0:
            out = result.stdout.lower()
            if 'protection on' in out:
                status = 'Protected'
                percent = 100
            elif 'protection off' in out:
                status = 'Unprotected'
                percent = 0
            elif 'encryption in progress' in out:
                status = 'Encrypting'
                percent = int(''.join(filter(str.isdigit, 
                        [l for l in result.stdout.split('\n') if 'percent' in l.lower()][:1])) or '0')
            elif 'decryption in progress' in out:
                status = 'Decrypting'
                percent = int(''.join(filter(str.isdigit, 
                        [l for l in result.stdout.split('\n') if 'percent' in l.lower()][:1])) or '0')
            else:
                status = 'Unknown'
                percent = 0
            
            return {
                'status': status,
                'protection': 'ON' if 'protection on' in out else 'OFF',
                'percent': percent,
                'error': None
            }
        else:
            # BitLocker might not be available on this edition
            if 'not compatible' in result.stderr.lower() or 'not supported' in result.stderr.lower():
                return {'status': 'Unavailable', 'protection': 'N/A', 'percent': 0, 
                       'error': 'BitLocker not available (requires Pro/Enterprise)'}
            return {'status': 'Error', 'protection': 'N/A', 'percent': 0, 'error': result.stderr.strip()}
    except FileNotFoundError:
        return {'status': 'Error', 'protection': 'N/A', 'percent': 0, 
               'error': 'manage-bde command not found'}
    except Exception as e:
        return {'status': 'Error', 'protection': 'N/A', 'percent': 0, 'error': str(e)}


def control_bitlocker(drive: str, action: str) -> tuple:
    """Enable or suspend BitLocker (Windows only)"""
    if sys.platform != "win32":
        return False, "BitLocker is Windows-only"
    
    if action not in ['on', 'off', 'suspend', 'resume']:
        return False, f"Invalid action: {action}"
    
    try:
        letter = drive.replace(':', '').strip().upper()
        
        if action == 'on':
            # Start encryption - requires TPM or password
            result = subprocess.run(['manage-bde', '-on', f'{letter}:'],
                                  capture_output=True, text=True, timeout=30,
                                  **_no_window_kwargs())
        elif action == 'off':
            # Decrypt
            result = subprocess.run(['manage-bde', '-off', f'{letter}:'],
                                  capture_output=True, text=True, timeout=30,
                                  **_no_window_kwargs())
        elif action == 'suspend':
            # Temporarily suspend protection
            result = subprocess.run(['manage-bde', '-protectors', '-disable', f'{letter}:'],
                                  capture_output=True, text=True, timeout=30,
                                  **_no_window_kwargs())
        else:  # resume
            # Resume protection
            result = subprocess.run(['manage-bde', '-protectors', '-enable', f'{letter}:'],
                                  capture_output=True, text=True, timeout=30,
                                  **_no_window_kwargs())
        
        if result.returncode == 0:
            action_text = {'on': 'started', 'off': 'stopped', 'suspend': 'suspended', 'resume': 'resumed'}
            return True, f"BitLocker {action_text.get(action, action)} for {drive}"
        else:
            error_msg = result.stderr.strip()
            if not error_msg:
                error_msg = result.stdout.strip()
            return False, f"manage-bde error: {error_msg[:100]}"
    except FileNotFoundError:
        return False, "manage-bde command not found (BitLocker may not be available)"
    except Exception as e:
        return False, f"Error: {str(e)}"


# ─── Processes ───────────────────────────────────────────────────────────────
def get_processes() -> list:
    if sys.platform == "win32":
        ok, out = run_cmd(['tasklist', '/FO', 'CSV', '/NH'])
        if ok:
            procs = []
            for line in out.splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 5:
                    procs.append({'name': parts[0], 'pid': parts[1],
                                  'mem': parts[4].replace('\xa0', ' '), 'status': 'Running'})
            return procs
    else:
        ok, out = run_cmd(['ps', 'aux', '--no-headers'])
        if ok:
            procs = []
            for line in out.splitlines()[:80]:
                p = line.split(None, 10)
                if len(p) >= 11:
                    procs.append({'name': p[10][:45], 'pid': p[1],
                                  'mem': f"{p[3]} %", 'status': p[7] if len(p) > 7 else '?'})
            return procs
    return []


def kill_process(pid: str) -> tuple:
    # Validate PID format
    if not pid.isdigit():
        return False, "Invalid PID format"
    if sys.platform == "win32":
        return run_cmd(['taskkill', '/PID', pid, '/F'])
    return run_cmd(['kill', '-9', pid])


# ─── Network ─────────────────────────────────────────────────────────────────
def get_network_info() -> dict:
    info = {'hostname': socket.gethostname(), 'ip': 'N/A', 'raw': '', 'connections': []}
    try:
        info['ip'] = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass
    if sys.platform == "win32":
        _, info['raw'] = run_cmd(['ipconfig'])
    else:
        ok, out = run_cmd(['ip', 'addr'])
        info['raw'] = out if ok else run_cmd(['ifconfig'])[1]
        ok2, out2 = run_cmd(['ss', '-tuln'])
        if ok2:
            for line in out2.splitlines()[1:20]:
                parts = line.split()
                if len(parts) >= 5:
                    info['connections'].append({'proto': parts[0], 'local': parts[4], 'state': parts[1]})
    return info


# ─── Services ────────────────────────────────────────────────────────────────
def get_services() -> list:
    if sys.platform == "win32":
        ok, out = run_cmd(['sc', 'query', 'type=', 'all', 'state=', 'all'])
        services = []
        if ok:
            current = {}
            for line in out.splitlines():
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    if current:
                        services.append(current)
                    current = {'name': line.split(':', 1)[1].strip(), 'status': '', 'type': ''}
                elif 'STATE' in line and ':' in line:
                    parts = line.split(':', 1)[1].strip().split()
                    current['status'] = parts[1] if len(parts) > 1 else parts[0]
            if current:
                services.append(current)
        return services
    else:
        ok, out = run_cmd(['systemctl', 'list-units', '--type=service', '--no-pager', '--no-legend'])
        if ok:
            svcs = []
            for line in out.splitlines()[:60]:
                parts = line.split(None, 4)
                if len(parts) >= 3:
                    svcs.append({'name': parts[0].replace('.service', ''),
                                 'status': parts[2], 'type': parts[3] if len(parts) > 3 else ''})
            return svcs
        ok2, out2 = run_cmd(['service', '--status-all'])
        svcs = []
        for line in (out2 or '').splitlines():
            if line.strip():
                st = 'running' if '[ + ]' in line else 'stopped'
                name = line.replace('[ + ]', '').replace('[ - ]', '').replace('[  ]', '').strip()
                svcs.append({'name': name, 'status': st, 'type': ''})
        return svcs


def control_service(name: str, action: str) -> tuple:
    # Validate service name and action
    valid_actions = ['start', 'stop', 'restart', 'pause', 'continue']
    if action not in valid_actions:
        return False, f"Invalid action. Allowed: {', '.join(valid_actions)}"
    if not name or not all(c.isalnum() or c in '-_.' for c in name):
        return False, "Invalid service name"
    if sys.platform == "win32":
        return run_cmd(['sc', action, name], timeout=20)
    return run_cmd(['sudo', 'systemctl', action, name + '.service'], timeout=20)


# ─── Logs ────────────────────────────────────────────────────────────────────
def get_logs() -> list:
    logs = []
    if sys.platform == "win32":
        ok, out = run_cmd(['wevtutil', 'qe', 'System', '/c:60', '/rd:true', '/f:text'])
        if ok:
            entry = {}
            for line in out.splitlines():
                line = line.strip()
                if line.startswith('Date:'):
                    if entry:
                        logs.append(entry)
                    entry = {'date': line[5:].strip(), 'level': 'INFO', 'source': '', 'message': ''}
                elif line.startswith('Level:'):
                    raw = line[6:].strip().lower()
                    entry['level'] = 'ERROR' if 'error' in raw else ('WARN' if 'warn' in raw else 'INFO')
                elif line.startswith('Source:'):
                    entry['source'] = line[7:].strip()
                elif line.startswith('Message:'):
                    entry['message'] = line[8:].strip()[:90]
            if entry:
                logs.append(entry)
    else:
        ok, out = run_cmd(['journalctl', '-n', '100', '--no-pager', '-o', 'short'])
        if ok:
            for line in out.splitlines():
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    msg = parts[4]
                    level = ('ERROR' if any(w in msg.lower() for w in ['error', 'fail', 'crit'])
                             else 'WARN' if any(w in msg.lower() for w in ['warn', 'warning'])
                             else 'INFO')
                    logs.append({'date': f"{parts[0]} {parts[1]}", 'level': level,
                                 'source': parts[3].rstrip(':'), 'message': msg[:90]})
        else:
            for path in ('/var/log/syslog', '/var/log/messages'):
                ok2, out2 = run_cmd(['tail', '-n', '100', path])
                if ok2:
                    for line in out2.splitlines():
                        level = ('ERROR' if 'error' in line.lower()
                                 else 'WARN' if 'warn' in line.lower() else 'INFO')
                        logs.append({'date': '', 'level': level, 'source': '', 'message': line[:90]})
                    break
    return logs


# ─────────────────────────────────────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────────────────────────────────────
class SystemManagementPanel(tk.Tk):

    # ── Colour palettes ───────────────────────────────────────────────────────
    DARK_THEME = {
        "BG":        "#1E2430",
        "SURFACE":   "#262D3D",
        "BORDER":    "#353F55",
        "ACCENT":    "#00C8FF",
        "ACCENT2":   "#0078D7",
        "DANGER":    "#FF4655",
        "SUCCESS":   "#00C853",
        "WARN":      "#FFB300",
        "TEXT":      "#E8EDF5",
        "MUTED":     "#7A8AA8",
        "HEADER_BG": "#181F2C",
    }

    LIGHT_THEME = {
        "BG":        "#F0F4F8",
        "SURFACE":   "#FFFFFF",
        "BORDER":    "#D0D7E3",
        "ACCENT":    "#0078D7",
        "ACCENT2":   "#005BB5",
        "DANGER":    "#D32F2F",
        "SUCCESS":   "#2E7D32",
        "WARN":      "#E65100",
        "TEXT":      "#1A1D24",
        "MUTED":     "#6B7A99",
        "HEADER_BG": "#1A2A4A",
    }

    # Active palette (start dark) – set as instance attrs in __init__
    CLR_BG        = DARK_THEME["BG"]
    CLR_SURFACE   = DARK_THEME["SURFACE"]
    CLR_BORDER    = DARK_THEME["BORDER"]
    CLR_ACCENT    = DARK_THEME["ACCENT"]
    CLR_ACCENT2   = DARK_THEME["ACCENT2"]
    CLR_DANGER    = DARK_THEME["DANGER"]
    CLR_SUCCESS   = DARK_THEME["SUCCESS"]
    CLR_WARN      = DARK_THEME["WARN"]
    CLR_TEXT      = DARK_THEME["TEXT"]
    CLR_MUTED     = DARK_THEME["MUTED"]
    CLR_HEADER_BG = DARK_THEME["HEADER_BG"]

    MODULES = [
        ("", "NTFSecur",   "NTFS Security"),
        ("", "BitLocker",  "BitLocker Encryption"),
        ("", "Processes",  "Process Manager"),
        ("", "Network",    "Network Info"),
        ("", "Services",   "Service Control"),
        ("", "Logs",       "System Logs"),
        ("", "Drives",     "Drives Diagnostics"),
        ("", "USB",        "USB Diagnostics"),
        ("", "Databases",  "Database Library"),
        ("", "FSLibrary",  "Partitions & Formats"),
        ("", "USBMass",    "USB Mass Memory DB"),
    ]

    def __init__(self):
        super().__init__()
        log_info("=" * 60)
        log_info(f"Starting {__product__} v{__version__}")

        # ── Load settings ─────────────────────────────────────────────────────
        self._cfg = get_settings()

        self.title("PolSoft – System Management Panel")
        geom = self._cfg.get("window_geometry", "820x560")
        self.geometry(geom)
        self.minsize(700, 460)

        # ── Window size lock (from settings) ──────────────────────────────────
        self._is_locked = bool(self._cfg.get("window_locked", False))
        if self._is_locked:
            # Parse saved geometry to enforce exact fixed size
            try:
                w, h = geom.split("+")[0].split("x")
                self.resizable(False, False)
                self.minsize(int(w), int(h))
                self.maxsize(int(w), int(h))
            except Exception:
                self._is_locked = False
                self.resizable(True, True)
        else:
            self.resizable(True, True)

        # ── Theme state (from settings) ───────────────────────────────────────
        saved_theme = self._cfg.get("theme", "dark")
        self._is_dark = (saved_theme != "light")
        self._load_palette(self.DARK_THEME if self._is_dark else self.LIGHT_THEME)
        self.configure(bg=self.CLR_BG)

        # ── Load icon & logo ──────────────────────────────────────────────────
        self._app_icon  = None
        self._logo_img  = None

        base_dir = os.path.dirname(os.path.abspath(__file__))
        ico_path  = os.path.join(base_dir, "icon.ico")
        png_path  = os.path.join(base_dir, "icon.png")
        logo_path = os.path.join(base_dir, "logo.png")

        # Window icon
        try:
            if os.path.exists(ico_path):
                if sys.platform == "win32":
                    self.iconbitmap(ico_path)
                else:
                    from PIL import Image, ImageTk   # type: ignore
                    img = Image.open(ico_path).resize((32, 32), Image.LANCZOS)
                    self._app_icon = ImageTk.PhotoImage(img)
                    self.iconphoto(True, self._app_icon)
            elif os.path.exists(png_path):
                from PIL import Image, ImageTk   # type: ignore
                img = Image.open(png_path).resize((32, 32), Image.LANCZOS)
                self._app_icon = ImageTk.PhotoImage(img)
                self.iconphoto(True, self._app_icon)
        except Exception:
            try:
                self.iconbitmap(default='')
            except Exception:
                pass

        # Logo image for header
        try:
            from PIL import Image, ImageTk   # type: ignore
            if os.path.exists(logo_path):
                img = Image.open(logo_path).resize((48, 48), Image.LANCZOS)
                self._logo_img = ImageTk.PhotoImage(img)
            elif os.path.exists(png_path):
                img = Image.open(png_path).resize((48, 48), Image.LANCZOS)
                self._logo_img = ImageTk.PhotoImage(img)
        except Exception:
            self._logo_img = None

        self.secure_states:  dict = {}
        self.status_labels:  dict = {}
        self.toggle_buttons: dict = {}
        self.sidebar_btns:   dict = {}

        start_module = self._cfg.get("last_module", "NTFSecur")
        # Validate module name
        valid_modules = [key for _, key, _ in self.MODULES]
        if start_module not in valid_modules:
            start_module = "NTFSecur"
        self.active_module = tk.StringVar(value=start_module)

        self._apply_dark_scrollbar()
        self._build_menu()
        self._build_ui()
        self._build_watermark()
        self._switch_module(start_module)
        log_info(f"UI ready – module: {start_module}, theme: {'dark' if self._is_dark else 'light'}")

    # ── Theme helpers ─────────────────────────────────────────────────────────
    def _load_palette(self, palette: dict):
        """Copy palette dict values into CLR_* instance attributes."""
        self.CLR_BG        = palette["BG"]
        self.CLR_SURFACE   = palette["SURFACE"]
        self.CLR_BORDER    = palette["BORDER"]
        self.CLR_ACCENT    = palette["ACCENT"]
        self.CLR_ACCENT2   = palette["ACCENT2"]
        self.CLR_DANGER    = palette["DANGER"]
        self.CLR_SUCCESS   = palette["SUCCESS"]
        self.CLR_WARN      = palette["WARN"]
        self.CLR_TEXT      = palette["TEXT"]
        self.CLR_MUTED     = palette["MUTED"]
        self.CLR_HEADER_BG = palette["HEADER_BG"]

    def _toggle_theme(self):
        """Switch between dark and light mode and rebuild the entire UI."""
        current = self.active_module.get() if hasattr(self, 'active_module') else "NTFSecur"

        self._is_dark = not self._is_dark
        palette = self.DARK_THEME if self._is_dark else self.LIGHT_THEME
        self._load_palette(palette)
        self.configure(bg=self.CLR_BG)

        # Persist theme choice
        theme_name = "dark" if self._is_dark else "light"
        self._cfg.set("theme", theme_name)
        self._cfg.save()
        log_info(f"Theme switched to: {theme_name}")

        for widget in self.winfo_children():
            widget.destroy()

        self.secure_states  = {}
        self.status_labels  = {}
        self.toggle_buttons = {}
        self.sidebar_btns   = {}
        self.active_module  = tk.StringVar(value=current)

        self._apply_scrollbar_style()
        self._build_menu()
        self._build_ui()
        self._build_watermark()
        self._switch_module(current)

        # Re-apply lock state after rebuild
        if self._is_locked:
            geom = self._cfg.get("window_geometry", "820x560")
            try:
                w, h = geom.split("x")
                self.resizable(False, False)
                self.minsize(int(w), int(h))
                self.maxsize(int(w), int(h))
            except Exception:
                pass

    # ── Dark/Light scrollbar style ────────────────────────────────────────────
    def _apply_scrollbar_style(self):
        style = ttk.Style(self)
        style.theme_use("default")
        for orient in ("Vertical", "Horizontal"):
            style.configure(
                f"{orient}.TScrollbar",
                background  = self.CLR_BORDER,
                troughcolor = self.CLR_BG,
                bordercolor = self.CLR_BG,
                arrowcolor  = self.CLR_MUTED,
                relief      = "flat",
                borderwidth = 0,
                arrowsize   = 12,
            )
            style.map(
                f"{orient}.TScrollbar",
                background = [("active",  self.CLR_ACCENT),
                              ("pressed", self.CLR_ACCENT2),
                              ("!active", self.CLR_BORDER)],
                arrowcolor = [("active",  self.CLR_ACCENT),
                              ("!active", self.CLR_MUTED)],
            )

    # ── Dark scrollbar style (legacy name, delegates) ─────────────────────────
    def _apply_dark_scrollbar(self):
        self._apply_scrollbar_style()

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_menu(self):
        """Build the top menu bar with all options"""
        menu_bar = tk.Menu(self, bg=self.CLR_HEADER_BG, fg=self.CLR_TEXT, 
                          activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_TEXT)
        self.config(menu=menu_bar)

        # FILE Menu
        file_menu = tk.Menu(menu_bar, bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                           activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_TEXT)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.quit, accelerator="Ctrl+Q")
        self.bind("<Control-q>", lambda e: self.quit())

        # VIEW Menu - Module shortcuts
        view_menu = tk.Menu(menu_bar, bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                           activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_TEXT)
        menu_bar.add_cascade(label="View", menu=view_menu)
        for icon, key, label in self.MODULES:
            view_menu.add_command(label=f"{key}", 
                                 command=lambda k=key: self._switch_module(k))
        view_menu.add_separator()
        lock_label = "Unlock Window Size" if self._is_locked else "Lock Window Size"
        view_menu.add_command(label=lock_label, command=self._toggle_lock_size,
                              accelerator="Ctrl+L")
        self.bind("<Control-l>", lambda e: self._toggle_lock_size())

        # NTFSECUR Menu
        ntfs_menu = tk.Menu(menu_bar, bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                           activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_TEXT)
        menu_bar.add_cascade(label="NTFSecur", menu=ntfs_menu)
        ntfs_menu.add_command(label="Go to NTFSecur Module", 
                             command=lambda: self._switch_module("NTFSecur"))
        ntfs_menu.add_separator()
        ntfs_menu.add_command(label="Refresh Partitions", 
                             command=self._refresh_ntfs_from_menu)
        ntfs_menu.add_command(label="View All Partitions Details",
                             command=self._show_partitions_info)

        # BITLOCKER Menu (Windows only)
        if sys.platform == "win32":
            bl_menu = tk.Menu(menu_bar, bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                             activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_TEXT)
            menu_bar.add_cascade(label="BitLocker", menu=bl_menu)
            bl_menu.add_command(label="Go to BitLocker Control",
                               command=lambda: self._switch_module("NTFSecur"))
            bl_menu.add_separator()
            bl_menu.add_command(label="View BitLocker Status",
                               command=self._show_bitlocker_status)
            bl_menu.add_command(label="Manage BitLocker",
                               command=self._bitlocker_management_panel)

        # DRIVES Menu
        drives_menu = tk.Menu(menu_bar, bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                              activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_TEXT)
        menu_bar.add_cascade(label="Drives", menu=drives_menu)
        drives_menu.add_command(label="Drives Diagnostics",
                                command=lambda: self._switch_module("Drives"))
        drives_menu.add_separator()
        drives_menu.add_command(label="Overview – Logical Drives",
                                command=lambda: (setattr(self, '_drives_tab',
                                    tk.StringVar(value='overview')),
                                    self._switch_module("Drives")))
        drives_menu.add_command(label="SMART Data",
                                command=lambda: self._drives_menu_tab("smart"))
        drives_menu.add_command(label="Partitions Table",
                                command=lambda: self._drives_menu_tab("partitions"))
        drives_menu.add_command(label="Physical Disks",
                                command=lambda: self._drives_menu_tab("physical"))
        drives_menu.add_command(label="Repair Log",
                                command=lambda: self._drives_menu_tab("log"))
        drives_menu.add_separator()
        drives_menu.add_command(label="CHKDSK / fsck ...",
                                command=lambda: (self._switch_module("Drives"),
                                    self.after(200, self._drives_chkdsk_dialog)))
        drives_menu.add_command(label="SMART Self-Test ...",
                                command=lambda: (self._switch_module("Drives"),
                                    self.after(200, self._drives_smart_dialog)))
        drives_menu.add_command(label="Repair File System ...",
                                command=lambda: (self._switch_module("Drives"),
                                    self.after(200, self._drives_repair_dialog)))
        drives_menu.add_command(label="Disk Cleanup ...",
                                command=lambda: (self._switch_module("Drives"),
                                    self.after(200, self._drives_cleanup_dialog)))
        drives_menu.add_command(label="Benchmark ...",
                                command=lambda: (self._switch_module("Drives"),
                                    self.after(200, self._drives_benchmark_dialog)))
        drives_menu.add_separator()
        drives_menu.add_command(label="Refresh Drives",
                                command=lambda: (self._switch_module("Drives"),
                                    self.after(100, self._refresh_drives_info)))

        # TOOLS Menu
        tools_menu = tk.Menu(menu_bar, bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                            activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_TEXT)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Processes", 
                              command=lambda: self._switch_module("Processes"))
        tools_menu.add_command(label="Network", 
                              command=lambda: self._switch_module("Network"))
        tools_menu.add_command(label="Services", 
                              command=lambda: self._switch_module("Services"))
        tools_menu.add_command(label="Logs", 
                              command=lambda: self._switch_module("Logs"))
        tools_menu.add_separator()
        tools_menu.add_command(label="Drives Diagnostics",
                              command=lambda: self._switch_module("Drives"))
        tools_menu.add_separator()
        tools_menu.add_command(label="Refresh All", command=self._refresh_all)

        # Help Menu
        help_menu = tk.Menu(menu_bar, bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                           activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_TEXT)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Help & User Guide",   command=self._show_help,     accelerator="F1")
        help_menu.add_separator()
        help_menu.add_command(label="About",            command=self._show_about)
        help_menu.add_command(label="Privileges",       command=self._show_privileges_info)
        help_menu.add_separator()
        help_menu.add_command(label="Reset to Factory Settings",
                             command=self._reset_factory_settings)
        self.bind("<F1>", lambda e: self._show_help())

        # Theme Menu
        theme_menu = tk.Menu(menu_bar, bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                             activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_TEXT)
        menu_bar.add_cascade(label="Theme", menu=theme_menu)
        theme_menu.add_command(label="Dark",  command=lambda: self._set_theme(dark=True))
        theme_menu.add_command(label="Light", command=lambda: self._set_theme(dark=False))
        theme_menu.add_separator()
        theme_menu.add_command(label="⇄  Toggle Theme  (Ctrl+T)", command=self._toggle_theme)
        self.bind("<Control-t>", lambda e: self._toggle_theme())

    def _drives_menu_tab(self, tab: str):
        """Switch to Drives module and activate the given tab."""
        self._switch_module("Drives")
        def _set_tab():
            if hasattr(self, '_drives_tab'):
                self._drives_tab.set(tab)
                for n, b in self._drives_tab_btns.items():
                    b.config(fg=self.CLR_ACCENT if n == tab else self.CLR_MUTED,
                             font=("Segoe UI", 9, "bold") if n == tab else ("Segoe UI", 9))
                self._refresh_drives_info()
        self.after(150, _set_tab)

    def _set_theme(self, dark: bool):
        if self._is_dark != dark:
            self._toggle_theme()

    def _toggle_lock_size(self):
        """Lock or unlock the window size, save state and geometry to settings."""
        if self._is_locked:
            # Unlock
            self._is_locked = False
            self.resizable(True, True)
            self.minsize(700, 460)
            self.maxsize(99999, 99999)
            self._cfg.set("window_locked", False)
            self._cfg.save()
            log_info("Window size unlocked.")
            self._set_status("Window size: unlocked – you can resize freely.")
        else:
            # Lock at current size
            self._is_locked = True
            geom = self.geometry()                        # e.g. "820x560+100+50"
            size_part = geom.split("+")[0]                # "820x560"
            w, h = size_part.split("x")
            self.resizable(False, False)
            self.minsize(int(w), int(h))
            self.maxsize(int(w), int(h))
            self._cfg.set("window_locked",   True)
            self._cfg.set("window_geometry", size_part)   # save locked size
            self._cfg.save()
            log_info(f"Window size locked at {size_part}.")
            self._set_status(f"Window size locked at {size_part}.")
        # Refresh header to update lock icon
        self._rebuild_ui_keep_module()

    def _rebuild_ui_keep_module(self):
        """Rebuild menu + chrome only (keeps window size/resizable state intact)."""
        current = self.active_module.get() if hasattr(self, 'active_module') else "NTFSecur"
        for widget in self.winfo_children():
            widget.destroy()
        self.secure_states  = {}
        self.status_labels  = {}
        self.toggle_buttons = {}
        self.sidebar_btns   = {}
        self.active_module  = tk.StringVar(value=current)
        self._apply_scrollbar_style()
        self._build_menu()
        self._build_ui()
        self._build_watermark()
        self._switch_module(current)

    def _refresh_ntfs_from_menu(self):
        """Refresh NTFSecur partitions from menu"""
        self._switch_module("NTFSecur")
        if hasattr(self, '_load_partitions'):
            self._load_partitions()

    def _show_partitions_info(self):
        """Show detailed partitions information"""
        partitions = get_ntfs_partitions()
        if not partitions:
            messagebox.showinfo("Partitions", "No NTFS partitions found.")
            return
        
        info_text = "NTFS Partitions:\n\n"
        for part in partitions:
            info_text += f"Drive: {part['drive']}\n"
            info_text += f"Label: {part['label']}\n"
            info_text += f"Size: {part['size']}\n\n"
        
        messagebox.showinfo("Partition Details", info_text)

    def _show_bitlocker_status(self):
        """Show BitLocker status for all drives"""
        if sys.platform != "win32":
            messagebox.showinfo("BitLocker", "BitLocker is Windows-only feature.")
            return
        
        window = tk.Toplevel(self)
        window.transient(self)
        window.attributes("-topmost", True)
        window.title("BitLocker Status")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.47), 340)
        _mh = max(int(_ph * 0.55), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        window.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        window.minsize(int(_mw * 0.7), int(_mh * 0.7))
        window.configure(bg=self.CLR_BG)
        
        tk.Label(window, text="BitLocker Protection Status", font=("Segoe UI", 12, "bold"),
                fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(padx=10, pady=10)
        
        frame = tk.Frame(window, bg=self.CLR_BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        canvas = tk.Canvas(frame, bg=self.CLR_BG, highlightthickness=0)
        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
        inner = tk.Frame(canvas, bg=self.CLR_BG)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor=tk.NW)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load status for each partition
        partitions = get_ntfs_partitions()
        for part in partitions:
            drive = part['drive']
            status = get_bitlocker_status(drive)
            
            card = tk.Frame(inner, bg=self.CLR_SURFACE)
            card.pack(fill=tk.X, padx=8, pady=4)
            
            info = tk.Label(card, text=f"{drive} - {part['label']}", 
                          font=("Segoe UI", 11, "bold"),
                          fg=self.CLR_ACCENT, bg=self.CLR_SURFACE)
            info.pack(anchor=tk.W, padx=10, pady=(6, 2))
            
            if status.get('error'):
                status_txt = f"Error: {status['error']}"
                color = self.CLR_DANGER
            else:
                status_txt = f"Status: {status.get('status', 'Unknown')}"
                color = self.CLR_SUCCESS if status.get('protection') == 'ON' else self.CLR_MUTED
            
            tk.Label(card, text=status_txt, font=("Segoe UI", 10),
                    fg=color, bg=self.CLR_SURFACE).pack(anchor=tk.W, padx=10, pady=(0, 6))

    def _bitlocker_management_panel(self):
        """Open BitLocker management panel"""
        if sys.platform != "win32":
            messagebox.showinfo("BitLocker", "BitLocker is Windows-only feature.")
            return
        
        self._switch_module("NTFSecur")

    def _refresh_all(self):
        """Refresh all modules"""
        self._set_status("Refreshing all data...")
        if hasattr(self, '_load_partitions'):
            self._load_partitions()
        if hasattr(self, '_refresh_processes'):
            self._refresh_processes()
        if hasattr(self, '_refresh_network'):
            self._refresh_network()
        if hasattr(self, '_refresh_services'):
            self._refresh_services()
        if hasattr(self, '_refresh_logs'):
            self._refresh_logs()

    def _show_help(self):
        """Open the full Help & User Guide window."""
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title("Help & User Guide – PolSoft System Management Panel")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.81), 340)
        _mh = max(int(_ph * 0.88), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.minsize(680, 480)
        win.configure(bg=self.CLR_BG)
        win.resizable(True, True)

        # ── Title bar ─────────────────────────────────────────────────────────
        hdr = tk.Frame(win, bg=self.CLR_HEADER_BG, height=52)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="Help & User Guide",
                 font=("Segoe UI", 14, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_HEADER_BG).pack(side=tk.LEFT, padx=20, pady=12)
        tk.Label(hdr, text=f"v{__version__}",
                 font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=self.CLR_HEADER_BG).pack(side=tk.RIGHT, padx=20, pady=18)
        tk.Frame(win, bg=self.CLR_ACCENT, height=2).pack(fill=tk.X)

        # ── Tab bar ───────────────────────────────────────────────────────────
        tab_bar = tk.Frame(win, bg=self.CLR_SURFACE)
        tab_bar.pack(fill=tk.X)
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X)

        content_host = tk.Frame(win, bg=self.CLR_BG)
        content_host.pack(fill=tk.BOTH, expand=True)

        # Scrollable text area builder
        def make_text_area():
            wrap = tk.Frame(content_host, bg=self.CLR_BG)
            wrap.pack(fill=tk.BOTH, expand=True)
            sb = ttk.Scrollbar(wrap, orient=tk.VERTICAL, style="Vertical.TScrollbar")
            sb.pack(side=tk.RIGHT, fill=tk.Y)
            txt = tk.Text(wrap, bg=self.CLR_BG, fg=self.CLR_TEXT,
                          font=("Segoe UI", 10), relief=tk.FLAT, bd=0,
                          wrap=tk.WORD, padx=24, pady=16,
                          yscrollcommand=sb.set, cursor="arrow",
                          state=tk.NORMAL, spacing1=2, spacing3=4)
            txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            sb.config(command=txt.yview)
            # Tag styles
            txt.tag_configure("h1",  font=("Segoe UI", 14, "bold"), foreground=self.CLR_ACCENT,
                              spacing1=12, spacing3=6)
            txt.tag_configure("h2",  font=("Segoe UI", 11, "bold"), foreground=self.CLR_TEXT,
                              spacing1=10, spacing3=4)
            txt.tag_configure("h3",  font=("Segoe UI", 10, "bold"), foreground=self.CLR_ACCENT2,
                              spacing1=8,  spacing3=2)
            txt.tag_configure("body",font=("Segoe UI", 10),         foreground=self.CLR_TEXT)
            txt.tag_configure("muted",font=("Segoe UI", 9),         foreground=self.CLR_MUTED)
            txt.tag_configure("key", font=("Segoe UI", 9, "bold"),  foreground=self.CLR_WARN,
                              background=self.CLR_SURFACE)
            txt.tag_configure("ok",  font=("Segoe UI", 10),         foreground=self.CLR_SUCCESS)
            txt.tag_configure("hr",  font=("Segoe UI", 1),          foreground=self.CLR_BORDER)
            txt.tag_configure("indent", lmargin1=20, lmargin2=20)
            return txt, wrap

        # ── Tab switching ──────────────────────────────────────────────────────
        _tab_frames = {}
        _tab_btns   = {}
        _active_tab = tk.StringVar(value="overview")

        def show_tab(name):
            _active_tab.set(name)
            for n, f in _tab_frames.items():
                f.pack_forget()
            _tab_frames[name].pack(fill=tk.BOTH, expand=True)
            for n, b in _tab_btns.items():
                b.config(fg=self.CLR_TEXT   if n == name else self.CLR_MUTED,
                         bg=self.CLR_BG     if n == name else self.CLR_SURFACE,
                         relief=tk.FLAT)

        def add_tab(name, label):
            btn = tk.Button(tab_bar, text=label,
                            font=("Segoe UI", 9, "bold"),
                            fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                            activeforeground=self.CLR_TEXT, activebackground=self.CLR_BG,
                            relief=tk.FLAT, bd=0, padx=14, pady=8, cursor="hand2",
                            command=lambda n=name: show_tab(n))
            btn.pack(side=tk.LEFT)
            _tab_btns[name] = btn
            frame = tk.Frame(content_host, bg=self.CLR_BG)
            _tab_frames[name] = frame
            return frame

        # ══════════════════════════════════════════════════════════════════════
        #  TAB 1 – Overview
        # ══════════════════════════════════════════════════════════════════════
        f_overview = add_tab("overview", "  Overview  ")
        txt, _ = make_text_area()
        _tab_frames["overview"] = txt.master.master   # point to the wrap frame

        def w(tag, text, newline=True):
            txt.insert(tk.END, text + ("\n" if newline else ""), tag)

        w("h1",  "PolSoft System Management Panel")
        w("muted", f"Version {__version__}  ·  {__copyright__}\n")
        w("body",
          "PolSoft SMP is a lightweight, cross-platform desktop utility that brings "
          "together the most commonly needed system-administration tasks into a single, "
          "clean interface. It runs on Windows and Linux without requiring any external "
          "dependencies beyond the Python standard library.\n")

        w("h2",  "What it does")
        w("body",
          "The panel is divided into modules, each focusing on a specific area of system "
          "management. Use the sidebar on the left or the View menu to switch between modules.\n")

        w("h2",  "Quick-start")
        for step, desc in [
            ("1. Launch",    "Run NTFSecur.py with Python 3.8+.  Administrator / root privileges "
                             "are recommended for full functionality."),
            ("2. Navigate",  "Click any module in the left sidebar or use View → <Module Name>."),
            ("3. Refresh",   "Every module has a ⟳ REFRESH button to reload live data."),
            ("4. Settings",  "Your window size, theme and last-opened module are remembered "
                             "automatically in settings.json."),
        ]:
            w("h3",    f"  {step}")
            w("body",  f"  {desc}\n", newline=True)

        w("h2",  "Data storage")
        w("body", "All persistent files are stored under:\n")
        w("key",  f"  {AppPaths.BASE}\n")
        for label, path in [
            ("settings.json", AppPaths.SETTINGS),
            ("NTFSecur.log",  AppPaths.LOG),
            ("error.log",     AppPaths.ERROR_LOG),
            ("usb_history.db",AppPaths.DB),
            ("report\\",      AppPaths.REPORT_DIR),
        ]:
            w("muted",  f"  {label:<18}", newline=False)
            w("body",   f"  {path}\n")

        txt.config(state=tk.DISABLED)

        # ══════════════════════════════════════════════════════════════════════
        #  TAB 2 – Modules
        # ══════════════════════════════════════════════════════════════════════
        f_modules = add_tab("modules", "  Modules  ")
        txt2, wrap2 = make_text_area()
        _tab_frames["modules"] = wrap2

        def w2(tag, text, newline=True):
            txt2.insert(tk.END, text + ("\n" if newline else ""), tag)

        modules_help = [
            ("🔒", "NTFSecur",
             "NTFS Write-Protection",
             "Displays all NTFS and removable partitions detected on the system. "
             "Each partition card shows its label, drive letter, size, and current "
             "NTFSecur state (LOCKED / UNLOCKED).\n\n"
             "  • Toggle – click SECURE ON/OFF to enable or disable write-protection "
             "via diskpart (Windows) or blockdev (Linux). Requires Administrator rights.\n"
             "  • BitLocker badge – shows live BitLocker encryption status next to each drive.\n"
             "  • Refresh – re-scans partitions at any time."),

            ("🔐", "BitLocker",
             "Drive Encryption (Windows only)",
             "Shows BitLocker status for every NTFS drive.\n\n"
             "  • Status cards display Protection ON/OFF, encryption percentage and "
             "any error conditions.\n"
             "  • Action buttons allow you to Enable encryption, Suspend protection, "
             "Resume protection or Decrypt (turn off) BitLocker for each drive.\n"
             "  • Progress bar is shown while encryption or decryption is in progress.\n"
             "  Note: requires manage-bde and Administrator privileges."),

            ("🖥️", "Processes",
             "Process Manager",
             "Lists all running processes with their PID, name and memory usage.\n\n"
             "  • Search bar – filters the list in real time.\n"
             "  • Kill – select a process and click KILL to terminate it (sends SIGKILL / taskkill /F).\n"
             "  • Refresh – reloads the process list.\n"
             "  Note: killing system processes may destabilise the OS. Use with caution."),

            ("🌐", "Network",
             "Network Information",
             "Displays hostname, primary IP address, and full adapter configuration "
             "(ipconfig on Windows, ip addr on Linux).\n\n"
             "  • Active connections – shows listening ports and their protocol (ss / netstat).\n"
             "  • Refresh reloads all network data."),

            ("🔧", "Services",
             "Service Control",
             "Lists all system services with their current status (Running / Stopped).\n\n"
             "  • Search bar – filter by name.\n"
             "  • Actions: Start, Stop, Restart (Linux also: Pause / Continue).\n"
             "  • Status indicator – green dot for running, grey for stopped.\n"
             "  Note: modifying services requires Administrator / root privileges."),

            ("📋", "Logs",
             "System Log Viewer",
             "Reads recent system events.\n\n"
             "  • Windows: queries the Application and System event logs via wevtutil.\n"
             "  • Linux: reads from journalctl or /var/log/syslog.\n"
             "  • Colour-coded by severity: ERROR (red), WARN (amber), INFO (normal).\n"
             "  • Search bar filters log entries in real time."),

            ("💾", "Drives",
             "Drive Diagnostics",
             "Enumerates all physical drives and logical volumes.\n\n"
             "  • Shows type (HDD/SSD/Removable), filesystem, total size, used/free space "
             "and BitLocker status.\n"
             "  • Available on both Windows (WMI/PowerShell) and Linux (lsblk)."),

            ("🔌", "USB Diagnostics",
             "USB Storage + History",
             "Four sub-tabs:\n\n"
             "  🔌 Live     – Shows currently connected USB storage devices with capacity "
             "bars, filesystem, manufacturer and serial number. Each scan is automatically "
             "saved to the SQLite history database.\n\n"
             "  📂 Device History – All USB devices ever connected, searchable and sortable. "
             "Click a row for full details. You can delete individual records or export "
             "the entire history to CSV.\n\n"
             "  📋 Event Log – Timestamped log of every DETECTED event (last 200 entries).\n\n"
             "  📊 Statistics – Summary cards (unique devices, total events, most-connected "
             "device, largest device) plus file-path reference. "
             "Generate HTML Report exports a styled, self-contained report to the report\\ folder."),

            ("🗄️", "Database Library",
             "DB Engine Reference",
             "Read-only reference library covering 25+ database engines.\n\n"
             "  • Columns: Engine, Type, License, Default Port, OS Support.\n"
             "  • Filter by type (Relational, NoSQL, OLAP, Time-Series, Graph, Embedded).\n"
             "  • Search bar matches across all fields.\n"
             "  • Click any row for a detail popup with Features and Notes."),

            ("📚", "FS Library",
             "Filesystem Format Reference",
             "Reference guide to filesystem formats (NTFS, exFAT, ext4, Btrfs, ZFS, etc.).\n\n"
             "  • Columns: Name, Type (Journal / COW / Simple / Log-struct / Virtual / RAM), "
             "Max Volume, Max File Size, OS Support.\n"
             "  • Filter by type or search by name.\n"
             "  • Click a row for full feature and notes detail."),

            ("🧲", "USB Mass DB",
             "USB Mass Storage Device Database",
             "Reference database of USB mass-storage controllers and devices.\n\n"
             "  • Covers flash drives, SSDs, HDDs and docks from major vendors.\n"
             "  • Filter by protocol (BOT, UAS, TB3).\n"
             "  • Click a row for speed, protocol, features and notes."),
        ]

        for icon, name, subtitle, desc in modules_help:
            w2("h2",  f"{icon}  {name}")
            w2("h3",  f"  {subtitle}")
            w2("body", f"{desc}\n\n")

        txt2.config(state=tk.DISABLED)

        # ══════════════════════════════════════════════════════════════════════
        #  TAB 3 – Menu Reference
        # ══════════════════════════════════════════════════════════════════════
        f_menus = add_tab("menus", "  Menu Reference  ")
        txt3, wrap3 = make_text_area()
        _tab_frames["menus"] = wrap3

        def w3(tag, text, newline=True):
            txt3.insert(tk.END, text + ("\n" if newline else ""), tag)

        menus = [
            ("File", [
                ("Exit  Ctrl+Q", "Close the application. Window geometry and settings are saved automatically."),
            ]),
            ("View", [
                ("<Module Name>",     "Jump directly to any of the 11 modules."),
                ("🔓 Lock / 🔒 Unlock Window Size  Ctrl+L",
                 "Freeze the window at its current pixel dimensions. The locked size is "
                 "saved to settings.json and restored on next launch. Click again (or press "
                 "Ctrl+L) to allow free resizing. The lock/unlock icon is also visible in "
                 "the header bar."),
            ]),
            ("NTFSecur", [
                ("Go to NTFSecur Module", "Switch to the NTFSecur partition view."),
                ("Refresh Partitions",    "Re-scan NTFS/removable partitions."),
                ("View All Partitions Details", "Show a summary popup of all detected partitions."),
            ]),
            ("BitLocker  (Windows only)", [
                ("View BitLocker Status",  "Open a popup showing protection state for all drives."),
                ("Manage BitLocker",       "Navigate to the BitLocker control module."),
            ]),
            ("Tools", [
                ("Processes",           "Switch to the Process Manager module."),
                ("Network",             "Switch to the Network Info module."),
                ("Services",            "Switch to the Service Control module."),
                ("Logs",                "Switch to the System Log Viewer."),
                ("Drives Information",  "Open the Drives Diagnostics popup."),
                ("Refresh All",         "Refresh every active module simultaneously."),
            ]),
            ("Help", [
                ("📖 Help & User Guide  F1", "Open this help window."),
                ("About",      "Show version, author and product information."),
                ("Privileges", "Show current user privileges and platform details."),
            ]),
            ("🌗 Theme", [
                ("🌙 Dark",              "Switch to dark colour scheme."),
                ("☀️ Light",             "Switch to light colour scheme."),
                ("⇄ Toggle Theme  Ctrl+T", "Toggle between dark and light mode."),
            ]),
        ]

        for menu_name, items in menus:
            w3("h2", f"  {menu_name}")
            for item, desc in items:
                w3("h3",    f"    {item}", newline=False)
                w3("body",  "")
                w3("body",  f"      {desc}\n", newline=True)
            w3("body", "")

        txt3.config(state=tk.DISABLED)

        # ══════════════════════════════════════════════════════════════════════
        #  TAB 4 – Keyboard Shortcuts
        # ══════════════════════════════════════════════════════════════════════
        f_keys = add_tab("keys", "  Shortcuts  ")
        txt4, wrap4 = make_text_area()
        _tab_frames["keys"] = wrap4

        def w4(tag, text, newline=True):
            txt4.insert(tk.END, text + ("\n" if newline else ""), tag)

        shortcuts = [
            ("F1",          "Open Help & User Guide"),
            ("Ctrl+Q",      "Exit the application"),
            ("Ctrl+T",      "Toggle dark / light theme"),
            ("Ctrl+L",      "Lock / Unlock window size"),
        ]

        w4("h1", "Keyboard Shortcuts")
        w4("body", "\n")
        for key, desc in shortcuts:
            w4("key",  f"  {key:<18}", newline=False)
            w4("body", f"  {desc}\n")

        w4("body", "\n")
        w4("h2",  "Header icons")
        w4("body", "\n")
        for icon, desc in [
            ("☀️ / 🌙",  "Click to toggle theme (dark ↔ light)"),
            ("🔓 / 🔒",  "Click to lock or unlock the window size"),
        ]:
            w4("key",  f"  {icon:<18}", newline=False)
            w4("body", f"  {desc}\n")

        txt4.config(state=tk.DISABLED)

        # ══════════════════════════════════════════════════════════════════════
        #  TAB 5 – Files & Paths
        # ══════════════════════════════════════════════════════════════════════
        f_paths = add_tab("paths", "  Files & Paths  ")
        txt5, wrap5 = make_text_area()
        _tab_frames["paths"] = wrap5

        def w5(tag, text, newline=True):
            txt5.insert(tk.END, text + ("\n" if newline else ""), tag)

        w5("h1",  "Application Files & Paths")
        w5("muted", "All application data is stored in the PolSoft user profile directory.\n\n")

        paths_info = [
            ("Base directory",
             AppPaths.BASE,
             "Root folder for all application data. Created automatically on first launch."),
            ("settings.json",
             AppPaths.SETTINGS,
             "Stores user preferences: theme (dark/light), last opened module, "
             "window geometry, and window lock state. Edited automatically – do not modify by hand."),
            ("NTFSecur.log",
             AppPaths.LOG,
             "General activity log. Records module switches, USB scans, theme changes, "
             "NTFSecur operations and application start/stop events."),
            ("error.log",
             AppPaths.ERROR_LOG,
             "Error and warning log. Contains full Python tracebacks for any exceptions "
             "that occur during operation. Useful for troubleshooting."),
            ("usb_history.db",
             AppPaths.DB,
             "SQLite database containing the full history of every USB storage device "
             "ever connected while the application was running. Tables: usb_devices, usb_events."),
            ("diskpart_tmp.txt",
             AppPaths.DISKPART_TMP,
             "Temporary diskpart script file used when applying NTFSecur on Windows. "
             "Created and deleted automatically during each operation."),
            ("report\\",
             AppPaths.REPORT_DIR,
             "Output folder for generated HTML reports. Each report is named "
             "usb_report_YYYYMMDD_HHMMSS.html and contains device history, "
             "event log and statistics in a styled, self-contained HTML file."),
        ]

        for title, path, desc in paths_info:
            w5("h2",   f"  {title}")
            w5("key",  f"  {path}\n")
            w5("body", f"  {desc}\n\n")

        txt5.config(state=tk.DISABLED)

        # ── Activate first tab ─────────────────────────────────────────────────
        show_tab("overview")

        # ── Close button ───────────────────────────────────────────────────────
        footer = tk.Frame(win, bg=self.CLR_HEADER_BG, height=40)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer.pack_propagate(False)
        tk.Button(footer, text="Close",
                  font=("Segoe UI", 9, "bold"),
                  fg=self.CLR_BG, bg=self.CLR_ACCENT,
                  activebackground=self.CLR_ACCENT2, activeforeground=self.CLR_BG,
                  relief=tk.FLAT, bd=0, padx=20, pady=6, cursor="hand2",
                  command=win.destroy).pack(side=tk.RIGHT, padx=16, pady=6)
        tk.Label(footer, text="Press F1 at any time to reopen this guide.",
                 font=("Segoe UI", 9), fg=self.CLR_MUTED,
                 bg=self.CLR_HEADER_BG).pack(side=tk.LEFT, padx=16, pady=10)

    def _show_about(self):
        """Show about dialog"""
        about_text = f"""PolSoft System Management Panel
Version {__version__}

Author: {__author__}
Email: {__email__}
GitHub: {__github__}

{__copyright__}

A comprehensive system management tool with:
• NTFSecur - NTFS partition protection
• BitLocker - Windows drive encryption
• Process Manager - Process control
• Network Tools - Network information
• Service Control - Windows services management
• System Logs - Event log viewer"""
        
        messagebox.showinfo("About PolSoft", about_text)

    def _show_privileges_info(self):
        """Show current privileges information"""
        admin_status = "ADMINISTRATOR" if is_admin() else "USER"
        platform_info = f"{platform.system()} {platform.release()}"
        arch = platform.machine()
        
        priv_text = f"""Current System Information:

Privileges: {admin_status}
Platform: {platform_info}
Architecture: {arch}

Administrator privileges are required for:
• NTFSecur - NTFS write-protection
• BitLocker - Drive encryption management
• Services - Service control
• Process - Kill processes

Without admin privileges, only viewing and
read-only operations are available."""
        
        messagebox.showinfo("Privileges & System Info", priv_text)

    def _reset_factory_settings(self):
        """Przywroc ustawienia fabryczne."""
        if not messagebox.askyesno(
                "Reset to Factory Settings",
                "This will restore ALL settings to factory defaults\n"
                "and restart the interface.\n\nContinue?"):
            return
        get_settings().reset_to_factory()
        messagebox.showinfo("Reset Complete",
                            "Factory settings restored.\n"
                            "Window geometry and theme have been reset.")
        self._toggle_theme() if not self._is_dark else None
        self._rebuild_ui_keep_module()

    def _build_ui(self):
        self._build_header()
        self._build_body()
        self._build_footer()

    def _build_header(self):
        header = tk.Frame(self, bg=self.CLR_HEADER_BG, height=64)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        brand = tk.Frame(header, bg=self.CLR_HEADER_BG)
        brand.pack(side=tk.LEFT, padx=20, fill=tk.Y)

        # Show logo image if available, otherwise fall back to text icon
        if self._logo_img:
            tk.Label(brand, image=self._logo_img,
                     bg=self.CLR_HEADER_BG).pack(side=tk.LEFT, pady=8)
        else:
            tk.Label(brand, text="PS", font=("Segoe UI", 18, "bold"),
                     fg=self.CLR_ACCENT, bg=self.CLR_HEADER_BG).pack(side=tk.LEFT, pady=14, padx=4)

        tf = tk.Frame(brand, bg=self.CLR_HEADER_BG)
        tf.pack(side=tk.LEFT, padx=10, fill=tk.Y)
        tk.Label(tf, text="SYSTEM MANAGEMENT PANEL", font=("Segoe UI", 13, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_HEADER_BG).pack(anchor=tk.W, pady=(18, 0))
        tk.Label(tf, text="polsoft.ITS™", font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=self.CLR_HEADER_BG).pack(anchor=tk.W)

        c = self.CLR_SUCCESS if is_admin() else self.CLR_DANGER
        t = "ADMIN" if is_admin() else "USER"
        tk.Label(header, text=t, font=("Segoe UI", 10, "bold"),
                 fg=c, bg=self.CLR_HEADER_BG).pack(side=tk.RIGHT, padx=20)

        # ── Theme toggle button ───────────────────────────────────────────────
        theme_txt = "Light" if self._is_dark else "Dark"
        theme_lbl = tk.Label(
            header,
            text=theme_txt,
            font=("Segoe UI", 9, "bold"),
            fg=self.CLR_MUTED,
            bg=self.CLR_HEADER_BG,
            cursor="hand2",
            bd=0,
            padx=8,
            pady=4,
        )
        theme_lbl.pack(side=tk.RIGHT, padx=(4, 4))
        theme_lbl.bind("<Button-1>", lambda e: self._toggle_theme())
        theme_lbl.bind("<Enter>", lambda e: theme_lbl.config(fg=self.CLR_ACCENT))
        theme_lbl.bind("<Leave>", lambda e: theme_lbl.config(fg=self.CLR_MUTED))

        # ── Window-lock label ─────────────────────────────────────────────────
        lock_txt = "Locked" if self._is_locked else "Unlocked"
        lock_lbl = tk.Label(
            header,
            text=lock_txt,
            font=("Segoe UI", 9, "bold"),
            fg=self.CLR_MUTED,
            bg=self.CLR_HEADER_BG,
            cursor="hand2",
            bd=0,
            padx=8,
            pady=4,
        )
        lock_lbl.pack(side=tk.RIGHT, padx=(4, 0))
        lock_lbl.bind("<Button-1>", lambda e: self._toggle_lock_size())
        lock_lbl.bind("<Enter>", lambda e: lock_lbl.config(fg=self.CLR_WARN))
        lock_lbl.bind("<Leave>", lambda e: lock_lbl.config(fg=self.CLR_MUTED))

        tk.Frame(self, bg=self.CLR_ACCENT, height=2).pack(fill=tk.X)

    def _build_body(self):
        body = tk.Frame(self, bg=self.CLR_BG)
        body.pack(fill=tk.BOTH, expand=True)
        self._build_sidebar(body)
        self.content_frame = tk.Frame(body, bg=self.CLR_BG)
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _build_sidebar(self, parent):
        sb = tk.Frame(parent, bg=self.CLR_SURFACE, width=200)
        sb.pack(side=tk.LEFT, fill=tk.Y)
        sb.pack_propagate(False)

        tk.Label(sb, text="MODULES", font=("Segoe UI", 9, "bold"),
                 fg=self.CLR_MUTED, bg=self.CLR_SURFACE).pack(anchor=tk.W, padx=16, pady=(18, 8))

        for icon, key, label in self.MODULES:
            container = tk.Frame(sb, bg=self.CLR_SURFACE)
            container.pack(fill=tk.X, padx=8, pady=2)
            self.sidebar_btns[key] = container

            strip = tk.Frame(container, width=3, bg=self.CLR_SURFACE)
            strip.pack(side=tk.LEFT, fill=tk.Y)

            lbl = tk.Label(container, text=f"  {key}",
                           font=("Segoe UI", 11), fg=self.CLR_MUTED,
                           bg=self.CLR_SURFACE, anchor=tk.W, cursor="hand2")
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8, padx=4)

            lbl.bind("<Button-1>",       lambda e, k=key: self._switch_module(k))
            container.bind("<Button-1>", lambda e, k=key: self._switch_module(k))

        tk.Label(sb, text=f"v{__version__}", font=("Segoe UI", 9),
                 fg=self.CLR_BORDER, bg=self.CLR_SURFACE).pack(side=tk.BOTTOM, pady=8)

        tk.Frame(parent, bg=self.CLR_BORDER, width=1).pack(side=tk.LEFT, fill=tk.Y)

    def _update_sidebar(self, active):
        for key, container in self.sidebar_btns.items():
            ch = container.winfo_children()
            strip = ch[0] if ch else None
            lbl   = ch[1] if len(ch) > 1 else None
            if key == active:
                container.configure(bg=self.CLR_BG)
                if strip: strip.configure(bg=self.CLR_ACCENT)
                if lbl:   lbl.configure(bg=self.CLR_BG, fg=self.CLR_ACCENT,
                                        font=("Segoe UI", 11, "bold"))
            else:
                container.configure(bg=self.CLR_SURFACE)
                if strip: strip.configure(bg=self.CLR_SURFACE)
                if lbl:   lbl.configure(bg=self.CLR_SURFACE, fg=self.CLR_MUTED,
                                        font=("Segoe UI", 11))

    def _build_watermark(self):
        """Place semi-transparent logo watermark in bottom-right corner."""
        self._wm_img = None
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png")
        if not os.path.exists(logo_path):
            return
        try:
            from PIL import Image, ImageTk, ImageEnhance  # type: ignore
            img = Image.open(logo_path).convert("RGBA")
            img = img.resize((80, 80), Image.LANCZOS)

            # Apply transparency to alpha channel → semi-transparent watermark
            r, g, b, a = img.split()
            a = ImageEnhance.Brightness(a).enhance(0.30)   # 30% opacity
            img = Image.merge("RGBA", (r, g, b, a))

            self._wm_img = ImageTk.PhotoImage(img)

            wm = tk.Label(self, image=self._wm_img, bg=self.CLR_BG,
                          cursor="arrow", bd=0, highlightthickness=0)
            # place in bottom-right; update position on resize
            def _reposition(event=None):
                w = self.winfo_width()
                h = self.winfo_height()
                wm.place(x=w - 88, y=h - 88)

            self.bind("<Configure>", _reposition)
            self.after(100, _reposition)   # initial placement after window draws
        except Exception:
            pass

    def _build_footer(self):
        tk.Frame(self, bg=self.CLR_BORDER, height=1).pack(fill=tk.X)
        footer = tk.Frame(self, bg=self.CLR_HEADER_BG, height=28)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer.pack_propagate(False)

        self.status_bar = tk.Label(footer, text="Ready.",
                                   font=("Segoe UI", 9), fg=self.CLR_MUTED,
                                   bg=self.CLR_HEADER_BG, anchor=tk.W)
        self.status_bar.pack(side=tk.LEFT, padx=12, fill=tk.Y)

        tk.Label(footer, text=__copyright__, font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=self.CLR_HEADER_BG, anchor=tk.E
                 ).pack(side=tk.RIGHT, padx=100, fill=tk.Y)

    # ── Utilities ─────────────────────────────────────────────────────────────
    def _switch_module(self, key: str):
        self.active_module.set(key)
        self._update_sidebar(key)
        for w in self.content_frame.winfo_children():
            w.destroy()
        # Persist last opened module
        if hasattr(self, '_cfg'):
            self._cfg.set("last_module", key)
            self._cfg.save()
        log_info(f"Module switched to: {key}")
        {
            "NTFSecur":    self._render_ntfsecur,
            "BitLocker":   self._render_bitlocker,
            "Drives":      self._render_drives_module,
            "Processes":   self._render_processes,
            "Network":     self._render_network,
            "Services":    self._render_services,
            "Logs":        self._render_logs,
            "USB":         self._render_usb,
            "Databases":   self._render_databases,
            "FSLibrary":   self._render_fslibrary,
            "USBMass":     self._render_usbmass,
        }[key]()

    def _set_status(self, text: str):
        self.status_bar.configure(text=text)

    def _module_header(self, icon, title, subtitle):
        hdr = tk.Frame(self.content_frame, bg=self.CLR_BG)
        hdr.pack(fill=tk.X, padx=24, pady=(20, 0))
        label_text = f"{icon}  {title}" if icon else title
        tk.Label(hdr, text=label_text, font=("Segoe UI", 20, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(side=tk.LEFT)
        tk.Label(hdr, text=f"  {subtitle}", font=("Segoe UI", 12),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, pady=(6, 0))
        tk.Frame(self.content_frame, bg=self.CLR_BORDER, height=1
                 ).pack(fill=tk.X, padx=20, pady=(10, 0))

    def _scrollable_area(self, parent=None) -> tk.Frame:
        container = parent if parent is not None else self.content_frame
        wrapper = tk.Frame(container, bg=self.CLR_BG)
        wrapper.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        canvas = tk.Canvas(wrapper, bg=self.CLR_BG, highlightthickness=0)
        sb = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=canvas.yview)
        inner = tk.Frame(canvas, bg=self.CLR_BG)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor=tk.NW)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        return inner

    def _action_btn(self, parent, text, color, command):
        return tk.Button(parent, text=text, font=("Segoe UI", 9, "bold"),
                         fg=self.CLR_BG, bg=color,
                         activebackground=self.CLR_ACCENT, activeforeground=self.CLR_BG,
                         relief=tk.FLAT, bd=0, padx=8, pady=4, cursor="hand2",
                         command=command)

    def _col_headers(self, cols_spec):
        cols = tk.Frame(self.content_frame, bg=self.CLR_SURFACE)
        cols.pack(fill=tk.X, padx=20, pady=(4, 0))
        for txt, w in cols_spec:
            tk.Label(cols, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: NTFSecur
    # ══════════════════════════════════════════════════════════════════════════
    def _render_ntfsecur(self):
        self._module_header("", "NTFSecur", "NTFS Partition Security")
        tk.Label(self.content_frame,
                 text=("Manage write-protection on NTFS volumes.\n"
                       "  ON  → partition is locked (read-only)\n"
                       "  OFF → partition is fully accessible (read + write)"),
                 font=("Segoe UI", 10), fg=self.CLR_MUTED, bg=self.CLR_BG,
                 justify=tk.LEFT).pack(anchor=tk.W, padx=26, pady=(6, 8))
        self.partition_container = self._scrollable_area()
        self._load_partitions()

    def _load_partitions(self):
        self._set_status("Scanning NTFS partitions…")
        for w in self.partition_container.winfo_children():
            w.destroy()
        partitions = get_ntfs_partitions()
        if not partitions:
            tk.Label(self.partition_container, text="No NTFS partitions detected.",
                     font=("Segoe UI", 12), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=40)
            self._set_status("No NTFS partitions found.")
            return
        for part in partitions:
            self._build_partition_card(self.partition_container, part)
        self._set_status(f"Found {len(partitions)} NTFS partition(s). Ready.")

    def _build_partition_card(self, parent, partition):
        drive, label, size = partition['drive'], partition['label'], partition['size']
        var = tk.BooleanVar(value=False)
        self.secure_states[drive] = var

        card = tk.Frame(parent, bg=self.CLR_SURFACE)
        card.pack(fill=tk.X, padx=8, pady=6)
        strip = tk.Frame(card, width=4, bg=self.CLR_MUTED)
        strip.pack(side=tk.LEFT, fill=tk.Y)
        inner = tk.Frame(card, bg=self.CLR_SURFACE)
        inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=16, pady=14)

        info = tk.Frame(inner, bg=self.CLR_SURFACE)
        info.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(info, text=drive, font=("Segoe UI", 15, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(anchor=tk.W)
        tk.Label(info, text=f"{label}  ·  NTFS  ·  {size}", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_SURFACE).pack(anchor=tk.W, pady=(2, 0))

        # Status frame with NTFSecur and BitLocker
        sf = tk.Frame(inner, bg=self.CLR_SURFACE)
        sf.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        
        # NTFSecur status
        slbl = tk.Label(sf, text="UNLOCKED", font=("Segoe UI", 10, "bold"),
                        fg=self.CLR_SUCCESS, bg=self.CLR_SURFACE, width=14)
        slbl.pack(anchor=tk.W)
        self.status_labels[drive] = slbl
        
        # BitLocker status (Windows only)
        if sys.platform == "win32":
            blbl = tk.Label(sf, text="BitLocker: —", font=("Segoe UI", 9),
                           fg=self.CLR_MUTED, bg=self.CLR_SURFACE, width=20)
            blbl.pack(anchor=tk.W, pady=(2, 0))
            self.bitlock_labels = getattr(self, 'bitlock_labels', {})
            self.bitlock_labels[drive] = blbl
            threading.Thread(target=self._load_bitlocker_status, args=(drive,), daemon=True).start()

        # Control buttons frame
        cf = tk.Frame(inner, bg=self.CLR_SURFACE)
        cf.pack(side=tk.RIGHT)

        def make_toggle(d=drive):
            return lambda: self._toggle_secure(d)

        btn = tk.Button(cf, text="SECURE  OFF", font=("Segoe UI", 10, "bold"),
                        fg=self.CLR_BG, bg=self.CLR_MUTED,
                        activebackground=self.CLR_ACCENT, activeforeground=self.CLR_BG,
                        relief=tk.FLAT, bd=0, padx=14, pady=8,
                        cursor="hand2", command=make_toggle())
        btn.pack(side=tk.LEFT, padx=2)
        self.toggle_buttons[drive] = btn
        
        # BitLocker button (Windows only)
        if sys.platform == "win32":
            blbtn = tk.Button(cf, text="BITLOCK", font=("Segoe UI", 10, "bold"),
                             fg=self.CLR_BG, bg=self.CLR_BORDER,
                             activebackground=self.CLR_ACCENT, activeforeground=self.CLR_BG,
                             relief=tk.FLAT, bd=0, padx=12, pady=8,
                             cursor="hand2", command=lambda d=drive: self._bitlocker_menu(d))
            blbtn.pack(side=tk.LEFT, padx=2)
            self.bitlock_buttons = getattr(self, 'bitlock_buttons', {})
            self.bitlock_buttons[drive] = blbtn

    def _load_bitlocker_status(self, drive):
        """Load BitLocker status in background"""
        status_info = get_bitlocker_status(drive)
        self.after(0, lambda: self._update_bitlocker_label(drive, status_info))
    
    def _update_bitlocker_label(self, drive, status_info):
        """Update BitLocker label with status"""
        if not hasattr(self, 'bitlock_labels') or drive not in self.bitlock_labels:
            return
        
        lbl = self.bitlock_labels[drive]
        error = status_info.get('error')
        
        if error:
            lbl.configure(text=f"BitLocker: {error[:25]}", fg=self.CLR_MUTED)
        else:
            status = status_info.get('status', 'Unknown')
            protection = status_info.get('protection', 'OFF')
            percent = status_info.get('percent', 0)
            
            if status == 'Protected':
                color = self.CLR_DANGER
                text = "🔒 BitLocker: ON"
            elif status == 'Unprotected':
                color = self.CLR_MUTED
                text = "🔓 BitLocker: OFF"
            elif 'nencrypt' in status.lower():
                color = self.CLR_WARN
                text = f"⟳ BitLocker: {status} {percent}%"
            else:
                color = self.CLR_MUTED
                text = f"BitLocker: {status}"
            
            lbl.configure(text=text, fg=color)

    def _bitlocker_menu(self, drive):
        """Show BitLocker control menu"""
        if not is_admin():
            messagebox.showwarning("Insufficient Privileges",
                                   "Administrator privileges required\n"
                                   "to manage BitLocker.\n\n"
                                   "Please restart as Administrator.")
            return
        
        status_info = get_bitlocker_status(drive)
        is_protected = status_info.get('protection') == 'ON'
        
        if status_info.get('error'):
            messagebox.showerror("BitLocker Error", status_info.get('error'))
            return
        
        # Create menu window
        menu = tk.Toplevel(self)
        menu.transient(self)
        menu.attributes("-topmost", True)
        menu.title(f"BitLocker - {drive}")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.36), 340)
        _mh = max(int(_ph * 0.31), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        menu.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        menu.minsize(int(_mw * 0.7), int(_mh * 0.7))
        menu.configure(bg=self.CLR_BG)
        
        tk.Label(menu, text=f"BitLocker Control: {drive}", font=("Segoe UI", 12, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(padx=10, pady=10)
        
        status_text = f"Status: {status_info.get('status', 'Unknown')}"
        tk.Label(menu, text=status_text, font=("Segoe UI", 11),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(padx=10, pady=(0, 10))
        
        btn_frame = tk.Frame(menu, bg=self.CLR_BG)
        btn_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        if is_protected:
            tk.Button(btn_frame, text="Suspend Protection", font=("Segoe UI", 11, "bold"),
                     fg=self.CLR_BG, bg=self.CLR_WARN, relief=tk.FLAT, bd=0, padx=10, pady=8,
                     cursor="hand2", command=lambda: self._bitlocker_action(drive, 'suspend', menu)
                     ).pack(fill=tk.X, pady=4)
            tk.Button(btn_frame, text="Decrypt (Turn OFF)", font=("Segoe UI", 11, "bold"),
                     fg=self.CLR_TEXT, bg=self.CLR_DANGER, relief=tk.FLAT, bd=0, padx=10, pady=8,
                     cursor="hand2", command=lambda: self._bitlocker_action(drive, 'off', menu)
                     ).pack(fill=tk.X, pady=4)
        else:
            tk.Button(btn_frame, text="Enable Encryption", font=("Segoe UI", 11, "bold"),
                     fg=self.CLR_BG, bg=self.CLR_SUCCESS, relief=tk.FLAT, bd=0, padx=10, pady=8,
                     cursor="hand2", command=lambda: self._bitlocker_action(drive, 'on', menu)
                     ).pack(fill=tk.X, pady=4)
    
    def _bitlocker_action(self, drive, action, window):
        """Perform BitLocker action"""
        if not messagebox.askyesno("Confirm", f"Execute BitLocker {action} on {drive}?"):
            return
        
        window.destroy()
        self._set_status(f"Executing BitLocker {action} on {drive}...")
        
        def worker():
            ok, msg = control_bitlocker(drive, action)
            self.after(0, lambda: (
                self._set_status(f"{'OK' if ok else 'ERROR'} {msg}"),
                self._load_partitions() if ok else None
            ))
        
        threading.Thread(target=worker, daemon=True).start()

    def _toggle_secure(self, drive):
        if not is_admin():
            messagebox.showwarning("Insufficient Privileges",
                                   "Administrator / root privileges are required\n"
                                   "to change NTFS write-protection settings.\n\n"
                                   "Please restart the application as Administrator.")
            return
        new_state = not self.secure_states[drive].get()
        btn = self.toggle_buttons.get(drive)
        if not btn:
            return
        btn.configure(state=tk.DISABLED, text="WORKING…", bg=self.CLR_WARN, fg=self.CLR_BG)
        self._set_status(f"Applying NTFSecur to {drive}…")

        def worker():
            ok, msg = set_ntfs_readonly(drive, new_state)
            self.after(0, lambda: self._apply_ntfs_result(drive, new_state, ok, msg))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_ntfs_result(self, drive, new_state, success, message):
        # Safely get widget references
        btn = self.toggle_buttons.get(drive)
        lbl = self.status_labels.get(drive)
        if not btn or not lbl:
            return
        
        if success:
            self.secure_states[drive].set(new_state)
            if new_state:
                btn.configure(text="SECURE   ON",  bg=self.CLR_DANGER, fg=self.CLR_TEXT, state=tk.NORMAL)
                lbl.configure(text="LOCKED",    fg=self.CLR_DANGER)
            else:
                btn.configure(text="SECURE  OFF", bg=self.CLR_MUTED, fg=self.CLR_BG, state=tk.NORMAL)
                lbl.configure(text="UNLOCKED",  fg=self.CLR_SUCCESS)
            self._set_status(f"OK {message}")
        else:
            btn.configure(text="SECURE  OFF", bg=self.CLR_MUTED, fg=self.CLR_BG, state=tk.NORMAL)
            self._set_status(f"ERROR: {message}")
            messagebox.showerror("NTFSecur Error", message)

    # ══════════════════════════════════════════════════════════════════════════
    #  UTILITIES: Drives Information
    # ══════════════════════════════════════════════════════════════════════════
    def _show_drives_info(self):
        """Show comprehensive information about all drives"""
        window = tk.Toplevel(self)
        window.transient(self)
        window.attributes("-topmost", True)
        window.title("Drives Information")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.73), 340)
        _mh = max(int(_ph * 0.94), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        window.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        window.minsize(int(_mw * 0.7), int(_mh * 0.7))
        window.configure(bg=self.CLR_BG)
        
        tk.Label(window, text="System Drives Information", font=("Segoe UI", 12, "bold"),
                fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(padx=10, pady=10)
        
        # Scrollable frame
        frame = tk.Frame(window, bg=self.CLR_BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        canvas = tk.Canvas(frame, bg=self.CLR_BG, highlightthickness=0)
        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
        inner = tk.Frame(canvas, bg=self.CLR_BG)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor=tk.NW)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Gather drive info
        if sys.platform == "win32":
            try:
                import win32api, win32con, win32file
                drives = win32api.GetLogicalDriveStrings().split('\x00')
                for drive in drives:
                    if not drive:
                        continue
                    drive = drive.strip('\\')
                    try:
                        dtype = win32file.GetDriveType(drive + '\\')
                        type_name = {
                            win32con.DRIVE_FIXED: 'Fixed Disk',
                            win32con.DRIVE_REMOVABLE: 'Removable',
                            win32con.DRIVE_CDROM: 'CD/DVD',
                            win32con.DRIVE_REMOTE: 'Network Drive'
                        }.get(dtype, 'Unknown')
                        
                        vol_info = win32api.GetVolumeInformation(drive + '\\')
                        free, total, avail = win32api.GetDiskFreeSpaceEx(drive + '\\')
                        used = total - free
                        
                        # Get BitLocker status
                        bl_status = get_bitlocker_status(drive)
                        
                        # Create card
                        card = tk.Frame(inner, bg=self.CLR_SURFACE)
                        card.pack(fill=tk.X, pady=6)
                        
                        tk.Label(card, text=f"  {drive}:  ({vol_info[0] or 'No Label'})", 
                                font=("Segoe UI", 11, "bold"),
                                fg=self.CLR_ACCENT, bg=self.CLR_SURFACE).pack(anchor=tk.W, padx=10, pady=(6, 2))
                        
                        info_text = f"""  Type:        {type_name}
  FileSystem:  {vol_info[4]}
  Total:       {round(total/(1024**3), 1)} GB
  Used:        {round(used/(1024**3), 1)} GB ({round(used*100/total, 1)}%)
  Free:        {round(free/(1024**3), 1)} GB ({round(free*100/total, 1)}%)
  BitLocker:   {bl_status.get('status', 'Unknown')}"""
                        
                        tk.Label(card, text=info_text, font=("Segoe UI", 9),
                                fg=self.CLR_MUTED, bg=self.CLR_SURFACE, justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=(2, 6))
                    except Exception as e:
                        pass
            except ImportError:
                tk.Label(inner, text="pywin32 not available. Using basic info.",
                        font=("Segoe UI", 10), fg=self.CLR_WARN, bg=self.CLR_BG).pack(pady=10)
        
        # Linux/Mac drive info
        if sys.platform != "win32":
            ok, out = run_cmd(['lsblk', '-o', 'NAME,FSTYPE,SIZE,MOUNTPOINT', '-h'], timeout=10)
            if ok:
                info_text = out
                tk.Label(inner, text=info_text, font=("Segoe UI", 9),
                        fg=self.CLR_TEXT, bg=self.CLR_SURFACE, justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=10)

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: BitLocker
    # ══════════════════════════════════════════════════════════════════════════
    def _render_bitlocker(self):
        if sys.platform != "win32":
            self._module_header("", "BitLocker", "Windows Drive Encryption")
            tk.Label(self.content_frame, 
                    text="BitLocker is only available on Windows Pro/Enterprise editions.",
                    font=("Segoe UI", 12), fg=self.CLR_WARN, bg=self.CLR_BG).pack(pady=40)
            return
        
        self._module_header("", "BitLocker", "Windows Drive Encryption Management")
        tk.Label(self.content_frame,
                text="View and manage BitLocker encryption on all NTFS volumes.",
                font=("Segoe UI", 10), fg=self.CLR_MUTED, bg=self.CLR_BG,
                justify=tk.LEFT).pack(anchor=tk.W, padx=26, pady=(6, 8))
        
        # Toolbar
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=20, pady=6)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                        self._refresh_bitlocker_list).pack(side=tk.LEFT, padx=(0, 8))
        
        self._bitlock_container = self._scrollable_area()
        self._refresh_bitlocker_list()

    def _refresh_bitlocker_list(self):
        """Refresh BitLocker status for all partitions"""
        self._set_status("Scanning BitLocker status...")
        for w in self._bitlock_container.winfo_children():
            w.destroy()
        
        tk.Label(self._bitlock_container, text="Loading…",
                font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)
        
        def worker():
            partitions = get_ntfs_partitions()
            bl_data = []
            for part in partitions:
                status = get_bitlocker_status(part['drive'])
                bl_data.append({'partition': part, 'status': status})
            self.after(0, lambda: self._display_bitlocker_list(bl_data))
        
        threading.Thread(target=worker, daemon=True).start()

    def _display_bitlocker_list(self, bl_data):
        """Display BitLocker status and controls for all drives"""
        for w in self._bitlock_container.winfo_children():
            w.destroy()
        
        if not bl_data:
            tk.Label(self._bitlock_container, text="No NTFS partitions found.",
                    font=("Segoe UI", 12), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=40)
            self._set_status("No NTFS partitions found.")
            return
        
        for item in bl_data:
            part = item['partition']
            status = item['status']
            self._build_bitlocker_card(self._bitlock_container, part, status)
        
        self._set_status(f"BitLocker: {len(bl_data)} partition(s) scanned. Ready.")

    def _build_bitlocker_card(self, parent, partition, status):
        """Build a BitLocker status and control card"""
        drive = partition['drive']
        label = partition['label']
        size = partition['size']
        
        card = tk.Frame(parent, bg=self.CLR_SURFACE)
        card.pack(fill=tk.X, padx=8, pady=6)
        
        # Color indicator
        if status.get('error'):
            strip_color = self.CLR_MUTED
            status_color = self.CLR_MUTED
            status_text = f"ERROR: {status['error'][:40]}"
        else:
            if status.get('protection') == 'ON':
                strip_color = self.CLR_DANGER
                status_color = self.CLR_DANGER
                if 'encrypt' in status.get('status', '').lower():
                    status_text = f"ENCRYPTING - {status.get('percent', 0)}%"
                else:
                    status_text = "PROTECTED (Encrypted)"
            else:
                strip_color = self.CLR_MUTED
                status_color = self.CLR_SUCCESS
                if 'decrypt' in status.get('status', '').lower():
                    status_text = f"DECRYPTING - {status.get('percent', 0)}%"
                else:
                    status_text = "UNPROTECTED"
        
        strip = tk.Frame(card, width=4, bg=strip_color)
        strip.pack(side=tk.LEFT, fill=tk.Y)
        
        inner = tk.Frame(card, bg=self.CLR_SURFACE)
        inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=16, pady=12)
        
        # Drive info
        info = tk.Frame(inner, bg=self.CLR_SURFACE)
        info.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(info, text=drive, font=("Segoe UI", 14, "bold"),
                fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(anchor=tk.W)
        tk.Label(info, text=f"{label}  ·  NTFS  ·  {size}", font=("Segoe UI", 10),
                fg=self.CLR_MUTED, bg=self.CLR_SURFACE).pack(anchor=tk.W, pady=(2, 0))
        
        # Status
        sf = tk.Frame(inner, bg=self.CLR_SURFACE)
        sf.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        
        tk.Label(sf, text=status_text, font=("Segoe UI", 11, "bold"),
                fg=status_color, bg=self.CLR_SURFACE).pack(anchor=tk.W)
        
        if not status.get('error') and status.get('percent', 0) > 0 and status.get('percent', 0) < 100:
            # Progress bar for encryption/decryption
            progress_frame = tk.Frame(sf, bg=self.CLR_BORDER, height=4)
            progress_frame.pack(anchor=tk.W, fill=tk.X, pady=(4, 0))
            
            progress_width = int(200 * status.get('percent', 0) / 100)
            progress_bar = tk.Frame(progress_frame, bg=self.CLR_ACCENT, height=4, width=progress_width)
            progress_bar.place(x=0, y=0)
        
        # Control buttons
        if not status.get('error'):
            cf = tk.Frame(inner, bg=self.CLR_SURFACE)
            cf.pack(side=tk.RIGHT)
            
            if status.get('protection') == 'ON':
                self._action_btn(cf, "SUSPEND", self.CLR_WARN,
                               lambda d=drive: self._bitlocker_quick_action(d, 'suspend')
                               ).pack(side=tk.LEFT, padx=2)
                self._action_btn(cf, "DECRYPT", self.CLR_DANGER,
                               lambda d=drive: self._bitlocker_quick_action(d, 'off')
                               ).pack(side=tk.LEFT, padx=2)
            else:
                self._action_btn(cf, "ENABLE", self.CLR_SUCCESS,
                               lambda d=drive: self._bitlocker_quick_action(d, 'on')
                               ).pack(side=tk.LEFT, padx=2)

    def _bitlocker_quick_action(self, drive, action):
        """Quick BitLocker action with confirmation"""
        if not is_admin():
            messagebox.showwarning("Insufficient Privileges",
                                  "Administrator privileges required\n"
                                  "to manage BitLocker.\n\n"
                                  "Please restart as Administrator.")
            return
        
        action_names = {'on': 'Enable Encryption', 'off': 'Decrypt Drive', 'suspend': 'Suspend Protection'}
        action_name = action_names.get(action, action)
        
        if not messagebox.askyesno("Confirm Action", 
                                  f"This operation may take a long time.\n\n"
                                  f"Execute: {action_name}\non {drive}?"):
            return
        
        self._set_status(f"BitLocker: {action_name} on {drive}...")
        
        def worker():
            ok, msg = control_bitlocker(drive, action)
            self.after(0, lambda: (
                self._set_status(f"{'OK' if ok else 'ERROR'} {msg}"),
                self._refresh_bitlocker_list() if ok else None
            ))
        
        threading.Thread(target=worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: Drives Diagnostics & Repair
    # ══════════════════════════════════════════════════════════════════════════
    def _render_drives_module(self):
        """Render the Drives Diagnostics & Repair Module"""
        self._module_header("", "Drives Diagnostics & Repair",
                            "SMART · Health · Repair · Benchmarks")

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=20, pady=6)
        self._action_btn(tb, "REFRESH",      self.CLR_ACCENT2,
                         self._refresh_drives_info).pack(side=tk.LEFT, padx=(0, 6))
        self._action_btn(tb, "CHKDSK",       self.CLR_WARN,
                         self._drives_chkdsk_dialog).pack(side=tk.LEFT, padx=(0, 6))
        self._action_btn(tb, "SMART",        self.CLR_SUCCESS,
                         self._drives_smart_dialog).pack(side=tk.LEFT, padx=(0, 6))
        self._action_btn(tb, "REPAIR FS",    self.CLR_DANGER,
                         self._drives_repair_dialog).pack(side=tk.LEFT, padx=(0, 6))
        self._action_btn(tb, "DISK CLEANUP", self.CLR_ACCENT,
                         self._drives_cleanup_dialog).pack(side=tk.LEFT, padx=(0, 6))
        self._action_btn(tb, "BENCHMARK",    self.CLR_MUTED,
                         self._drives_benchmark_dialog).pack(side=tk.LEFT, padx=(0, 6))

        # ── Tab bar ───────────────────────────────────────────────────────────
        tab_bar = tk.Frame(self.content_frame, bg=self.CLR_SURFACE)
        tab_bar.pack(fill=tk.X, padx=20, pady=(4, 0))

        self._drives_tab      = tk.StringVar(value="overview")
        self._drives_tab_btns = {}

        def _switch_dtab(name):
            self._drives_tab.set(name)
            for n, b in self._drives_tab_btns.items():
                b.config(fg=self.CLR_ACCENT if n == name else self.CLR_MUTED,
                         font=("Segoe UI", 9, "bold") if n == name else ("Segoe UI", 9))
            self._refresh_drives_info()

        for tab_key, tab_lbl in [("overview", "Overview"),
                                  ("smart",    "SMART Data"),
                                  ("partitions","Partitions"),
                                  ("physical", "Physical Disks"),
                                  ("log",      "Repair Log")]:
            b = tk.Button(tab_bar, text=f"  {tab_lbl}  ",
                          font=("Segoe UI", 9),
                          fg=self.CLR_ACCENT if tab_key == "overview" else self.CLR_MUTED,
                          bg=self.CLR_SURFACE,
                          activeforeground=self.CLR_ACCENT, activebackground=self.CLR_SURFACE,
                          relief=tk.FLAT, bd=0, padx=4, pady=6, cursor="hand2",
                          command=lambda k=tab_key: _switch_dtab(k))
            b.pack(side=tk.LEFT)
            self._drives_tab_btns[tab_key] = b

        tk.Frame(self.content_frame, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20)

        # ── Output area (log-like text widget for Repair Log tab) + scrollable area
        self._drives_output_frame = tk.Frame(self.content_frame, bg=self.CLR_BG)
        self._drives_output_frame.pack(fill=tk.BOTH, expand=True)

        self._drives_container = self._scrollable_area(self._drives_output_frame)

        # Persistent repair/op log list
        if not hasattr(self, '_drives_repair_log'):
            self._drives_repair_log = []

        self._refresh_drives_info()

    # ── Data gathering ────────────────────────────────────────────────────────
    def _gather_drives_data(self):
        """Gather all drives: logical + physical + SMART where possible."""
        result = {"logical": [], "physical": [], "smart": {}}

        # ── Logical / Partition info ──────────────────────────────────────────
        if sys.platform == "win32":
            # Try win32api first
            try:
                import win32api, win32con, win32file
                drives_str = win32api.GetLogicalDriveStrings().split('\x00')
                for drive in drives_str:
                    if not drive:
                        continue
                    drive = drive.strip('\\')
                    try:
                        dtype = win32file.GetDriveType(drive + '\\')
                        type_name = {
                            win32con.DRIVE_FIXED:    "Fixed Disk",
                            win32con.DRIVE_REMOVABLE:"Removable",
                            win32con.DRIVE_CDROM:    "CD/DVD",
                            win32con.DRIVE_REMOTE:   "Network",
                            win32con.DRIVE_RAMDISK:  "RAM Disk",
                        }.get(dtype, "Unknown")
                        vol = win32api.GetVolumeInformation(drive + '\\')
                        free, total, _ = win32api.GetDiskFreeSpaceEx(drive + '\\')
                        bl = get_bitlocker_status(drive)
                        result["logical"].append({
                            "drive": drive, "label": vol[0] or "No Label",
                            "fstype": vol[4], "type": type_name,
                            "total": total, "used": total - free, "free": free,
                            "percent": round((total-free)*100/total, 1) if total else 0,
                            "bitlocker": bl.get("status", "N/A"),
                            "serial": str(vol[1]) if vol[1] else "N/A",
                        })
                    except Exception:
                        pass
            except ImportError:
                # PowerShell fallback
                ok, out = run_cmd(["powershell", "-NoProfile", "-Command",
                    "Get-PSDrive -PSProvider FileSystem | "
                    "Select-Object Name,Used,Free,Description | ConvertTo-Csv -NoTypeInformation"],
                    timeout=15)
                if ok:
                    for line in out.strip().split('\n')[1:]:
                        parts = [p.strip('"') for p in line.split(',')]
                        if len(parts) >= 3 and parts[0] and parts[1].isdigit():
                            used = int(parts[1]); free = int(parts[2])
                            total = used + free
                            result["logical"].append({
                                "drive": parts[0] + ":", "label": parts[3] if len(parts) > 3 else "",
                                "fstype": "?", "type": "Fixed",
                                "total": total, "used": used, "free": free,
                                "percent": round(used*100/total, 1) if total else 0,
                                "bitlocker": "N/A", "serial": "N/A",
                            })

            # ── Physical disks (Win) ──────────────────────────────────────────
            ok, out = run_cmd(["powershell", "-NoProfile", "-Command",
                "Get-PhysicalDisk | Select-Object FriendlyName,MediaType,Size,"
                "HealthStatus,OperationalStatus,SerialNumber | ConvertTo-Csv -NoTypeInformation"],
                timeout=20)
            if ok:
                for line in out.strip().split('\n')[1:]:
                    parts = [p.strip('"') for p in line.split(',')]
                    if len(parts) >= 5 and parts[0]:
                        try:
                            sz = int(parts[2]) if parts[2].isdigit() else 0
                        except Exception:
                            sz = 0
                        result["physical"].append({
                            "name":   parts[0],
                            "media":  parts[1] or "Unknown",
                            "size":   sz,
                            "health": parts[3] or "Unknown",
                            "status": parts[4] or "Unknown",
                            "serial": parts[5] if len(parts) > 5 else "N/A",
                        })

            # ── SMART via PowerShell / wmic ───────────────────────────────────
            ok2, out2 = run_cmd(["powershell", "-NoProfile", "-Command",
                "Get-WmiObject -Namespace root\\wmi -Class MSStorageDriver_FailurePredictStatus "
                "| Select-Object InstanceName,PredictFailure,Reason | ConvertTo-Csv -NoTypeInformation"],
                timeout=15)
            if ok2:
                for line in out2.strip().split('\n')[1:]:
                    parts = [p.strip('"') for p in line.split(',')]
                    if len(parts) >= 3 and parts[0]:
                        result["smart"][parts[0]] = {
                            "predict_failure": parts[1].lower() == "true",
                            "reason": parts[2] or "0",
                        }

        else:
            # ── Linux: lsblk + smartctl ──────────────────────────────────────
            ok, out = run_cmd(["lsblk", "-o",
                "NAME,TYPE,FSTYPE,SIZE,MOUNTPOINT,LABEL,MODEL,VENDOR,SERIAL,ROTA",
                "-J"], timeout=10)
            if ok:
                try:
                    data = json.loads(out)
                    for bd in data.get("blockdevices", []):
                        if bd.get("type") not in ("disk", "part", "lvm"):
                            continue
                        mp = bd.get("mountpoint") or ""
                        total = used = free = 0
                        if mp:
                            ok2, df = run_cmd(["df", "-B1", mp], timeout=5)
                            if ok2:
                                lines = df.strip().split('\n')
                                if len(lines) > 1:
                                    cols = lines[1].split()
                                    if len(cols) >= 4:
                                        total = int(cols[1]); used = int(cols[2]); free = int(cols[3])
                        result["logical"].append({
                            "drive": "/dev/" + bd.get("name", "?"),
                            "label": bd.get("label") or bd.get("model") or "No Label",
                            "fstype": bd.get("fstype") or "?",
                            "type": "SSD" if bd.get("rota") == "0" else "HDD",
                            "total": total, "used": used, "free": free,
                            "percent": round(used*100/total, 1) if total else 0,
                            "bitlocker": "N/A",
                            "serial": bd.get("serial") or "N/A",
                        })
                        # Physical disk entry for disks
                        if bd.get("type") == "disk":
                            result["physical"].append({
                                "name":   bd.get("model") or bd.get("name", "?"),
                                "media":  "SSD" if bd.get("rota") == "0" else "HDD",
                                "size":   total,
                                "health": "Unknown",
                                "status": "OK" if mp else "Not mounted",
                                "serial": bd.get("serial") or "N/A",
                            })
                except Exception:
                    pass

            # SMART via smartctl (if installed)
            ok3, out3 = run_cmd(["which", "smartctl"], timeout=3)
            if ok3:
                ok4, devs = run_cmd(["lsblk", "-d", "-o", "NAME", "-n"], timeout=5)
                if ok4:
                    for dev in devs.strip().split('\n'):
                        dev = dev.strip()
                        if not dev:
                            continue
                        ok5, smart_out = run_cmd(
                            ["smartctl", "-H", "-A", f"/dev/{dev}"], timeout=10)
                        if ok5 or smart_out:
                            result["smart"][dev] = smart_out

        return result

    # ── Refresh / Display dispatcher ──────────────────────────────────────────
    def _refresh_drives_info(self):
        """Refresh drives diagnostics (threaded)."""
        self._set_status("Scanning drives…")
        for w in self._drives_container.winfo_children():
            w.destroy()
        tk.Label(self._drives_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED,
                 bg=self.CLR_BG).pack(pady=20)

        def worker():
            data = self._gather_drives_data()
            self.after(0, lambda: self._display_drives_tab(data))

        threading.Thread(target=worker, daemon=True).start()

    def _display_drives_tab(self, data):
        for w in self._drives_container.winfo_children():
            w.destroy()

        tab = self._drives_tab.get()
        if tab == "overview":
            self._drives_tab_overview(data)
        elif tab == "smart":
            self._drives_tab_smart(data)
        elif tab == "partitions":
            self._drives_tab_partitions(data)
        elif tab == "physical":
            self._drives_tab_physical(data)
        elif tab == "log":
            self._drives_tab_log()

    # ── TAB: Overview ─────────────────────────────────────────────────────────
    def _drives_tab_overview(self, data):
        logical = data.get("logical", [])
        if not logical:
            tk.Label(self._drives_container,
                     text="No drives detected.",
                     font=("Segoe UI", 12), fg=self.CLR_MUTED,
                     bg=self.CLR_BG).pack(pady=40)
            self._set_status("No drives detected.")
            return

        for info in logical:
            pct = info["percent"]
            color = (self.CLR_SUCCESS if pct < 60 else
                     self.CLR_WARN    if pct < 85 else self.CLR_DANGER)

            card = tk.Frame(self._drives_container, bg=self.CLR_SURFACE)
            card.pack(fill=tk.X, padx=8, pady=5)

            strip = tk.Frame(card, width=4, bg=color)
            strip.pack(side=tk.LEFT, fill=tk.Y)

            inner = tk.Frame(card, bg=self.CLR_SURFACE)
            inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=14, pady=10)

            # Header row
            head = tk.Frame(inner, bg=self.CLR_SURFACE)
            head.pack(fill=tk.X)
            tk.Label(head, text=f"{info['drive']}  {info['label']}",
                     font=("Segoe UI", 13, "bold"),
                     fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(side=tk.LEFT)
            tk.Label(head, text=info["type"],
                     font=("Segoe UI", 9), fg=self.CLR_MUTED,
                     bg=self.CLR_SURFACE).pack(side=tk.LEFT, padx=10)
            tk.Label(head, text=info["fstype"],
                     font=("Segoe UI", 9, "bold"), fg=self.CLR_ACCENT,
                     bg=self.CLR_SURFACE).pack(side=tk.LEFT)

            # Usage bar
            bar_outer = tk.Frame(inner, bg=self.CLR_BG, height=8)
            bar_outer.pack(fill=tk.X, pady=(6, 2))
            bar_outer.pack_propagate(False)
            bar_inner = tk.Frame(bar_outer, bg=color, height=8)
            bar_inner.place(relwidth=pct / 100, relheight=1.0)

            # Capacity row
            total_gb = round(info['total'] / (1024**3), 1) if info['total'] else 0
            used_gb  = round(info['used']  / (1024**3), 1) if info['used']  else 0
            free_gb  = round(info['free']  / (1024**3), 1) if info['free']  else 0
            cap_txt  = (f"Total: {total_gb} GB   Used: {used_gb} GB ({pct}%)   "
                        f"Free: {free_gb} GB   S/N: {info['serial']}   "
                        f"BitLocker: {info['bitlocker']}")
            tk.Label(inner, text=cap_txt,
                     font=("Segoe UI", 9), fg=self.CLR_MUTED,
                     bg=self.CLR_SURFACE).pack(anchor=tk.W)

            # Quick-action buttons per drive
            btn_row = tk.Frame(inner, bg=self.CLR_SURFACE)
            btn_row.pack(anchor=tk.W, pady=(8, 0))
            drive_letter = info["drive"].replace(":", "").strip()
            self._action_btn(btn_row, "CHKDSK", self.CLR_WARN,
                             lambda d=drive_letter: self._run_chkdsk(d, fix=False)
                             ).pack(side=tk.LEFT, padx=(0, 4))
            self._action_btn(btn_row, "CHKDSK /F", self.CLR_DANGER,
                             lambda d=drive_letter: self._run_chkdsk(d, fix=True)
                             ).pack(side=tk.LEFT, padx=(0, 4))
            if sys.platform == "win32":
                self._action_btn(btn_row, "Defrag", self.CLR_ACCENT2,
                                 lambda d=drive_letter: self._run_defrag(d)
                                 ).pack(side=tk.LEFT, padx=(0, 4))
                self._action_btn(btn_row, "Trim (SSD)", self.CLR_SUCCESS,
                                 lambda d=drive_letter: self._run_trim(d)
                                 ).pack(side=tk.LEFT, padx=(0, 4))
            self._action_btn(btn_row, "Properties", self.CLR_MUTED,
                             lambda i=info: self._drive_properties_window(i)
                             ).pack(side=tk.LEFT, padx=(0, 4))

        self._set_status(f"Drives: {len(logical)} logical drive(s) found. Ready.")

    # ── TAB: SMART Data ───────────────────────────────────────────────────────
    def _drives_tab_smart(self, data):
        smart = data.get("smart", {})
        if not smart:
            tk.Label(self._drives_container,
                     text=("No SMART data available.\n"
                           "On Windows this requires WMI access (run as Administrator).\n"
                           "On Linux install smartmontools: sudo apt install smartmontools"),
                     font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG,
                     justify=tk.CENTER).pack(pady=40)
            return

        for dev, val in smart.items():
            card = tk.Frame(self._drives_container, bg=self.CLR_SURFACE)
            card.pack(fill=tk.X, padx=8, pady=5)

            if isinstance(val, dict):
                fail = val.get("predict_failure", False)
                color = self.CLR_DANGER if fail else self.CLR_SUCCESS
                status_txt = "FAILURE PREDICTED" if fail else "HEALTHY"
                tk.Label(card, text=f"  {dev}", font=("Segoe UI", 11, "bold"),
                         fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(anchor=tk.W, padx=10, pady=(8, 2))
                tk.Label(card, text=f"  SMART Status: {status_txt}   Reason code: {val.get('reason','0')}",
                         font=("Segoe UI", 10), fg=color,
                         bg=self.CLR_SURFACE).pack(anchor=tk.W, padx=10, pady=(0, 8))
            else:
                # Raw smartctl output (Linux)
                tk.Label(card, text=f"  {dev}", font=("Segoe UI", 11, "bold"),
                         fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(anchor=tk.W, padx=10, pady=(8, 4))
                txt = tk.Text(card, bg=self.CLR_BG, fg=self.CLR_TEXT,
                              font=("Consolas", 9), relief=tk.FLAT, bd=0,
                              height=min(20, val.count('\n') + 2),
                              wrap=tk.NONE, state=tk.NORMAL)
                txt.insert(tk.END, val)
                txt.config(state=tk.DISABLED)
                txt.pack(fill=tk.X, padx=10, pady=(0, 8))

    # ── TAB: Partitions ───────────────────────────────────────────────────────
    def _drives_tab_partitions(self, data):
        logical = data.get("logical", [])
        if not logical:
            tk.Label(self._drives_container, text="No partitions found.",
                     font=("Segoe UI", 12), fg=self.CLR_MUTED,
                     bg=self.CLR_BG).pack(pady=40)
            return

        # Column headers
        hdr = tk.Frame(self._drives_container, bg=self.CLR_HEADER_BG)
        hdr.pack(fill=tk.X, padx=4, pady=(0, 2))
        for txt, w in [("Drive", 12), ("Label", 18), ("FS", 10),
                       ("Type", 14), ("Total GB", 10), ("Used GB", 10),
                       ("Free GB", 10), ("Use %", 8), ("S/N", 18)]:
            tk.Label(hdr, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_HEADER_BG,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

        for i, info in enumerate(logical):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            row = tk.Frame(self._drives_container, bg=bg)
            row.pack(fill=tk.X, padx=4, pady=1)
            pct = info["percent"]
            pct_color = (self.CLR_SUCCESS if pct < 60 else
                         self.CLR_WARN    if pct < 85 else self.CLR_DANGER)
            vals = [
                (info["drive"],                        12, self.CLR_ACCENT),
                (info["label"][:17],                   18, self.CLR_TEXT),
                (info["fstype"],                       10, self.CLR_TEXT),
                (info["type"],                         14, self.CLR_MUTED),
                (str(round(info["total"]/(1024**3),1)),10, self.CLR_TEXT),
                (str(round(info["used"] /(1024**3),1)),10, self.CLR_TEXT),
                (str(round(info["free"] /(1024**3),1)),10, self.CLR_TEXT),
                (f"{pct}%",                             8, pct_color),
                (info["serial"][:17],                  18, self.CLR_MUTED),
            ]
            for val, w, fg in vals:
                tk.Label(row, text=val, font=("Segoe UI", 9),
                         fg=fg, bg=bg, width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=3)

    # ── TAB: Physical Disks ───────────────────────────────────────────────────
    def _drives_tab_physical(self, data):
        phys = data.get("physical", [])
        if not phys:
            tk.Label(self._drives_container,
                     text=("No physical disk data available.\n"
                           "Run as Administrator for full physical disk information."),
                     font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG,
                     justify=tk.CENTER).pack(pady=40)
            return

        for info in phys:
            health_color = (self.CLR_SUCCESS if info["health"].lower() in ("healthy", "ok", "unknown") else
                            self.CLR_DANGER)
            card = tk.Frame(self._drives_container, bg=self.CLR_SURFACE)
            card.pack(fill=tk.X, padx=8, pady=5)
            strip = tk.Frame(card, width=4, bg=health_color)
            strip.pack(side=tk.LEFT, fill=tk.Y)
            inner = tk.Frame(card, bg=self.CLR_SURFACE)
            inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=14, pady=10)

            head = tk.Frame(inner, bg=self.CLR_SURFACE)
            head.pack(fill=tk.X)
            tk.Label(head, text=info["name"], font=("Segoe UI", 13, "bold"),
                     fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(side=tk.LEFT)
            tk.Label(head, text=f"  {info['media']}",
                     font=("Segoe UI", 10), fg=self.CLR_ACCENT,
                     bg=self.CLR_SURFACE).pack(side=tk.LEFT)

            sz_gb = round(info["size"] / (1024**3), 1) if info["size"] else 0
            details = (f"Size: {sz_gb} GB   Health: {info['health']}   "
                       f"Status: {info['status']}   S/N: {info['serial']}")
            tk.Label(inner, text=details, font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE).pack(anchor=tk.W, pady=(4, 0))

    # ── TAB: Repair Log ───────────────────────────────────────────────────────
    def _drives_tab_log(self):
        if not self._drives_repair_log:
            tk.Label(self._drives_container,
                     text="No repair / diagnostic operations have been run yet.",
                     font=("Segoe UI", 11), fg=self.CLR_MUTED,
                     bg=self.CLR_BG).pack(pady=40)
            return

        # Header
        hdr = tk.Frame(self._drives_container, bg=self.CLR_HEADER_BG)
        hdr.pack(fill=tk.X, padx=4, pady=(0, 4))
        tk.Label(hdr, text="Repair & Diagnostic Log",
                 font=("Segoe UI", 10, "bold"), fg=self.CLR_ACCENT,
                 bg=self.CLR_HEADER_BG).pack(side=tk.LEFT, padx=12, pady=4)
        self._action_btn(hdr, "Clear Log", self.CLR_DANGER,
                         self._clear_drives_log).pack(side=tk.RIGHT, padx=8, pady=4)

        for entry in reversed(self._drives_repair_log):
            frame = tk.Frame(self._drives_container, bg=self.CLR_SURFACE)
            frame.pack(fill=tk.X, padx=4, pady=3)
            color = self.CLR_SUCCESS if entry.get("ok") else self.CLR_DANGER
            tk.Label(frame, text=entry.get("time", ""),
                     font=("Segoe UI", 8), fg=self.CLR_MUTED,
                     bg=self.CLR_SURFACE).pack(anchor=tk.W, padx=10, pady=(6, 0))
            tk.Label(frame, text=entry.get("title", ""),
                     font=("Segoe UI", 10, "bold"), fg=color,
                     bg=self.CLR_SURFACE).pack(anchor=tk.W, padx=10)
            txt = tk.Text(frame, bg=self.CLR_BG, fg=self.CLR_TEXT,
                          font=("Consolas", 8), relief=tk.FLAT, bd=0,
                          height=min(10, entry.get("output","").count('\n') + 2),
                          wrap=tk.WORD, state=tk.NORMAL)
            txt.insert(tk.END, entry.get("output", ""))
            txt.config(state=tk.DISABLED)
            txt.pack(fill=tk.X, padx=10, pady=(2, 8))

    def _clear_drives_log(self):
        self._drives_repair_log.clear()
        self._refresh_drives_info()

    def _log_drive_op(self, title: str, output: str, ok: bool):
        self._drives_repair_log.append({
            "time":   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "title":  title,
            "output": output,
            "ok":     ok,
        })

    # ── Drive Properties Popup ────────────────────────────────────────────────
    def _drive_properties_window(self, info: dict):
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title(f"Properties – {info['drive']}")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.44), 340)
        _mh = max(int(_ph * 0.5), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)

        tk.Label(win, text=f"  {info['drive']}  {info['label']}",
                 font=("Segoe UI", 14, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20, pady=(18, 8))
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20)

        props = [
            ("Drive",       info["drive"]),
            ("Label",       info["label"]),
            ("File System", info["fstype"]),
            ("Type",        info["type"]),
            ("Total",       f"{round(info['total']/(1024**3),2)} GB" if info['total'] else "N/A"),
            ("Used",        f"{round(info['used'] /(1024**3),2)} GB ({info['percent']}%)"),
            ("Free",        f"{round(info['free'] /(1024**3),2)} GB"),
            ("Serial No.",  info["serial"]),
            ("BitLocker",   info["bitlocker"]),
        ]
        for key, val in props:
            row = tk.Frame(win, bg=self.CLR_SURFACE)
            row.pack(fill=tk.X, padx=20, pady=2)
            tk.Label(row, text=f"  {key}", font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE, width=16,
                     anchor=tk.W).pack(side=tk.LEFT, pady=4)
            tk.Label(row, text=val, font=("Segoe UI", 9),
                     fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(side=tk.LEFT, pady=4)

        tk.Button(win, text="Close", font=("Segoe UI", 9, "bold"),
                  fg=self.CLR_BG, bg=self.CLR_ACCENT, relief=tk.FLAT, bd=0,
                  padx=20, pady=6, cursor="hand2",
                  command=win.destroy).pack(side=tk.BOTTOM, pady=16)

    # ── CHKDSK ────────────────────────────────────────────────────────────────
    def _drives_chkdsk_dialog(self):
        """Select drive and run CHKDSK."""
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title("CHKDSK – Check Disk")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.42), 340)
        _mh = max(int(_ph * 0.44), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)

        tk.Label(win, text="Check Disk (CHKDSK / fsck)",
                 font=("Segoe UI", 13, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(padx=20, pady=(18, 4), anchor=tk.W)
        tk.Label(win,
                 text=("Scans the file system for errors.\n"
                       "/F flag fixes errors (may require reboot on Windows).\n"
                       "On Linux uses fsck (unmounted partitions only)."),
                 font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_BG,
                 justify=tk.LEFT).pack(padx=20, anchor=tk.W)
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20, pady=8)

        r = tk.Frame(win, bg=self.CLR_BG)
        r.pack(fill=tk.X, padx=20, pady=4)
        tk.Label(r, text="Drive / Device:", font=("Segoe UI", 10),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(side=tk.LEFT)
        drive_var = tk.StringVar(value="C" if sys.platform == "win32" else "/dev/sda1")
        tk.Entry(r, textvariable=drive_var, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=18).pack(side=tk.LEFT, padx=8)

        fix_var = tk.BooleanVar(value=False)
        tk.Checkbutton(win, text="Fix errors automatically (/F)", variable=fix_var,
                       font=("Segoe UI", 10), fg=self.CLR_TEXT, bg=self.CLR_BG,
                       activebackground=self.CLR_BG, selectcolor=self.CLR_SURFACE).pack(padx=20, pady=4, anchor=tk.W)

        scan_var = tk.BooleanVar(value=False)
        tk.Checkbutton(win, text="Scan for bad sectors (/R)", variable=scan_var,
                       font=("Segoe UI", 10), fg=self.CLR_TEXT, bg=self.CLR_BG,
                       activebackground=self.CLR_BG, selectcolor=self.CLR_SURFACE).pack(padx=20, anchor=tk.W)

        btn_row = tk.Frame(win, bg=self.CLR_BG)
        btn_row.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=14)
        tk.Button(btn_row, text="Cancel", font=("Segoe UI", 9),
                  fg=self.CLR_TEXT, bg=self.CLR_SURFACE, relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2",
                  command=win.destroy).pack(side=tk.RIGHT, padx=(8, 0))
        tk.Button(btn_row, text="Run CHKDSK", font=("Segoe UI", 9, "bold"),
                  fg=self.CLR_BG, bg=self.CLR_WARN, relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2",
                  command=lambda: (win.destroy(),
                                   self._run_chkdsk(drive_var.get(),
                                                    fix=fix_var.get(),
                                                    scan=scan_var.get()))
                  ).pack(side=tk.RIGHT)

    def _run_chkdsk(self, drive: str, fix: bool = False, scan: bool = False):
        drive = drive.strip().replace(":", "").upper()
        if sys.platform == "win32":
            cmd = ["chkdsk", f"{drive}:"]
            if fix:  cmd.append("/F")
            if scan: cmd.append("/R")
            title = f"CHKDSK {drive}: {'  /F' if fix else ''}{'  /R' if scan else ''}"
        else:
            cmd = ["fsck", "-n" if not fix else "-y", drive]
            title = f"fsck {drive}"

        if not messagebox.askyesno("Confirm CHKDSK",
                                   f"Run: {' '.join(cmd)}\n\n"
                                   "This may take a long time.\n"
                                   "Continue?"):
            return

        self._set_status(f"Running {title}…")
        self._drives_tab.set("log")
        self._switch_module("Drives")

        def worker():
            ok, out = run_cmd(cmd, timeout=600)
            self._log_drive_op(title, out or "(no output)", ok)
            self.after(0, lambda: (self._set_status(f"{'OK' if ok else 'Error'}: {title}"),
                                   self._refresh_drives_info()))

        threading.Thread(target=worker, daemon=True).start()

    # ── SMART Dialog ──────────────────────────────────────────────────────────
    def _drives_smart_dialog(self):
        """Show SMART dialog to pick device."""
        if sys.platform != "win32":
            # Linux: ask for device
            win = tk.Toplevel(self)
            win.transient(self)
            win.attributes("-topmost", True)
            win.title("SMART – Self-Monitoring Analysis")
            _pw = self.winfo_width() or self.winfo_reqwidth()
            _ph = self.winfo_height() or self.winfo_reqheight()
            _mw = max(int(_pw * 0.38), 340)
            _mh = max(int(_ph * 0.31), 200)
            _mx = self.winfo_rootx() + (_pw - _mw) // 2
            _my = self.winfo_rooty() + (_ph - _mh) // 2
            win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
            win.minsize(int(_mw * 0.7), int(_mh * 0.7))
            win.configure(bg=self.CLR_BG)
            win.resizable(False, False)
            tk.Label(win, text="SMART Self-Test",
                     font=("Segoe UI", 13, "bold"),
                     fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(padx=20, pady=(18, 4), anchor=tk.W)
            r = tk.Frame(win, bg=self.CLR_BG)
            r.pack(fill=tk.X, padx=20, pady=8)
            tk.Label(r, text="Device:", font=("Segoe UI", 10),
                     fg=self.CLR_TEXT, bg=self.CLR_BG).pack(side=tk.LEFT)
            dev_var = tk.StringVar(value="/dev/sda")
            tk.Entry(r, textvariable=dev_var, font=("Segoe UI", 10),
                     bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                     relief=tk.FLAT, bd=4, width=18).pack(side=tk.LEFT, padx=8)
            test_var = tk.StringVar(value="short")
            tf = tk.Frame(win, bg=self.CLR_BG)
            tf.pack(fill=tk.X, padx=20)
            tk.Label(tf, text="Test type:", font=("Segoe UI", 10),
                     fg=self.CLR_TEXT, bg=self.CLR_BG).pack(side=tk.LEFT)
            for t in ("short", "long"):
                tk.Radiobutton(tf, text=t, variable=test_var, value=t,
                               font=("Segoe UI", 10), fg=self.CLR_TEXT, bg=self.CLR_BG,
                               activebackground=self.CLR_BG,
                               selectcolor=self.CLR_SURFACE).pack(side=tk.LEFT, padx=8)
            btn_row = tk.Frame(win, bg=self.CLR_BG)
            btn_row.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=14)
            tk.Button(btn_row, text="Cancel", font=("Segoe UI", 9),
                      fg=self.CLR_TEXT, bg=self.CLR_SURFACE, relief=tk.FLAT, bd=0,
                      padx=14, pady=6, cursor="hand2",
                      command=win.destroy).pack(side=tk.RIGHT, padx=(8, 0))
            tk.Button(btn_row, text="Run SMART Test",
                      font=("Segoe UI", 9, "bold"),
                      fg=self.CLR_BG, bg=self.CLR_SUCCESS, relief=tk.FLAT, bd=0,
                      padx=14, pady=6, cursor="hand2",
                      command=lambda: (win.destroy(),
                                       self._run_smart_test(dev_var.get(), test_var.get()))
                      ).pack(side=tk.RIGHT)
        else:
            # Windows: switch to SMART tab
            self._drives_tab.set("smart")
            self._switch_module("Drives")

    def _run_smart_test(self, device: str, test_type: str = "short"):
        cmd = ["smartctl", "-t", test_type, device]
        title = f"SMART {test_type} test – {device}"
        self._set_status(f"Running {title}…")
        self._drives_tab.set("log")
        self._switch_module("Drives")

        def worker():
            ok, out = run_cmd(cmd, timeout=300)
            self._log_drive_op(title, out or "(no output)", ok)
            self.after(0, lambda: (self._set_status(f"{'OK' if ok else 'Error'}: {title}"),
                                   self._refresh_drives_info()))

        threading.Thread(target=worker, daemon=True).start()

    # ── Repair FS Dialog ──────────────────────────────────────────────────────
    def _drives_repair_dialog(self):
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title("Repair File System")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.44), 340)
        _mh = max(int(_ph * 0.53), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)

        tk.Label(win, text="Repair File System",
                 font=("Segoe UI", 13, "bold"),
                 fg=self.CLR_DANGER, bg=self.CLR_BG).pack(padx=20, pady=(18, 4), anchor=tk.W)
        tk.Label(win,
                 text=("Windows: SFC /scannow, DISM RestoreHealth, chkdsk /F /R\n"
                       "Linux: fsck -y (unmounted partition), e2fsck -f"),
                 font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_BG,
                 justify=tk.LEFT).pack(padx=20, anchor=tk.W)
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20, pady=8)

        ops = []
        if sys.platform == "win32":
            ops = [
                ("SFC /scannow  – System File Checker",        "sfc"),
                ("DISM RestoreHealth  – Component Store Repair","dism"),
                ("chkdsk C: /F /R  – Full disk check & repair", "chkdsk"),
            ]
        else:
            ops = [
                ("fsck -f /dev/sda1  – Force filesystem check", "fsck"),
                ("e2fsck -f /dev/sda1  – Ext2/3/4 repair",     "e2fsck"),
            ]

        op_var = tk.StringVar(value=ops[0][1] if ops else "")
        for label, key in ops:
            tk.Radiobutton(win, text=label, variable=op_var, value=key,
                           font=("Segoe UI", 10), fg=self.CLR_TEXT, bg=self.CLR_BG,
                           activebackground=self.CLR_BG,
                           selectcolor=self.CLR_SURFACE).pack(padx=24, anchor=tk.W, pady=2)

        drive_row = tk.Frame(win, bg=self.CLR_BG)
        drive_row.pack(fill=tk.X, padx=20, pady=(8, 4))
        tk.Label(drive_row, text="Drive / Device:", font=("Segoe UI", 10),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(side=tk.LEFT)
        drive_var = tk.StringVar(value="C" if sys.platform == "win32" else "/dev/sda1")
        tk.Entry(drive_row, textvariable=drive_var, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=18).pack(side=tk.LEFT, padx=8)

        btn_row = tk.Frame(win, bg=self.CLR_BG)
        btn_row.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=14)
        tk.Button(btn_row, text="Cancel", font=("Segoe UI", 9),
                  fg=self.CLR_TEXT, bg=self.CLR_SURFACE, relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2",
                  command=win.destroy).pack(side=tk.RIGHT, padx=(8, 0))
        tk.Button(btn_row, text="RUN REPAIR", font=("Segoe UI", 9, "bold"),
                  fg=self.CLR_BG, bg=self.CLR_DANGER, relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2",
                  command=lambda: (win.destroy(),
                                   self._run_repair_op(op_var.get(), drive_var.get()))
                  ).pack(side=tk.RIGHT)

    def _run_repair_op(self, op: str, drive: str):
        drive = drive.strip()
        if op == "sfc":
            cmd = ["sfc", "/scannow"]
            title = "SFC /scannow"
        elif op == "dism":
            cmd = ["dism", "/Online", "/Cleanup-Image", "/RestoreHealth"]
            title = "DISM RestoreHealth"
        elif op == "chkdsk":
            letter = drive.replace(":", "").upper()
            cmd = ["chkdsk", f"{letter}:", "/F", "/R"]
            title = f"chkdsk {letter}: /F /R"
        elif op == "fsck":
            cmd = ["fsck", "-f", "-y", drive]
            title = f"fsck {drive}"
        elif op == "e2fsck":
            cmd = ["e2fsck", "-f", "-y", drive]
            title = f"e2fsck {drive}"
        else:
            return

        if not messagebox.askyesno("Confirm Repair",
                                   f"Run: {' '.join(cmd)}\n\nThis operation may take several minutes.\n"
                                   "Ensure the target is not the active system drive.\nContinue?"):
            return

        self._set_status(f"Running {title}…")
        self._drives_tab.set("log")
        self._switch_module("Drives")

        def worker():
            ok, out = run_cmd(cmd, timeout=900)
            self._log_drive_op(title, out or "(no output)", ok)
            self.after(0, lambda: (self._set_status(f"{'OK' if ok else 'Error'}: {title}"),
                                   self._refresh_drives_info()))

        threading.Thread(target=worker, daemon=True).start()

    # ── Defrag ────────────────────────────────────────────────────────────────
    def _run_defrag(self, drive: str):
        drive = drive.replace(":", "").upper()
        cmd = ["defrag", f"{drive}:", "/U", "/V"]
        title = f"Defrag {drive}:"
        if not messagebox.askyesno("Confirm Defrag",
                                   f"Defragment drive {drive}:?\n\nThis may take a long time."):
            return
        self._set_status(f"Running {title}…")
        self._drives_tab.set("log")
        self._switch_module("Drives")

        def worker():
            ok, out = run_cmd(cmd, timeout=3600)
            self._log_drive_op(title, out or "(no output)", ok)
            self.after(0, lambda: (self._set_status(f"{'OK' if ok else 'Error'}: {title}"),
                                   self._refresh_drives_info()))

        threading.Thread(target=worker, daemon=True).start()

    # ── Trim (SSD) ────────────────────────────────────────────────────────────
    def _run_trim(self, drive: str):
        drive = drive.replace(":", "").upper()
        cmd = ["defrag", f"{drive}:", "/L"]  # /L = retrim SSD
        title = f"Trim (SSD) {drive}:"
        if not messagebox.askyesno("Confirm SSD Trim",
                                   f"Run TRIM on drive {drive}:?\n\nOptimises SSD performance."):
            return
        self._set_status(f"Running {title}…")
        self._drives_tab.set("log")
        self._switch_module("Drives")

        def worker():
            ok, out = run_cmd(cmd, timeout=300)
            self._log_drive_op(title, out or "(no output)", ok)
            self.after(0, lambda: (self._set_status(f"{'OK' if ok else 'Error'}: {title}"),
                                   self._refresh_drives_info()))

        threading.Thread(target=worker, daemon=True).start()

    # ── Disk Cleanup Dialog ───────────────────────────────────────────────────
    def _drives_cleanup_dialog(self):
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title("Disk Cleanup")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.4), 340)
        _mh = max(int(_ph * 0.41), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)

        tk.Label(win, text="Disk Cleanup",
                 font=("Segoe UI", 13, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(padx=20, pady=(18, 4), anchor=tk.W)
        tk.Label(win,
                 text=("Windows: cleanmgr (disk cleanup wizard)\n"
                       "or DISM /StartComponentCleanup for WinSxS\n"
                       "Linux: apt autoremove / journalctl vacuum"),
                 font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_BG,
                 justify=tk.LEFT).pack(padx=20, anchor=tk.W)
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20, pady=8)

        if sys.platform == "win32":
            ops = [
                ("Disk Cleanup Wizard  (cleanmgr)", "cleanmgr"),
                ("WinSxS Cleanup  (DISM)",           "dism_cleanup"),
                ("Temp files – %TEMP%",              "temp"),
            ]
        else:
            ops = [
                ("APT autoremove",             "apt"),
                ("Journal vacuum (30 days)",   "journal"),
                ("Clear /tmp",                 "tmp"),
            ]

        op_var = tk.StringVar(value=ops[0][1])
        for label, key in ops:
            tk.Radiobutton(win, text=label, variable=op_var, value=key,
                           font=("Segoe UI", 10), fg=self.CLR_TEXT, bg=self.CLR_BG,
                           activebackground=self.CLR_BG,
                           selectcolor=self.CLR_SURFACE).pack(padx=24, anchor=tk.W, pady=2)

        btn_row = tk.Frame(win, bg=self.CLR_BG)
        btn_row.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=14)
        tk.Button(btn_row, text="Cancel", font=("Segoe UI", 9),
                  fg=self.CLR_TEXT, bg=self.CLR_SURFACE, relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2",
                  command=win.destroy).pack(side=tk.RIGHT, padx=(8, 0))
        tk.Button(btn_row, text="Run Cleanup", font=("Segoe UI", 9, "bold"),
                  fg=self.CLR_BG, bg=self.CLR_ACCENT, relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2",
                  command=lambda: (win.destroy(),
                                   self._run_cleanup_op(op_var.get()))
                  ).pack(side=tk.RIGHT)

    def _run_cleanup_op(self, op: str):
        if op == "cleanmgr":
            cmd = ["cleanmgr"]; title = "Disk Cleanup Wizard"
        elif op == "dism_cleanup":
            cmd = ["dism", "/Online", "/Cleanup-Image", "/StartComponentCleanup"]
            title = "DISM WinSxS Cleanup"
        elif op == "temp":
            import tempfile
            tmp = tempfile.gettempdir()
            cmd = ["cmd", "/c", f"del /q /f /s \"{tmp}\\*\""]
            title = "Delete Temp Files"
        elif op == "apt":
            cmd = ["apt-get", "autoremove", "-y"]; title = "APT Autoremove"
        elif op == "journal":
            cmd = ["journalctl", "--vacuum-time=30d"]; title = "Journal Vacuum (30d)"
        elif op == "tmp":
            cmd = ["rm", "-rf", "/tmp/*"]; title = "Clear /tmp"
        else:
            return

        self._set_status(f"Running {title}…")
        self._drives_tab.set("log")
        self._switch_module("Drives")

        def worker():
            ok, out = run_cmd(cmd, timeout=300)
            self._log_drive_op(title, out or "(no output)", ok)
            self.after(0, lambda: (self._set_status(f"{'OK' if ok else 'Done'}: {title}"),
                                   self._refresh_drives_info()))

        threading.Thread(target=worker, daemon=True).start()

    # ── Benchmark Dialog ──────────────────────────────────────────────────────
    def _drives_benchmark_dialog(self):
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title("Drive Benchmark")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.42), 340)
        _mh = max(int(_ph * 0.5), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)

        tk.Label(win, text="Drive Benchmark",
                 font=("Segoe UI", 13, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(padx=20, pady=(18, 4), anchor=tk.W)
        tk.Label(win,
                 text=("Measures sequential read / write speed using a temporary test file.\n"
                       "File size: 256 MB.  Results logged to Repair Log."),
                 font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_BG,
                 justify=tk.LEFT).pack(padx=20, anchor=tk.W)
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20, pady=8)

        r = tk.Frame(win, bg=self.CLR_BG)
        r.pack(fill=tk.X, padx=20, pady=4)
        tk.Label(r, text="Target path:", font=("Segoe UI", 10),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(side=tk.LEFT)
        default_path = os.environ.get("TEMP", "/tmp") if sys.platform == "win32" else "/tmp"
        path_var = tk.StringVar(value=default_path)
        tk.Entry(r, textvariable=path_var, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=22).pack(side=tk.LEFT, padx=8)

        result_var = tk.StringVar(value="")
        result_lbl = tk.Label(win, textvariable=result_var,
                              font=("Segoe UI", 11, "bold"),
                              fg=self.CLR_SUCCESS, bg=self.CLR_BG, justify=tk.LEFT)
        result_lbl.pack(padx=20, pady=8, anchor=tk.W)

        btn_row = tk.Frame(win, bg=self.CLR_BG)
        btn_row.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=14)
        tk.Button(btn_row, text="Close", font=("Segoe UI", 9),
                  fg=self.CLR_TEXT, bg=self.CLR_SURFACE, relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2",
                  command=win.destroy).pack(side=tk.RIGHT, padx=(8, 0))
        tk.Button(btn_row, text="Run Benchmark", font=("Segoe UI", 9, "bold"),
                  fg=self.CLR_BG, bg=self.CLR_ACCENT, relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2",
                  command=lambda: self._run_benchmark(path_var.get(), result_var)
                  ).pack(side=tk.RIGHT)

    def _run_benchmark(self, path: str, result_var: tk.StringVar):
        """Simple sequential R/W benchmark using Python file I/O."""
        import time, os
        test_file = os.path.join(path, "_bench_tmp_.bin")
        size_mb = 256
        chunk = b'\x00' * (1024 * 1024)  # 1 MB chunks
        result_var.set("Running…")
        self._set_status("Benchmark running…")

        def worker():
            try:
                # Write
                t0 = time.perf_counter()
                with open(test_file, "wb") as f:
                    for _ in range(size_mb):
                        f.write(chunk)
                    f.flush()
                    os.fsync(f.fileno())
                write_time = time.perf_counter() - t0
                write_speed = size_mb / write_time

                # Read
                t1 = time.perf_counter()
                with open(test_file, "rb") as f:
                    while f.read(1024 * 1024):
                        pass
                read_time = time.perf_counter() - t1
                read_speed = size_mb / read_time

                os.remove(test_file)

                msg = (f"Write: {write_speed:.1f} MB/s   ({size_mb} MB in {write_time:.1f}s)\n"
                       f"Read:  {read_speed:.1f} MB/s   ({size_mb} MB in {read_time:.1f}s)")
                self._log_drive_op(f"Benchmark – {path}", msg, True)
                self.after(0, lambda: (result_var.set(msg),
                                       self._set_status("Benchmark complete.")))
            except Exception as e:
                err = str(e)
                self.after(0, lambda: (result_var.set(f"Error: {err}"),
                                       self._set_status(f"Benchmark error: {err}")))
                try:
                    os.remove(test_file)
                except Exception:
                    pass

        threading.Thread(target=worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: Processes
    # ══════════════════════════════════════════════════════════════════════════
    def _render_processes(self):
        self._module_header("", "Processes", "Process Manager")

        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=20, pady=6)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         self._refresh_processes).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(tb, text="Search:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(8, 4))
        self._proc_search = tk.StringVar()
        tk.Entry(tb, textvariable=self._proc_search, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=22).pack(side=tk.LEFT)
        self._proc_search.trace_add("write", lambda *a: self._filter_processes())

        self._col_headers([("PID", 8), ("NAZWA PROCESU", 42), ("PAMIĘĆ", 12), ("STATUS", 10), ("", 12)])
        self._proc_container = self._scrollable_area()
        self._all_procs = []
        self._refresh_processes()

    def _refresh_processes(self):
        self._set_status("Loading processes…")
        for w in self._proc_container.winfo_children():
            w.destroy()
        tk.Label(self._proc_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)
        threading.Thread(target=lambda: self.after(0, lambda: self._display_processes(get_processes())),
                         daemon=True).start()

    def _display_processes(self, procs):
        self._all_procs = procs
        self._filter_processes()
        self._set_status(f"Processes: {len(procs)}")

    def _filter_processes(self):
        q = self._proc_search.get().lower() if hasattr(self, '_proc_search') else ""
        for w in self._proc_container.winfo_children():
            w.destroy()
        procs = [p for p in self._all_procs if q in p['name'].lower() or q in p['pid']]
        for i, p in enumerate(procs[:200]):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            row = tk.Frame(self._proc_container, bg=bg)
            row.pack(fill=tk.X, padx=8, pady=1)
            tk.Label(row, text=p['pid'], font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=bg, width=8, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=3)
            tk.Label(row, text=p['name'][:44], font=("Segoe UI", 10),
                     fg=self.CLR_TEXT, bg=bg, width=42, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=p['mem'], font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=bg, width=12, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            sc = self.CLR_SUCCESS if p['status'] in ('Running', 'S', 'R') else self.CLR_MUTED
            tk.Label(row, text=p['status'], font=("Segoe UI", 9),
                     fg=sc, bg=bg, width=10, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            self._action_btn(row, "KILL", self.CLR_DANGER,
                             lambda pid=p['pid'], name=p['name']: self._kill_process(pid, name)
                             ).pack(side=tk.RIGHT, padx=8)

    def _kill_process(self, pid, name):
        # Validate PID before confirmation
        if not pid or not pid.isdigit():
            messagebox.showerror("Error", "Invalid process ID.")
            return
        if not messagebox.askyesno("Confirm", f"Terminate process:\n{name}  (PID {pid})?"):
            return
        self._set_status(f"Terminating process {pid}…")
        def worker():
            ok, msg = kill_process(pid)
            self.after(0, lambda: (self._set_status(f"{'OK' if ok else 'ERROR'} {msg}"),
                                   self._refresh_processes() if ok else None))
        threading.Thread(target=worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: Network
    # ══════════════════════════════════════════════════════════════════════════
    def _render_network(self):
        self._module_header("", "Network", "Network Info")
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=20, pady=6)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         self._refresh_network).pack(side=tk.LEFT)
        self._net_container = self._scrollable_area()
        self._refresh_network()

    def _refresh_network(self):
        self._set_status("Fetching network info…")
        for w in self._net_container.winfo_children():
            w.destroy()
        tk.Label(self._net_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)
        threading.Thread(target=lambda: self.after(0, lambda: self._display_network(get_network_info())),
                         daemon=True).start()

    def _display_network(self, info):
        for w in self._net_container.winfo_children():
            w.destroy()

        def section(t):
            tk.Label(self._net_container, text=t, font=("Segoe UI", 11, "bold"),
                     fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(anchor=tk.W, padx=12, pady=(14, 2))
            tk.Frame(self._net_container, bg=self.CLR_BORDER, height=1
                     ).pack(fill=tk.X, padx=12, pady=(0, 6))

        def kv(key, val, color=None):
            row = tk.Frame(self._net_container, bg=self.CLR_SURFACE)
            row.pack(fill=tk.X, padx=12, pady=2)
            tk.Label(row, text=f"  {key}", font=("Segoe UI", 10, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE, width=22, anchor=tk.W
                     ).pack(side=tk.LEFT, pady=4)
            tk.Label(row, text=val, font=("Segoe UI", 10),
                     fg=color or self.CLR_TEXT, bg=self.CLR_SURFACE).pack(side=tk.LEFT, pady=4)

        section("PODSTAWOWE INFORMACJE")
        kv("Hostname",     info.get('hostname', 'N/A'))
        kv("IP (primary)",  info.get('ip', 'N/A'), self.CLR_ACCENT)
        kv("System",       platform.system() + " " + platform.release())
        kv("Architektura", platform.machine())

        section("TEST POŁĄCZENIA")
        for name, host in [("Google DNS", "8.8.8.8"), ("Cloudflare", "1.1.1.1")]:
            cmd = ['ping', '-n', '1', '-w', '1000', host] if sys.platform == "win32" \
                  else ['ping', '-c', '1', '-W', '1', host]
            ok, _ = run_cmd(cmd)
            kv(f"{name} ({host})", "ONLINE" if ok else "OFFLINE",
               self.CLR_SUCCESS if ok else self.CLR_DANGER)

        if info.get('raw'):
            section("INTERFEJSY SIECIOWE")
            txt = tk.Text(self._net_container, height=12, font=("Segoe UI", 9),
                          bg=self.CLR_SURFACE, fg=self.CLR_TEXT, relief=tk.FLAT, bd=0,
                          insertbackground=self.CLR_ACCENT)
            txt.pack(fill=tk.X, padx=12, pady=4)
            txt.insert("1.0", info['raw'])
            txt.configure(state=tk.DISABLED)

        if info.get('connections'):
            section("AKTYWNE PORTY")
            for conn in info['connections']:
                kv(conn.get('proto', ''),
                   f"{conn.get('local', '')}  [{conn.get('state', '')}]")

        self._set_status(f"Network: {info.get('hostname','?')} / {info.get('ip','?')}")

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: Services
    # ══════════════════════════════════════════════════════════════════════════
    def _render_services(self):
        self._module_header("", "Services", "Service Control")
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=20, pady=6)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         self._refresh_services).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(tb, text="Search:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(8, 4))
        self._svc_search = tk.StringVar()
        tk.Entry(tb, textvariable=self._svc_search, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=22).pack(side=tk.LEFT)
        self._svc_search.trace_add("write", lambda *a: self._filter_services())

        self._col_headers([("NAZWA USŁUGI", 34), ("STATUS", 12), ("TYP", 20), ("AKCJE", 26)])
        self._svc_container = self._scrollable_area()
        self._all_services = []
        self._refresh_services()

    def _refresh_services(self):
        self._set_status("Loading services…")
        for w in self._svc_container.winfo_children():
            w.destroy()
        tk.Label(self._svc_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)
        threading.Thread(target=lambda: self.after(0, lambda: self._display_services(get_services())),
                         daemon=True).start()

    def _display_services(self, svcs):
        self._all_services = svcs
        self._filter_services()
        self._set_status(f"Services: {len(svcs)}")

    def _filter_services(self):
        q = self._svc_search.get().lower() if hasattr(self, '_svc_search') else ""
        for w in self._svc_container.winfo_children():
            w.destroy()
        svcs = [s for s in self._all_services if q in s['name'].lower()]
        for i, svc in enumerate(svcs[:150]):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            row = tk.Frame(self._svc_container, bg=bg)
            row.pack(fill=tk.X, padx=8, pady=1)
            tk.Label(row, text=svc['name'][:35], font=("Segoe UI", 10),
                     fg=self.CLR_TEXT, bg=bg, width=34, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)
            running = svc['status'].lower() in ('running', 'active', '+')
            sc = self.CLR_SUCCESS if running else self.CLR_DANGER
            tk.Label(row, text="● " + svc['status'][:10], font=("Segoe UI", 9, "bold"),
                     fg=sc, bg=bg, width=12, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=svc.get('type', '')[:20], font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=bg, width=20, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            bf = tk.Frame(row, bg=bg)
            bf.pack(side=tk.RIGHT, padx=8)
            for label, action, color in [("START", "start", self.CLR_SUCCESS),
                                          ("STOP",  "stop",  self.CLR_DANGER),
                                          ("↺",     "restart", self.CLR_WARN)]:
                self._action_btn(bf, label, color,
                                 lambda n=svc['name'], a=action: self._svc_action(n, a)
                                 ).pack(side=tk.LEFT, padx=2)

    def _svc_action(self, name, action):
        if not is_admin():
            messagebox.showwarning("Uprawnienia", "Wymagane uprawnienia administratora.")
            return
        # Validate service name
        if not name or not all(c.isalnum() or c in '-_.' for c in name):
            messagebox.showerror("Error", "Invalid service name.")
            return
        if not messagebox.askyesno("Confirm",
                                   f"Execute '{action.upper()}' on service:\n{name}?"):
            return
        self._set_status(f"Executing {action} → {name}…")
        def worker():
            ok, msg = control_service(name, action)
            self.after(0, lambda: (self._set_status(f"{'OK' if ok else 'ERROR'} {msg}"),
                                   self._refresh_services()))
        threading.Thread(target=worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: Logs
    # ══════════════════════════════════════════════════════════════════════════
    def _render_logs(self):
        self._module_header("", "Logs", "System Logs")
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=20, pady=6)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         self._refresh_logs).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(tb, text="Filtr:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(8, 4))
        self._log_filter = tk.StringVar(value="ALL")
        for val, color in [("ALL", self.CLR_MUTED), ("INFO", self.CLR_SUCCESS),
                            ("WARN", self.CLR_WARN), ("ERROR", self.CLR_DANGER)]:
            tk.Radiobutton(tb, text=val, variable=self._log_filter, value=val,
                           font=("Segoe UI", 9, "bold"), fg=color,
                           bg=self.CLR_BG, selectcolor=self.CLR_SURFACE,
                           activebackground=self.CLR_BG,
                           command=self._filter_logs).pack(side=tk.LEFT, padx=4)
        tk.Label(tb, text="Search:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(10, 4))
        self._log_search = tk.StringVar()
        tk.Entry(tb, textvariable=self._log_search, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=18).pack(side=tk.LEFT)
        self._log_search.trace_add("write", lambda *a: self._filter_logs())

        self._col_headers([("POZIOM", 8), ("DATA/CZAS", 22), ("ŹRÓDŁO", 22), ("KOMUNIKAT", 60)])
        self._log_container = self._scrollable_area()
        self._all_logs = []
        self._refresh_logs()

    def _refresh_logs(self):
        self._set_status("Fetching logs…")
        for w in self._log_container.winfo_children():
            w.destroy()
        tk.Label(self._log_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)
        threading.Thread(target=lambda: self.after(0, lambda: self._display_logs(get_logs())),
                         daemon=True).start()

    def _display_logs(self, logs):
        self._all_logs = logs
        self._filter_logs()
        self._set_status(f"Entries: {len(logs)}")

    def _filter_logs(self):
        lf = self._log_filter.get() if hasattr(self, '_log_filter') else "ALL"
        q  = self._log_search.get().lower() if hasattr(self, '_log_search') else ""
        for w in self._log_container.winfo_children():
            w.destroy()
        logs = self._all_logs
        if lf != "ALL":
            logs = [l for l in logs if l['level'] == lf]
        if q:
            logs = [l for l in logs if q in l['message'].lower() or q in l['source'].lower()]
        COLORS = {"ERROR": self.CLR_DANGER, "WARN": self.CLR_WARN, "INFO": self.CLR_SUCCESS}
        for i, entry in enumerate(logs[:300]):
            bg  = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            lvl = entry.get('level', 'INFO')
            row = tk.Frame(self._log_container, bg=bg)
            row.pack(fill=tk.X, padx=8, pady=1)
            tk.Label(row, text=lvl, font=("Segoe UI", 9, "bold"),
                     fg=COLORS.get(lvl, self.CLR_MUTED), bg=bg, width=8, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4, pady=3)
            tk.Label(row, text=entry.get('date', '')[:22], font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=bg, width=22, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=entry.get('source', '')[:22], font=("Segoe UI", 9),
                     fg=self.CLR_ACCENT2, bg=bg, width=22, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=entry.get('message', '')[:90], font=("Segoe UI", 9),
                     fg=self.CLR_TEXT, bg=bg, anchor=tk.W).pack(side=tk.LEFT, padx=4, fill=tk.X)
        if not logs:
            tk.Label(self._log_container, text="No log entries match the filter.",
                     font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=30)



    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: USB Diagnostics
    # ══════════════════════════════════════════════════════════════════════════
    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: Database Library
    # ══════════════════════════════════════════════════════════════════════════
    def _render_databases(self):
        self._module_header("🗄️", "Database Library", "Database Engine Knowledge Base")

        # Toolbar with search
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=20, pady=6)
        tk.Label(tb, text="Search:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(0, 4))
        self._db_search = tk.StringVar()
        tk.Entry(tb, textvariable=self._db_search, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=26).pack(side=tk.LEFT)
        self._db_search.trace_add("write", lambda *a: self._filter_db())

        # Type filter
        self._db_type = tk.StringVar(value="ALL")
        types = ["ALL", "Relational", "NoSQL", "Embedded", "OLAP", "Time-Series", "Graph"]
        for t in types:
            tk.Radiobutton(tb, text=t, variable=self._db_type, value=t,
                           font=("Segoe UI", 8, "bold"), fg=self.CLR_ACCENT,
                           bg=self.CLR_BG, selectcolor=self.CLR_SURFACE,
                           activebackground=self.CLR_BG,
                           command=self._filter_db).pack(side=tk.LEFT, padx=3)

        # Column headers
        hdr = tk.Frame(self.content_frame, bg=self.CLR_SURFACE)
        hdr.pack(fill=tk.X, padx=20, pady=(4, 0))
        for txt, w in [("Engine", 18), ("Typ", 20), ("Port", 8),
                       ("License", 14), ("OS", 22)]:
            tk.Label(hdr, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

        self._db_container = self._scrollable_area()
        self._filter_db()

    def _filter_db(self):
        q   = self._db_search.get().lower() if hasattr(self, '_db_search') else ""
        typ = self._db_type.get()           if hasattr(self, '_db_type')   else "ALL"
        for w in self._db_container.winfo_children():
            w.destroy()

        rows = DB_LIBRARY
        if typ != "ALL":
            rows = [r for r in rows if typ.lower() in r[1].lower()]
        if q:
            rows = [r for r in rows if any(q in str(f).lower() for f in r)]

        for i, (name, dbtype, lic, port, os_, features, notes) in enumerate(rows):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            row = tk.Frame(self._db_container, bg=bg, cursor="hand2")
            row.pack(fill=tk.X, padx=8, pady=1)

            tk.Label(row, text=name, font=("Segoe UI", 10, "bold"),
                     fg=self.CLR_ACCENT, bg=bg, width=18, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4, pady=4)
            tk.Label(row, text=dbtype, font=("Segoe UI", 9),
                     fg=self.CLR_TEXT, bg=bg, width=20, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=port, font=("Segoe UI", 9),
                     fg=self.CLR_WARN, bg=bg, width=8, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=lic, font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=bg, width=14, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=os_, font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=bg, width=22, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)

            # Expandable detail on click
            row.bind("<Button-1>", lambda e, n=name, f=features, nt=notes, t=dbtype:
                     self._show_db_detail(n, t, f, nt))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, n=name, f=features, nt=notes, t=dbtype:
                           self._show_db_detail(n, t, f, nt))

        if not rows:
            tk.Label(self._db_container, text="No results for the selected filter.",
                     font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=30)

    def _show_db_detail(self, name, dbtype, features, notes):
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title(f"DB Info – {name}")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.54), 340)
        _mh = max(int(_ph * 0.41), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)

        tk.Label(win, text=f"🗄️  {name}", font=("Segoe UI", 14, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20, pady=(16, 4))
        tk.Label(win, text=f"Type: {dbtype}", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(anchor=tk.W, padx=20)

        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20, pady=10)

        tk.Label(win, text="Features:", font=("Segoe UI", 10, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20)
        tk.Label(win, text=features, font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=self.CLR_BG, wraplength=480, justify=tk.LEFT
                 ).pack(anchor=tk.W, padx=20, pady=(2, 10))

        tk.Label(win, text="Notes:", font=("Segoe UI", 10, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20)
        tk.Label(win, text=notes, font=("Segoe UI", 9),
                 fg=self.CLR_SUCCESS, bg=self.CLR_BG, wraplength=480, justify=tk.LEFT
                 ).pack(anchor=tk.W, padx=20, pady=(2, 16))

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: Filesystem / Partition Format Library
    # ══════════════════════════════════════════════════════════════════════════
    def _render_fslibrary(self):
        self._module_header("📚", "FS Library", "Partition Formats & Filesystem Reference")

        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=20, pady=6)
        tk.Label(tb, text="Search:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(0, 4))
        self._fs_search = tk.StringVar()
        tk.Entry(tb, textvariable=self._fs_search, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=24).pack(side=tk.LEFT)
        self._fs_search.trace_add("write", lambda *a: self._filter_fs())

        # Type filter
        self._fs_type = tk.StringVar(value="ALL")
        for t in ["ALL", "Journal", "COW", "Simple", "Log-struct", "Virtual", "RAM"]:
            tk.Radiobutton(tb, text=t, variable=self._fs_type, value=t,
                           font=("Segoe UI", 8, "bold"), fg=self.CLR_ACCENT,
                           bg=self.CLR_BG, selectcolor=self.CLR_SURFACE,
                           activebackground=self.CLR_BG,
                           command=self._filter_fs).pack(side=tk.LEFT, padx=2)

        hdr = tk.Frame(self.content_frame, bg=self.CLR_SURFACE)
        hdr.pack(fill=tk.X, padx=20, pady=(4, 0))
        for txt, w in [("FS", 10), ("Typ", 12), ("Max Vol", 10),
                       ("Max File", 10), ("OS Support", 30)]:
            tk.Label(hdr, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

        self._fs_container = self._scrollable_area()
        self._filter_fs()

    def _filter_fs(self):
        q   = self._fs_search.get().lower() if hasattr(self, '_fs_search') else ""
        typ = self._fs_type.get()           if hasattr(self, '_fs_type')   else "ALL"
        for w in self._fs_container.winfo_children():
            w.destroy()

        TYPE_COLORS = {
            "Journal":    self.CLR_ACCENT2,
            "COW":        self.CLR_SUCCESS,
            "Simple":     self.CLR_MUTED,
            "Log-struct": self.CLR_WARN,
            "Virtual":    "#AA88FF",
            "RAM":        "#FF88AA",
        }

        rows = FS_LIBRARY
        if typ != "ALL":
            rows = [r for r in rows if r[1] == typ]
        if q:
            rows = [r for r in rows if any(q in str(f).lower() for f in r)]

        for i, (name, fstype, maxvol, maxfile, os_, features, notes) in enumerate(rows):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            color = TYPE_COLORS.get(fstype, self.CLR_MUTED)

            row = tk.Frame(self._fs_container, bg=bg, cursor="hand2")
            row.pack(fill=tk.X, padx=8, pady=1)

            tk.Label(row, text=name, font=("Segoe UI", 10, "bold"),
                     fg=self.CLR_ACCENT, bg=bg, width=10, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4, pady=4)
            tk.Label(row, text=fstype, font=("Segoe UI", 9, "bold"),
                     fg=color, bg=bg, width=12, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=maxvol, font=("Segoe UI", 9),
                     fg=self.CLR_TEXT, bg=bg, width=10, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=maxfile, font=("Segoe UI", 9),
                     fg=self.CLR_TEXT, bg=bg, width=10, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=os_, font=("Segoe UI", 8),
                     fg=self.CLR_MUTED, bg=bg, width=30, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)

            row.bind("<Button-1>", lambda e, n=name, ft=fstype, f=features, nt=notes:
                     self._show_fs_detail(n, ft, f, nt))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, n=name, ft=fstype, f=features, nt=notes:
                           self._show_fs_detail(n, ft, f, nt))

        if not rows:
            tk.Label(self._fs_container, text="No results.",
                     font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=30)

    def _show_fs_detail(self, name, fstype, features, notes):
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title(f"FS Info – {name}")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.54), 340)
        _mh = max(int(_ph * 0.38), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)

        tk.Label(win, text=f"📚  {name}", font=("Segoe UI", 14, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20, pady=(16, 2))
        tk.Label(win, text=f"Type: {fstype}", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(anchor=tk.W, padx=20)
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20, pady=8)
        tk.Label(win, text="Features:", font=("Segoe UI", 10, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20)
        tk.Label(win, text=features, font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=self.CLR_BG, wraplength=480, justify=tk.LEFT
                 ).pack(anchor=tk.W, padx=20, pady=(2, 8))
        tk.Label(win, text="Notes:", font=("Segoe UI", 10, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20)
        tk.Label(win, text=notes, font=("Segoe UI", 9),
                 fg=self.CLR_SUCCESS, bg=self.CLR_BG, wraplength=480, justify=tk.LEFT
                 ).pack(anchor=tk.W, padx=20, pady=(2, 16))

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: USB Mass Memory DB
    # ══════════════════════════════════════════════════════════════════════════
    def _render_usbmass(self):
        self._module_header("🧲", "USB Mass DB", "USB Mass Storage Device Database")

        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=20, pady=6)
        tk.Label(tb, text="Search:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(0, 4))
        self._usb_db_search = tk.StringVar()
        tk.Entry(tb, textvariable=self._usb_db_search, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=28).pack(side=tk.LEFT)
        self._usb_db_search.trace_add("write", lambda *a: self._filter_usbmass())

        # Protocol filter
        self._usb_proto = tk.StringVar(value="ALL")
        for t in ["ALL", "BOT", "UAS", "TB3"]:
            tk.Radiobutton(tb, text=t, variable=self._usb_proto, value=t,
                           font=("Segoe UI", 8, "bold"), fg=self.CLR_ACCENT,
                           bg=self.CLR_BG, selectcolor=self.CLR_SURFACE,
                           activebackground=self.CLR_BG,
                           command=self._filter_usbmass).pack(side=tk.LEFT, padx=3)

        hdr = tk.Frame(self.content_frame, bg=self.CLR_SURFACE)
        hdr.pack(fill=tk.X, padx=20, pady=(4, 0))
        for txt, w in [("Manufacturer", 18), ("Model / Controller", 28),
                       ("Max Speed", 20), ("Protocol", 12)]:
            tk.Label(hdr, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

        self._usbmass_container = self._scrollable_area()
        self._filter_usbmass()

    def _filter_usbmass(self):
        q     = self._usb_db_search.get().lower() if hasattr(self, '_usb_db_search') else ""
        proto = self._usb_proto.get()             if hasattr(self, '_usb_proto')     else "ALL"
        for w in self._usbmass_container.winfo_children():
            w.destroy()

        SPEED_COLORS = {
            "USB 2.0":      self.CLR_MUTED,
            "USB 3.0":      self.CLR_ACCENT2,
            "USB 3.1":      self.CLR_ACCENT,
            "USB 3.2 Gen1": self.CLR_ACCENT2,
            "USB 3.2 Gen2": self.CLR_SUCCESS,
            "USB-C":        self.CLR_SUCCESS,
            "TB3":          self.CLR_WARN,
        }

        rows = USB_MASS_DB
        if proto != "ALL":
            rows = [r for r in rows if proto in r[3]]
        if q:
            rows = [r for r in rows if any(q in str(f).lower() for f in r)]

        for i, (vendor, model, speed, protocol, features, notes) in enumerate(rows):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG

            # Determine speed color
            spd_color = self.CLR_MUTED
            for key, col in SPEED_COLORS.items():
                if key in speed:
                    spd_color = col
                    break

            row = tk.Frame(self._usbmass_container, bg=bg, cursor="hand2")
            row.pack(fill=tk.X, padx=8, pady=1)

            tk.Label(row, text=vendor, font=("Segoe UI", 10, "bold"),
                     fg=self.CLR_ACCENT, bg=bg, width=18, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4, pady=5)
            tk.Label(row, text=model, font=("Segoe UI", 9),
                     fg=self.CLR_TEXT, bg=bg, width=28, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=speed, font=("Segoe UI", 9, "bold"),
                     fg=spd_color, bg=bg, width=20, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=protocol, font=("Segoe UI", 9),
                     fg=self.CLR_WARN, bg=bg, width=12, anchor=tk.W
                     ).pack(side=tk.LEFT, padx=4)

            row.bind("<Button-1>", lambda e, v=vendor, m=model, s=speed,
                     p=protocol, f=features, n=notes:
                     self._show_usbmass_detail(v, m, s, p, f, n))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, v=vendor, m=model, s=speed,
                           p=protocol, f=features, n=notes:
                           self._show_usbmass_detail(v, m, s, p, f, n))

        if not rows:
            tk.Label(self._usbmass_container, text="No results for the selected filter.",
                     font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=30)

    def _show_usbmass_detail(self, vendor, model, speed, protocol, features, notes):
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title(f"USB Info – {vendor}")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.54), 340)
        _mh = max(int(_ph * 0.42), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)

        tk.Label(win, text=f"🧲  {vendor}", font=("Segoe UI", 13, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20, pady=(16, 2))
        tk.Label(win, text=f"Model / Controller: {model}",
                 font=("Segoe UI", 10), fg=self.CLR_TEXT,
                 bg=self.CLR_BG).pack(anchor=tk.W, padx=20)
        tk.Label(win, text=f"Speed: {speed}  |  Protocol: {protocol}",
                 font=("Segoe UI", 10), fg=self.CLR_WARN,
                 bg=self.CLR_BG).pack(anchor=tk.W, padx=20, pady=(2, 0))
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20, pady=8)
        tk.Label(win, text="Features:", font=("Segoe UI", 10, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20)
        tk.Label(win, text=features, font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=self.CLR_BG, wraplength=480, justify=tk.LEFT
                 ).pack(anchor=tk.W, padx=20, pady=(2, 8))
        tk.Label(win, text="Notes:", font=("Segoe UI", 10, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(anchor=tk.W, padx=20)
        tk.Label(win, text=notes, font=("Segoe UI", 9),
                 fg=self.CLR_SUCCESS, bg=self.CLR_BG, wraplength=480, justify=tk.LEFT
                 ).pack(anchor=tk.W, padx=20, pady=(2, 16))

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: USB Diagnostics
    # ══════════════════════════════════════════════════════════════════════════
    def _render_usb(self):
        self._module_header("🔌", "USB Diagnostics", "USB Storage Devices + History (SQLite)")

        # ── Tab bar ──────────────────────────────────────────────────────────
        tab_bar = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tab_bar.pack(fill=tk.X, padx=20, pady=(0, 4))

        self._usb_tab = tk.StringVar(value="live")

        def _tab_btn(label, tag):
            def activate():
                self._usb_tab.set(tag)
                for t, b in _tab_btns.items():
                    b.config(
                        fg=self.CLR_TEXT if t == tag else self.CLR_MUTED,
                        bg=self.CLR_SURFACE if t == tag else self.CLR_BG,
                    )
                _show_tab(tag)

            btn = tk.Button(tab_bar, text=label, font=("Segoe UI", 10, "bold"),
                            fg=self.CLR_MUTED, bg=self.CLR_BG, relief=tk.FLAT,
                            activeforeground=self.CLR_TEXT, activebackground=self.CLR_SURFACE,
                            bd=0, padx=14, pady=5, cursor="hand2", command=activate)
            btn.pack(side=tk.LEFT, padx=(0, 2))
            return btn

        _tab_btns = {}
        _tab_btns["live"]    = _tab_btn("🔌  Live", "live")
        _tab_btns["history"] = _tab_btn("📂  Device History", "history")
        _tab_btns["events"]  = _tab_btn("📋  Event Log", "events")
        _tab_btns["stats"]   = _tab_btn("📊  Statistics", "stats")

        # Style initial active
        _tab_btns["live"].config(fg=self.CLR_TEXT, bg=self.CLR_SURFACE)

        tk.Frame(self.content_frame, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20, pady=(0, 6))

        # ── Tab content frame ────────────────────────────────────────────────
        self._usb_tab_frame = tk.Frame(self.content_frame, bg=self.CLR_BG)
        self._usb_tab_frame.pack(fill=tk.BOTH, expand=True)

        def _show_tab(tag):
            for w in self._usb_tab_frame.winfo_children():
                w.destroy()
            if tag == "live":
                self._render_usb_live(self._usb_tab_frame)
            elif tag == "history":
                self._render_usb_history(self._usb_tab_frame)
            elif tag == "events":
                self._render_usb_events(self._usb_tab_frame)
            elif tag == "stats":
                self._render_usb_stats(self._usb_tab_frame)

        _show_tab("live")

    # ─── Live tab ────────────────────────────────────────────────────────────
    def _render_usb_live(self, parent):
        tb = tk.Frame(parent, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=0, pady=4)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         self._refresh_usb).pack(side=tk.LEFT, padx=(0, 8))

        if sys.platform == "win32":
            self._action_btn(tb, "⏏  SAFE REMOVE", self.CLR_WARN,
                             self._safe_remove_usb).pack(side=tk.LEFT, padx=(0, 8))

        self._usb_container = self._scrollable_area(parent)
        self._refresh_usb()

    def _refresh_usb(self):
        self._set_status("Scanning USB devices…")
        for w in self._usb_container.winfo_children():
            w.destroy()
        tk.Label(self._usb_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)

        def worker():
            devs = get_usb_devices()
            # Save to DB in background
            try:
                if devs:
                    get_usb_db().record_scan(devs)
            except Exception:
                pass
            self.after(0, lambda: self._display_usb(devs))

        threading.Thread(target=worker, daemon=True).start()

    def _display_usb(self, devices):
        for w in self._usb_container.winfo_children():
            w.destroy()

        if not devices:
            tk.Label(self._usb_container,
                     text="No USB storage devices connected.",
                     font=("Segoe UI", 12), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=40)
            self._set_status("No USB devices found.")
            return

        for dev in devices:
            self._build_usb_card(self._usb_container, dev)

        self._set_status(f"USB: {len(devices)} device(s) found. Records saved to database.")

    # ─── History tab ─────────────────────────────────────────────────────────
    def _render_usb_history(self, parent):
        db = get_usb_db()

        # Toolbar
        tb = tk.Frame(parent, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=0, pady=4)

        tk.Label(tb, text="Search:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(0, 4))
        self._usb_hist_search = tk.StringVar()
        tk.Entry(tb, textvariable=self._usb_hist_search, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=22).pack(side=tk.LEFT)

        tk.Label(tb, text="  Sort:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(8, 4))
        self._usb_hist_order = tk.StringVar(value="last_seen DESC")
        sort_opts = [
            ("Last Seen", "last_seen DESC"),
            ("First Seen", "first_seen DESC"),
            ("Liczba połączeń ↓",  "connect_count DESC"),
            ("Name A→Z",          "name ASC"),
            ("Size ↓",          "total_bytes DESC"),
        ]
        om = tk.OptionMenu(tb, self._usb_hist_order, *[v for _, v in sort_opts])
        om.config(font=("Segoe UI", 9), bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                  activebackground=self.CLR_ACCENT2, bd=0, highlightthickness=0)
        om["menu"].config(bg=self.CLR_SURFACE, fg=self.CLR_TEXT, font=("Segoe UI", 9))
        for label, value in sort_opts:
            om["menu"].entryconfigure(label, label=label)
        om.pack(side=tk.LEFT)

        self._action_btn(tb, "🔍", self.CLR_ACCENT,
                         lambda: self._load_usb_history(container)).pack(side=tk.LEFT, padx=6)
        self._action_btn(tb, "💾  EXPORT CSV", self.CLR_SUCCESS,
                         self._export_usb_csv).pack(side=tk.LEFT, padx=(0, 6))
        self._action_btn(tb, "🗑  CLEAR HISTORY", self.CLR_DANGER,
                         self._clear_usb_history).pack(side=tk.LEFT)

        self._usb_hist_search.trace_add("write",
                                         lambda *a: self._load_usb_history(container))

        # Column headers
        hdr = tk.Frame(parent, bg=self.CLR_SURFACE)
        hdr.pack(fill=tk.X, padx=0, pady=(4, 0))
        for txt, w in [("Name", 20), ("Serial", 14), ("Manufacturer", 16),
                       ("FS", 8), ("Size", 10), ("Połączeń", 8),
                       ("Pierwsze", 16), ("Ostatnie", 16)]:
            tk.Label(hdr, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

        container = self._scrollable_area(parent)
        self._usb_hist_container = container
        self._load_usb_history(container)

    def _load_usb_history(self, container):
        db = get_usb_db()
        search = self._usb_hist_search.get() if hasattr(self, '_usb_hist_search') else ""
        order  = self._usb_hist_order.get()  if hasattr(self, '_usb_hist_order')  else "last_seen DESC"

        for w in container.winfo_children():
            w.destroy()

        devices = db.get_all_devices(search, order)
        if not devices:
            tk.Label(container, text="No USB devices in history database.",
                     font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=30)
            return

        for i, dev in enumerate(devices):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            row = tk.Frame(container, bg=bg, cursor="hand2")
            row.pack(fill=tk.X, padx=4, pady=1)

            size_gb = round(dev.get('total_bytes', 0) / 1024**3, 2) if dev.get('total_bytes') else 0

            def mk_lbl(text, width, color=None):
                tk.Label(row, text=str(text), font=("Segoe UI", 9),
                         fg=color or self.CLR_TEXT, bg=bg,
                         width=width, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

            mk_lbl(dev.get('name', '?')[:20],          20, self.CLR_ACCENT)
            mk_lbl(dev.get('serial', 'N/A')[:14],       14)
            mk_lbl(dev.get('manufacturer', '?')[:16],   16, self.CLR_MUTED)
            mk_lbl(dev.get('fstype', '?')[:8],           8, self.CLR_WARN)
            mk_lbl(f"{size_gb} GB",                     10)
            mk_lbl(dev.get('connect_count', 0),          8, self.CLR_SUCCESS)
            mk_lbl(str(dev.get('first_seen', ''))[:16], 16, self.CLR_MUTED)
            mk_lbl(str(dev.get('last_seen',  ''))[:16], 16, self.CLR_MUTED)

            # Delete button
            dev_id = dev['id']
            tk.Button(row, text="✕", font=("Segoe UI", 9), fg=self.CLR_DANGER,
                      bg=bg, relief=tk.FLAT, cursor="hand2", bd=0,
                      command=lambda d=dev_id, c=container: self._delete_usb_device(d, c)
                      ).pack(side=tk.RIGHT, padx=6)

            # Click for details
            click_cb = lambda e, d=dev: self._show_usb_history_detail(d)
            row.bind("<Button-1>", click_cb)
            for child in row.winfo_children():
                child.bind("<Button-1>", click_cb)

        tk.Label(container, text=f"Total: {len(devices)} unique device(s).",
                 font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(anchor=tk.W, padx=8, pady=4)

    def _show_usb_history_detail(self, dev: dict):
        win = tk.Toplevel(self)
        win.transient(self)
        win.attributes("-topmost", True)
        win.title(f"USB History – {dev.get('name', '?')}")
        _pw = self.winfo_width() or self.winfo_reqwidth()
        _ph = self.winfo_height() or self.winfo_reqheight()
        _mw = max(int(_pw * 0.58), 340)
        _mh = max(int(_ph * 0.62), 200)
        _mx = self.winfo_rootx() + (_pw - _mw) // 2
        _my = self.winfo_rooty() + (_ph - _mh) // 2
        win.geometry(f"{_mw}x{_mh}+{_mx}+{_my}")
        win.minsize(int(_mw * 0.7), int(_mh * 0.7))
        win.configure(bg=self.CLR_BG)
        win.resizable(True, True)

        tk.Label(win, text=f"🔌  {dev.get('name', 'USB Drive')}",
                 font=("Segoe UI", 14, "bold"), fg=self.CLR_ACCENT, bg=self.CLR_BG
                 ).pack(anchor=tk.W, padx=20, pady=(16, 4))

        info = [
            ("Serial",          dev.get('serial', 'N/A')),
            ("Manufacturer",       dev.get('manufacturer', 'Unknown')),
            ("File System",   dev.get('fstype', '?')),
            ("Drive / Path",dev.get('drive', '?')),
            ("Size",         f"{round(dev.get('total_bytes',0)/1024**3, 2)} GB"),
            ("Used",          f"{round(dev.get('used_bytes',0)/1024**3, 2)} GB"),
            ("Free",           f"{round(dev.get('free_bytes',0)/1024**3, 2)} GB"),
            ("Connections", dev.get('connect_count', 0)),
            ("First Seen",dev.get('first_seen', '?')),
            ("Last Seen",dev.get('last_seen', '?')),
        ]
        for label, value in info:
            row = tk.Frame(win, bg=self.CLR_BG)
            row.pack(fill=tk.X, padx=20, pady=1)
            tk.Label(row, text=f"{label}:", width=22, anchor=tk.W,
                     font=("Segoe UI", 9, "bold"), fg=self.CLR_MUTED, bg=self.CLR_BG
                     ).pack(side=tk.LEFT)
            tk.Label(row, text=str(value), anchor=tk.W,
                     font=("Segoe UI", 9), fg=self.CLR_TEXT, bg=self.CLR_BG
                     ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=20, pady=10)
        tk.Label(win, text="Recent Events:",
                 font=("Segoe UI", 10, "bold"), fg=self.CLR_TEXT, bg=self.CLR_BG
                 ).pack(anchor=tk.W, padx=20, pady=(0, 4))

        evframe = tk.Frame(win, bg=self.CLR_BG)
        evframe.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 12))

        sb = ttk.Scrollbar(evframe, orient=tk.VERTICAL, style="Vertical.TScrollbar")
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        lb = tk.Listbox(evframe, bg=self.CLR_SURFACE, fg=self.CLR_MUTED,
                        font=("Segoe UI", 9), relief=tk.FLAT, bd=0,
                        yscrollcommand=sb.set, selectbackground=self.CLR_ACCENT2)
        lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.config(command=lb.yview)

        events = get_usb_db().get_events(device_id=dev['id'], limit=50)
        if events:
            for ev in events:
                lb.insert(tk.END, f"  {ev['ts']}  [{ev['event_type']}]  {ev['drive']}")
        else:
            lb.insert(tk.END, "  No events for this device.")

    def _delete_usb_device(self, device_id: int, container):
        if messagebox.askyesno("Delete", "Remove this device from history?"):
            get_usb_db().delete_device(device_id)
            self._load_usb_history(container)

    def _export_usb_csv(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All", "*.*")],
            initialfile="usb_history.csv",
            title="Export USB History to CSV")
        if not filepath:
            return
        ok, msg = get_usb_db().export_csv(filepath)
        if ok:
            messagebox.showinfo("Export", msg)
        else:
            messagebox.showerror("Error", msg)

    def _clear_usb_history(self):
        if messagebox.askyesno("Clear History", "Delete ALL USB device history?\nThis action cannot be undone."):
            get_usb_db().clear_all()
            if hasattr(self, '_usb_hist_container'):
                self._load_usb_history(self._usb_hist_container)
            self._set_status("USB history cleared.")

    # ─── Events log tab ──────────────────────────────────────────────────────
    def _render_usb_events(self, parent):
        tb = tk.Frame(parent, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=0, pady=4)
        tk.Label(tb, text="Last 200 USB Events:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         lambda: self._load_usb_events(ev_container)).pack(side=tk.LEFT, padx=8)

        hdr = tk.Frame(parent, bg=self.CLR_SURFACE)
        hdr.pack(fill=tk.X, padx=0, pady=(4, 0))
        for txt, w in [("Czas", 18), ("Typ", 10), ("Name", 22),
                       ("Drive", 8), ("FS", 8), ("Serial", 14), ("Manufacturer", 16)]:
            tk.Label(hdr, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

        ev_container = self._scrollable_area(parent)
        self._load_usb_events(ev_container)

    def _load_usb_events(self, container):
        for w in container.winfo_children():
            w.destroy()

        events = get_usb_db().get_events(limit=200)
        if not events:
            tk.Label(container, text="No USB events in database.",
                     font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=30)
            return

        TYPE_COLORS = {'DETECTED': self.CLR_SUCCESS, 'REMOVED': self.CLR_DANGER}
        for i, ev in enumerate(events):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            row = tk.Frame(container, bg=bg)
            row.pack(fill=tk.X, padx=4, pady=1)

            color = TYPE_COLORS.get(ev.get('event_type', ''), self.CLR_MUTED)

            def mk(text, w, fg=None):
                tk.Label(row, text=str(text)[:w], font=("Segoe UI", 9),
                         fg=fg or self.CLR_TEXT, bg=bg,
                         width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=3)

            mk(ev.get('ts', ''),           18)
            mk(ev.get('event_type', ''),   10, color)
            mk(ev.get('name', ''),         22, self.CLR_ACCENT)
            mk(ev.get('drive', ''),         8)
            mk(ev.get('fstype', ''),        8, self.CLR_WARN)
            mk(ev.get('serial', ''),       14, self.CLR_MUTED)
            mk(ev.get('manufacturer', ''), 16, self.CLR_MUTED)

    # ─── Stats tab ───────────────────────────────────────────────────────────
    def _render_usb_stats(self, parent):
        btn_row = tk.Frame(parent, bg=self.CLR_BG)
        btn_row.pack(fill=tk.X, padx=4, pady=6)
        self._action_btn(btn_row, "⟳  REFRESH", self.CLR_ACCENT2,
                         lambda: [w.destroy() for w in parent.winfo_children()] or
                                  self._render_usb_stats(parent)).pack(side=tk.LEFT, padx=(0, 8))
        self._action_btn(btn_row, "📄  GENERATE HTML REPORT", self.CLR_SUCCESS,
                         self._generate_usb_html_report).pack(side=tk.LEFT)

        try:
            stats = get_usb_db().get_stats()
        except Exception as e:
            tk.Label(parent, text=f"Error fetching stats: {e}",
                     font=("Segoe UI", 11), fg=self.CLR_DANGER, bg=self.CLR_BG).pack(pady=20)
            return

        cards = [
            ("🔌", "Unique Devices",  str(stats.get('total_devices', 0)),  self.CLR_ACCENT),
            ("📋", "Log Events",     str(stats.get('total_events', 0)),   self.CLR_ACCENT2),
            ("🏆", "Most Connected",
             f"{stats['most_connected'].get('name', 'N/A')}\n"
             f"({stats['most_connected'].get('connect_count', 0)}x)",            self.CLR_SUCCESS),
            ("💽", "Largest Device",
             f"{stats['biggest_device'].get('name', 'N/A')}\n"
             f"{round(stats['biggest_device'].get('total_bytes', 0)/1024**3, 2)} GB",
             self.CLR_WARN),
        ]

        grid = tk.Frame(parent, bg=self.CLR_BG)
        grid.pack(fill=tk.X, padx=8, pady=12)

        for col, (icon, title, value, color) in enumerate(cards):
            card = tk.Frame(grid, bg=self.CLR_SURFACE, padx=16, pady=14)
            card.grid(row=0, column=col, padx=8, sticky=tk.NSEW)
            grid.columnconfigure(col, weight=1)

            tk.Label(card, text=icon, font=("Segoe UI", 22),
                     fg=color, bg=self.CLR_SURFACE).pack(anchor=tk.W)
            tk.Label(card, text=title, font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE).pack(anchor=tk.W, pady=(2, 4))
            tk.Label(card, text=value, font=("Segoe UI", 12, "bold"),
                     fg=color, bg=self.CLR_SURFACE, justify=tk.LEFT).pack(anchor=tk.W)

        tk.Frame(parent, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=8, pady=12)

        # Paths info
        for label, path in [
            ("📁  Database", AppPaths.DB),
            ("⚙️  Settings",  AppPaths.SETTINGS),
            ("📋  App Log", AppPaths.LOG),
            ("🚨  Error Log",  AppPaths.ERROR_LOG),
            ("📂  HTML Reports", AppPaths.REPORT_DIR),
        ]:
            tk.Label(parent, text=f"{label}:   {path}",
                     font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_BG
                     ).pack(anchor=tk.W, padx=12, pady=1)

    def _generate_usb_html_report(self):
        """Generate an HTML report of USB device history and save to report dir."""
        try:
            db = get_usb_db()
            devices = db.get_all_devices()
            events  = db.get_events(limit=100)
            stats   = db.get_stats()

            ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"usb_report_{ts}.html"
            filepath = AppPaths.report_path(filename)

            rows_html = ""
            for dev in devices:
                size_gb = round(dev.get('total_bytes', 0) / 1024**3, 2)
                rows_html += f"""
                <tr>
                    <td>{dev.get('name','?')}</td>
                    <td>{dev.get('serial','N/A')}</td>
                    <td>{dev.get('manufacturer','?')}</td>
                    <td>{dev.get('fstype','?')}</td>
                    <td>{size_gb} GB</td>
                    <td>{dev.get('connect_count', 0)}</td>
                    <td>{dev.get('first_seen','?')}</td>
                    <td>{dev.get('last_seen','?')}</td>
                </tr>"""

            ev_rows = ""
            for ev in events:
                ev_rows += f"""
                <tr>
                    <td>{ev.get('ts','')}</td>
                    <td>{ev.get('event_type','')}</td>
                    <td>{ev.get('name','')}</td>
                    <td>{ev.get('drive','')}</td>
                    <td>{ev.get('serial','')}</td>
                </tr>"""

            html = f"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>NTFSecur – Raport USB {ts}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#f5f7fa; color:#222; margin:0; padding:0; }}
  header {{ background:#1a2a4a; color:#fff; padding:24px 40px; }}
  header h1 {{ margin:0; font-size:22px; }}
  header p  {{ margin:4px 0 0; font-size:12px; color:#aac; }}
  .container {{ max-width:1100px; margin:30px auto; padding:0 24px; }}
  .stat-grid {{ display:flex; gap:16px; margin-bottom:28px; }}
  .stat-card {{ background:#fff; border-radius:8px; padding:20px 24px;
                flex:1; box-shadow:0 1px 4px rgba(0,0,0,.1); }}
  .stat-card .value {{ font-size:28px; font-weight:700; color:#0078d7; }}
  .stat-card .label {{ font-size:12px; color:#888; margin-top:4px; }}
  h2 {{ color:#1a2a4a; border-bottom:2px solid #0078d7; padding-bottom:6px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           border-radius:8px; overflow:hidden; box-shadow:0 1px 4px rgba(0,0,0,.08);
           margin-bottom:32px; font-size:13px; }}
  th {{ background:#1a2a4a; color:#fff; padding:10px 12px; text-align:left; }}
  td {{ padding:9px 12px; border-bottom:1px solid #eee; }}
  tr:last-child td {{ border-bottom:none; }}
  tr:nth-child(even) {{ background:#f9fbff; }}
  footer {{ text-align:center; color:#aaa; font-size:11px; padding:24px; }}
</style>
</head>
<body>
<header>
  <h1>🔌 NTFSecur – USB Device History Report</h1>
  <p>Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp;
     {__product__} v{__version__} &nbsp;|&nbsp; {__copyright__}</p>
</header>
<div class="container">
  <div class="stat-grid">
    <div class="stat-card"><div class="value">{stats['total_devices']}</div><div class="label">Unique Devices</div></div>
    <div class="stat-card"><div class="value">{stats['total_events']}</div><div class="label">Events</div></div>
    <div class="stat-card"><div class="value">{stats['most_connected'].get('name','N/A')}</div>
      <div class="label">Most Connected ({stats['most_connected'].get('connect_count',0)}x)</div></div>
    <div class="stat-card"><div class="value">{round(stats['biggest_device'].get('total_bytes',0)/1024**3,2)} GB</div>
      <div class="label">Largest: {stats['biggest_device'].get('name','N/A')}</div></div>
  </div>

  <h2>USB Device History</h2>
  <table>
    <thead><tr>
      <th>Name</th><th>Serial</th><th>Manufacturer</th><th>FS</th>
      <th>Size</th><th>Connections</th><th>First Seen</th><th>Last Seen</th>
    </tr></thead>
    <tbody>{rows_html}</tbody>
  </table>

  <h2>Last 100 Events</h2>
  <table>
    <thead><tr><th>Time</th><th>Type</th><th>Name</th><th>Drive</th><th>Serial</th></tr></thead>
    <tbody>{ev_rows}</tbody>
  </table>
</div>
<footer>{__product__} v{__version__} &nbsp;·&nbsp; {__copyright__}</footer>
</body>
</html>"""

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)

            log_info(f"HTML report generated: {filepath}")
            self._set_status(f"Report saved: {filepath}")
            messagebox.showinfo("Report Generated",
                                f"HTML report saved:\n{filepath}\n\n"
                                f"Open in your browser to view.")
        except Exception as e:
            log_error(f"HTML report generation failed: {e}", e)
            messagebox.showerror("Report Error", f"Failed to generate report:\n{e}")

    def _build_usb_card(self, parent, dev):
        pct   = dev.get('pct', 0)
        total = dev.get('total', 0)
        used  = dev.get('used', 0)
        free  = dev.get('free', 0)

        # Strip colour by usage
        if pct < 60:
            bar_color = self.CLR_SUCCESS
        elif pct < 85:
            bar_color = self.CLR_WARN
        else:
            bar_color = self.CLR_DANGER

        card = tk.Frame(parent, bg=self.CLR_SURFACE)
        card.pack(fill=tk.X, padx=8, pady=6)

        strip = tk.Frame(card, width=4, bg=bar_color)
        strip.pack(side=tk.LEFT, fill=tk.Y)

        inner = tk.Frame(card, bg=self.CLR_SURFACE)
        inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=14, pady=12)

        # ── top row: icon + name + drive ─────────────────────────────────────
        top = tk.Frame(inner, bg=self.CLR_SURFACE)
        top.pack(fill=tk.X)

        tk.Label(top, text="🔌", font=("Segoe UI", 18),
                 fg=self.CLR_ACCENT, bg=self.CLR_SURFACE).pack(side=tk.LEFT, padx=(0, 8))

        name_frame = tk.Frame(top, bg=self.CLR_SURFACE)
        name_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(name_frame,
                 text=f"{dev.get('name', 'USB Drive')}",
                 font=("Segoe UI", 12, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(anchor=tk.W)

        tk.Label(name_frame,
                 text=f"{dev.get('drive', '?')}  ·  {dev.get('fstype', '?')}  ·  "
                      f"Manufacturer: {dev.get('manufacturer', 'Unknown')}  ·  "
                      f"S/N: {dev.get('serial', 'N/A')}",
                 font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=self.CLR_SURFACE).pack(anchor=tk.W, pady=(2, 0))

        # Status badge
        status_color = self.CLR_SUCCESS if dev.get('status', 'OK') in ('OK', 'Mounted') else self.CLR_WARN
        tk.Label(top, text=dev.get('status', 'OK'),
                 font=("Segoe UI", 9, "bold"),
                 fg=status_color, bg=self.CLR_SURFACE).pack(side=tk.RIGHT, padx=6)

        # ── usage bar ────────────────────────────────────────────────────────
        if total > 0:
            bar_bg = tk.Frame(inner, bg=self.CLR_BORDER, height=6)
            bar_bg.pack(fill=tk.X, pady=(10, 2))

            bar_fill = tk.Frame(bar_bg, bg=bar_color, height=6)
            bar_fill.place(relx=0, rely=0, relwidth=pct / 100, relheight=1)

            total_gb = round(total / 1024**3, 2)
            used_gb  = round(used  / 1024**3, 2)
            free_gb  = round(free  / 1024**3, 2)

            tk.Label(inner,
                     text=f"Used: {used_gb} GB ({pct}%)  ·  Free: {free_gb} GB  ·  "
                          f"Total: {total_gb} GB",
                     font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE).pack(anchor=tk.W)
        else:
            tk.Label(inner, text="No capacity data (device not mounted).",
                     font=("Segoe UI", 9), fg=self.CLR_MUTED,
                     bg=self.CLR_SURFACE).pack(anchor=tk.W, pady=(8, 0))

    def _safe_remove_usb(self):
        """Safely eject all USB drives (Windows)."""
        if sys.platform != "win32":
            return
        ok, msg = run_cmd(
            ['powershell', '-NoProfile', '-Command',
             '$drives = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 2};'
             'foreach ($d in $drives) {'
             '  $vol = [System.Runtime.InteropServices.Marshal]::GetActiveObject("Shell.Application");'
             '  $vol.NameSpace(17).Items() | Where-Object {$_.Path -eq $d.DeviceID} | '
             '  ForEach-Object { $_.InvokeVerb("Eject") }'
             '}; "Done"'],
            timeout=20)
        if ok:
            messagebox.showinfo("USB", "Safe removal request sent.\n"
                                       "You may now disconnect the USB device.")
        else:
            messagebox.showwarning("USB", f"Failed to remove device:\n{msg[:120]}")
        self._refresh_usb()


# ─── USB Diagnostics ─────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
#  KNOWLEDGE BASES
# ─────────────────────────────────────────────────────────────────────────────

# ── Filesystem / Partition format library ─────────────────────────────────────
FS_LIBRARY = [
    # name, type, max_vol, max_file, os_support, features, notes
    ("NTFS",        "Journal",   "256 TB",   "16 TB",   "Windows 2000+, Linux (rw), macOS (ro)",
     "ACL, EFS, Compression, Sparse, Quota, VSS",
     "Domyślny FS Windows. Obowiązkowy dla dysków >32 GB na Win."),
    ("FAT32",       "Simple",    "8 TB",     "4 GB",    "Windows, Linux, macOS, konsole, aparaty",
     "Brak praw dostępu, brak journalingu",
     "Limit 4 GB na plik! Najszersza kompatybilność."),
    ("exFAT",       "Simple",    "128 PB",   "16 EB",   "Windows XP+, Linux 5.4+, macOS 10.6.5+",
     "Brak journalingu, wsparcie dla dużych plików",
     "Następca FAT32 dla nośników flash. Brak limitu 4 GB."),
    ("ext4",        "Journal",   "1 EB",     "16 TB",   "Linux natywnie, Windows (sterownik), macOS (sterownik)",
     "Journaling, extents, nanosecond timestamps, inline data",
     "Domyślny FS Linux. Najdojrzalszy ext*."),
    ("ext3",        "Journal",   "32 TB",    "2 TB",    "Linux, partial Windows/macOS",
     "Journaling (3 tryby), backward compat z ext2",
     "Poprzednik ext4. Brak extents."),
    ("ext2",        "Simple",    "32 TB",    "2 TB",    "Linux, Windows (sterownik)",
     "Bez journalingu – szybszy dla flash",
     "Stosowany na małych kartach SD/boot."),
    ("Btrfs",       "COW",       "16 EB",    "16 EB",   "Linux",
     "Snapshots, RAID wbudowany, kompresja, subvolumes, checksums",
     "Nowoczesny FS Linux z COW. Zastępuje ext4 w Fedora/openSUSE."),
    ("XFS",         "Journal",   "8 EB",     "8 EB",    "Linux, IRIX",
     "64-bit, parallel I/O, delayed allocation, reflinks",
     "Domyślny FS RHEL/CentOS. Doskonały dla dużych plików."),
    ("ZFS",         "COW",       "256 ZB",   "16 EB",   "Linux (OpenZFS), FreeBSD, macOS (tylko odczyt)",
     "RAID-Z, snapshots, deduplikacja, ARC cache, checksums",
     "Najbardziej zaawansowany FS. Wymaga dużo RAM."),
    ("APFS",        "COW",       "16 EB",    "8 EB",    "macOS 10.13+, iOS 10.3+",
     "Snapshots, encryption, space sharing, clones",
     "Natywny FS Apple (SSD-first)."),
    ("HFS+",        "Journal",   "8 EB",     "8 EB",    "macOS, Linux (ro)",
     "Journaling, Unicode filenames, resource forks",
     "Poprzedni FS Apple (HDD-era)."),
    ("F2FS",        "Log-struct", "16 TB",   "3.94 TB", "Linux, Android",
     "Flash-friendly, adaptive logging, heap-based allocation",
     "Zoptymalizowany pod NAND flash (telefony, SSD)."),
    ("UDF",         "Simple",    "~ 2 TB",   "~ 2 TB",  "Windows, Linux, macOS, konsole",
     "Optyczny standard ISO 13346, inkrementalne nagrywanie",
     "Stosowany na DVD/Blu-ray i przenośnych dyskach."),
    ("ISO 9660",    "Simple",    "~8 GB",    "2 GB",    "Wszystkie systemy",
     "Read-only, Joliet (Unicode), Rock Ridge (POSIX)",
     "Standard obrazów CD-ROM."),
    ("ReFS",        "COW",       "35 PB",    "35 PB",   "Windows Server 2012+, Windows 10 Pro",
     "Integrity streams, block clone, mirror accelerated parity",
     "Następca NTFS dla serwerów. Brak szyfrowania EFS."),
    ("FAT16",       "Simple",    "4 GB",     "2 GB",    "DOS, Windows, embedded",
     "Brak praw, brak journalingu",
     "Starszy FAT. Stosowany w embedded/BIOS EFI."),
    ("FAT12",       "Simple",    "32 MB",    "32 MB",   "DOS, dyskietki, embedded",
     "Minimalny narzut",
     "Stosowany na dyskietkach i małych flash."),
    ("nilfs2",      "Log-struct", "1 EB",    "1 EB",    "Linux",
     "Continuous snapshotting, fast recovery",
     "Log-structured FS z ciągłym snapshotowaniem."),
    ("JFFS2",       "Log-struct", "N/A",     "N/A",     "Linux (MTD)",
     "Wear leveling, compression, dla raw flash",
     "Stosowany w routerach / embedded bez FTL."),
    ("UBIFS",       "Journal",   "N/A",      "N/A",     "Linux (UBI/MTD)",
     "Journaling, kompresja, wear leveling przez UBI",
     "Następca JFFS2 dla dużych nand flash."),
    ("HAMMER2",     "COW",       "1 EB",     "1 EB",    "DragonFly BSD",
     "Clustered, snapshots, dedup, multi-volume",
     "Natywny FS DragonFly BSD."),
    ("tmpfs",       "RAM",       "RAM limit","RAM limit","Linux, BSD, macOS",
     "In-memory, volatile",
     "Wirtualny FS w pamięci RAM. Nie przeżywa restartu."),
    ("procfs",      "Virtual",   "N/A",      "N/A",     "Linux, BSD",
     "Kernel/process info as files",
     "/proc – interfejs jądra jako drzewo plików."),
    ("sysfs",       "Virtual",   "N/A",      "N/A",     "Linux",
     "Kernel objects as files",
     "/sys – urządzenia i sterowniki jako pliki."),
]

# ── USB Mass Memory / Controller DB ──────────────────────────────────────────
USB_MASS_DB = [
    # vendor, chip/controller, max_speed, protocol, features, notes
    ("SanDisk / WD",       "SanDisk SDCZ48 / SN series",   "USB 3.2 Gen1 – 150 MB/s",
     "BOT (Bulk-Only)",   "nCache 2.0, SecureAccess",
     "Najpopularniejsza seria pendrive. SN740 = NVMe M.2."),
    ("Samsung",            "Bar Plus / Fit Plus (ISP)",    "USB 3.1 Gen1 – 300 MB/s",
     "BOT",               "MLC/TLC NAND, compact form",
     "Fit Plus idealny do hub-ów. Znakomita trwałość."),
    ("Kingston",           "DataTraveler / IronKey",       "USB 3.2 Gen1 – 200 MB/s",
     "BOT / UAP",         "256-bit AES XTS (IronKey), FIPS 140-2",
     "IronKey = certyfikowany szyfrowany USB dla korporacji."),
    ("Corsair",            "Flash Voyager GTX",            "USB 3.1 Gen1 – 440 MB/s",
     "BOT",               "SSD-grade MLC NAND",
     "Najszybsze tradycyjne pendrive Corsair."),
    ("Samsung",            "T7 / T9 (Portable SSD)",       "USB 3.2 Gen2 – 1050 MB/s",
     "UAS (UASP)",        "NVMe wewnętrznie, AES 256, shock-proof",
     "T9 = do 2000 MB/s. Najszybszy portable SSD Samsung."),
    ("WD",                 "My Passport / Elements",       "USB 3.0 – 130 MB/s",
     "BOT / UAS",         "256-bit AES HW enc. (Passport), SMR HDD",
     "Elements = najtańszy WD portable. Passport = szyfrowanie HW."),
    ("Seagate",            "Expansion / One Touch",        "USB 3.0 – 120 MB/s",
     "BOT / UAS",         "SMR HDD, automatyczny backup",
     "One Touch ma klawiaturę biometryczną w wersji z fingerprint."),
    ("Transcend",          "JetDrive Go / ESD380C",        "USB 3.2 Gen2 – 2000 MB/s",
     "UAS",               "Type-C, NVMe SSD w środku",
     "ESD380C = dwuzłączowy Type-A + Type-C, NVMe."),
    ("Silicon Power",      "Blaze B75 / PC60",             "USB 3.2 Gen2 – 540 MB/s",
     "UAS",               "SATA SSD, aluminium obudowa",
     "PC60 = portable SATA SSD z dobra relacją cena/MB/s."),
    ("Lexar",              "JumpDrive S75 / Professional", "USB 3.0 – 150 MB/s",
     "BOT",               "TLC NAND",
     "S75 popularny w fotografii. Seria Pro do kart CFexpress."),
    ("PNY",                "Pro Elite / Turbo",            "USB 3.2 Gen1 – 200 MB/s",
     "BOT",               "TLC NAND",
     "Tania seria z przyzwoitą wydajnością."),
    ("Verbatim",           "Store 'n' Go / Executive",     "USB 3.2 Gen1 – 100 MB/s",
     "BOT",               "MLC NAND",
     "Klasyczne przemysłowe USB, wysoka trwałość."),
    ("Crucial",            "X9 / X10 Pro (Portable SSD)", "USB 3.2 Gen2 – 2100 MB/s",
     "UAS (NVMe bridge)", "Type-C, NVMe, AES 256",
     "X10 Pro najszybszy portable SSD Crucial. Rewelacyjna cena."),
    ("ADATA",              "SE920 / SC685",                "USB 3.2 Gen2x2 – 3800 MB/s",
     "UAS (NVMe)",        "Type-C 20Gbps, RGB (SE920)",
     "SE920 = jeden z najszybszych portable SSD na rynku."),
    ("Generic MTK",        "MediaTek MT7601 / Phison U17", "USB 2.0 – 25 MB/s",
     "BOT",               "brak, TLC/QLC budżetowy",
     "Tanie noname USB z Aliexpress. Najsłabsza trwałość."),
    ("Phison",             "PS2251 / PS2307 (controller)", "USB 3.2 Gen1 – 120 MB/s",
     "BOT",               "Powszechny kontroler w mid-range USB",
     "Phison produkuje kontrolery stosowane przez wielu vendorów."),
    ("SMI",                "SM3281 / SM3268 (controller)", "USB 3.1 Gen2 – 500 MB/s",
     "UAS",               "DRAM-less możliwy",
     "Silicon Motion – dostawca kontrolerów dla Lexar, Kingston."),
    ("ASMedia",            "ASM235CM (bridge NVMe–USB)",   "USB 3.2 Gen2x2 – 20 Gbps",
     "UAS (NVMe)",        "NVMe PCIe 3.0 x2 bridge, najszybszy mostek",
     "Używany w obudowach M.2 NVMe i portable SSD premium."),
    ("Realtek",            "RTS5411 / RTL9210B",           "USB 3.2 Gen2 – 10 Gbps",
     "UAS",               "SATA/NVMe bridge, popularny w obudowach",
     "RTL9210B = najpopularniejszy mostek SATA/NVMe dla obudów M.2."),
    ("JMicron",            "JMS583 / JMS586A",             "USB 3.2 Gen2x2 – 20 Gbps",
     "UAS",               "NVMe PCIe bridge, TRIM pass-through",
     "JMS583 szeroko stosowany w obudowach NVMe M.2."),
    ("LaCie",              "Rugged / Mobile SSD Pro",      "USB-C – 1000 MB/s",
     "UAS",               "IP67, shock-resist, NVMe (Pro)",
     "Rugged = odporny na upadki, pył, wodę."),
    ("G-Technology",       "ArmorATD / G-Drive",           "USB 3.2 Gen1 – 140 MB/s",
     "UAS",               "IP54 woda+pył, CMR HDD",
     "Stosowany przez kreatorów wideo (Western Digital brand)."),
    ("OWC",                "Envoy Pro FX / Elektron",      "TB3/USB-C – 2800 MB/s",
     "UAS / TB3",         "Thunderbolt 3 + USB-C dual mode, NVMe",
     "Pełna kompatybilność TB3 i USB 3.2. Wysoka cena, wysoka jakość."),
    ("CalDigit",           "Tuff Nano / Tuff Nano Plus",   "USB-C – 1000 MB/s",
     "UAS",               "IP67, SSD, macOS/Win",
     "Tuff Nano Plus = najszybszy w klasie IP67."),
]

# ── Database engines library ──────────────────────────────────────────────────
DB_LIBRARY = [
    # name, type, license, port, os, features, notes
    ("SQLite",        "Relacyjna – embedded", "Public Domain", "—",
     "Wszystkie",
     "ACID, triggers, views, FTS5, JSON1, bez serwera",
     "Domyślna baza Pythona (sqlite3). Idealna do aplikacji desktopowych."),
    ("PostgreSQL",    "Relacyjna – serwer",   "PostgreSQL",    "5432",
     "Linux, Win, macOS",
     "MVCC, JSONB, GIS (PostGIS), partycje, replikacja logiczna",
     "Najpotężniejsza open-source RDBMS. Pełna zgodność SQL."),
    ("MySQL",         "Relacyjna – serwer",   "GPL / Commercial","3306",
     "Linux, Win, macOS",
     "InnoDB (ACID), MyISAM, replikacja, partycje, JSON",
     "Najszersze użycie webowe (LAMP stack)."),
    ("MariaDB",       "Relacyjna – serwer",   "GPL",           "3306",
     "Linux, Win, macOS",
     "Fork MySQL, Aria engine, Columnstore, temporalne tabele",
     "Drop-in replacement MySQL z lepszym performance."),
    ("Microsoft SQL Server", "Relational",     "Commercial/Express", "1433",
     "Windows, Linux",
     "Always On, In-Memory OLTP, PolyBase, R/Python Integration",
     "Express = darmowy limit 10 GB. Developer = pełny do dev."),
    ("Oracle DB",     "Relational",            "Commercial",    "1521",
     "Linux, Windows, Solaris",
     "RAC, Exadata, partycje, flashback, Advanced Security",
     "Najdroższa i najpotężniejsza komercyjna RDBMS."),
    ("MongoDB",       "Dokument – NoSQL",     "SSPL",          "27017",
     "Linux, Win, macOS",
     "BSON, Atlas Search, aggregation pipeline, change streams, sharding",
     "Najbardziej popularna baza dokumentowa."),
    ("Redis",         "Klucz-wartość – NoSQL","BSD",           "6379",
     "Linux, Win (WSL), macOS",
     "In-memory, pub/sub, streams, Lua scripts, clustering",
     "Baza cache i kolejek. Najszybsza key-value store."),
    ("Cassandra",     "Kolumnowa – NoSQL",    "Apache",        "9042",
     "Linux, macOS",
     "Distributed, tunable consistency, wide rows, materialized views",
     "Facebook-born. Idealna do zapisu dużych wolumenów danych."),
    ("Elasticsearch", "Wyszukiwarka / NoSQL", "SSPL / Elastic","9200/9300",
     "Linux, Win, macOS",
     "Full-text search, agregacje, Kibana dashboards, ML",
     "De facto standard wyszukiwania i logowania (ELK stack)."),
    ("InfluxDB",      "Czasowa – NoSQL",      "MIT / Commercial","8086",
     "Linux, Win, macOS",
     "Flux language, retention policies, down-sampling, Telegraf",
     "Najbardziej popularna baza szeregów czasowych."),
    ("TimescaleDB",   "Czasowa (pg extension)","Apache / TSL", "5432",
     "Linux, Win, macOS",
     "Hypertables, compression, continuous aggregates, na bazie PG",
     "Wydajność InfluxDB + pełny SQL PostgreSQL."),
    ("Neo4j",         "Graph",              "GPL / Commercial","7687",
     "Linux, Win, macOS",
     "Cypher query, APOC plugins, GDS library, native graph engine",
     "Lider baz grafowych. Idealna do sieci relacji."),
    ("CockroachDB",   "Relacyjna – Distributed","BSL",        "26257",
     "Linux, macOS",
     "PostgreSQL-compatible, multi-region, SERIALIZABLE",
     "Distributed SQL z geograficznym rozłożeniem danych."),
    ("DuckDB",        "Analityczna – embedded","MIT",          "—",
     "Wszystkie",
     "Columnar, OLAP, Apache Arrow, Parquet, WASM",
     "SQLite dla analityki. Rewelacyjna dla Pandas/Polars."),
    ("ClickHouse",    "Kolumnowa – OLAP",     "Apache",        "8123/9000",
     "Linux, macOS",
     "MergeTree, vectorized execution, multi-tiered storage, Real-time",
     "Najszybsza kolumnowa OLAP. Miliardy wierszy w sekundy."),
    ("Firebird",      "Relacyjna – embedded/serwer","IPL/IDPL","3050",
     "Linux, Win, macOS",
     "Multi-generational architecture, PSQL, triggers",
     "Lekka alternatywa dla SQLite z trybem serwera."),
    ("RocksDB",       "Klucz-wartość – embedded","Apache",     "—",
     "Linux, macOS",
     "LSM tree, compaction, column families, merge operator",
     "Facebook. Silnik używany przez Kafka, TiKV, MyRocks."),
    ("LevelDB",       "Klucz-wartość – embedded","BSD",        "—",
     "Linux, macOS, Win",
     "LSM tree, ordered keys, bloom filters",
     "Google. Prosta biblioteka C++. Baza RocksDB."),
    ("LMDB",          "Klucz-wartość – embedded","OpenLDAP",   "—",
     "Wszystkie",
     "Memory-mapped, ACID, single writer, zero-copy reads",
     "Najszybsza embedded key-value. Używana przez OpenLDAP."),
    ("Apache HBase",  "Kolumnowa – NoSQL",    "Apache",        "16000/16010",
     "Linux",
     "Hadoop HDFS storage, Bloom filters, snapshot",
     "Google Bigtable open-source clone. Petabajty danych."),
    ("Couchbase",     "Dokument – NoSQL",     "BSL / Community","8091",
     "Linux, Win, macOS",
     "N1QL SQL, FTS, Eventing, XDCR replication",
     "MongoDB alternative z wbudowaną warstwą cache."),
    ("Apache Kafka",  "Strumień / Log",       "Apache",        "9092",
     "Linux, macOS",
     "Partitioned log, consumer groups, streams API, exactly-once",
     "Nie baza danych, ale platforma streamingu jako storage."),
]



def get_usb_devices() -> list:
    """Return list of connected USB storage devices with details."""
    devices = []

    if sys.platform == "win32":
        # Try pywin32 first
        try:
            import win32api, win32con, win32file
            drives = win32api.GetLogicalDriveStrings().split('\x00')
            for drive in drives:
                if not drive:
                    continue
                drive = drive.strip('\\')
                try:
                    dtype = win32file.GetDriveType(drive + '\\')
                    if dtype != win32con.DRIVE_REMOVABLE:
                        continue
                    vol = win32api.GetVolumeInformation(drive + '\\')
                    free, total, _ = win32api.GetDiskFreeSpaceEx(drive + '\\')
                    used = total - free
                    devices.append({
                        'name':   vol[0] or 'USB Drive',
                        'drive':  drive,
                        'fstype': vol[4],
                        'total':  total,
                        'used':   used,
                        'free':   free,
                        'pct':    round(used * 100 / total, 1) if total else 0,
                        'serial': str(vol[1]) if vol[1] else 'N/A',
                        'status': 'OK',
                    })
                except Exception:
                    pass
        except ImportError:
            # Fallback: PowerShell
            ok, out = run_cmd(
                ['powershell', '-NoProfile', '-Command',
                 'Get-WmiObject Win32_LogicalDisk | '
                 'Where-Object {$_.DriveType -eq 2} | '
                 'Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace,VolumeSerialNumber | '
                 'ConvertTo-Csv -NoTypeInformation'],
                timeout=15)
            if ok:
                for line in out.strip().split('\n')[1:]:
                    parts = [p.strip('"') for p in line.split(',')]
                    if len(parts) >= 6 and parts[0]:
                        try:
                            total = int(parts[3]) if parts[3] else 0
                            free  = int(parts[4]) if parts[4] else 0
                            used  = total - free
                            devices.append({
                                'name':   parts[1] or 'USB Drive',
                                'drive':  parts[0],
                                'fstype': parts[2] or 'Unknown',
                                'total':  total,
                                'used':   used,
                                'free':   free,
                                'pct':    round(used * 100 / total, 1) if total else 0,
                                'serial': parts[5] or 'N/A',
                                'status': 'OK',
                            })
                        except Exception:
                            pass

        # USB device details via WMI / PowerShell
        ok2, out2 = run_cmd(
            ['powershell', '-NoProfile', '-Command',
             'Get-WmiObject Win32_USBControllerDevice | '
             'ForEach-Object { [wmi]($_.Dependent) } | '
             'Where-Object { $_.Caption } | '
             'Select-Object Caption,Manufacturer,DeviceID | '
             'ConvertTo-Csv -NoTypeInformation'],
            timeout=15)
        usb_info = {}
        if ok2:
            for line in out2.strip().split('\n')[1:]:
                parts = [p.strip('"') for p in line.split(',')]
                if len(parts) >= 2 and parts[0]:
                    usb_info[parts[0]] = parts[1] if len(parts) > 1 else ''

        # Attach manufacturer where possible
        for dev in devices:
            for caption, mfr in usb_info.items():
                if 'USB' in caption.upper() or 'DISK' in caption.upper():
                    dev['manufacturer'] = mfr
                    break
            if 'manufacturer' not in dev:
                dev['manufacturer'] = 'Unknown'

    else:
        # Linux: lsblk + udevadm
        ok, out = run_cmd(['lsblk', '-o',
                           'NAME,TRAN,FSTYPE,SIZE,MOUNTPOINT,LABEL,VENDOR,MODEL',
                           '-J'], timeout=10)
        if ok:
            try:
                import json
                data = json.loads(out)
                for bd in data.get('blockdevices', []):
                    if bd.get('tran') != 'usb':
                        continue
                    vendor = (bd.get('vendor') or '').strip()
                    model  = (bd.get('model')  or '').strip()
                    for child in bd.get('children', [bd]):
                        mp = child.get('mountpoint') or ''
                        total = used = free = 0
                        pct = 0
                        if mp:
                            ok2, df = run_cmd(['df', '-B1', mp], timeout=5)
                            if ok2:
                                lines = df.strip().split('\n')
                                if len(lines) > 1:
                                    cols = lines[1].split()
                                    if len(cols) >= 4:
                                        total = int(cols[1])
                                        used  = int(cols[2])
                                        free  = int(cols[3])
                                        pct   = round(used * 100 / total, 1) if total else 0
                        devices.append({
                            'name':         child.get('label') or model or 'USB Drive',
                            'drive':        '/dev/' + child.get('name', '?'),
                            'fstype':       child.get('fstype') or 'Unknown',
                            'total':        total,
                            'used':         used,
                            'free':         free,
                            'pct':          pct,
                            'serial':       'N/A',
                            'manufacturer': vendor or 'Unknown',
                            'status':       'Mounted' if mp else 'Not mounted',
                        })
            except Exception:
                pass

    return devices


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SystemManagementPanel()
    def _on_close():
        global _usb_db
        try:
            # Save window geometry (only when unlocked – locked size already saved on lock)
            if not app._is_locked:
                geom = app.geometry().split("+")[0]   # "WxH" without position
                get_settings().set("window_geometry", geom)
            get_settings().set("window_locked", app._is_locked)
            get_settings().save()
            log_info(f"Application closing. Geometry: {app.geometry()} locked={app._is_locked}")
        except Exception as e:
            log_error("Error saving settings on exit", e)
        if _usb_db:
            _usb_db.close()
            log_info("USB database closed.")
        log_info("Application terminated.")
        app.destroy()
    app.protocol("WM_DELETE_WINDOW", _on_close)
    app.mainloop()