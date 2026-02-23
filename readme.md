# 🔒 NTFSecur — PolSoft System Management Panel

![Logo]([https://example.com/logo.png](https://github.com/seb07uk/NTFSecur---System-Management-Panel/blob/main/screenshot/screenshot4.png))

> **v2.1.0** · polsoft.ITS™ · © 2026 Sebastian Januchowski · All rights reserved

A professional Windows system management centre built in Python as a portable EXE. Combines NTFS partition security, BitLocker management, process monitoring, network diagnostics, services control, USB tracking, system backup and many more modules — all in a single dark-themed window.

---

## 📋 Table of Contents

- [System Requirements](#system-requirements)
- [Installation & Launch](#installation--launch)
- [File Structure](#file-structure)
- [User Interface](#user-interface)
- [Modules — Features & Functions](#modules--features--functions)
  - [🔒 NTFSecur — NTFS Security](#-ntfsecur--ntfs-security)
  - [🔐 BitLocker](#-bitlocker)
  - [💾 Drives](#-drives)
  - [🚀 Autostart](#-autostart)
  - [📊 Processes](#-processes)
  - [🌐 Network](#-network)
  - [🔧 Services](#-services)
  - [📋 Logs](#-logs)
  - [🔌 USB](#-usb)
  - [📁 Databases](#-databases)
  - [📚 FS Library](#-fs-library)
  - [📦 USB Mass DB](#-usb-mass-db)
  - [💾🛡 Backup](#-backup)
- [HTML Reports](#html-reports)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Configuration & Settings](#configuration--settings)
- [Logging & Diagnostics](#logging--diagnostics)
- [Building to EXE (build.bat)](#building-to-exe-buildbat)
- [Known Limitations](#known-limitations)
- [Contact & License](#contact--license)

---

## System Requirements

| Component | Minimum |
|---|---|
| Operating System | Windows 10 / Windows 11 (64-bit) |
| Privileges | **Administrator** (required for most features) |
| Python | 3.10 or newer (source mode only) |
| RAM | 256 MB |
| Disk Space | 100 MB (EXE) + space for logs and backups |

**Python dependencies (source mode):**

```
tkinter       – built into Python (stdlib)
pillow        – optional (logo / icons)
pywin32       – optional (extended Windows API features)
```

**System tools required by specific modules:**

| Module | Tool |
|---|---|
| BitLocker | `manage-bde.exe` (Windows Pro/Enterprise) |
| Drives — SMART | `smartctl` (smartmontools) or `wmic` |
| Drives — Repair | `chkdsk.exe` (built-in Windows) |
| Drives — Wipe | `cipher /w` (Windows) or `shred` (Linux) |
| Driver Backup | `dism.exe` or `pnputil.exe` |
| File History Backup | `fhmanagew.exe` (Windows) |
| BCD Backup | `bcdedit.exe` |
| USB Diagnostics | `usbipd`, `devcon` (optional) |

---

## Installation & Launch

### Option A — ready EXE (recommended)

1. Download `NTFSecur.exe` from the `dist/` folder
2. Right-click → **Run as Administrator**
3. The application launches immediately — no installation required

### Option B — run from source

```bash
# Clone or download the repository
cd NTFSecur

# Install optional dependencies
pip install pillow pywin32

# Run as administrator (cmd with admin rights)
python NTFSecur.py
```

### Option C — build to EXE

```bash
# Standard build
build.bat

# Without UPX compression
build.bat --no-upx

# Debug mode
build.bat --debug

# Clean previous build then compile
build.bat --clean
```

> Output file: `dist\NTFSecur.exe`

---

## File Structure

```
NTFSecur/
├── NTFSecur.py              – main application file
├── NTFSecur.spec            – PyInstaller configuration
├── build.bat                – EXE build script
├── ntfsecur/                – package modules (optional)
│   ├── core/
│   │   ├── backup.py        – backup functions
│   │   ├── bitlocker.py     – BitLocker handling
│   │   ├── logging.py       – logging
│   │   ├── paths.py         – application paths
│   │   ├── security.py      – UAC, validation
│   │   ├── settings.py      – settings
│   │   └── system.py        – partitions, processes, network
│   ├── i18n.py              – internationalisation (EN/PL)
│   └── ui/
│       └── helpers.py       – threads, UI mixins
└── dist/
    └── NTFSecur.exe         – compiled EXE
```

**User data (created automatically):**

```
%USERPROFILE%\.polsoft\software\NTFSecur\
├── settings.json            – preferences and theme
├── NTFSecur.log             – activity log
├── error.log                – error / exception log
├── usb_history.db           – USB history database (SQLite)
├── diskpart_tmp.txt         – temporary diskpart script (auto-deleted)
└── report\                  – generated HTML reports
```

**System backups:**

```
%USERPROFILE%\.polsoft\backup\
├── windows\                 – Windows system backup
├── DriverBackup\            – exported drivers
└── DriverBackup-Win.zip     – drivers archive
```

---

## User Interface

The application uses a **dark Aero Glass theme** with a left-side navigation panel (sidebar). Each module loads dynamically on click — no separate windows.

**UI elements:**

- **Sidebar** — list of 13 modules with emoji icons
- **Status bar** — bottom bar showing current operation status and date/time
- **GlassScrollbar** — custom styled scrollbar (Canvas-based)
- **Partition cards** — animated Aero Glass gradient cards for each NTFS volume
- **Menu bar** — File, View, Tools, Reports, Help
- **Language switcher** — EN / PL in the View menu
- **Always on top toggle** — `Ctrl+T`
- **Window size lock** — `Ctrl+L`

**Default window size:** `1280×780 px`

---

## Modules — Features & Functions

### 🔒 NTFSecur — NTFS Security

The main module of the application. Manages write protection on NTFS volumes.

**Features:**
- Scan and display all NTFS partitions
- **Read-only / full access** toggle for each partition individually
- Each partition card shows: drive letter, label, size
- Visual state animation (coloured side strip on each card)
- **Lock All** button — sets all partitions to read-only at once
- **Unlock All** button — restores full read+write access to all partitions
- Protection state: `ON` = read-only, `OFF` = read + write

> ⚠️ Requires administrator privileges.

---

### 🔐 BitLocker

Full Windows disk encryption management.

**Features:**
- List all volumes with current BitLocker status
- Enable / disable BitLocker encryption
- Lock and unlock drives (by password or recovery key)
- Suspend and resume BitLocker protection
- View and copy recovery key
- Back up recovery key to Active Directory
- Add protectors: password, TPM, recovery key
- Change TPM PIN
- Wipe free space
- Dedicated `BitLockerPanel` popup per drive

> ⚠️ Requires Windows Pro or Enterprise. Requires administrator privileges.

---

### 💾 Drives

Drive diagnostics, repair, recovery and regeneration. Split into **6 tabs**:

**🔍 Scan** — scan the drive for logical and physical errors

**📊 SMART** — read drive SMART attributes:
- Overall health status (Passed / Failed)
- Temperature, reallocated sectors, pending sectors, uncorrectable errors
- Power-on count and power-on hours

**🛠 Repair** — volume repair:
- `chkdsk /f` — fix file system errors
- `chkdsk /r` — fix errors + scan for bad sectors
- Schedule repair on next Windows boot

**♻️ Recovery** — data recovery:
- Guidance and integration with recovery tools
- Volume cloning

**🧹 Wipe** — secure data erasure:
- `cipher /w` (Windows) — overwrite free space
- `shred` (Linux/WSL) — multi-pass overwrite
- Full drive wipe

**⚡ Regen** — regeneration and optimisation:
- Defragmentation
- SSD optimisation (TRIM)
- Disk space usage analysis

---

### 🚀 Autostart

Manage programs that launch with Windows.

**Features:**
- List all autostart entries (Registry + Startup folders)
- Sources: `HKCU\Run`, `HKLM\Run`, user and system Startup folders
- Enable and disable entries without deleting them
- Delete autostart entries
- Add new entries
- Refresh list
- Status per entry: enabled / disabled

> ⚠️ Modifying system entries (`HKLM`) requires administrator privileges.

---

### 📊 Processes

Real-time system process monitor.

**Features:**
- List all running processes (PID, name, CPU%, RAM, path)
- Sort by any column
- Search / filter processes
- Kill process — send SIGTERM / TASKKILL
- Force-terminate a process
- Automatic and manual refresh
- Highlight processes with high CPU/RAM usage

---

### 🌐 Network

Network diagnostics and information.

**Features:**
- List all network interfaces with IP addresses, MAC, status
- Default gateway and DNS information
- Transfer statistics (bytes sent / received)
- Active connections (netstat) — local/remote address, port, state, PID
- Refresh connection list
- Quick ping to a selected host
- Hostname and domain information

---

### 🔧 Services

Windows services management.

**Features:**
- List all services: name, description, status, startup type
- Start, stop, restart a service
- Change startup type: Automatic / Manual / Disabled
- Filter: all / running / stopped
- Search services
- Refresh list

> ⚠️ Changing the state of system services requires administrator privileges.

---

### 📋 Logs

Windows Event Log and application log viewer.

**Features:**
- Display logs from Windows Event Log (Application, System, Security)
- Application's own logs from `NTFSecur.log`
- Filter by level: INFO, WARNING, ERROR, CRITICAL
- Search within logs (`Ctrl+F` in the preview window)
- Export logs to `.txt` file
- Refresh logs
- Row colouring by severity level

---

### 🔌 USB

Advanced USB device monitoring and diagnostics. Split into **4 tabs**:

**Live** — currently connected devices:
- Name, VID/PID, type, device path
- Safe device removal
- Auto-refresh every few seconds

**History** — USB connection history from SQLite database:
- Date and time of connection / disconnection
- Device name, VID/PID, serial number
- Export history to CSV and HTML
- Search and filter

**Events** — USB events from Windows Event Log:
- Full list of system USB events
- Filter by event type

**Statistics** — aggregated data:
- Number of unique devices seen
- Most frequently connected devices
- Activity chart

---

### 📁 Databases

Reference library of database engines.

**Covers:**

| Engine | Type | Licence | Port |
|---|---|---|---|
| PostgreSQL | Relational | PostgreSQL | 5432 |
| MySQL | Relational | GPL / Commercial | 3306 |
| MariaDB | Relational | GPL | 3306 |
| Oracle DB | Relational | Commercial | 1521 |
| MongoDB | Document (NoSQL) | SSPL | 27017 |
| InfluxDB | Time-series | MIT / Commercial | 8086 |
| TimescaleDB | Time-series (PG ext.) | Apache / TSL | 5432 |
| CockroachDB | Relational (Distributed) | BSL | 26257 |
| SQLite | Embedded | Public Domain | — |
| Redis | Key-Value | BSD | 6379 |
| Elasticsearch | Search / Analytics | Apache / Elastic | 9200 |
| Cassandra | Wide-column | Apache | 9042 |

**Features:**
- Full table with descriptions, ports, and licences
- Generate HTML report of the database list
- Search within the table

---

### 📚 FS Library

Encyclopedia of file systems.

**Covers:** NTFS, FAT32, exFAT, ext4, ext3, ext2, Btrfs, XFS, ZFS, APFS, HFS+, ReFS, F2FS and more.

**For each file system:**
- Platform (Windows, Linux, macOS, cross-platform)
- Maximum volume and file size
- Permissions, encryption, journaling, compression support
- Typical use cases and notes

---

### 📦 USB Mass DB

Database of USB mass storage controllers and devices.

**Contains:**
- List of popular USB chipsets and controllers
- Manufacturer, model, supported protocols (USB 2.0/3.0/3.2, NVMe)
- Typical use cases (flash drive, external HDD, hub)
- Information useful for diagnosing unrecognised devices

---

### 💾🛡 Backup

Comprehensive Windows system backup module.

**Available operations:**

| Operation | Tool | Admin |
|---|---|---|
| File History backup (user files) | `fhmanagew.exe` | No |
| Full Windows Registry backup | `reg export` | Yes |
| BCD backup (bootloader) | `bcdedit /export` | Yes |
| Driver backup | `dism /export-driver` or `pnputil` | Yes |
| Drivers ZIP archive | `Compress-Archive` (PowerShell) | Yes |
| Full backup (all operations) | sequential execution | Yes |

**Destination paths:**
- System / files: `C:\.polsoft\backup\windows`
- Drivers: `%USERPROFILE%\.polsoft\backup\DriverBackup\`
- Drivers ZIP: `%USERPROFILE%\.polsoft\backup\DriverBackup-Win.zip`

**Real-time log** — every operation displays a timestamp `[HH:MM:SS]` and status icon (`▶`, `✔`, `✘`).

**Open folder** — instantly open the destination directory in Explorer.

---

## HTML Reports

The application generates HTML reports with data from all modules.

**Report types:**

| Type | Contents |
|---|---|
| Quick | NTFSecur + BitLocker |
| Normal | + Processes + Network + Services |
| Full | + Logs + USB + Databases |
| Detailed | Complete report with all modules |

**Single-module reports** available via Reports menu → Module:
NTFS, BitLocker, Processes, Services, Network, Logs, Databases, FS Library

**Report Wizard** (`Ctrl+Shift+R`) — interactive selection:
- Choose which modules to include
- Logo in header (on/off)
- Dark / light theme
- Report author name
- Auto-open after generation

**Report location:** `%USERPROFILE%\.polsoft\software\NTFSecur\report\`

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `F1` | Open Handbook |
| `F5` | Refresh active module |
| `Ctrl+T` | Toggle always on top |
| `Ctrl+L` | Lock / unlock window size |
| `Ctrl+F` | Search (in windows with search bar) |
| `Ctrl+Shift+R` | Report Wizard |
| `Ctrl+Shift+1` | Quick report |
| `Ctrl+Shift+2` | Normal report |
| `Ctrl+Shift+3` | Full report |
| `Ctrl+Shift+4` | Detailed report |
| `Ctrl+1` | Switch to NTFSecur module |
| `Ctrl+2` | Switch to BitLocker |
| `Ctrl+3` | Switch to Drives |
| `Ctrl+4` | Switch to Autostart |
| `Ctrl+5` | Switch to Processes |
| `Ctrl+6` | Switch to Network |
| `Ctrl+7` | Switch to Services |
| `Ctrl+8` | Switch to Logs |
| `Ctrl+9` | Switch to USB |

---

## Configuration & Settings

Settings are stored in `%USERPROFILE%\.polsoft\software\NTFSecur\settings.json`.

**Default values:**

| Key | Default | Description |
|---|---|---|
| `theme` | `"dark"` | UI theme |
| `last_module` | `"ntfsecur"` | Last active module |
| `window_geometry` | `"1280x780"` | Window size |
| `window_locked` | `false` | Window size lock |
| `window_topmost` | `false` | Always on top |
| `log_level` | `"INFO"` | Logging level |
| `confirm_dangerous` | `true` | Confirm before destructive operations |
| `show_watermark` | `true` | Watermark visibility |
| `bench_size_mb` | `256` | Drive benchmark test size |

The file is created automatically on first launch with factory defaults.

**Reset settings:** Menu → File → Reset Settings (or manually delete `settings.json`)

---

## Logging & Diagnostics

The application maintains two log files:

**`NTFSecur.log`** — activity log (INFO and above):
```
2026-02-21 15:40:02  [INFO    ]  Starting PolSoft System Management Panel v2.1.0
2026-02-21 15:40:05  [INFO    ]  UI ready – theme: dark
```

**`error.log`** — errors and exceptions only (WARNING and above):
```
2026-02-21 15:40:11  [WARNING ]  backup_file_history failed: exit code 1
```

Format: `YYYY-MM-DD HH:MM:SS  [LEVEL   ]  message`

Logs are accessible from within the app: Menu → Tools → Show System Logs.

---

## Building to EXE (build.bat)

```
Usage: build.bat [--no-upx] [--debug] [--clean]
```

| Flag | Description |
|---|---|
| *(none)* | Standard build with UPX (if available) |
| `--no-upx` | Build without UPX compression |
| `--debug` | Debug mode (PyInstaller verbose logs, `--debug all`) |
| `--clean` | Delete `dist/` and `build/` folders before compiling |

**Steps performed by build.bat:**

1. Check Python is available in PATH
2. Check / install PyInstaller
3. Check UPX (optional)
4. Install dependencies: `pillow`, `pywin32`
5. Clean previous build (if `--clean`)
6. Run PyInstaller with `NTFSecur.spec`
7. Verify the resulting EXE file
8. Open `dist/` folder in Explorer

**Build requirements:**
- Python 3.10+ in PATH
- PyInstaller (auto-installed if missing)
- UPX in PATH (optional, download from https://upx.github.io/)

---

## Known Limitations

- **BitLocker** is only available on Windows Pro / Enterprise — not supported on Windows Home
- **File History Backup** requires File History to be configured first in Windows Settings (destination drive must be selected) — without this it returns `exit code 1`
- **Block cloning (dd)** is not available on Windows — use Clonezilla or Macrium Reflect instead
- **Standalone mode** — without the `ntfsecur/` package, some features use the built-in fallback implementation in `NTFSecur.py`; full functionality requires the package to be present
- **Running without administrator privileges** — features that require UAC will show a warning and will not execute
- The application is designed primarily for **Windows** — on Linux/macOS only a limited subset of features is available (paths, processes)

---

## Contact & License

| | |
|---|---|
| **Author** | Sebastian Januchowski |
| **Email** | polsoft.its@fastservice.com |
| **GitHub** | https://github.com/seb07uk |
| **Product** | PolSoft System Management Panel |
| **Version** | 2.1.0 |
| **License** | © 2026 polsoft.ITS™ · All rights reserved |

This software is proprietary. Copying, modification and distribution without the written consent of the author is prohibited.

---

*Auto-generated from NTFSecur v2.1.0 source code*
