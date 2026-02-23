# -*- mode: python ; coding: utf-8 -*-
# =============================================================================
#  NTFSecur.spec  –  PyInstaller spec dla PolSoft System Management Panel
#  Wersja: 2.1.0
#  Kompilacja: pyinstaller NTFSecur.spec
# =============================================================================

import os, sys
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# ── Ścieżka do katalogu projektu (gdzie leży NTFSecur.py) ────────────────────
PROJECT_DIR = os.path.abspath(os.path.dirname(SPEC))   # katalog tego .spec
SRC_DIR     = PROJECT_DIR                               # NTFSecur.py jest tu

# ── Zasoby dołączane do EXE (datas) ──────────────────────────────────────────
#    Format: (źródło, cel_w_paczce)
datas = [
    # ikona i logo
    (os.path.join(SRC_DIR, "ntfsecur", "pic", "icon.ico"),  "ntfsecur/pic"),
    (os.path.join(SRC_DIR, "ntfsecur", "pic", "logo.png"),  "ntfsecur/pic"),
    # cały pakiet ntfsecur (moduły .py potrzebne w runtime gdy pakiet ładowany)
    (os.path.join(SRC_DIR, "ntfsecur"),                      "ntfsecur"),
]

# ── Ukryte importy (importowane dynamicznie, niewidoczne dla analizatora) ─────
hiddenimports = [
    # pakiety ntfsecur
    "ntfsecur",
    "ntfsecur.i18n",
    "ntfsecur.core",
    "ntfsecur.core.backup",
    "ntfsecur.core.bitlocker",
    "ntfsecur.core.logging",
    "ntfsecur.core.paths",
    "ntfsecur.core.security",
    "ntfsecur.core.settings",
    "ntfsecur.core.system",
    "ntfsecur.ui",
    "ntfsecur.ui.helpers",
    "ntfsecur.ui.backup_panel",
    "ntfsecur.ui.bitlocker_panel",
    # stdlib używane dynamicznie
    "sqlite3",
    "csv",
    "json",
    "socket",
    "threading",
    "tempfile",
    "platform",
    "traceback",
    "logging",
    "datetime",
    "ctypes",
    "ctypes.wintypes",
    # tkinter – wszystkie moduły
    "tkinter",
    "tkinter.ttk",
    "tkinter.messagebox",
    "tkinter.filedialog",
    "tkinter.font",
    "tkinter.scrolledtext",
    # opcjonalne – załadowane dynamicznie (brak = wyłączona funkcja)
    "PIL",
    "PIL.Image",
    "PIL.ImageTk",
    "PIL.ImageEnhance",
    "win32api",
    "win32con",
    "win32file",
    "winreg",
]

# ── Analiza pliku wejściowego ─────────────────────────────────────────────────
a = Analysis(
    [os.path.join(SRC_DIR, "NTFSecur.py")],
    pathex=[SRC_DIR],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # wykluczamy niepotrzebne ciężkie pakiety
        "numpy",
        "pandas",
        "matplotlib",
        "scipy",
        "PyQt5",
        "PyQt6",
        "wx",
        "gi",
        "IPython",
        "notebook",
        "pytest",
        "setuptools",
        "pip",
        "distutils",
        "email",
        "html",
        "http",
        "unittest",
        "xmlrpc",
        "pydoc",
        "doctest",
        "lib2to3",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ── PYZ – archiwum skompilowanych modułów ─────────────────────────────────────
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ── EXE – pojedynczy plik wykonywalny ────────────────────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="NTFSecur",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,                           # kompresja UPX (wymaga upx.exe w PATH)
    upx_exclude=[
        "vcruntime140.dll",             # nie kompresuj runtime DLL — mogą się psuć
        "python3*.dll",
        "_tkinter*.pyd",
    ],
    runtime_tmpdir=None,                # brak tmpdir = rozpakowanie do %TEMP%\...
    console=False,                      # GUI — brak okna konsoli
    disable_windowed_traceback=False,
    target_arch=None,                   # x64 (automatycznie z pythona kompilującego)
    codesign_identity=None,
    entitlements_file=None,
    # ── metadane wersji i ikona ───────────────────────────────────────────────
    icon=os.path.join(SRC_DIR, "ntfsecur", "pic", "icon.ico"),
    version="version_info.txt",         # plik z metadanymi (generowany przez build.bat)
    uac_admin=True,                     # żądanie UAC przy starcie
    uac_uiaccess=False,
)
