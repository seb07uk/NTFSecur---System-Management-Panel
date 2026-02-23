# NTFSecur — Compiling to a Portable EXE

## File Structure

```
NTFSecur/
├── NTFSecur.py             ← main file (resource_path patch required)
├── ntfsecur/
│   ├── pic/
│   │   ├── icon.ico
│   │   └── logo.png
│   ├── core/  ui/  i18n/   ← modules
├── NTFSecur.spec           ← PyInstaller spec  ← copy here
├── version_info.txt        ← EXE metadata      ← copy here
├── build.bat               ← build script      ← copy here
└── build_requirements.txt  ← dependencies      ← copy here
```

---

## Step 1 — Patch NTFSecur.py (required, once)

Add the `resource_path()` function right **after the `_HERE = ...` line** (approx. line 43):

```python
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ── PyInstaller resource_path ─────────────────────────────────────────────────
def resource_path(*parts: str) -> str:
    """
    Returns the absolute path to a resource.
    In frozen mode (EXE): based on sys._MEIPASS (PyInstaller's temp directory).
    In normal mode:       based on the script directory (_HERE).
    """
    base = getattr(sys, "_MEIPASS", _HERE)
    return os.path.join(base, *parts)
```

Then **replace all** occurrences of resource paths:

| Before | After |
|---|---|
| `os.path.join(os.path.dirname(os.path.abspath(__file__)), "ntfsecur", "pic", "icon.ico")` | `resource_path("ntfsecur", "pic", "icon.ico")` |
| `os.path.join(os.path.dirname(os.path.abspath(__file__)), "ntfsecur", "pic", "logo.png")` | `resource_path("ntfsecur", "pic", "logo.png")` |

Lines to replace in NTFSecur.py: **3299** (icon.ico) and **9716** (logo.png).

---

## Step 2 — Install Requirements

```bat
pip install -r build_requirements.txt
```

Or manually:
```bat
pip install pyinstaller pillow pywin32
```

### UPX (optional — smaller EXE)
Download `upx.exe` from https://upx.github.io/ and place it in `C:\Windows\System32\` or the project directory.
Without UPX the EXE will be ~15–20 MB larger. Use `build.bat --no-upx` to skip.

---

## Step 3 — Compilation

### Method A: `build.bat` script (recommended)
```bat
build.bat
```

Options:
```bat
build.bat --clean      # clean previous build before compiling
build.bat --no-upx     # without UPX compression
build.bat --debug      # build with full debug logs
```

### Method B: manually via PyInstaller
```bat
pyinstaller --clean --noconfirm NTFSecur.spec
```

---

## Output

```
dist\
└── NTFSecur.exe    ← single-file portable EXE (~25–40 MB with UPX)
```

The `NTFSecur.exe` file:
- **requires no installation** — copy and run
- **requests UAC** (administrator) on startup — required by BitLocker, registry, BCD
- **requires no Python** — everything is bundled
- runs on **Windows 10/11 x64**

---

## System Requirements for Compilation

| Item | Requirement |
|---|---|
| OS | Windows 10/11 x64 |
| Python | 3.10 – 3.13 (64-bit) |
| PyInstaller | ≥ 6.0 |
| Pillow | ≥ 10.0 (optional) |
| pywin32 | ≥ 306 (optional) |
| UPX | any version (optional) |

> **Note:** compiling with 32-bit Python will produce a 32-bit EXE.
> For full compatibility with the Windows API (e.g. `ctypes.wintypes`) use **64-bit Python**.

---

## Troubleshooting

### `ModuleNotFoundError: ntfsecur` after launching the EXE
→ Make sure `NTFSecur.spec` is in the **same directory** as `NTFSecur.py` and the `ntfsecur/` folder.

### No icon in the EXE
→ Check that `ntfsecur/pic/icon.ico` exists. The icon must be in `.ico` format (not `.png`).

### EXE starts with a console window
→ In `NTFSecur.spec` make sure `console=False` is set in the `EXE(...)` section.

### UAC prompt does not appear
→ In `NTFSecur.spec` make sure `uac_admin=True` is set in the `EXE(...)` section.

### Antivirus blocks the EXE
→ This is a normal false positive for PyInstaller-built files. Add an exception or sign the EXE with a Code Signing certificate.

### `PIL` not found — logo not displayed
→ Install `pip install pillow` and recompile. Missing Pillow does not interrupt the program.