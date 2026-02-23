# NTFSecur — Kompilacja do portable EXE

## Struktura plików

```
NTFSecur/
├── NTFSecur.py             ← główny plik (patch resource_path wymagany)
├── ntfsecur/
│   ├── pic/
│   │   ├── icon.ico
│   │   └── logo.png
│   ├── core/  ui/  i18n/   ← moduły
├── NTFSecur.spec           ← spec PyInstaller  ← skopiuj tu
├── version_info.txt        ← metadane EXE      ← skopiuj tu
├── build.bat               ← skrypt budowania  ← skopiuj tu
└── build_requirements.txt  ← zależności        ← skopiuj tu
```

---

## Krok 1 — Patch NTFSecur.py (wymagany, raz)

Dodaj funkcję `resource_path()` zaraz **po linii `_HERE = ...`** (ok. linia 43):

```python
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ── PyInstaller resource_path ─────────────────────────────────────────────────
def resource_path(*parts: str) -> str:
    """
    Zwraca bezwzględną ścieżkę do zasobu.
    W trybie frozen (EXE): bazuje na sys._MEIPASS (tymczasowy katalog PyInstaller).
    W trybie normalnym:    bazuje na katalogu skryptu (_HERE).
    """
    base = getattr(sys, "_MEIPASS", _HERE)
    return os.path.join(base, *parts)
```

Następnie **zamień wszystkie** wystąpienia ścieżek do zasobów:

| Przed | Po |
|---|---|
| `os.path.join(os.path.dirname(os.path.abspath(__file__)), "ntfsecur", "pic", "icon.ico")` | `resource_path("ntfsecur", "pic", "icon.ico")` |
| `os.path.join(os.path.dirname(os.path.abspath(__file__)), "ntfsecur", "pic", "logo.png")` | `resource_path("ntfsecur", "pic", "logo.png")` |

Linie do zamiany w NTFSecur.py: **3299** (icon.ico) i **9716** (logo.png).

---

## Krok 2 — Instalacja wymagań

```bat
pip install -r build_requirements.txt
```

Lub ręcznie:
```bat
pip install pyinstaller pillow pywin32
```

### UPX (opcjonalne — mniejszy EXE)
Pobierz `upx.exe` z https://upx.github.io/ i umieść w `C:\Windows\System32\` lub w katalogu projektu.  
Bez UPX EXE będzie ~15–20 MB większy. Użyj `build.bat --no-upx` aby pominąć.

---

## Krok 3 — Kompilacja

### Metoda A: skrypt `build.bat` (zalecana)
```bat
build.bat
```

Opcje:
```bat
build.bat --clean      # wyczyść poprzedni build przed kompilacją
build.bat --no-upx     # bez kompresji UPX
build.bat --debug      # build z pełnymi logami debug
```

### Metoda B: ręcznie przez PyInstaller
```bat
pyinstaller --clean --noconfirm NTFSecur.spec
```

---

## Wynik

```
dist\
└── NTFSecur.exe    ← jednolikowy portable EXE (~25–40 MB z UPX)
```

Plik `NTFSecur.exe`:
- **nie wymaga instalacji** — kopiuj i uruchamiaj
- **prosi o UAC** (administrator) przy starcie — wymagane przez BitLocker, rejestr, BCD
- **nie wymaga Pythona** — wszystko wbudowane
- działa na **Windows 10/11 x64**

---

## Wymagania systemowe do kompilacji

| Element | Wymaganie |
|---|---|
| System | Windows 10/11 x64 |
| Python | 3.10 – 3.13 (64-bit) |
| PyInstaller | ≥ 6.0 |
| Pillow | ≥ 10.0 (opcjonalne) |
| pywin32 | ≥ 306 (opcjonalne) |
| UPX | dowolna wersja (opcjonalne) |

> **Uwaga:** kompilacja na Pythonie 32-bit wygeneruje EXE 32-bit.  
> Dla pełnej kompatybilności z API Windows (np. `ctypes.wintypes`) używaj **Python 64-bit**.

---

## Rozwiązywanie problemów

### `ModuleNotFoundError: ntfsecur` po uruchomieniu EXE
→ Upewnij się że `NTFSecur.spec` leży **w tym samym katalogu** co `NTFSecur.py` i katalog `ntfsecur/`.

### Brak ikony w EXE
→ Sprawdź czy `ntfsecur/pic/icon.ico` istnieje. Ikona musi być w formacie `.ico` (nie `.png`).

### EXE startuje z oknem konsoli
→ W `NTFSecur.spec` upewnij się że `console=False` w sekcji `EXE(...)`.

### UAC nie pojawia się
→ W `NTFSecur.spec` upewnij się że `uac_admin=True` w sekcji `EXE(...)`.

### Antywirus blokuje EXE
→ To normalny false-positive dla plików PyInstaller. Dodaj wyjątek lub podpisz EXE certyfikatem Code Signing.

### `PIL` nie znaleziony — logo nie wyświetla się
→ Zainstaluj `pip install pillow` i zrekompiluj. Brak Pillow nie przerywa pracy programu.
