# NTFSecur v2.1.0 – Refactoring Guide
## Nowa struktura modułowa

```
ntfsecur/
├── __init__.py                  ← metadane pakietu
├── i18n/
│   └── __init__.py              ← system tłumaczeń (neutralne klucze)
├── core/
│   ├── __init__.py
│   ├── paths.py                 ← AppPaths – centralne ścieżki
│   ├── logging.py               ← log_info / log_warn / log_error
│   ├── settings.py              ← Settings singleton + FACTORY_SETTINGS
│   ├── security.py              ← is_admin, require_admin, validate_drive,
│   │                               safe_run, SecureString
│   ├── bitlocker.py             ← bl_* – wszystkie operacje BitLocker
│   └── system.py                ← get_processes, get_services, get_logs,
│                                   get_ntfs_partitions, get_usb_devices …
└── ui/
    ├── __init__.py
    ├── helpers.py               ← thread_worker, AdminMixin
    └── bitlocker_panel.py       ← BitLockerPanel (refactored)
```

---

## Kluczowe zmiany i jak migrować

### 1. i18n – neutralne klucze

**Przed:**
```python
_t("Wymagane uprawnienia administratora.")
_t("Uprawnienia")
```

**Po:**
```python
from ntfsecur.i18n import t
t("common.admin_required")
t("common.permissions")
```

Stare polskie klucze nadal działają przez tabelę `_LEGACY_EN` dla wstecznej kompatybilności.

---

### 2. Dekorator `@require_admin`

**Przed (powtarzane 12x):**
```python
def _action_lock(self):
    if not is_admin():
        messagebox.showwarning(_t("Uprawnienia"), "Wymagane uprawnienia administratora.")
        return
    self._run_async("Blokowanie partycji", bl_lock, self.drive, False)
```

**Po:**
```python
from ntfsecur.core.security import require_admin

@require_admin
def _action_lock(self) -> None:
    self._run_async("Locking drive", bl_lock, self.drive, False)
```

---

### 3. `thread_worker` decorator

**Przed (powtarzane ~10x):**
```python
def _action_get_keys(self):
    self._set_bot("Fetching keys…")
    def worker():
        ok, msg = bl_get_recovery_key(self.drive)
        def done():
            self._write(self._txt_keys, msg)
            self._set_bot(f"Keys: {msg[:120]}")
        self.after(0, done)
    threading.Thread(target=worker, daemon=True).start()
```

**Po:**
```python
from ntfsecur.ui.helpers import thread_worker

@thread_worker()
def _action_get_keys(self) -> None:
    ok, msg = bl_get_recovery_key(self.drive)
    self.after(0, lambda: self._write(self._txt_keys, msg))
```

---

### 4. `safe_run()` zamiast `subprocess.run()` rozrzuconych po kodzie

**Przed:**
```python
result = subprocess.run(
    ['tasklist', '/fo', 'csv', '/nh'],
    capture_output=True, text=True, timeout=10
)
```

**Po:**
```python
from ntfsecur.core.security import safe_run

ok, output = safe_run(['tasklist', '/fo', 'csv', '/nh'], timeout=10)
```

`safe_run()` zawsze używa `shell=False`, ukrywa okno konsoli na Windows, loguje komendy i zwraca `(bool, str)`.

---

### 5. `SecureString` dla haseł i kluczy

**Przed:**
```python
pwd = self._ent_pwd.get().strip()
self._run_async("Unlocking", bl_unlock_password, self.drive, pwd)
# hasło pozostaje w pamięci
```

**Po:**
```python
from ntfsecur.core.security import SecureString

raw = self._ent_pwd.get().strip()
with SecureString(raw) as pwd:
    self._ent_pwd.delete(0, tk.END)   # wyczyść pole
    bl_unlock_password(self.drive, pwd.value)
# pwd.value jest teraz wyzerowany
```

---

### 6. `validate_drive()` chroni przed injection

Wszystkie funkcje `bl_*` oraz `set_ntfs_readonly()` automatycznie wywołują
`validate_drive()` zanim wykonają jakąkolwiek komendę. Dla Windows akceptuje
tylko format `X:` (litera + dwukropek), dla Linux tylko ścieżki pod `/dev/`.

---

### 7. Obsługa błędów w wątkach

`thread_worker` łapie **każdy** nieobsłużony wyjątek w wątku roboczym,
loguje go i wyświetla komunikat `✘ Error: …` w statusbarze widgetu.
W oryginalnym kodzie błędy w `worker()` ginęły bezgłośnie.

---

## Import

Stary kod z `NTFSecur.py` można stopniowo migrować, zastępując:

```python
# Stare
from NTFSecur import is_admin, bl_enable, _t, run_cmd

# Nowe
from ntfsecur.core.security  import is_admin, require_admin, safe_run
from ntfsecur.core.bitlocker import bl_enable
from ntfsecur.i18n           import t
```

Oryginalny `NTFSecur.py` pozostaje w pełni funkcjonalny. Nowe moduły
można włączać stopniowo, jeden panel na raz.
