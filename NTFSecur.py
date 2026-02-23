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
Version     : 2.1.0
Description : System Management Panel – NTFSecur + BitLocker + Processes +
              Network + Services + Logs + USB + Drives + Databases +
              FSLibrary + Autostart modules.
              Merged from NTFSecur v2.0.0 + New v1.0.0 →  v2.1.0
              Adds: i18n (EN/PL), GlassScrollbar, BitLockerPanel,
              Autostart module, extended reports, topmost toggle,
              enhanced colour palette.
=============================================================================
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import ctypes
import sys
import os
import threading
import socket
import json
import time
import tempfile
import platform
import logging as _logging
import traceback as _traceback
import csv
import datetime
import sqlite3

# ── Integrated package modules ────────────────────────────────────────────────
# Add the directory containing this file to path so the ntfsecur package
# is always found regardless of the working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ── PyInstaller resource_path ─────────────────────────────────────────────────
def resource_path(*parts: str) -> str:
    """
    Zwraca bezwzględną ścieżkę do zasobu (pic, dane).
    W trybie frozen (EXE): sys._MEIPASS — tymczasowy katalog PyInstaller.
    W trybie normalnym:    katalog skryptu (_HERE).
    """
    base = getattr(sys, "_MEIPASS", _HERE)
    return os.path.join(base, *parts)

try:
    from ntfsecur.i18n import t as _t_new, set_locale as _set_locale_new, get_locale as _get_locale_new
    from ntfsecur.core.security import (
        is_admin as _is_admin_new,
        require_admin,
        validate_drive,
        safe_run as _safe_run,
        SecureString,
        no_window_kwargs as _no_window_kwargs_new,
    )
    from ntfsecur.core.bitlocker import (
        bl_run, bl_status, bl_enable, bl_disable, bl_lock,
        bl_unlock_password, bl_unlock_recovery,
        bl_suspend, bl_resume,
        bl_get_recovery_key, bl_backup_recovery_to_ad,
        bl_add_password_protector, bl_add_tpm_protector,
        bl_add_recovery_protector, bl_change_pin, bl_wipe_free_space,
    )
    from ntfsecur.core.system import (
        get_ntfs_partitions as _get_ntfs_partitions_new,
        set_ntfs_readonly as _set_ntfs_readonly_new,
        get_processes as _get_processes_new,
        kill_process as _kill_process_new,
        get_network_info as _get_network_info_new,
        get_services as _get_services_new,
        control_service as _control_service_new,
        get_logs as _get_logs_new,
        get_usb_devices as _get_usb_devices_new,
    )
    from ntfsecur.core.settings import get_settings as _get_settings_new
    from ntfsecur.core.logging import log_info, log_debug, log_warn, log_error
    from ntfsecur.ui.helpers import thread_worker, AdminMixin
    from ntfsecur.core.backup import (
        backup_file_history,
        backup_file_history_location,
        backup_registry,
        backup_bcd,
        run_all_backups,
    )
    from ntfsecur.core.paths import AppPaths
    _PACKAGE_LOADED = True
except ImportError as _pkg_err:
    _PACKAGE_LOADED = False
    print(f"[NTFSecur] ntfsecur package not found, running in standalone mode: {_pkg_err}")


# ─────────────────────────────────────────────────────────────────────────────
#  i18n – Internationalisation / Translation Library
# ─────────────────────────────────────────────────────────────────────────────
# Supported locales: "pl" (Polish – default), "en" (English)
# Usage:  _t("Wymagane uprawnienia administratora.")
#         _t("Wymagane uprawnienia administratora.", "pl")   # explicit locale
# To switch locale at runtime:  set_locale("en")

_LOCALE: str = "en"   # default locale

_TRANSLATIONS: dict = {
    # Common / shared
    "Wymagane uprawnienia administratora.":
        "Administrator privileges required.",
    "Wymagane uprawnienia administratora":
        "Administrator privileges required",
    "Brak uprawnień administratora":
        "No administrator privileges",
    "Błąd":
        "Error",
    "Ostrzeżenie":
        "Warning",
    "Informacja":
        "Information",
    "Tak":
        "Yes",
    "Nie":
        "No",
    "OK":
        "OK",
    "Anuluj":
        "Cancel",
    "Zapisz":
        "Save",
    "Otwórz":
        "Open",
    "Zamknij":
        "Close",
    "Odśwież":
        "Refresh",
    "Usuń":
        "Delete",
    "Wyczyść":
        "Clear",
    "Kopiuj":
        "Copy",
    "Wklej":
        "Paste",
    "Szukaj…":
        "Search…",
    "Szukaj":
        "Search",
    "Filtruj":
        "Filter",
    "Eksportuj":
        "Export",
    "Importuj":
        "Import",
    "Raport":
        "Report",
    "Generuj raport":
        "Generate Report",
    "Zapisz raport":
        "Save Report",
    "Ustawienia":
        "Settings",
    "Pomoc":
        "Help",
    "O programie":
        "About",
    "Wyjdź":
        "Exit",
    "Uruchom":
        "Run",
    "Zatrzymaj":
        "Stop",
    "Wstrzymaj":
        "Pause",
    "Wznów":
        "Resume",
    "Skanuj":
        "Scan",
    "Połącz":
        "Connect",
    "Rozłącz":
        "Disconnect",
    "Aktualizuj":
        "Update",
    "Szczegóły":
        "Details",
    "Status":
        "Status",
    "Włączony":
        "Enabled",
    "Wyłączony":
        "Disabled",
    "Aktywny":
        "Active",
    "Nieaktywny":
        "Inactive",
    "Uruchomiony":
        "Running",
    "Zatrzymany":
        "Stopped",
    "Nieznany":
        "Unknown",
    "Brak danych":
        "No data",
    "Ładowanie…":
        "Loading…",
    "Proszę czekać…":
        "Please wait…",
    "Operacja zakończona.":
        "Operation completed.",
    "Operacja zakończona pomyślnie.":
        "Operation completed successfully.",
    "Operacja nie powiodła się.":
        "Operation failed.",
    "Przekroczono czas oczekiwania.":
        "Operation timed out.",


    # Header / Sidebar
    "SYSTEM MANAGEMENT PANEL":
        "SYSTEM MANAGEMENT PANEL",
    "polsoft.ITS™   ·   Profesjonalne centrum zarządzania systemem   ·   NTFSecur":
        "polsoft.ITS™   ·   Professional System Management Centre   ·   NTFSecur",
    "Zawsze na wierzchu":
        "Always on top",
    "WŁĄCZONE":
        "ENABLED",
    "WYŁĄCZONE":
        "DISABLED",
    "ADMIN":
        "ADMIN",
    "USER":
        "USER",


    # Modules / menu
    "NTFSecur":
        "NTFSecur",
    "Procesy":
        "Processes",
    "Sieć":
        "Network",
    "Usługi":
        "Services",
    "Logi":
        "Logs",
    "USB":
        "USB",
    "Dyski":
        "Drives",
    "BitLocker":
        "BitLocker",
    "Bazy danych":
        "Databases",
    "Pulpit":
        "Dashboard",


    # NTFSecur module
    "Partycja NTFS":
        "NTFS Partition",
    "Tylko do odczytu":
        "Read-Only",
    "Pełny dostęp":
        "Full Access",
    "Włącz ochronę":
        "Enable Protection",
    "Wyłącz ochronę":
        "Disable Protection",
    "Stan partycji":
        "Partition Status",
    "Rozmiar":
        "Size",
    "Etykieta":
        "Label",
    "Dysk":
        "Drive",


    # Processes module
    "Nazwa procesu":
        "Process Name",
    "PID":
        "PID",
    "Pamięć":
        "Memory",
    "Zakończ proces":
        "End Process",
    "Odśwież procesy":
        "Refresh Processes",


    # Network module
    "Interfejs":
        "Interface",
    "Adres IP":
        "IP Address",
    "Typ":
        "Type",
    "Nazwa hosta":
        "Hostname",


    # Services module
    "Nazwa usługi":
        "Service Name",
    "Uruchom usługę":
        "Start Service",
    "Zatrzymaj usługę":
        "Stop Service",
    "Restartuj usługę":
        "Restart Service",


    # Logs module
    "Poziom":
        "Level",
    "Źródło":
        "Source",
    "Wiadomość":
        "Message",
    "Czas":
        "Time",


    # USB module
    "Urządzenie USB":
        "USB Device",
    "Producent":
        "Manufacturer",
    "System plików":
        "File System",
    "Pojemność":
        "Capacity",
    "Zajęte":
        "Used",
    "Wolne":
        "Free",
    "Numer seryjny":
        "Serial Number",
    "Historia USB":
        "USB History",
    "Wyczyść historię":
        "Clear History",
    "Eksportuj historię":
        "Export History",
    "Historia urządzeń USB":
        "USB Device History",
    "Brak urządzeń USB":
        "No USB devices connected",


    # Settings
    "Motyw":
        "Theme",
    "Ciemny":
        "Dark",
    "Jasny":
        "Light",
    "Język":
        "Language",
    "Przywróć ustawienia fabryczne":
        "Restore Factory Settings",
    "Zapisz ustawienia":
        "Save Settings",
    "Poziom logowania":
        "Log Level",
    "Interwał skanowania":
        "Scan Interval",
    "Potwierdź niebezpieczne operacje":
        "Confirm Dangerous Operations",
    "Pokaż znak wodny":
        "Show Watermark",
    "wymagają ponownego uruchomienia jako Administrator.":
        "require restarting as Administrator.",
    "Brak uprawnień":
        "Insufficient Privileges",
    "Uprawnienia":
        "Permissions",


    # BitLocker
    "Szyfrowanie":
        "Encryption",
    "Odszyfrowanie":
        "Decryption",
    "Klucz odzyskiwania":
        "Recovery Key",
    "Zaszyfrowany":
        "Encrypted",
    "Niezaszyfrowany":
        "Unencrypted",
    "Chroniony":
        "Protected",
    "Niechroniony":
        "Unprotected",
    "Zaszyfrowane dyski":
        "Encrypted Drives",
    "Aktywnych":
        "Active",


    # Reports
    "Aktywnych procesów":
        "Active Processes",
    "Uruchomione":
        "Running",
    "aktywnych":
        "active",


    # ── Extended i18n – all remaining UI strings ──────────────────────────────

    # Navigation / sidebar
    "NAWIGACJA":
        "NAVIGATION",


    # Common actions (duplicates guarded by dict)
    "Zaznacz wszystkie":
        "Select All",
    "Odznacz wszystkie":
        "Deselect All",
    "Wczytywanie…":
        "Loading…",
    "Gotowy.":
        "Ready.",
    "Przebiegi:":
        "Passes:",


    # Report dialog
    "Typ raportu:":
        "Report type:",
    "Sekcje (opcjonalne nadpisanie):":
        "Sections (optional override):",
    "Brak sekcji":
        "No sections",
    "Wybierz co najmniej jedną sekcję.":
        "Select at least one section.",
    "Raport gotowy":
        "Report ready",
    "Zapisano:\n{path}":
        "Saved:\n{path}",
    "Błąd raportu":
        "Report error",
    "Ustawienia stosowane przy kolejnym generowaniu raportu.":
        "Settings applied on the next report generation.",
    "Timeout zbierania danych (s):":
        "Data collection timeout (s):",
    "Maksimum wierszy:":
        "Maximum rows:",
    "Zmienne: {type}  {date}  {time}  {host}  {user}":
        "Variables: {type}  {date}  {time}  {host}  {user}",
    "HTML Report Settings":
        "HTML Report Settings",
    "Configure appearance, content, metadata, and report export":
        "Configure appearance, content, metadata, and report export",
    "Select Reports Folder":
        "Select Reports Folder",


    # Handbook / About
    "Handbook – User Manual":
        "Handbook – User Manual",
    "Search the handbook…  (Enter)":
        "Search the handbook…  (Enter)",
    "Wersja":
        "Version",
    "Autor:":
        "Author:",
    "Uprawnienia administratora":
        "Administrator privileges",
    "Uprawnienia użytkownika":
        "User privileges",


    # Logs export
    "Eksportuj logi systemowe":
        "Export system logs",
    "Eksport logów":
        "Log export",
    "Logi zapisane pomyślnie:\n{path}":
        "Logs saved successfully:\n{path}",
    "Błąd eksportu":
        "Export error",


    # NTFSecur dialogs
    "NTFSecur – Zablokuj wszystko":
        "NTFSecur – Lock All",
    "NTFSecur – Odblokuj wszystko":
        "NTFSecur – Unlock All",
    "Błąd NTFSecur":
        "NTFSecur Error",
    "Niewystarczające uprawnienia":
        "Insufficient privileges",
    "Potwierdź działanie":
        "Confirm action",


    # Drives module
    "Test SMART (długi)":
        "SMART Test (long)",
    "Bezpieczeństwo":
        "Security",
    "Nie można sformatować dysku systemowego!":
        "Cannot format the system drive!",
    "Nie można wyczyścić dysku systemowego!":
        "Cannot wipe the system drive!",
    "Formatuj FAT32":
        "Format FAT32",
    "Formatuj NTFS":
        "Format NTFS",
    "Klonowanie dysku":
        "Drive cloning",
    "Klonowanie":
        "Cloning",
    "Brak dostępnych dysków docelowych.":
        "No available target drives.",
    "Wypełnienie zerami":
        "Zero fill",
    "Bezpieczne kasowanie":
        "Secure erase",
    "Losowe dane":
        "Random data",
    "Wymagane uprawnienia Administratora.":
        "Administrator privileges required.",
    "Reset zakończony":
        "Reset complete",


    # BitLocker panel
    "Ochrona: …":
        "Protection: …",
    "Blokada: …":
        "Lock: …",
    "Metoda: …":
        "Method: …",
    "View and manage BitLocker encryption on all NTFS volumes.":
        "View and manage BitLocker encryption on all NTFS volumes.",
    "BitLocker is only available on Windows Pro/Enterprise editions.":
        "BitLocker is only available on Windows Pro/Enterprise editions.",
    "No NTFS partitions found.":
        "No NTFS partitions found.",
    "No NTFS partitions detected.":
        "No NTFS partitions detected.",
    "No autostart entries.":
        "No autostart entries.",
    "Scans all drives for autorun.inf files (malicious autorun)":
        "Scans all drives for autorun.inf files (malicious autorun)",
    "Click 'SCAN DRIVES' to search for autorun.inf files on all media.":
        "Click 'SCAN DRIVES' to search for autorun.inf files on all media.",
    "Usuń autorun.inf":
        "Delete autorun.inf",
    "Dodawanie wpisów działa tylko na Windows.":
        "Adding entries only works on Windows.",
    "Nazwa i polecenie są wymagane.":
        "Name and command are required.",
    "Wybierz plik wykonywalny":
        "Select executable file",


    # Scheduled tasks
    "Loading tasks…":
        "Loading tasks…",
    "No scheduled tasks.":
        "No scheduled tasks.",


    # Processes module
    "Szukaj:":
        "Search:",
    "Potwierdź":
        "Confirm",
    "Nieprawidłowy identyfikator procesu.":
        "Invalid process ID.",


    # Services module
    "Wykonać '{act}' na usłudze:\n{name}?":
        "Perform '{act}' on service:\n{name}?",

    "Nieprawidłowa nazwa usługi.":
        "Invalid service name.",


    # Logs module
    "Filtr:":
        "Filter:",
    "No log entries match the filter.":
        "No log entries match the filter.",


    # Databases module
    "No results for the selected filter.":
        "No results for the selected filter.",
    "Features:":
        "Features:",
    "Notes:":
        "Notes:",


    # Filesystem library
    "No results.":
        "No results.",


    # USB module
    "No USB storage devices connected.":
        "No USB storage devices connected.",
    "No USB devices in history database.":
        "No USB devices in history database.",
    "No USB events in database.":
        "No USB events in database.",
    "Last 200 USB Events:":
        "Last 200 USB Events:",
    "Recent Events:":
        "Recent Events:",
    "Remove this device from history?":
        "Remove this device from history?",
    "Export USB History to CSV":
        "Export USB History to CSV",
    "Delete ALL USB device history?\nThis action cannot be undone.":
        "Delete ALL USB device history?\nThis action cannot be undone.",
    "No capacity data (device not mounted).":
        "No capacity data (device not mounted).",
    "Safe removal request sent.\n":
        "Safe removal request sent.\n",
    "Sort:":
        "Sort:",


    # Dashboard / report
    "Report Generated":
        "Report Generated",
    "Save BitLocker Operation Log":
        "Save BitLocker Operation Log",
    "Save BitLocker Recovery Key":
        "Save BitLocker Recovery Key",
    "Wipe Free Space":
        "Wipe Free Space",
    "Show password":
        "Show password",
    "Klucz odzysku:":
        "Recovery key:",
    "Stary PIN:":
        "Old PIN:",
    "Nowy PIN:":
        "New PIN:",
    "Password:":
        "Password:",
    "New BitLocker Password:":
        "New BitLocker Password:",
    "Confirm Password:":
        "Confirm Password:",
    "Add":
        "Add",
    "Format: 123456-123456-123456-123456-123456-123456-123456-123456":
        "Format: 123456-123456-123456-123456-123456-123456-123456-123456",
    "Open Report in Browser After Generation":
        "Open Report in Browser After Generation",
    "NTFSecur Report":
        "NTFSecur Report",
    "NTFSecur v{v}  ·  F1 — Handbook  ·  Ctrl+F — Search  ·  Esc — Close":
        "NTFSecur v{v}  ·  F1 — Handbook  ·  Ctrl+F — Search  ·  Esc — Close",


    # ── Drives / disk operations ───────────────────────────────────────────────
    "  Testy SMART, naprawa systemu plików, kasowanie, odzyskiwanie danych, klonowanie.":
        "  SMART tests, filesystem repair, erasing, data recovery, cloning.",
    "  WYŁ → partycja w pełni dostępna (odczyt + zapis)":
        "  OFF → partition fully accessible (read + write)",
    "  WŁ  → partycja zablokowana (tylko odczyt, brak zapisu)\n":
        "  ON  → partition locked (read-only, no write)\n",
    "Baza urządzeń masowych USB":
        "USB Mass Storage Database",
    "Brak uprawnień administratora.\n":
        "No administrator privileges.\n",
    "Brak uprawnień. Uruchom jako Administrator.":
        "No privileges. Run as Administrator.",
    "Brak uprawnień.\nUruchom jako Administrator.":
        "No privileges.\nRun as Administrator.",
    "Czy na pewno chcesz ODBLOKOWAĆ (pełny dostęp)\nwszystkie partycje NTFS?":
        "Are you sure you want to UNLOCK (full access)\nall NTFS partitions?",
    "Czy na pewno chcesz ZABLOKOWAĆ (tylko odczyt)\nwszystkie partycje NTFS?":
        "Are you sure you want to LOCK (read-only)\nall NTFS partitions?",
    "Format: FAT32.  Kontynuować?":
        "Format: FAT32.  Continue?",
    "Format: NTFS.  Kontynuować?":
        "Format: NTFS.  Continue?",
    "Formaty partycji i systemy plików – baza wiedzy":
        "Partition formats and file systems – knowledge base",
    "Geometria okna i motyw zostały zresetowane.":
        "Window geometry and theme have been reset.",
    "Klonowanie bloków przez dd nie jest dostępne w Windows.\n\n":
        "Block cloning via dd is not available on Windows.\n\n",
    "ℹ  Na Windows użyj Clonezilla lub Macrium Reflect.":
        "ℹ  On Windows use Clonezilla or Macrium Reflect.",
    "Ta operacja może zająć dużo czasu.\n\n":
        "This operation may take a long time.\n\n",
    "Wszystkie dane zostaną nieodwracalnie zniszczone!":
        "All data will be irreversibly destroyed!",
    "Użyj Eraser lub Cipher z wieloma przebiegami.":
        "Use Eraser or Cipher with multiple passes.",
    "Zalecane narzędzia:\n":
        "Recommended tools:\n",
    "⚠  WSZYSTKIE DANE na {path} zostaną USUNIĘTE!\n":
        "⚠  ALL DATA on {path} will be DELETED!\n",
    "⚠  WSZYSTKIE DANE na {path} zostaną ZNISZCZONE zerami!\nKontynuować?":
        "⚠  ALL DATA on {path} will be WIPED with zeros!\nContinue?",
    "⚠  Wypełnić {path} losowymi danymi?\nWszystkie istniejące dane zostaną utracone.":
        "⚠  Fill {path} with random data?\nAll existing data will be lost.",
    "⚠  BEZPIECZNE KASOWANIE {path}  ({passes} przebieg(ów))\n":
        "⚠  SECURE ERASE {path}  ({passes} pass(es))\n",
    "Wypełnienie losowymi danymi przez dd nie jest dostępne na Windows.\n":
        "Random data fill via dd is not available on Windows.\n",
    "Skanuj, diagnozuj i naprawiaj nośniki: USB, SD, HDD, SSD.\n":
        "Scan, diagnose and repair media: USB, SD, HDD, SSD.\n",


    # ── NTFSecur / partitions ─────────────────────────────────────────────────
    "Zarządzaj ochroną zapisu na woluminach NTFS.\n":
        "Manage write protection on NTFS volumes.\n",
    "do zmiany ustawień ochrony zapisu NTFS.\n\n":
        "to change NTFS write protection settings.\n\n",
    "Odblokuj wszystkie partycje (pełny dostęp)":
        "Unlock all partitions (full access)",
    "Znaleziono {len(partitions)} partycję/partycji NTFS. Gotowy.":
        "Found {len(partitions)} NTFS partition(s). Ready.",


    # ── Modules / menu labels ─────────────────────────────────────────────────
    "Moduły":
        "Modules",
    "Menedżer procesów":
        "Process Manager",
    "Kontrola usług systemowych":
        "System Services Control",
    "Zarządzanie programami startowymi i autostart":
        "Startup programs and autostart management",
    "Zarządzanie szyfrowaniem dysków Windows":
        "Windows disk encryption management",
    "Szyfrowanie dysków Windows":
        "Windows Disk Encryption",
    "Urządzenia USB + historia (SQLite)":
        "USB devices + history (SQLite)",


    # ── Sidebar menu tooltips ─────────────────────────────────────────────────
    "Odśwież bieżący widok":
        "Refresh current view",
    "Odśwież listę procesów":
        "Refresh process list",
    "Odśwież informacje sieciowe":
        "Refresh network info",
    "Odśwież listę usług":
        "Refresh service list",
    "Odśwież logi":
        "Refresh logs",
    "Pokaż procesy":
        "Show processes",
    "Pokaż interfejsy sieciowe":
        "Show network interfaces",
    "Pokaż usługi":
        "Show services",
    "Pokaż logi systemowe":
        "Show system logs",
    "Wyczyść widok logów":
        "Clear log view",
    "Otwórz po wygenerowaniu":
        "Open after generation",
    "Uruchom zaznaczoną usługę":
        "Start selected service",
    "Zatrzymaj zaznaczoną usługę":
        "Stop selected service",
    "Usuń autostart":
        "Remove from autostart",
    "↩  Przywróć domyślny rozmiar okna":
        "↩  Restore default window size",
    "Sprawdź uprawnienia administratora":
        "Check administrator privileges",


    # ── Settings / reset ──────────────────────────────────────────────────────
    "Spowoduje to przywrócenie WSZYSTKICH ustawień do wartości fabrycznych\n":
        "This will restore ALL settings to factory values\n",
    "i ponowne uruchomienie interfejsu.\n\nKontynuować?":
        "and restart the interface.\n\nContinue?",
    "Przywrócono ustawienia fabryczne.\n":
        "Factory settings restored.\n",


    # ── Admin / user status messages ──────────────────────────────────────────
    "✔  Aplikacja działa z uprawnieniami ADMINISTRATORA.\n\n":
        "✔  Application running with ADMINISTRATOR privileges.\n\n",
    "Wszystkie operacje systemowe są dostępne.":
        "All system operations are available.",
    "⚠  Aplikacja działa BEZ uprawnień administratora.\n\n":
        "⚠  Application running WITHOUT administrator privileges.\n\n",
    "Niektóre funkcje (NTFSecur, zarządzanie usługami)\n":
        "Some features (NTFSecur, service management)\n",
    "Uruchom ponownie aplikację jako Administrator.":
        "Restart the application as Administrator.",


    # ── Report type labels ─────────────────────────────────────────────────────
    "⚡  Szybki – Kluczowe wskaźniki":
        "⚡  Quick – Key indicators",
    "📊  Normalny – Przegląd systemu":
        "📊  Normal – System overview",
    "📋  Pełny – Wszystkie sekcje":
        "📋  Full – All sections",
    "🔬  Szczegółowy – Pełny + tabele":
        "🔬  Detailed – Full + tables",
    "📁  Raport częściowy…":
        "📁  Partial report…",
    "📖  Podręcznik użytkownika":
        "📖  User manual",
    "🌐  Sieć – Interfejsy":
        "🌐  Network – Interfaces",
    "🛠  Usługi – Stan usług":
        "🛠  Services – Service status",
    "📁  Bazy danych – Przegląd":
        "📁  Databases – Overview",
    "📚  Biblioteka FS – Systemy plików":
        "📚  FS Library – File systems",
    "🔌  USB – Historia urządzeń":
        "🔌  USB – Device history",


    # ── Process / service operations ───────────────────────────────────────────
    "Zakończyć proces:\n{name}  (PID {pid})?":
        "Terminate process:\n{name}  (PID {pid})?",
    "Kończenie procesu {pid}…":
        "Terminating process {pid}…",
    "Wykonać '{action.upper()}' na usłudze:\n{name}?":
        "Execute '{action.upper()}' on service:\n{name}?",


    # ── BitLocker extended ────────────────────────────────────────────────────
    "Wykonać: {action_name}\nna {drive}?":
        "Execute: {action_name}\non {drive}?",
    "do zarządzania BitLockerem.\n\n":
        "to manage BitLocker.\n\n",


    # ── USB / device operations ────────────────────────────────────────────────
    "Plik usunięty: {entry['name']}":
        "File deleted: {entry['name']}",
    "Usunięto z rejestru: {entry['name']}":
        "Removed from registry: {entry['name']}",
    "Usunięto: {path}":
        "Deleted: {path}",
    "Usunąć plik:\n{path}?":
        "Delete file:\n{path}?",
    "Źródło: {entry['source']}?":
        "Source: {entry['source']}?",
    "Czy na pewno chcesz usunąć:\n\n{entry['name']}\n\n":
        "Are you sure you want to delete:\n\n{entry['name']}\n\n",


    # ── Disk scan / repair ─────────────────────────────────────────────────────
    "Naprawa systemu plików: {path}…":
        "Filesystem repair: {path}…",
    "Odświeżanie tablicy partycji: {path}…":
        "Refreshing partition table: {path}…",
    "Regeneracja sektorów: {path}…":
        "Sector regeneration: {path}…",
    "Skanowanie zakończone: {path}":
        "Scan completed: {path}",
    "Skanowanie {path} w poszukiwaniu usuniętych plików…":
        "Scanning {path} for deleted files…",
    "Wypełnienie zerami: {path}…":
        "Zero fill: {path}…",
    "Wypełnianie losowymi danymi: {path}…":
        "Filling with random data: {path}…",
    "Klonowanie {path} → {tgt}…":
        "Cloning {path} → {tgt}…",


    # ── Drives long SMART ──────────────────────────────────────────────────────
    "Długi test na {path} może zająć 30–120 min.\nKontynuować?":
        "Long test on {path} may take 30–120 min.\nContinue?",
    "Znaleziono {count} partycję/partycji NTFS. Gotowy.":
        "Found {count} NTFS partition(s). Ready.",
    "Usunięto z rejestru: {name}":
        "Removed from registry: {name}",
    "Plik usunięty: {name}":
        "File deleted: {name}",
    "Czy na pewno chcesz usunąć:\n\n{name}\n\n":
        "Are you sure you want to delete:\n\n{name}\n\n",
    "Wykonać \'{act}\' na usłudze:\n{name}?":
        "Execute \'{act}\' on service:\n{name}?",
    "Źródło: {source}?":
        "Source: {source}?",
    "✘  Błąd: {e}":
        "✘  Error: {e}",
    "Włącz szyfrowanie":
        "Enable encryption",
    "Odszyfruj dysk":
        "Decrypt drive",
    "Wstrzymaj ochronę":
        "Suspend protection",


    # Status badge labels (canvas button text)
    "⏳  PRACUJE…":
        "⏳  WORKING…",
    "🔒  ZABLOKOWANY":
        "🔒  LOCKED",
    "🔓  ODBLOKOWANY":
        "🔓  UNLOCKED",
    "⬤  ODBLOKOWANY":
        "⬤  UNLOCKED",


    # Status / error messages
    "Nie znaleziono partycji NTFS.":
        "No NTFS partitions found.",
    "Skanowanie partycji NTFS…":
        "Scanning NTFS partitions…",
    "Stosowanie NTFSecur na {drive}…":
        "Applying NTFSecur to {drive}…",


    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: Drives – Diagnostics · Repair · Recovery · Regeneration
    # ══════════════════════════════════════════════════════════════════════════

    # Header / description
    "💾 Dyski":
        "💾 Drives",
    "Diagnostyka · Naprawa · Odzyskiwanie · Regeneracja":
        "Diagnostics · Repair · Recovery · Regeneration",


    # Tab labels
    "🔍  Skanowanie":
        "🔍  Scanning",


    # Drive selector
    "Brak etykiety":
        "No Label",
    "Wymienny":
        "Removable",
    "Skanowanie {path}…":
        "Scanning {path}…",


    # SMART tab
    "Krótki test uruchomiony (~2 min).":
        "Short test started (~2 min).",
    "Długi test uruchomiony (w tle).":
        "Long test started (in background).",


    # Repair tab
    "🔎  Tylko weryfikacja":
        "🔎  Verify Only",
    "Sprawdzanie i naprawa: {path}":
        "Check and repair: {path}",
    "Weryfikacja (tylko odczyt): {path}":
        "Verify (read-only): {path}",
    "Weryfikacja {path}…":
        "Verifying {path}…",
    "Naprawa zakończona.":
        "Repair completed.",
    "Weryfikacja zakończona.":
        "Verification completed.",
    "Formatowanie zakończone.":
        "Formatting completed.",
    "Formatowanie NTFS zakończone.":
        "NTFS formatting completed.",
    "Formatowanie {path} jako FAT32…":
        "Formatting {path} as FAT32…",
    "Formatowanie {path} jako NTFS…":
        "Formatting {path} as NTFS…",
    "Skanowanie tablicy partycji: {path}…":
        "Scanning partition table: {path}…",
    "Skan tablicy partycji: {path}":
        "Partition table scan: {path}",
    "Skanowanie partycji zakończone.":
        "Partition scan completed.",
    "TestDisk uruchomiony w nowym oknie.":
        "TestDisk launched in a new window.",
    "TestDisk uruchomiony.":
        "TestDisk launched.",
    "TestDisk uruchomiony w terminalu.":
        "TestDisk launched in terminal.",
    "PhotoRec uruchomiony.":
        "PhotoRec launched.",
    "Dysk docelowy:":
        "Target drive:",
    "Klonuj dysk":
        "Clone Drive",
    "Klonowanie zakończone.":
        "Cloning completed.",
    "▶  KLONUJ":
        "▶  CLONE",
    "Uruchamiam TestDisk: {path}…":
        "Launching TestDisk: {path}…",


    # Wipe tab
    "🔒  Bezpieczne kasowanie":
        "🔒  Secure Erase",
    "🎲  Losowe dane":
        "🎲  Random Data",
    "Zero-fill: najszybsze — nadpisuje zerami (0x00)":
        "Zero-fill: fastest — overwrites with zeros (0x00)",
    "Bezpieczne: shred (Linux) / cipher /w (Windows)":
        "Secure: shred (Linux) / cipher /w (Windows)",
    "Losowe dane: nadpisuje losowymi bajtami (dobre dla SSD)":
        "Random data: overwrites with random bytes (good for SSD)",
    "Wypełnienie zerami zakończone.":
        "Zero fill completed.",
    "Bezpieczne kasowanie zakończone.":
        "Secure erase completed.",
    "Wypełnienie losowymi danymi zakończone.":
        "Random data fill completed.",
    "Bezpieczne kasowanie: {path}…":
        "Secure erase: {path}…",
    "Bezpieczne kasowanie: {path}":
        "Secure erase: {path}",
    "Zero-fill: {path}":
        "Zero-fill: {path}",
    "Losowe dane: {path}":
        "Random data: {path}",


    # Regeneration tab
    "🧲  Napraw sektory (HDD)":
        "🧲  Repair Sectors (HDD)",
    "Odświeżenie MBR/GPT zakończone.":
        "MBR/GPT refresh completed.",
    "Odświeżenie MBR zakończone.":
        "MBR refresh completed.",
    "Naprawa sektorów zakończona.":
        "Sector repair completed.",
    "Przywracanie tablicy partycji: {path}":
        "Restoring partition table: {path}",
    "Uruchamiam TestDisk: {path}":
        "Launching TestDisk: {path}",
    "Zresetowano: {sysf}":
        "Reset: {sysf}",


    # Tab labels
    "💿  Autorun.inf":
        "💿  Autorun.inf",
    "⏰  Zaplanowane zadania":
        "⏰  Scheduled Tasks",


    # Startup tab – toolbar buttons
    "➕  DODAJ WPIS":
        "➕  ADD ENTRY",
    "🔍  SKANUJ DYSKI":
        "🔍  SCAN DRIVES",


    # Add-entry dialog
    "Dodaj wpis autostartu":
        "Add Autostart Entry",
    "Nazwa wpisu:":
        "Entry name:",
    "Klucz rejestru:":
        "Registry key:",
    "✔  DODAJ":
        "✔  ADD",
    "Dodano: {name}":
        "Added: {name}",


    # Entry types (used as data labels and for colour-coding)
    "Rejestr":
        "Registry",
    "Folder startowy":
        "Startup Folder",
    "Plik nie znaleziony: {path}":
        "File not found: {path}",


    # Scheduled tasks tab – column headers
    "NAZWA ZADANIA":
        "TASK NAME",
    "WYZWALACZ":
        "TRIGGER",
    "OSTATNIE URUCHOMIENIE":
        "LAST RUN",



    # ══════════════════════════════════════════════════════════════════════════
    #  HANDBOOK – chapter titles, labels, UI strings
    # ══════════════════════════════════════════════════════════════════════════

    # Sidebar / chapter list
    "🖥️  Interfejs":
        "🖥️  Interface",
    "Wymagania systemowe":
        "System Requirements",
    "Uruchamianie jako Administrator":
        "Running as Administrator",
    "Kliknij PPM na":
        "Right-click",
    "Uruchom jako administrator":
        "Run as administrator",
    "Pliki i foldery aplikacji":
        "Application Files and Folders",
    "Folder bazowy:":
        "Base folder:",
    "Folder z wygenerowanymi raportami HTML":
        "Folder with generated HTML reports",


    # Interface chapter
    "② Pasek menu (Menu bar)":
        "② Menu Bar",
    "Operacje masowe: Zablokuj/Odblokuj wszystkie partycje":
        "Bulk operations: Lock/Unlock all partitions",
    "③ Panel boczny (Sidebar)":
        "③ Sidebar Panel",
    "④ Pasek statusu (Footer)":
        "④ Status Bar (Footer)",
    "✔ Sukces":
        "✔ Success",
    "wymagana uwaga, ale operacja wykonana":
        "attention required, but operation completed",
    "Motywy i personalizacja":
        "Themes and Customisation",
    "Motyw jest zapisywany i przywracany przy kolejnym uruchomieniu.":
        "Theme is saved and restored on next launch.",


    # Modules chapter
    "Ochrona przed zapisem partycji NTFS (diskpart). Wymaga administratora.":
        "NTFS partition write protection (diskpart). Requires administrator.",
    "Live monitoring USB, historia w SQLite, eksport CSV/HTML.":
        "Live USB monitoring, history in SQLite, CSV/HTML export.",


    # NTFSecur chapter
    "Panel partycji":
        "Partition Panel",
    "Aktualny status ochrony (ON/OFF)":
        "Current protection status (ON/OFF)",
    "Przycisk SECURE ON/OFF":
        "SECURE ON/OFF button",
    "Operacje masowe (menu NTFSecur)":
        "Bulk Operations (NTFSecur menu)",
    "Zablokuj wszystkie partycje":
        "Lock all partitions",
    "Operacja wymaga potwierdzenia.":
        "Operation requires confirmation.",
    "Odblokuj wszystkie partycje":
        "Unlock all partitions",


    # BitLocker chapter
    "Odblokuj kluczem":
        "Unlock with key",
    "Odblokowuje kluczem odzysku (48 cyfr)":
        "Unlocks with recovery key (48 digits)",
    "Zapisz klucz":
        "Save key",
    "Zapisuje klucz odzysku do pliku tekstowego":
        "Saves recovery key to a text file",
    "Backup do AD":
        "Backup to AD",
    "Archiwizuje klucz w Active Directory":
        "Archives key in Active Directory",
    "Dodaj TPM":
        "Add TPM",
    "Dodaje protektor TPM":
        "Adds a TPM protector",
    "Dodaj klucz odzysku":
        "Add recovery key",
    "Generuje nowy 48-cyfrowy klucz":
        "Generates a new 48-digit key",
    "Bezpieczne nadpisywanie wolnej przestrzeni":
        "Securely overwrites free space",


    # Autostart chapter
    "Lokalizacje skanowane":
        "Scanned Locations",
    "Rejestr HKCU\\Run":
        "Registry HKCU\\Run",
    "Rejestr HKCU\\RunOnce":
        "Registry HKCU\\RunOnce",
    "Rejestr HKLM\\Run":
        "Registry HKLM\\Run",
    "Rejestr HKLM\\RunOnce":
        "Registry HKLM\\RunOnce",
    "Zadania zaplanowane":
        "Scheduled Tasks",
    "Windows Task Scheduler — zadania z triggerem @startup":
        "Windows Task Scheduler — tasks with @startup trigger",


    # Processes chapter
    "Kolumny tabeli":
        "Table Columns",
    "Identyfikator procesu nadany przez system operacyjny":
        "Process identifier assigned by the operating system",
    "Nazwa pliku wykonywalnego procesu":
        "Executable file name of the process",
    "Running / Sleeping / Zombie (Linux) lub brak danych (Windows)":
        "Running / Sleeping / Zombie (Linux) or no data (Windows)",
    "Operacje":
        "Operations",
    "na Windows":
        "on Windows",
    "na Linux":
        "on Linux",


    # Network chapter
    "Nazwa komputera w sieci":
        "Computer name on the network",
    "Wersja systemu operacyjnego":
        "Operating system version",
    "Architektura":
        "Architecture",


    # Services chapter
    "Zbieranie danych":
        "Data Collection",
    "Filtrowanie — wpisz fragment nazwy w pole filtra":
        "Filtering — type a name fragment in the filter field",


    # Logs chapter
    "zdarzenia informacyjne":
        "informational events",
    "Filtrowanie i eksport":
        "Filtering and Export",


    # USB chapter
    "Plik bazy danych":
        "Database File",
    "Dane przechowywane w SQLite:":
        "Data stored in SQLite:",
    "Tabele:":
        "Tables:",
    "(zdarzenia)":
        "(events)",


    # Reports chapter
    "Zaawansowany kreator":
        "Advanced Wizard",
    "Automatyczne otwarcie po wygenerowaniu":
        "Automatic opening after generation",


    # Databases chapter
    "Licencja":
        "License",
    "Systemy OS":
        "OS Support",
    "Filtrowanie":
        "Filtering",


    # FS Library chapter
    "Max wolumen":
        "Max volume",
    "Max plik":
        "Max file",
    "Wsparcie OS":
        "OS Support",
    "Maksymalny rozmiar woluminu (np. 256 TB dla NTFS)":
        "Maximum volume size (e.g. 256 TB for NTFS)",
    "Maksymalny rozmiar pojedynczego pliku":
        "Maximum size of a single file",
    "Systemy operacyjne: Windows / Linux / macOS / BSD / inne":
        "Operating systems: Windows / Linux / macOS / BSD / other",
    "Kompresja, deduplikacja, snapshoty, szyfrowanie, POSIX ACL itp.":
        "Compression, deduplication, snapshots, encryption, POSIX ACL, etc.",
    "i inne.":
        "and more.",
    "Filtrowanie po protokole":
        "Filter by Protocol",
    "Wszystkie":
        "All",


    # Shortcuts chapter
    "Nawigacja":
        "Navigation",
    "Generuj raport Szybki":
        "Generate Quick report",
    "Generuj raport Normalny":
        "Generate Normal report",
    "Fokus na polu wyszukiwania":
        "Focus the search field",
    "Zamknij okno":
        "Close window",


    # FAQ chapter
    "Historia USB jest pusta.":
        "USB History is empty.",
    "BitLocker pokazuje 'Unavailable' lub 'N/A'.":
        "BitLocker shows 'Unavailable' or 'N/A'.",
    "BitLocker wymaga Windows Pro/Enterprise/Education.":
        "BitLocker requires Windows Pro/Enterprise/Education.",
    "Dlaczego raport ma tylko podstawowe dane?":
        "Why does the report contain only basic data?",
    "settings.json   — ustawienia":
        "settings.json   — application settings",
    "usb_history.db  — baza USB":
        "usb_history.db  — USB history database",
    "przycisk '…' przy polu Katalog docelowy.":
        "the '…' button next to the Target Folder field.",
    "Tak — diskpart ustawia atrybut read-only woluminu trwale.":
        "Yes — diskpart sets the volume read-only attribute permanently.",


    # About chapter
    "Produkt:":
        "Product:",
    "Stos technologiczny":
        "Technology Stack",
    "Framework GUI — natywny interfejs Windows/Linux":
        "GUI framework — native Windows/Linux interface",
    "Baza danych historii USB — wbudowana w Python":
        "USB history database — built into Python",
    "Operacje asynchroniczne — nie blokuje UI":
        "Asynchronous operations — non-blocking UI",
    "Redystrybucja bez pisemnej zgody autora jest zabroniona.":
        "Redistribution without the author's written consent is prohibited.",


    # ── Top menu bar ──────────────────────────────────────────────────────────
    "Plik":
        "File",
    "Eksportuj logi do pliku…":
        "Export logs to file…",
    "Skanuj partycje NTFS":
        "Scan NTFS partitions",
    "Zablokuj wszystkie partycje (tylko odczyt)":
        "Lock all partitions (read-only)",
    "Zabij zaznaczony proces":
        "Kill selected process",
    "Raporty":
        "Reports",
    "🔒  NTFS – Stan partycji":
        "🔒  NTFS – Partition status",
    "🔐  BitLocker – Szyfrowanie":
        "🔐  BitLocker – Encryption",
    "⚙️  Procesy – Uruchomione":
        "⚙️  Processes – Running",
    "📄  Logi – Zdarzenia":
        "📄  Logs – Events",
    "🚀  Autostart – Wpisy startowe":
        "🚀  Autostart – Startup entries",
    "💾  Dyski – Diagnostyka":
        "💾  Drives – Diagnostics",
    "⚙️  Zaawansowany kreator…":
        "⚙️  Advanced wizard…",
    "🎨  Ustawienia raportu…":
        "🎨  Report settings…",
    "Generuj z wykresami / grafikami":
        "Generate with charts / graphics",
    "Motyw ciemny (Dark)":
        "Dark theme",
    "Widok":
        "View",
    "📌  Zawsze na wierzchu":
        "📌  Always on top",
    "🔒  Zablokuj rozmiar okna":
        "🔒  Lock window size",
    "O programie…":
        "About…",


    # ── Module subtitles ──────────────────────────────────────────────────────
    "Zabezpieczenia partycji NTFS":
        "NTFS Partition Security",
    "Informacje sieciowe":
        "Network Information",
    "Logi systemowe":
        "System Logs",
    "Biblioteka baz danych":
        "Database Library",
    "Baza wiedzy o silnikach baz danych":
        "Database engine knowledge base",
    "E-mail:":
        "E-mail:",


    # ── Network module ────────────────────────────────────────────────────────
    "PODSTAWOWE INFORMACJE":
        "BASIC INFORMATION",
    "INTERFEJSY SIECIOWE":
        "NETWORK INTERFACES",
    "AKTYWNE PORTY":
        "ACTIVE PORTS",


    # ── USB module ────────────────────────────────────────────────────────────
    "USB – Diagnostyka":
        "USB – Diagnostics",
    "First Seen":
        "First Seen",
    "Last Seen":
        "Last Seen",
    "Time":
        "Time",
    "Type":
        "Type",
    "No events for this device.":
        "No events for this device.",
    "Delete":
        "Delete",
    "Clear History":
        "Clear History",
    "Export":
        "Export",
    "Executing {action} → {name}…":
        "Executing {action} → {name}…",
    "Biblioteka FS":
        "FS Library",
    "USB Mass DB":
        "USB Mass DB",


    # ── Driver Backup tab ────────────────────────────────────────────────
    "Kopia zapasowa sterowników":
        "Driver Backup",
    "Otwarto":
        "Opened",
    "○  Oczekuje":
        "○  Idle",
    "⏳  W toku…":
        "⏳  Running…",
    "🗜  Pakowanie ZIP…":
        "🗜  Creating ZIP…",
    "✔  Backup gotowy":
        "✔  Backup ready",
    "✘  Błąd":
        "✘  Error",
    "Wersja GUI":
        "GUI version",
    "bazuje na Backup.bat":
        "based on Backup.bat",
    "Metody eksportu":
        "Export methods",
    "Folder docelowy":
        "Target folder",
    "Archiwum ZIP":
        "ZIP archive",
    "Kliknij przycisk aby rozpoćąć backup.":
        "Click a button to start backup.",
    "Tworzenie archiwum ZIP":
        "Creating ZIP archive",
    "Eksport sterowników zakończony":
        "Driver export completed",
    "Backup zakończony pomyślnie!":
        "Backup completed successfully!",
    "Usunięto stary ZIP.":
        "Old ZIP removed.",

    # ── Backup systemu ────────────────────────────────────────────────────
    "Backup":
        "Backup",
    "Kopie zapasowe systemu Windows":
        "Windows system backups",
    "Backup plików użytkownika (File History)":
        "User File Backup (File History)",
    "Uruchom teraz historię plików":
        "Start File History backup now",
    "Ręczne wskazanie lokalizacji historii plików":
        "Set File History location manually",
    "Backup rejestru Windows (pełny)":
        "Windows Registry Backup (full)",
    "Eksport gałęzi rejestru HKLM":
        "Export HKLM registry hive",
    "Eksport gałęzi rejestru HKCU":
        "Export HKCU registry hive",
    "Backup BCD (bootloader)":
        "BCD Backup (bootloader)",
    "Eksport magazynu BCD":
        "Export BCD store",
    "Folder docelowy kopii zapasowych":
        "Backup destination folder",
    "Otwórz folder kopii zapasowych":
        "Open backup folder",
    "Wykonaj pełny backup":
        "Run Full Backup",
    "Wszystkie zadania tworzenia kopii zapasowych zostały ukończone.":
        "All backup tasks completed.",
    "Backup sterowników Windows":
        "Windows Driver Backup",
    "Uruchom teraz":
        "Start now",
    "Lokalizacja":
        "Location",
    "Eksport BCD":
        "Export BCD",
    "Kopia zapasowa systemu":
        "System Backup",
    "DISM":
        "DISM",
    "PnPUtil":
        "PnPUtil",
    "Folder":
        "Folder",
    "Niektóre zadania zakończyły się błędem – sprawdź log.":
        "Some tasks failed – check the log.",

}


def set_locale(locale: str) -> None:
    """Switch the active UI locale. Supported: 'pl', 'en'."""
    global _LOCALE
    if locale in ("pl", "en"):
        _LOCALE = locale
    else:
        raise ValueError(f"Unsupported locale: {locale!r}. Use 'pl' or 'en'.")
    # Sync with package if loaded
    if _PACKAGE_LOADED:
        _set_locale_new(locale)


def get_locale() -> str:
    """Return the currently active locale code."""
    return _LOCALE


def _t(text: str, locale: str = None) -> str:
    """
    Translate *text* to the requested locale.

    Uses the ntfsecur.i18n package when available (supports both legacy
    Polish string keys and new neutral keys).  Falls back to the built-in
    _TRANSLATIONS dict when running in standalone mode.
    """
    if _PACKAGE_LOADED:
        return _t_new(text, locale)
    target = locale or _LOCALE
    if target == "pl":
        return text
    return _TRANSLATIONS.get(text, text)


# ─────────────────────────────────────────────────────────────────────────────
#  Metadata
# ─────────────────────────────────────────────────────────────────────────────
__author__    = "Sebastian Januchowski"
__email__     = "polsoft.its@fastservice.com"
__github__    = "https://github.com/seb07uk"
__copyright__ = "2026© polsoft.ITS™ and Sebastian Januchowski. All rights reserved."
__version__   = "2.1.0"
__product__   = "PolSoft System Management Panel"


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers – admin check & NTFS operations
# ─────────────────────────────────────────────────────────────────────────────
def is_admin() -> bool:
    """Return True if the current process has administrator / root privileges."""
    if _PACKAGE_LOADED:
        return _is_admin_new()
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_ntfs_partitions() -> list:
    if _PACKAGE_LOADED:
        return _get_ntfs_partitions_new()
    partitions = []
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
                    if dtype not in (win32con.DRIVE_FIXED, win32con.DRIVE_REMOVABLE):
                        continue
                    vol_info = win32api.GetVolumeInformation(drive + '\\')
                    fs = vol_info[4]
                    if 'NTFS' in fs:
                        free, total, _ = win32api.GetDiskFreeSpaceEx(drive + '\\')
                        size_gb = round(total / (1024 ** 3), 1)
                        label = vol_info[0] if vol_info[0] else "No Label"
                        partitions.append({'drive': drive, 'label': label, 'size': f"{size_gb} GB"})
                except Exception:
                    pass
        except ImportError:
            partitions = [
                {'drive': 'C:', 'label': 'System',  'size': '237 GB'},
                {'drive': 'D:', 'label': 'Data',    'size': '465 GB'},
                {'drive': 'E:', 'label': 'Backup',  'size': '931 GB'},
            ]
    else:
        partitions = [
            {'drive': '/dev/sda1', 'label': 'System',  'size': '237 GB'},
            {'drive': '/dev/sdb1', 'label': 'Data',    'size': '465 GB'},
            {'drive': '/dev/sdc1', 'label': 'Backup',  'size': '931 GB'},
        ]
    return partitions


def set_ntfs_readonly(drive: str, readonly: bool):
    if _PACKAGE_LOADED:
        return _set_ntfs_readonly_new(drive, readonly)
    if sys.platform == "win32":
        try:
            letter = drive.replace(':', '').strip()
            attrib_cmd = "attributes volume set readonly" if readonly else "attributes volume clear readonly"
            script = f"select volume {letter}\n{attrib_cmd}\nexit\n"
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
                tf.write(script)
                tmp_script = tf.name
            try:
                result = subprocess.run(['diskpart', '/s', tmp_script], capture_output=True, text=True, timeout=30)
            finally:
                try:
                    os.remove(tmp_script)
                except OSError:
                    pass
            if result.returncode == 0:
                state = "ENABLED (Read-Only)" if readonly else "DISABLED (Full Access)"
                return True, f"NTFSecur {state} on {drive}"
            return False, f"diskpart error: {result.stderr.strip()}"
        except Exception as e:
            return False, f"Windows error: {e}"
    else:
        try:
            flag = '--setro' if readonly else '--setrw'
            result = subprocess.run(['sudo', 'blockdev', flag, drive], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                state = "ENABLED (Read-Only)" if readonly else "DISABLED (Full Access)"
                return True, f"NTFSecur {state} on {drive}"
            return False, f"blockdev error: {result.stderr.strip()}"
        except Exception as e:
            return False, f"Linux error: {e}"


def get_processes() -> list:
    if _PACKAGE_LOADED:
        return _get_processes_new()
    procs = []
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ['tasklist', '/fo', 'csv', '/nh'],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.strip().split('\n')[:30]:
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 5:
                    procs.append({'name': parts[0], 'pid': parts[1],
                                  'mem': parts[4].replace('\xa0', ' '), 'status': 'Running'})
        except Exception:
            pass
    else:
        try:
            result = subprocess.run(['ps', 'aux', '--no-header'],
                                    capture_output=True, text=True, timeout=10)
            for line in result.stdout.strip().split('\n')[:30]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    procs.append({'name': parts[10][:40], 'pid': parts[1],
                                  'mem': f"{parts[3]}%", 'status': parts[7]})
        except Exception:
            pass
    if not procs:
        procs = [
            {'name': 'System',      'pid': '4',    'mem': '0.1 MB',   'status': 'Running'},
            {'name': 'explorer.exe','pid': '1234', 'mem': '48.2 MB',  'status': 'Running'},
            {'name': 'svchost.exe', 'pid': '876',  'mem': '12.4 MB',  'status': 'Running'},
            {'name': 'chrome.exe',  'pid': '5432', 'mem': '320.1 MB', 'status': 'Running'},
            {'name': 'python.exe',  'pid': '9988', 'mem': '24.6 MB',  'status': 'Running'},
        ]
    return procs


def get_network_info() -> list:
    interfaces = []
    try:
        # We use a temporary UDP socket — it sends no data, but returns
        # the correct IP of the outgoing interface, not loopback
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        interfaces.append({'name': 'Local', 'ip': local_ip, 'status': 'Up', 'type': 'Ethernet'})
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
            current = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'adapter' in line.lower() and ':' in line:
                    if current.get('name'):
                        interfaces.append(current)
                    current = {'name': line.split(':')[0].replace('Ethernet adapter', '').replace('Wireless', '').strip(),
                               'ip': 'N/A', 'status': 'Up', 'type': 'Adapter'}
                elif 'IPv4' in line and ':' in line:
                    current['ip'] = line.split(':', 1)[1].strip()
                elif 'Media disconnected' in line:
                    current['status'] = 'Down'
            if current.get('name'):
                interfaces.append(current)
        except Exception:
            pass
    else:
        try:
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=10)
            current = {}
            for line in result.stdout.split('\n'):
                if line and line[0].isdigit():
                    if current.get('name'):
                        interfaces.append(current)
                    parts = line.split(':')
                    name   = parts[1].strip() if len(parts) > 1 else '?'
                    status = 'Up' if 'UP' in line else 'Down'
                    current = {'name': name, 'ip': 'N/A', 'status': status, 'type': 'Interface'}
                elif 'inet ' in line:
                    current['ip'] = line.strip().split()[1].split('/')[0]
            if current.get('name'):
                interfaces.append(current)
        except Exception:
            pass
    if not interfaces:
        interfaces = [
            {'name': 'Ethernet', 'ip': '192.168.1.10', 'status': 'Up',   'type': 'Ethernet'},
            {'name': 'Wi-Fi',    'ip': '192.168.1.11', 'status': 'Up',   'type': 'Wireless'},
            {'name': 'Loopback', 'ip': '127.0.0.1',    'status': 'Up',   'type': 'Loopback'},
        ]
    interfaces = interfaces[:10]
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = 'N/A'
    raw_lines = '\n'.join(
        f"{iface['name']:<20} {iface['ip']:<18} {iface['status']:<8} {iface['type']}"
        for iface in interfaces
    )
    interfaces[0]['hostname'] = hostname
    interfaces[0]['raw'] = raw_lines
    return interfaces


def get_services() -> list:
    if _PACKAGE_LOADED:
        return _get_services_new()
    services = []
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ['sc', 'query', 'type=', 'all', 'state=', 'all'],
                capture_output=True, text=True, timeout=15
            )
            name, state = None, None
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    name = line.split(':', 1)[1].strip()
                elif line.startswith('STATE') and ':' in line:
                    parts = line.split(':', 1)[1].strip().split()
                    state = parts[1] if len(parts) > 1 else parts[0]
                    if name:
                        services.append({'name': name, 'status': state, 'type': 'Win32'})
                        name, state = None, None
                    if len(services) >= 25:
                        break
        except Exception:
            pass
    else:
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--no-pager', '--no-legend', '--all'],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.strip().split('\n')[:25]:
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    services.append({'name': parts[0].replace('.service', ''),
                                     'status': parts[2], 'type': 'systemd'})
        except Exception:
            pass
    if not services:
        services = [
            {'name': 'Windows Update', 'status': 'RUNNING', 'type': 'Win32'},
            {'name': 'Task Scheduler', 'status': 'RUNNING', 'type': 'Win32'},
            {'name': 'DNS Client',     'status': 'RUNNING', 'type': 'Win32'},
            {'name': 'Print Spooler',  'status': 'STOPPED', 'type': 'Win32'},
            {'name': 'Remote Desktop', 'status': 'STOPPED', 'type': 'Win32'},
        ]
    return services


def get_logs() -> list:
    if _PACKAGE_LOADED:
        return _get_logs_new()
    logs = []
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ['wevtutil', 'qe', 'System', '/c:20', '/rd:true', '/f:text'],
                capture_output=True, text=True, timeout=15
            )
            entry = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Date:'):
                    entry['time'] = line[5:].strip()[:19]
                elif line.startswith('Level:'):
                    entry['level'] = line[6:].strip()
                elif line.startswith('Source:'):
                    entry['source'] = line[7:].strip()
                elif line.startswith('Message:'):
                    entry['msg'] = line[8:].strip()[:60]
                    if 'time' in entry:
                        logs.append(entry); entry = {}
        except Exception:
            pass
    else:
        try:
            result = subprocess.run(
                ['journalctl', '-n', '20', '--no-pager', '-o', 'short'],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.strip().split('\n'):
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    level = 'ERROR' if 'error' in line.lower() else ('WARN' if 'warn' in line.lower() else 'INFO')
                    logs.append({'time': f"{parts[0]} {parts[1]}", 'level': level,
                                 'source': parts[3], 'msg': parts[4][:60]})
        except Exception:
            pass
    if not logs:
        logs = [
            {'time': '2026-02-19 12:01', 'level': 'INFO',  'source': 'Kernel',   'msg': 'System boot completed successfully'},
            {'time': '2026-02-19 12:02', 'level': 'INFO',  'source': 'Network',  'msg': 'Ethernet interface connected'},
            {'time': '2026-02-19 12:05', 'level': 'WARN',  'source': 'Disk',     'msg': 'High I/O latency detected on sda'},
            {'time': '2026-02-19 12:10', 'level': 'INFO',  'source': 'Service',  'msg': 'DNS resolver started'},
            {'time': '2026-02-19 12:15', 'level': 'ERROR', 'source': 'Security', 'msg': 'Failed login attempt (user: admin)'},
            {'time': '2026-02-19 12:20', 'level': 'INFO',  'source': 'Update',   'msg': 'No updates available'},
        ]
    return logs



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

if _PACKAGE_LOADED:
    # Loggers already initialized by ntfsecur.core.logging
    from ntfsecur.core.logging import app_log, error_log, log_info, log_debug, log_warn, log_error
else:
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

FACTORY_SETTINGS: dict = {
    # Interfejs
    "theme":              "dark",
    "last_module":        "ntfsecur",
    "window_geometry":    "1280x780",
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
    "version":            "2.1.0",
    "build_date":         "2026-02-21",
    "author":             __author__,
    "product":            __product__,
}

# Alias dla kompatybilnosci wstecznej
_DEFAULT_SETTINGS: dict = FACTORY_SETTINGS


class Settings:
    """Read/write application settings to settings.json.

    Priorytety:
      1. FACTORY_SETTINGS  – built-in default values
      2. settings.json     – saved user preferences  (overrides factory)
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
                # First run – save factory settings
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
    if _PACKAGE_LOADED:
        return _get_settings_new()
    if _settings is None:
        _settings = Settings()
    return _settings

def _no_window_kwargs() -> dict:
    """Return subprocess kwargs that suppress the console window on Windows."""
    if _PACKAGE_LOADED:
        return _no_window_kwargs_new()
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        return {"startupinfo": si, "creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


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
                _pct_line = next((l for l in result.stdout.split('\n') if 'percent' in l.lower()), '')
                percent = int(''.join(c for c in _pct_line if c.isdigit()) or '0')
            elif 'decryption in progress' in out:
                status = 'Decrypting'
                _pct_line = next((l for l in result.stdout.split('\n') if 'percent' in l.lower()), '')
                percent = int(''.join(c for c in _pct_line if c.isdigit()) or '0')
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


def kill_process(pid: str) -> tuple:
    if _PACKAGE_LOADED:
        return _kill_process_new(pid)
    if not pid.isdigit():
        return False, "Invalid PID format"
    if sys.platform == "win32":
        return run_cmd(['taskkill', '/PID', pid, '/F'])
    return run_cmd(['kill', '-9', pid])

def control_service(name: str, action: str) -> tuple:
    if _PACKAGE_LOADED:
        return _control_service_new(name, action)
    valid_actions = ['start', 'stop', 'restart', 'pause', 'continue']
    if action not in valid_actions:
        return False, f"Invalid action. Allowed: {', '.join(valid_actions)}"
    if not name or not all(c.isalnum() or c in '-_.' for c in name):
        return False, "Invalid service name"
    if sys.platform == "win32":
        return run_cmd(['sc', action, name], timeout=20)
    return run_cmd(['sudo', 'systemctl', action, name + '.service'], timeout=20)


# ── Filesystem / Partition format library ─────────────────────────────────────
FS_LIBRARY = [
    # name, type, max_vol, max_file, os_support, features, notes
    ("NTFS",        "Journal",   "256 TB",   "16 TB",   "Windows 2000+, Linux (rw), macOS (ro)",
     "ACL, EFS, Compression, Sparse, Quota, VSS",
     "Default Windows FS. Required for drives >32 GB on Win."),
    ("FAT32",       "Simple",    "8 TB",     "4 GB",    "Windows, Linux, macOS, konsole, aparaty",
     "No access rights, no journaling",
     "4 GB file size limit! Widest compatibility."),
    ("exFAT",       "Simple",    "128 PB",   "16 EB",   "Windows XP+, Linux 5.4+, macOS 10.6.5+",
     "No journaling, large file support",
     "FAT32 successor for flash media. No 4 GB limit."),
    ("ext4",        "Journal",   "1 EB",     "16 TB",   "Linux natywnie, Windows (sterownik), macOS (sterownik)",
     "Journaling, extents, nanosecond timestamps, inline data",
     "Default Linux FS. Most mature ext*."),
    ("ext3",        "Journal",   "32 TB",    "2 TB",    "Linux, partial Windows/macOS",
     "Journaling (3 tryby), backward compat z ext2",
     "Poprzednik ext4. Brak extents."),
    ("ext2",        "Simple",    "32 TB",    "2 TB",    "Linux, Windows (sterownik)",
     "No journaling – faster for flash",
     "Used on small SD/boot cards."),
    ("Btrfs",       "COW",       "16 EB",    "16 EB",   "Linux",
     "Snapshots, RAID wbudowany, kompresja, subvolumes, checksums",
     "Modern Linux FS with COW. Replaces ext4 in Fedora/openSUSE."),
    ("XFS",         "Journal",   "8 EB",     "8 EB",    "Linux, IRIX",
     "64-bit, parallel I/O, delayed allocation, reflinks",
     "Default RHEL/CentOS FS. Excellent for large files."),
    ("ZFS",         "COW",       "256 ZB",   "16 EB",   "Linux (OpenZFS), FreeBSD, macOS (tylko odczyt)",
     "RAID-Z, snapshots, deduplikacja, ARC cache, checksums",
     "Most advanced FS. Requires a lot of RAM."),
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
     "Used on DVD/Blu-ray and portable discs."),
    ("ISO 9660",    "Simple",    "~8 GB",    "2 GB",    "Wszystkie systemy",
     "Read-only, Joliet (Unicode), Rock Ridge (POSIX)",
     "CD-ROM image standard."),
    ("ReFS",        "COW",       "35 PB",    "35 PB",   "Windows Server 2012+, Windows 10 Pro",
     "Integrity streams, block clone, mirror accelerated parity",
     "NTFS successor for servers. No EFS encryption."),
    ("FAT16",       "Simple",    "4 GB",     "2 GB",    "DOS, Windows, embedded",
     "Brak praw, brak journalingu",
     "Starszy FAT. Stosowany w embedded/BIOS EFI."),
    ("FAT12",       "Simple",    "32 MB",    "32 MB",   "DOS, dyskietki, embedded",
     "Minimalny narzut",
     "Used on floppy disks and small flash drives."),
    ("nilfs2",      "Log-struct", "1 EB",    "1 EB",    "Linux",
     "Continuous snapshotting, fast recovery",
     "Log-structured FS with continuous snapshotting."),
    ("JFFS2",       "Log-struct", "N/A",     "N/A",     "Linux (MTD)",
     "Wear leveling, compression, dla raw flash",
     "Stosowany w routerach / embedded bez FTL."),
    ("UBIFS",       "Journal",   "N/A",      "N/A",     "Linux (UBI/MTD)",
     "Journaling, kompresja, wear leveling przez UBI",
     "JFFS2 successor for large NAND flash."),
    ("HAMMER2",     "COW",       "1 EB",     "1 EB",    "DragonFly BSD",
     "Clustered, snapshots, dedup, multi-volume",
     "Natywny FS DragonFly BSD."),
    ("tmpfs",       "RAM",       "RAM limit","RAM limit","Linux, BSD, macOS",
     "In-memory, volatile",
     "Virtual FS in RAM. Does not survive reboots."),
    ("procfs",      "Virtual",   "N/A",      "N/A",     "Linux, BSD",
     "Kernel/process info as files",
     "/proc – kernel interface as a file tree."),
    ("sysfs",       "Virtual",   "N/A",      "N/A",     "Linux",
     "Kernel objects as files",
     "/sys – devices and drivers as files."),
]

# ── USB Mass Memory / Controller DB ──────────────────────────────────────────
USB_MASS_DB = [
    # vendor, chip/controller, max_speed, protocol, features, notes
    ("SanDisk / WD",       "SanDisk SDCZ48 / SN series",   "USB 3.2 Gen1 – 150 MB/s",
     "BOT (Bulk-Only)",   "nCache 2.0, SecureAccess",
     "Najpopularniejsza seria pendrive. SN740 = NVMe M.2."),
    ("Samsung",            "Bar Plus / Fit Plus (ISP)",    "USB 3.1 Gen1 – 300 MB/s",
     "BOT",               "MLC/TLC NAND, compact form",
     "Fit Plus ideal for hubs. Excellent durability."),
    ("Kingston",           "DataTraveler / IronKey",       "USB 3.2 Gen1 – 200 MB/s",
     "BOT / UAP",         "256-bit AES XTS (IronKey), FIPS 140-2",
     "IronKey = certyfikowany szyfrowany USB dla korporacji."),
    ("Corsair",            "Flash Voyager GTX",            "USB 3.1 Gen1 – 440 MB/s",
     "BOT",               "SSD-grade MLC NAND",
     "Najszybsze tradycyjne pendrive Corsair."),
    ("Samsung",            "T7 / T9 (Portable SSD)",       "USB 3.2 Gen2 – 1050 MB/s",
     "UAS (UASP)",        "NVMe internally, AES 256, shock-proof",
     "T9 = do 2000 MB/s. Najszybszy portable SSD Samsung."),
    ("WD",                 "My Passport / Elements",       "USB 3.0 – 130 MB/s",
     "BOT / UAS",         "256-bit AES HW enc. (Passport), SMR HDD",
     "Elements = cheapest WD portable. Passport = HW encryption."),
    ("Seagate",            "Expansion / One Touch",        "USB 3.0 – 120 MB/s",
     "BOT / UAS",         "SMR HDD, automatyczny backup",
     "One Touch has a biometric keyboard in the fingerprint version."),
    ("Transcend",          "JetDrive Go / ESD380C",        "USB 3.2 Gen2 – 2000 MB/s",
     "UAS",               "Type-C, NVMe SSD inside",
     "ESD380C = dual-connector Type-A + Type-C, NVMe."),
    ("Silicon Power",      "Blaze B75 / PC60",             "USB 3.2 Gen2 – 540 MB/s",
     "UAS",               "SATA SSD, aluminium obudowa",
     "PC60 = portable SATA SSD with good price/MB/s ratio."),
    ("Lexar",              "JumpDrive S75 / Professional", "USB 3.0 – 150 MB/s",
     "BOT",               "TLC NAND",
     "S75 popularny w fotografii. Seria Pro do kart CFexpress."),
    ("PNY",                "Pro Elite / Turbo",            "USB 3.2 Gen1 – 200 MB/s",
     "BOT",               "TLC NAND",
     "Budget series with decent performance."),
    ("Verbatim",           "Store 'n' Go / Executive",     "USB 3.2 Gen1 – 100 MB/s",
     "BOT",               "MLC NAND",
     "Classic industrial USB, high durability."),
    ("Crucial",            "X9 / X10 Pro (Portable SSD)", "USB 3.2 Gen2 – 2100 MB/s",
     "UAS (NVMe bridge)", "Type-C, NVMe, AES 256",
     "X10 Pro najszybszy portable SSD Crucial. Rewelacyjna cena."),
    ("ADATA",              "SE920 / SC685",                "USB 3.2 Gen2x2 – 3800 MB/s",
     "UAS (NVMe)",        "Type-C 20Gbps, RGB (SE920)",
     "SE920 = jeden z najszybszych portable SSD na rynku."),
    ("Generic MTK",        "MediaTek MT7601 / Phison U17", "USB 2.0 – 25 MB/s",
     "BOT",               "none, budget TLC/QLC",
     "Cheap no-name USB from Aliexpress. Worst durability."),
    ("Phison",             "PS2251 / PS2307 (controller)", "USB 3.2 Gen1 – 120 MB/s",
     "BOT",               "Powszechny kontroler w mid-range USB",
     "Phison manufactures controllers used by many vendors."),
    ("SMI",                "SM3281 / SM3268 (controller)", "USB 3.1 Gen2 – 500 MB/s",
     "UAS",               "DRAM-less possible",
     "Silicon Motion – controller supplier for Lexar, Kingston."),
    ("ASMedia",            "ASM235CM (bridge NVMe–USB)",   "USB 3.2 Gen2x2 – 20 Gbps",
     "UAS (NVMe)",        "NVMe PCIe 3.0 x2 bridge, najszybszy mostek",
     "Used in M.2 NVMe enclosures and premium portable SSDs."),
    ("Realtek",            "RTS5411 / RTL9210B",           "USB 3.2 Gen2 – 10 Gbps",
     "UAS",               "SATA/NVMe bridge, popularny w obudowach",
     "RTL9210B = most popular SATA/NVMe bridge for M.2 enclosures."),
    ("JMicron",            "JMS583 / JMS586A",             "USB 3.2 Gen2x2 – 20 Gbps",
     "UAS",               "NVMe PCIe bridge, TRIM pass-through",
     "JMS583 szeroko stosowany w obudowach NVMe M.2."),
    ("LaCie",              "Rugged / Mobile SSD Pro",      "USB-C – 1000 MB/s",
     "UAS",               "IP67, shock-resist, NVMe (Pro)",
     "Rugged = resistant to drops, dust, water."),
    ("G-Technology",       "ArmorATD / G-Drive",           "USB 3.2 Gen1 – 140 MB/s",
     "UAS",               "IP54 water+dust, CMR HDD",
     "Used by video creators (Western Digital brand)."),
    ("OWC",                "Envoy Pro FX / Elektron",      "TB3/USB-C – 2800 MB/s",
     "UAS / TB3",         "Thunderbolt 3 + USB-C dual mode, NVMe",
     "Full TB3 and USB 3.2 compatibility. High price, high quality."),
    ("CalDigit",           "Tuff Nano / Tuff Nano Plus",   "USB-C – 1000 MB/s",
     "UAS",               "IP67, SSD, macOS/Win",
     "Tuff Nano Plus = najszybszy w klasie IP67."),
]

# ── Database engines library ──────────────────────────────────────────────────
DB_LIBRARY = [
    # name, type, license, port, os, features, notes
    ("SQLite",        "Relational – embedded", "Public Domain", "—",
     "Wszystkie",
     "ACID, triggers, views, FTS5, JSON1, bez serwera",
     "Default Python database (sqlite3). Ideal for desktop applications."),
    ("PostgreSQL",    "Relational – server",   "PostgreSQL",    "5432",
     "Linux, Win, macOS",
     "MVCC, JSONB, GIS (PostGIS), partycje, replikacja logiczna",
     "Most powerful open-source RDBMS. Full SQL compliance."),
    ("MySQL",         "Relational – server",   "GPL / Commercial","3306",
     "Linux, Win, macOS",
     "InnoDB (ACID), MyISAM, replikacja, partycje, JSON",
     "Widest web usage (LAMP stack)."),
    ("MariaDB",       "Relational – server",   "GPL",           "3306",
     "Linux, Win, macOS",
     "Fork MySQL, Aria engine, Columnstore, temporalne tabele",
     "Drop-in replacement MySQL z lepszym performance."),
    ("Microsoft SQL Server", "Relational",     "Commercial/Express", "1433",
     "Windows, Linux",
     "Always On, In-Memory OLTP, PolyBase, R/Python Integration",
     "Express = free 10 GB limit. Developer = full for dev."),
    ("Oracle DB",     "Relational",            "Commercial",    "1521",
     "Linux, Windows, Solaris",
     "RAC, Exadata, partycje, flashback, Advanced Security",
     "Most expensive and most powerful commercial RDBMS."),
    ("MongoDB",       "Document – NoSQL",     "SSPL",          "27017",
     "Linux, Win, macOS",
     "BSON, Atlas Search, aggregation pipeline, change streams, sharding",
     "Najbardziej popularna baza dokumentowa."),
    ("Redis",         "Key-value – NoSQL","BSD",           "6379",
     "Linux, Win (WSL), macOS",
     "In-memory, pub/sub, streams, Lua scripts, clustering",
     "Baza cache i kolejek. Najszybsza key-value store."),
    ("Cassandra",     "Columnar – NoSQL",    "Apache",        "9042",
     "Linux, macOS",
     "Distributed, tunable consistency, wide rows, materialized views",
     "Facebook-born. Ideal for writing large data volumes."),
    ("Elasticsearch", "Wyszukiwarka / NoSQL", "SSPL / Elastic","9200/9300",
     "Linux, Win, macOS",
     "Full-text search, agregacje, Kibana dashboards, ML",
     "De facto standard wyszukiwania i logowania (ELK stack)."),
    ("InfluxDB",      "Time-series – NoSQL",      "MIT / Commercial","8086",
     "Linux, Win, macOS",
     "Flux language, retention policies, down-sampling, Telegraf",
     "Most popular time-series database."),
    ("TimescaleDB",   "Czasowa (pg extension)","Apache / TSL", "5432",
     "Linux, Win, macOS",
     "Hypertables, compression, continuous aggregates, na bazie PG",
     "InfluxDB performance + full PostgreSQL SQL."),
    ("Neo4j",         "Graph",              "GPL / Commercial","7687",
     "Linux, Win, macOS",
     "Cypher query, APOC plugins, GDS library, native graph engine",
     "Lider baz grafowych. Idealna do sieci relacji."),
    ("CockroachDB",   "Relational – Distributed","BSL",        "26257",
     "Linux, macOS",
     "PostgreSQL-compatible, multi-region, SERIALIZABLE",
     "Distributed SQL with geographic data distribution."),
    ("DuckDB",        "Analytical – embedded","MIT",          "—",
     "Wszystkie",
     "Columnar, OLAP, Apache Arrow, Parquet, WASM",
     "SQLite dla analityki. Rewelacyjna dla Pandas/Polars."),
    ("ClickHouse",    "Columnar – OLAP",     "Apache",        "8123/9000",
     "Linux, macOS",
     "MergeTree, vectorized execution, multi-tiered storage, Real-time",
     "Najszybsza kolumnowa OLAP. Miliardy wierszy w sekundy."),
    ("Firebird",      "Relational – embedded/server","IPL/IDPL","3050",
     "Linux, Win, macOS",
     "Multi-generational architecture, PSQL, triggers",
     "Lekka alternatywa dla SQLite z trybem serwera."),
    ("RocksDB",       "Key-value – embedded","Apache",     "—",
     "Linux, macOS",
     "LSM tree, compaction, column families, merge operator",
     "Facebook. Engine used by Kafka, TiKV, MyRocks."),
    ("LevelDB",       "Key-value – embedded","BSD",        "—",
     "Linux, macOS, Win",
     "LSM tree, ordered keys, bloom filters",
     "Google. Prosta biblioteka C++. Baza RocksDB."),
    ("LMDB",          "Key-value – embedded","OpenLDAP",   "—",
     "Wszystkie",
     "Memory-mapped, ACID, single writer, zero-copy reads",
     "Fastest embedded key-value. Used by OpenLDAP."),
    ("Apache HBase",  "Columnar – NoSQL",    "Apache",        "16000/16010",
     "Linux",
     "Hadoop HDFS storage, Bloom filters, snapshot",
     "Google Bigtable open-source clone. Petabajty danych."),
    ("Couchbase",     "Document – NoSQL",     "BSL / Community","8091",
     "Linux, Win, macOS",
     "N1QL SQL, FTS, Eventing, XDCR replication",
     "MongoDB alternative with built-in cache layer."),
    ("Apache Kafka",  "Stream / Log",       "Apache",        "9092",
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
#  BitLocker helpers
# ─────────────────────────────────────────────────────────────────────────────

def bl_run(args: list, timeout: int = 30):
    """Run a manage-bde / PowerShell command; return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, encoding="cp1250", errors="replace")
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError as e:
        return -1, "", str(e)
    except subprocess.TimeoutExpired:
        return -2, "", "Timeout"
    except Exception as e:
        return -99, "", str(e)


def bl_status(drive: str) -> dict:
    """Return dict with BitLocker status for *drive* (e.g. 'C:')."""
    rc, out, err = bl_run(["manage-bde", "-status", drive])
    info = {
        "drive":        drive,
        "protection":   "Unknown",
        "conversion":   "Unknown",
        "percentage":   "–",
        "method":       "–",
        "lock_status":  "Unknown",
        "key_protectors": [],
        "raw":          out or err,
        "error":        rc != 0,
    }
    if rc != 0:
        # Try PowerShell fallback
        ps = (
            f"Get-BitLockerVolume -MountPoint '{drive}' | "
            "Select-Object -Property MountPoint,ProtectionStatus,"
            "EncryptionMethod,EncryptionPercentage,LockStatus,"
            "KeyProtector | ConvertTo-Json"
        )
        rc2, out2, _ = bl_run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            timeout=20
        )
        if rc2 == 0 and out2.strip():
            try:
                j = json.loads(out2.strip())
                kp = j.get("KeyProtector", []) or []
                info.update({
                    "protection":  str(j.get("ProtectionStatus", "Unknown")),
                    "conversion":  f"{j.get('EncryptionPercentage', 0)}%",
                    "percentage":  f"{j.get('EncryptionPercentage', 0)}%",
                    "method":      str(j.get("EncryptionMethod", "–")),
                    "lock_status": str(j.get("LockStatus", "Unknown")),
                    "key_protectors": [str(k.get("KeyProtectorType", k)) for k in kp],
                    "error": False,
                })
                return info
            except Exception:
                pass
        info["raw"] = err or out or "manage-bde not available"
        return info

    for line in out.splitlines():
        l = line.strip()
        if ":" not in l:
            continue
        key, _, val = l.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if "protection" in key and "status" in key:
            info["protection"] = val
        elif "conversion" in key and "status" in key:
            info["conversion"] = val
        elif "percentage" in key:
            info["percentage"] = val
        elif "encryption method" in key:
            info["method"] = val
        elif "lock status" in key:
            info["lock_status"] = val
        elif "key protector" in key or "protectors" in key:
            info["key_protectors"].append(val)
    return info


def bl_enable(drive: str, recovery_password: bool = True) -> tuple:
    args = ["manage-bde", "-on", drive]
    if recovery_password:
        args += ["-RecoveryPassword"]
    rc, out, err = bl_run(args, timeout=60)
    if rc == 0:
        return True, out.strip() or "Szyfrowanie BitLocker uruchomione."
    return False, err.strip() or out.strip() or "Error enabling BitLocker."


def bl_disable(drive: str) -> tuple:
    rc, out, err = bl_run(["manage-bde", "-off", drive], timeout=60)
    if rc == 0:
        return True, out.strip() or "BitLocker disabled."
    return False, err.strip() or out.strip() or "Error disabling BitLocker."


def bl_lock(drive: str, force: bool = False) -> tuple:
    args = ["manage-bde", "-lock", drive]
    if force:
        args.append("-ForceDismount")
    rc, out, err = bl_run(args, timeout=20)
    if rc == 0:
        return True, out.strip() or "Partycja zablokowana."
    return False, err.strip() or out.strip() or "Error locking drive."


def bl_unlock_password(drive: str, password: str) -> tuple:
    # SECURITY NOTE: manage-bde requires password as CLI arg (Windows limitation).
    # The password is not logged — bl_run logs the command, so we build args separately.
    cmd = ["manage-bde", "-unlock", drive, "-Password", password]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=20, encoding="cp1250", errors="replace",
                           **_no_window_kwargs())
        if r.returncode == 0:
            return True, r.stdout.strip() or "Unlocked with password."
        return False, r.stderr.strip() or r.stdout.strip() or "Error unlocking drive."
    except Exception as e:
        return False, str(e)


def bl_unlock_recovery(drive: str, recovery_key: str) -> tuple:
    rc, out, err = bl_run(
        ["manage-bde", "-unlock", drive, "-RecoveryPassword", recovery_key], timeout=20)
    if rc == 0:
        return True, out.strip() or "Odblokowano kluczem odzysku."
    return False, err.strip() or out.strip() or "Error unlocking drive."


def bl_get_recovery_key(drive: str) -> tuple:
    """Try to get the recovery key / password ID via manage-bde -protectors."""
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-get", drive, "-Type", "RecoveryPassword"],
        timeout=20)
    if rc == 0:
        return True, out.strip()
    # fallback: list all protectors
    rc2, out2, err2 = bl_run(["manage-bde", "-protectors", "-get", drive], timeout=20)
    if rc2 == 0:
        return True, out2.strip()
    return False, err.strip() or err2.strip() or "Brak danych klucza odzysku."


def bl_backup_recovery_to_ad(drive: str) -> tuple:
    ps = (
        f"$vol = Get-BitLockerVolume -MountPoint '{drive}';"
        f"$kp = $vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq 'RecoveryPassword' }};"
        f"if ($kp) {{ Backup-BitLockerKeyProtector -MountPoint '{drive}' "
        f"-KeyProtectorId $kp[0].KeyProtectorId; Write-Output 'OK' }}"
        f" else {{ Write-Output 'NoKey' }}"
    )
    rc, out, err = bl_run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=20)
    if rc == 0 and "OK" in out:
        return True, "Klucz odzysku zarchiwizowany w Active Directory."
    return False, err.strip() or out.strip() or "AD backup error."


def bl_add_password_protector(drive: str, password: str) -> tuple:
    # SECURITY NOTE: password passed as CLI arg (manage-bde limitation) — not logged.
    try:
        r = subprocess.run(
            ["manage-bde", "-protectors", "-add", drive, "-Password", password],
            capture_output=True, text=True, timeout=20,
            encoding="cp1250", errors="replace", **_no_window_kwargs())
        if r.returncode == 0:
            return True, r.stdout.strip() or "Password added as protector."
        return False, r.stderr.strip() or r.stdout.strip() or "Error adding password."
    except Exception as e:
        return False, str(e)


def bl_add_tpm_protector(drive: str) -> tuple:
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-add", drive, "-Tpm"], timeout=20)
    if rc == 0:
        return True, out.strip() or "Protektor TPM dodany."
    return False, err.strip() or out.strip() or "Error adding TPM."


def bl_add_recovery_protector(drive: str) -> tuple:
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-add", drive, "-RecoveryPassword"], timeout=30)
    if rc == 0:
        return True, out.strip() or "Klucz odzysku dodany."
    return False, err.strip() or out.strip() or "Error generating recovery key."


def bl_suspend(drive: str, reboot_count: int = 1) -> tuple:
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-disable", drive,
         "-RebootCount", str(reboot_count)], timeout=20)
    if rc == 0:
        return True, out.strip() or f"Ochrona wstrzymana na {reboot_count} restart(y)."
    return False, err.strip() or out.strip() or "Error suspending protection."


def bl_resume(drive: str) -> tuple:
    rc, out, err = bl_run(
        ["manage-bde", "-protectors", "-enable", drive], timeout=20)
    if rc == 0:
        return True, out.strip() or "Ochrona wznowiona."
    return False, err.strip() or out.strip() or "Error resuming protection."


def bl_change_pin(drive: str, old_pin: str, new_pin: str) -> tuple:
    # SECURITY NOTE: PINs passed as CLI args (manage-bde limitation) — not logged.
    try:
        r = subprocess.run(
            ["manage-bde", "-changepin", drive, "-OldPIN", old_pin, "-NewPIN", new_pin],
            capture_output=True, text=True, timeout=20,
            encoding="cp1250", errors="replace", **_no_window_kwargs())
        if r.returncode == 0:
            return True, r.stdout.strip() or "PIN zmieniony."
        return False, r.stderr.strip() or r.stdout.strip() or "Error changing PIN."
    except Exception as e:
        return False, str(e)


def bl_wipe_free_space(drive: str) -> tuple:
    rc, out, err = bl_run(
        ["manage-bde", "-wipefreespace", drive], timeout=120)
    if rc == 0:
        return True, out.strip() or "Free space wiped."
    return False, err.strip() or out.strip() or "Error wiping free space."


# ─────────────────────────────────────────────────────────────────────────────
#  Glass Scrollbar
# ─────────────────────────────────────────────────────────────────────────────
class GlassScrollbar(tk.Canvas):
    """Minimal pill-shaped glass scrollbar rendered on a Canvas."""

    TRACK  = "#18202E"
    THUMB  = "#3A4E6A"
    HOVER  = "#5A7EA0"
    ACTIVE = "#50E8FF"

    def __init__(self, master, command=None, **kwargs):
        kwargs.setdefault("width", 8)
        kwargs.setdefault("bg", self.TRACK)
        kwargs.setdefault("highlightthickness", 0)
        kwargs.setdefault("bd", 0)
        super().__init__(master, **kwargs)

        self._command    = command
        self._thumb_bbox = None   # (y1, y2)
        self._drag_start = None
        self._drag_top   = 0.0
        self._top        = 0.0
        self._bottom     = 1.0
        self._hovering   = False
        self._dragging   = False

        self.bind("<Configure>",       self._redraw)
        self.bind("<ButtonPress-1>",   self._on_press)
        self.bind("<B1-Motion>",       self._on_drag)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Enter>",           lambda e: self._set_hover(True))
        self.bind("<Leave>",           lambda e: self._set_hover(False))

    # ── Public API ────────────────────────────────────────────────────────────
    def set(self, first, last):
        self._top, self._bottom = float(first), float(last)
        self._redraw()

    def get(self):
        return self._top, self._bottom

    # ── Drawing ───────────────────────────────────────────────────────────────
    def _redraw(self, _=None):
        h = self.winfo_height()
        w = self.winfo_width()
        if h < 4 or w < 4:
            return
        self.delete("all")

        # Track gradient background
        for y in range(h):
            t   = y / max(1, h)
            tt  = 4*t*(1-t)
            r1,g1,b1 = int(0x0E),int(0x16),int(0x24)
            r2,g2,b2 = int(0x1A),int(0x28),int(0x40)
            r = r1 + int((r2-r1)*tt*0.4)
            g = g1 + int((g2-g1)*tt*0.4)
            b = b1 + int((b2-b1)*tt*0.4)
            col = f"#{r:02x}{g:02x}{b:02x}"
            self.create_line(0, y, w, y, fill=col)

        y1 = max(0, int(self._top    * h))
        y2 = min(h, int(self._bottom * h))
        y2 = max(y2, y1 + 22)

        if self._dragging:
            color = self.ACTIVE
        elif self._hovering:
            color = self.HOVER
        else:
            color = self.THUMB

        # Draw pill with 3D gloss
        self._pill(2, y1 + 2, w - 2, y2 - 2, color)
        self._thumb_bbox = (y1, y2)

    @staticmethod
    def _hex_lerp(c1, c2, t):
        c1=c1.lstrip("#"); c2=c2.lstrip("#")
        r1,g1,b1 = int(c1[0:2],16),int(c1[2:4],16),int(c1[4:6],16)
        r2,g2,b2 = int(c2[0:2],16),int(c2[2:4],16),int(c2[4:6],16)
        r=max(0,min(255,int(r1+(r2-r1)*t)))
        g=max(0,min(255,int(g1+(g2-g1)*t)))
        b=max(0,min(255,int(b1+(b2-b1)*t)))
        return f"#{r:02x}{g:02x}{b:02x}"

    def _pill(self, x1, y1, x2, y2, color):
        """Draw a glossy 3D pill / capsule shape."""
        r = max(1, (x2 - x1) // 2)
        r = min(r, (y2 - y1) // 2)
        h_pill = y2 - y1
        # Body fill with vertical gradient (lighter top → darker bottom)
        for y in range(y1, y2):
            t   = (y - y1) / max(1, h_pill)
            # Cylindrical: peak brightness at ~30%
            if t < 0.30:
                tt = t / 0.30
                col = self._hex_lerp(self._hex_lerp("#FFFFFF", color, 0.55), color, tt)
            else:
                tt = (t - 0.30) / 0.70
                col = self._hex_lerp(color, self._hex_lerp(color, "#000000", 0.5), tt*0.6)
            # Clip to pill shape
            if y <= y1+r:
                dy = y1+r - y
                hw = int((r*r - dy*dy)**0.5) if r*r > dy*dy else 0
                self.create_line(x1+r-hw, y, x2-r+hw, y, fill=col)
            elif y >= y2-r:
                dy = y - (y2-r)
                hw = int((r*r - dy*dy)**0.5) if r*r > dy*dy else 0
                self.create_line(x1+r-hw, y, x2-r+hw, y, fill=col)
            else:
                self.create_line(x1, y, x2, y, fill=col)
        # Rim highlight top
        bright = self._hex_lerp(color, "#FFFFFF", 0.45)
        self.create_oval(x1, y1, x1+2*r, y1+2*r, fill=bright, outline="")
        self.create_oval(x2-2*r, y1, x2, y1+2*r, fill=bright, outline="")
        self.create_rectangle(x1+r, y1, x2-r, y1+r, fill=bright, outline="")
        # Bottom shadow
        dark = self._hex_lerp(color, "#000000", 0.4)
        self.create_oval(x1, y2-2*r, x1+2*r, y2, fill=dark, outline="")
        self.create_oval(x2-2*r, y2-2*r, x2, y2, fill=dark, outline="")
        self.create_rectangle(x1+r, y2-r, x2-r, y2, fill=dark, outline="")
        # Left edge specular
        spec = self._hex_lerp(color, "#FFFFFF", 0.3)
        self.create_line(x1, y1+r, x1, y2-r, fill=spec, width=1)

    # ── Events ────────────────────────────────────────────────────────────────
    def _set_hover(self, state: bool):
        self._hovering = state
        self._redraw()

    def _on_press(self, e):
        if self._thumb_bbox and self._thumb_bbox[0] <= e.y <= self._thumb_bbox[1]:
            self._dragging   = True
            self._drag_start = e.y
            self._drag_top   = self._top
        else:
            h = self.winfo_height()
            if h > 0 and self._command:
                self._command("moveto", str(e.y / h))

    def _on_drag(self, e):
        if not self._dragging or self._drag_start is None:
            return
        h = self.winfo_height()
        if h <= 0:
            return
        delta   = (e.y - self._drag_start) / h
        new_top = max(0.0, min(1.0, self._drag_top + delta))
        if self._command:
            self._command("moveto", str(new_top))

    def _on_release(self, _):
        self._dragging = False
        self._redraw()


# ─────────────────────────────────────────────────────────────────────────────
#  GUI Application
# ─────────────────────────────────────────────────────────────────────────────
class SystemManagementPanel(tk.Tk):

    # ── Colour palettes ───────────────────────────────────────────────────────
    DARK_THEME = {
        "BG":        "#0A1220",
        "SURFACE":   "#121E30",
        "SURFACE2":  "#1A2840",
        "BORDER":    "#2C4870",
        "BORDER_LT": "#4C82CC",
        "ACCENT":    "#40E8FF",
        "ACCENT2":   "#1C9CFF",
        "DANGER":    "#FF4F5E",
        "SUCCESS":   "#20FFB0",
        "WARN":      "#FFD870",
        "TEXT":      "#F0F8FF",
        "TEXT2":     "#B8D8F8",
        "MUTED":     "#6898C8",
        "HEADER_BG": "#060C18",
        "CARD_TOP":  "#1C3050",
        "CARD_BOT":  "#101C30",
        "GLOW":      "#083870",
    }

    LIGHT_THEME = {
        "BG":        "#F0F4F8",
        "SURFACE":   "#FFFFFF",
        "SURFACE2":  "#E8EEF6",
        "BORDER":    "#D0D7E3",
        "BORDER_LT": "#A0B0CC",
        "ACCENT":    "#0078D7",
        "ACCENT2":   "#005BB5",
        "DANGER":    "#D32F2F",
        "SUCCESS":   "#2E7D32",
        "WARN":      "#E65100",
        "TEXT":      "#1A1D24",
        "TEXT2":     "#4A5568",
        "MUTED":     "#6B7A99",
        "HEADER_BG": "#1A2A4A",
        "CARD_TOP":  "#E0E8F0",
        "CARD_BOT":  "#D0DCE8",
        "GLOW":      "#CCE4FF",
    }

    CLR_BG        = DARK_THEME["BG"]
    CLR_SURFACE   = "#121E30"
    CLR_SURFACE2  = "#1A2840"
    CLR_BORDER    = "#2C4870"
    CLR_BORDER_LT = "#4C82CC"
    CLR_ACCENT    = "#40E8FF"
    CLR_ACCENT2   = "#1C9CFF"
    CLR_DANGER    = "#FF4F5E"
    CLR_SUCCESS   = "#20FFB0"
    CLR_WARN      = "#FFD870"
    CLR_TEXT      = "#F0F8FF"
    CLR_TEXT2     = "#B8D8F8"
    CLR_MUTED     = "#6898C8"
    CLR_HEADER_BG = "#060C18"
    CLR_CARD_TOP  = "#1C3050"
    CLR_CARD_BOT  = "#101C30"
    CLR_GLOW      = "#083870"

    @property
    def MODULES(self):
        """Return module list with labels translated to the current locale."""
        return [
            ("ntfsecur",   "🔒", "NTFSecur",             "_show_ntfsecur"),
            ("bitlocker",  "🔐", "BitLocker",             "_render_bitlocker"),
            ("drives",     "💾", _t("Dyski"),             "_show_drives"),
            ("autostart",  "🚀", "Autostart",             "_render_autostart"),
            ("processes",  "📊", _t("Procesy"),           "_render_processes"),
            ("network",    "🌐", _t("Sieć"),              "_render_network"),
            ("services",   "🔧", _t("Usługi"),            "_render_services"),
            ("logs",       "📋", _t("Logi"),              "_render_logs"),
            ("usb",        "🔌", "USB",                   "_render_usb"),
            ("databases",  "📁", _t("Bazy danych"),       "_render_databases"),
            ("fslibrary",  "📚", _t("Biblioteka FS"),     "_render_fslibrary"),
            ("usbmass",    "📦", _t("USB Mass DB"),       "_render_usbmass"),
            ("backup",     "💾🛡", _t("Backup"),           "_render_backup"),
        ]

    def __init__(self):
        super().__init__()
        log_info("=" * 60)
        log_info(f"Starting {__product__} v{__version__}")

        self._cfg = get_settings()

        self.title("PolSoft – System Management Panel")
        geom = self._cfg.get("window_geometry", "1280x780")
        self.geometry(geom)
        self.minsize(1100, 680)
        # Topmost state (persistent)
        self._topmost_on = bool(self._cfg.get("window_topmost", False))
        self.attributes("-topmost", self._topmost_on)

        self._is_locked = bool(self._cfg.get("window_locked", False))
        if self._is_locked:
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

        saved_theme = self._cfg.get("theme", "dark")
        self._is_dark = (saved_theme != "light")
        self._load_palette(self.DARK_THEME if self._is_dark else self.LIGHT_THEME)
        self.configure(bg=self.CLR_BG)

        self._logo_img = None

        try:
            _ico = resource_path("ntfsecur", "pic", "icon.ico")
            if os.path.exists(_ico):
                self.iconbitmap(default=_ico)
            else:
                self.iconbitmap(default='')
        except Exception:
            pass

        self.secure_states:    dict = {}
        self.status_labels:    dict = {}
        self.toggle_buttons:   dict = {}
        self._active_module    = "ntfsecur"
        self._sidebar_buttons  = {}

        # Report – options (must exist before _build_menubar)
        self._report_format        = tk.StringVar(value="html")
        self._report_autoopen      = tk.BooleanVar(value=True)
        # ── Extended report options
        self._report_graphics      = tk.BooleanVar(value=True)   # wykresy/donuty
        self._report_logo          = tk.BooleanVar(value=True)   # logo in header
        self._report_timestamp     = tk.BooleanVar(value=True)   # data generowania
        self._report_hostname      = tk.BooleanVar(value=True)   # nazwa komputera
        self._report_toc           = tk.BooleanVar(value=True)   # table of contents
        self._report_dark_theme    = tk.BooleanVar(value=True)   # motyw dark/light
        self._report_page_break    = tk.BooleanVar(value=False)  # page-break css
        self._report_compact       = tk.BooleanVar(value=False)  # compact layout
        self._report_author        = tk.StringVar(value=__author__)
        self._report_company       = tk.StringVar(value="")
        self._report_notes         = tk.StringVar(value="")
        # ── New report options (extended)
        self._report_accent_color  = tk.StringVar(value="#50e8ff")  # kolor akcentu CSS
        self._report_table_limit   = tk.IntVar(value=100)           # max wierszy w tabeli
        self._report_footer_text   = tk.StringVar(value="")         # custom footer
        self._report_default_type  = tk.StringVar(value="full")     # default report type
        self._report_font_size     = tk.StringVar(value="medium")   # rozmiar czcionki
        self._report_show_summary  = tk.BooleanVar(value=True)      # karta podsumowania
        self._report_show_alerts   = tk.BooleanVar(value=True)      # alerty w raporcie
        self._report_show_footer   = tk.BooleanVar(value=True)      # stopka raportu
        self._report_copy_to_clip  = tk.BooleanVar(value=False)     # copy path

        self._apply_dark_scrollbar()
        self._build_ui()
        self._build_watermark()
        self._switch_module("ntfsecur")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        log_info(f"UI ready – theme: {'dark' if self._is_dark else 'light'}")

    def _on_close(self):
        """Clean shutdown — saves settings, closes USB database, destroys window."""
        try:
            self.unbind_all("<MouseWheel>")
        except Exception:
            pass
        try:
            if not self._is_locked:
                # Save full geometry: size + window position
                get_settings().set("window_geometry", self.geometry())
            get_settings().set("window_locked", self._is_locked)
            get_settings().set("window_topmost", self._topmost_on)
            get_settings().save()
            log_info(f"Application closing. Geometry: {self.geometry()}")
        except Exception as e:
            log_error("Error saving settings on exit", e)
        try:
            global _usb_db
            if _usb_db:
                _usb_db.close()
                log_info("USB database closed.")
        except Exception:
            pass
        log_info("Application terminated.")
        self.destroy()

    # ── UI shell ───────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_menubar()
        self._build_header()
        self._build_footer()   # footer BEFORE body so expand=True doesn't swallow it
        self._build_body()

    # ── Menu bar ───────────────────────────────────────────────────────────────
    def _build_menubar(self):
        menubar = tk.Menu(self, bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                          activebackground=self.CLR_ACCENT,
                          activeforeground=self.CLR_HEADER_BG,
                          relief=tk.FLAT, bd=0)

        # ── Plik ──────────────────────────────────────────────────────────────
        menu_file = tk.Menu(menubar, tearoff=0,
                            bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                            activebackground=self.CLR_ACCENT,
                            activeforeground=self.CLR_HEADER_BG)
        menu_file.add_command(label=_t("Odśwież bieżący widok"),
                              accelerator="F5",
                              command=self._menu_refresh)
        menu_file.add_separator()
        menu_file.add_command(label=_t("Eksportuj logi do pliku…"),
                              command=self._menu_export_logs)
        menu_file.add_separator()
        menu_file.add_command(label=_t("Zamknij"),
                              accelerator="Alt+F4",
                              command=self._on_close)
        menubar.add_cascade(label=_t("Plik"), menu=menu_file)

        # ── Modules ────────────────────────────────────────────────────────────
        menu_modules = tk.Menu(menubar, tearoff=0,
                               bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                               activebackground=self.CLR_ACCENT,
                               activeforeground=self.CLR_HEADER_BG)
        for mod_id, icon, label, _ in self.MODULES:
            menu_modules.add_command(
                label=f"{icon}  {label}",
                command=lambda m=mod_id: self._switch_module(m))
        menubar.add_cascade(label=_t("Moduły"), menu=menu_modules)

        # ── NTFSecur ──────────────────────────────────────────────────────────
        menu_ntfs = tk.Menu(menubar, tearoff=0,
                            bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                            activebackground=self.CLR_ACCENT,
                            activeforeground=self.CLR_HEADER_BG)
        menu_ntfs.add_command(label=_t("Skanuj partycje NTFS"),
                              command=self._menu_scan_partitions)
        menu_ntfs.add_separator()
        menu_ntfs.add_command(label=_t("Zablokuj wszystkie partycje (tylko odczyt)"),
                              command=self._menu_lock_all)
        menu_ntfs.add_command(label=_t("Odblokuj wszystkie partycje (pełny dostęp)"),
                              command=self._menu_unlock_all)
        menubar.add_cascade(label="NTFSecur", menu=menu_ntfs)

        # ── Procesy ───────────────────────────────────────────────────────────
        menu_proc = tk.Menu(menubar, tearoff=0,
                            bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                            activebackground=self.CLR_ACCENT,
                            activeforeground=self.CLR_HEADER_BG)
        menu_proc.add_command(label=_t("Pokaż procesy"),
                              command=lambda: self._switch_module("processes"))
        menu_proc.add_command(label=_t("Odśwież listę procesów"),
                              command=self._menu_refresh_processes)
        menu_proc.add_separator()
        menu_proc.add_command(label=_t("Zabij zaznaczony proces"),
                              command=self._menu_kill_process)
        menubar.add_cascade(label=_t("Procesy"), menu=menu_proc)

        # ── Services ───────────────────────────────────────────────────────────
        menu_svc = tk.Menu(menubar, tearoff=0,
                           bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                           activebackground=self.CLR_ACCENT,
                           activeforeground=self.CLR_HEADER_BG)
        menu_svc.add_command(label=_t("Pokaż usługi"),
                             command=lambda: self._switch_module("services"))
        menu_svc.add_command(label=_t("Odśwież listę usług"),
                             command=self._menu_refresh_services)
        menu_svc.add_separator()
        menu_svc.add_command(label=_t("Uruchom zaznaczoną usługę"),
                             command=self._menu_start_service)
        menu_svc.add_command(label=_t("Zatrzymaj zaznaczoną usługę"),
                             command=self._menu_stop_service)
        menubar.add_cascade(label=_t("Usługi"), menu=menu_svc)

        # ── Network ────────────────────────────────────────────────────────────
        menu_net = tk.Menu(menubar, tearoff=0,
                           bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                           activebackground=self.CLR_ACCENT,
                           activeforeground=self.CLR_HEADER_BG)
        menu_net.add_command(label=_t("Pokaż interfejsy sieciowe"),
                             command=lambda: self._switch_module("network"))
        menu_net.add_command(label=_t("Odśwież informacje sieciowe"),
                             command=self._menu_refresh_network)
        menubar.add_cascade(label=_t("Sieć"), menu=menu_net)

        # ── Logi ─────────────────────────────────────────────────────────────
        menu_logs = tk.Menu(menubar, tearoff=0,
                            bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                            activebackground=self.CLR_ACCENT,
                            activeforeground=self.CLR_HEADER_BG)
        menu_logs.add_command(label=_t("Pokaż logi systemowe"),
                              command=lambda: self._switch_module("logs"))
        menu_logs.add_command(label=_t("Odśwież logi"),
                              command=self._menu_refresh_logs)
        menu_logs.add_command(label=_t("Wyczyść widok logów"),
                              command=self._menu_clear_logs)
        menubar.add_cascade(label=_t("Logi"), menu=menu_logs)

        # ── Raporty ──────────────────────────────────────────────────────────
        menu_rep = tk.Menu(menubar, tearoff=0,
                           bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                           activebackground=self.CLR_ACCENT,
                           activeforeground=self.CLR_HEADER_BG)

        # Aggregate report types
        menu_rep.add_command(label=_t("⚡  Szybki – Kluczowe wskaźniki"),
                             accelerator="Ctrl+Shift+1",
                             command=lambda: self._report_full("quick"))
        menu_rep.add_command(label=_t("📊  Normalny – Przegląd systemu"),
                             accelerator="Ctrl+Shift+2",
                             command=lambda: self._report_full("normal"))
        menu_rep.add_command(label=_t("📋  Pełny – Wszystkie sekcje"),
                             accelerator="Ctrl+Shift+3",
                             command=lambda: self._report_full("full"))
        menu_rep.add_command(label=_t("🔬  Szczegółowy – Pełny + tabele"),
                             accelerator="Ctrl+Shift+4",
                             command=lambda: self._report_full("detailed"))
        menu_rep.add_separator()

        # Partial reports (always detailed)
        menu_rep_single = tk.Menu(menu_rep, tearoff=0,
                                  bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                                  activebackground=self.CLR_ACCENT,
                                  activeforeground=self.CLR_HEADER_BG)
        menu_rep_single.add_command(label=_t("🔒  NTFS – Stan partycji"),
                                    command=lambda: self._report_single("ntfs"))
        menu_rep_single.add_command(label=_t("🔐  BitLocker – Szyfrowanie"),
                                    command=lambda: self._report_single("bitlocker"))
        menu_rep_single.add_command(label=_t("⚙️  Procesy – Uruchomione"),
                                    command=lambda: self._report_single("processes"))
        menu_rep_single.add_command(label=_t("🛠  Usługi – Stan usług"),
                                    command=lambda: self._report_single("services"))
        menu_rep_single.add_command(label=_t("🌐  Sieć – Interfejsy"),
                                    command=lambda: self._report_single("network"))
        menu_rep_single.add_command(label=_t("📄  Logi – Zdarzenia"),
                                    command=lambda: self._report_single("logs"))
        menu_rep_single.add_command(label=_t("🔌  USB – Historia urządzeń"),
                                    command=lambda: self._report_single("usb"))
        menu_rep_single.add_command(label=_t("🚀  Autostart – Wpisy startowe"),
                                    command=lambda: self._report_single("autostart"))
        menu_rep_single.add_command(label=_t("💾  Dyski – Diagnostyka"),
                                    command=lambda: self._report_single("drives"))
        menu_rep_single.add_command(label=_t("📁  Bazy danych – Przegląd"),
                                    command=lambda: self._report_single("databases"))
        menu_rep_single.add_command(label=_t("📚  Biblioteka FS – Systemy plików"),
                                    command=lambda: self._report_single("fslibrary"))
        menu_rep.add_cascade(label=_t("📁  Raport częściowy…"),
                             menu=menu_rep_single)
        menu_rep.add_separator()

        # Opcje
        menu_rep.add_command(label=_t("⚙️  Zaawansowany kreator…"),
                             accelerator="Ctrl+Shift+R",
                             command=self._report_wizard)
        menu_rep.add_command(label=_t("🎨  Ustawienia raportu…"),
                             command=self._report_settings_dialog)
        menu_rep.add_separator()
        menu_rep.add_checkbutton(label=_t("Otwórz po wygenerowaniu"),
                                 variable=self._report_autoopen)
        menu_rep.add_checkbutton(label=_t("Generuj z wykresami / grafikami"),
                                 variable=self._report_graphics)
        menu_rep.add_checkbutton(label=_t("Motyw ciemny (Dark)"),
                                 variable=self._report_dark_theme)
        menubar.add_cascade(label=_t("Raporty"), menu=menu_rep)

        # ── Widok ─────────────────────────────────────────────────────────────
        menu_view = tk.Menu(menubar, tearoff=0,
                            bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                            activebackground=self.CLR_ACCENT,
                            activeforeground=self.CLR_HEADER_BG)

        # BooleanVar bound to current states (updated on toggle)
        self._menu_topmost_var   = tk.BooleanVar(value=self._topmost_on)
        self._menu_locksize_var  = tk.BooleanVar(value=self._is_locked)

        def _menu_toggle_topmost():
            # Invoke pin logic and synchronize var
            self._topmost_on = not self._topmost_on
            self.attributes("-topmost", self._topmost_on)
            self._menu_topmost_var.set(self._topmost_on)
            # Refresh pin drawing if canvas exists
            if hasattr(self, '_pin_canvas'):
                _draw_pin_ext(self._topmost_on)
            get_settings().set("window_topmost", self._topmost_on)
            get_settings().save()

        def _draw_pin_ext(active):
            if hasattr(self, "_draw_pin_fn"):
                self._draw_pin_fn(active)
            else:
                c = self._pin_canvas
                c.delete("all")
                col    = self.CLR_ACCENT if active else self.CLR_MUTED
                bg_col = self.CLR_GLOW   if active else self.CLR_HEADER_BG
                c.create_oval(2, 2, 40, 40, fill=bg_col, outline=col, width=1)
                c.create_polygon(21, 8, 30, 18, 21, 23, 12, 18, fill=col, outline=col)
                c.create_line(21, 23, 21, 32, fill=col, width=2, capstyle=tk.ROUND)
                c.create_oval(17, 6, 25, 12, fill=col, outline=col)

        def _menu_toggle_locksize():
            self._toggle_lock_size()
            self._menu_locksize_var.set(self._is_locked)

        menu_view.add_checkbutton(
            label=_t("📌  Zawsze na wierzchu"),
            accelerator="Ctrl+T",
            variable=self._menu_topmost_var,
            command=_menu_toggle_topmost)
        menu_view.add_separator()
        menu_view.add_checkbutton(
            label=_t("🔒  Zablokuj rozmiar okna"),
            accelerator="Ctrl+L",
            variable=self._menu_locksize_var,
            command=_menu_toggle_locksize)
        menu_view.add_command(
            label=_t("↩  Przywróć domyślny rozmiar okna"),
            command=lambda: (self.geometry("1280x780"),
                             get_settings().set("window_geometry", "1280x780"),
                             get_settings().save()))
        menubar.add_cascade(label=_t("Widok"), menu=menu_view)

        # Shortcuts for View
        self.bind("<Control-t>", lambda e: _menu_toggle_topmost())
        self.bind("<Control-l>", lambda e: _menu_toggle_locksize())

        # ── Pomoc ────────────────────────────────────────────────────────────
        menu_help = tk.Menu(menubar, tearoff=0,
                            bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                            activebackground=self.CLR_ACCENT,
                            activeforeground=self.CLR_HEADER_BG)
        menu_help.add_command(label=_t("O programie…"),
                              command=self._menu_about)
        menu_help.add_command(label=_t("📖  Podręcznik użytkownika"),
                              accelerator="F1",
                              command=self._menu_handbook)
        menu_help.add_separator()
        menu_help.add_command(label=_t("Sprawdź uprawnienia administratora"),
                              command=self._menu_check_admin)
        menubar.add_cascade(label=_t("Pomoc"), menu=menu_help)

        self.config(menu=menubar)

        # Keyboard shortcuts – Ctrl+1…9 for each module
        self.bind("<F5>", lambda e: self._menu_refresh())
        self.bind("<F1>", lambda e: self._menu_handbook())
        self.bind("<Control-Shift-R>", lambda e: self._report_wizard())
        self.bind("<Control-Shift-1>", lambda e: self._report_full("quick"))
        self.bind("<Control-Shift-2>", lambda e: self._report_full("normal"))
        self.bind("<Control-Shift-3>", lambda e: self._report_full("full"))
        self.bind("<Control-Shift-4>", lambda e: self._report_full("detailed"))
        for idx, (mod_id, _, _, _) in enumerate(self.MODULES, 1):
            if idx > 9:
                break
            self.bind(f"<Control-{idx}>", lambda e, m=mod_id: self._switch_module(m))

    # ── Menu action handlers ────────────────────────────────────────────────────
    def _menu_refresh(self):
        """Refresh the currently active module."""
        self._switch_module(self._active_module)

    def _menu_export_logs(self):
        """Eksportuj logi do pliku tekstowego."""
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title=_t("Eksportuj logi systemowe"))
        if not path:
            return
        try:
            logs = get_logs()
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"=== PolSoft System Management Panel – Log Export ===\n")
                f.write(f"Export date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for entry in logs:
                    f.write(f"[{entry.get('time','')}] [{entry.get('level','')}] "
                            f"{entry.get('source','')}: {entry.get('msg','')}\n")
            self._set_status(f"✔ Logs exported to: {path}")
            messagebox.showinfo(_t("Eksport logów"), _t("Logi zapisane pomyślnie:\n{path}").format(path=path))
        except Exception as e:
            messagebox.showerror(_t("Błąd eksportu"), str(e))

    def _menu_scan_partitions(self):
        self._switch_module("ntfsecur")

    def _menu_lock_all(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora."))
            return
        if not messagebox.askyesno(_t("NTFSecur – Zablokuj wszystko"),
                                   _t("Czy na pewno chcesz ZABLOKOWAĆ (tylko odczyt)\nwszystkie partycje NTFS?")):
            return
        self._switch_module("ntfsecur")
        partitions = get_ntfs_partitions()
        for p in partitions:
            d = p['drive']
            if d in self.toggle_buttons:
                if not self.secure_states.get(d, tk.BooleanVar(value=False)).get():
                    strip = self.toggle_buttons[d].master.master.winfo_children()[0]
                    self._toggle_secure(d, strip)

    def _menu_unlock_all(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora."))
            return
        if not messagebox.askyesno(_t("NTFSecur – Odblokuj wszystko"),
                                   _t("Czy na pewno chcesz ODBLOKOWAĆ (pełny dostęp)\nwszystkie partycje NTFS?")):
            return
        self._switch_module("ntfsecur")
        partitions = get_ntfs_partitions()
        for p in partitions:
            d = p['drive']
            if d in self.toggle_buttons:
                if self.secure_states.get(d, tk.BooleanVar(value=False)).get():
                    strip = self.toggle_buttons[d].master.master.winfo_children()[0]
                    self._toggle_secure(d, strip)

    def _menu_refresh_processes(self):
        if self._active_module == "processes" and hasattr(self, '_reload_processes'):
            self._reload_processes()
        else:
            self._switch_module("processes")

    def _menu_kill_process(self):
        """Switch to the Processes module where the user can use the KILL button per row."""
        self._switch_module("processes")
        self._set_status("Wybierz proces z listy i kliknij przycisk KILL.")

    def _menu_refresh_services(self):
        if self._active_module == "services" and hasattr(self, '_reload_services'):
            self._reload_services()
        else:
            self._switch_module("services")

    def _menu_start_service(self):
        if self._active_module != "services":
            self._switch_module("services")
            return
        if hasattr(self, '_start_service'):
            self._start_service()

    def _menu_stop_service(self):
        if self._active_module != "services":
            self._switch_module("services")
            return
        if hasattr(self, '_stop_service'):
            self._stop_service()

    def _menu_refresh_network(self):
        if self._active_module == "network" and hasattr(self, '_reload_network'):
            self._reload_network()
        else:
            self._switch_module("network")

    def _menu_refresh_logs(self):
        if self._active_module == "logs" and hasattr(self, '_reload_logs'):
            self._reload_logs()
        else:
            self._switch_module("logs")

    def _menu_clear_logs(self):
        if self._active_module != "logs":
            self._switch_module("logs")
            return
        if hasattr(self, '_clear_logs_view'):
            self._clear_logs_view()

    # ═══════════════════════════════════════════════════════════════════════════
    #  REPORT SYSTEM
    # ═══════════════════════════════════════════════════════════════════════════

    # ── Publiczne handlery menu ───────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════
    #  REPORT ENGINE – 4 types: Quick / Normal / Full / Detailed
    # ═══════════════════════════════════════════════════════════════════════════

    # Type definitions
    REPORT_TYPES = {
        "quick": {
            "label":    "⚡ Quick",
            "desc":     "Key indicators and alerts – numbers and % only",
            "sections": ["ntfs", "bitlocker", "services", "logs"],
            "depth":    "summary",
        },
        "normal": {
            "label":    "📊 Normal",
            "desc":     "System overview with charts and statistics",
            "sections": ["ntfs", "bitlocker", "processes", "services", "network", "logs"],
            "depth":    "charts",
        },
        "full": {
            "label":    "📋 Full",
            "desc":     "Wszystkie sekcje z wykresami i podsumowaniami",
            "sections": ["ntfs", "bitlocker", "processes", "services",
                         "network", "logs", "usb", "autostart",
                         "drives", "databases", "fslibrary"],
            "depth":    "charts",
        },
        "detailed": {
            "label":    "🔬 Detailed",
            "desc":     "Full report + complete data tables",
            "sections": ["ntfs", "bitlocker", "processes", "services",
                         "network", "logs", "usb", "autostart",
                         "drives", "databases", "fslibrary"],
            "depth":    "full",
        },
    }

    # ── Handlery menu ─────────────────────────────────────────────────────────
    def _report_full(self, rtype: str = "full"):
        self._report_generate(rtype=rtype, sections=self.REPORT_TYPES[rtype]["sections"])

    def _report_single(self, section: str):
        self._report_generate(rtype="detailed", sections=[section])

    def _report_wizard(self):
        self._report_show_dialog()

    # ── Zaawansowany kreator ──────────────────────────────────────────────────
    def _report_show_dialog(self):
        win = tk.Toplevel(self)
        win.title("System Report Wizard")
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)
        win.grab_set()
        win.update_idletasks()
        W, H = 560, 620
        x = self.winfo_x() + (self.winfo_width()  - W) // 2
        y = self.winfo_y() + (self.winfo_height() - H) // 2
        win.geometry(f"{W}x{H}+{x}+{y}")

        tk.Frame(win, bg=self.CLR_ACCENT, height=3).pack(fill=tk.X)
        hdr = tk.Frame(win, bg=self.CLR_HEADER_BG)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="📋  System Report Wizard",
                 font=("Segoe UI", 12, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_HEADER_BG).pack(anchor=tk.W, padx=16, pady=12)

        body = tk.Frame(win, bg=self.CLR_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=10)

        # ── Typ raportu
        tk.Label(body, text=_t("Typ raportu:"),
                 font=("Segoe UI", 10, "bold"), fg=self.CLR_TEXT, bg=self.CLR_BG
                 ).pack(anchor=tk.W, pady=(0, 6))

        rtype_var = tk.StringVar(value="full")
        type_frame = tk.Frame(body, bg=self.CLR_SURFACE)
        type_frame.pack(fill=tk.X, pady=(0, 12))

        TYPE_INFO = [
            ("quick",    "⚡ Quick",       "Key indicators, alerts, numbers and % only",           self.CLR_WARN),
            ("normal",   "📊 Normal",      "Overview with charts and statistics",                  self.CLR_ACCENT2),
            ("full",     "📋 Full",        "All sections with charts and summaries",               self.CLR_ACCENT),
            ("detailed", "🔬 Detailed",    "Full report + complete raw data tables",               self.CLR_SUCCESS),
        ]
        for val, label, desc, color in TYPE_INFO:
            row = tk.Frame(type_frame, bg=self.CLR_SURFACE)
            row.pack(fill=tk.X, padx=8, pady=3)
            rb = tk.Radiobutton(row, text=label, variable=rtype_var, value=val,
                                font=("Segoe UI", 10, "bold"),
                                fg=color, bg=self.CLR_SURFACE,
                                selectcolor=self.CLR_BG,
                                activebackground=self.CLR_SURFACE,
                                activeforeground=color)
            rb.pack(side=tk.LEFT)
            tk.Label(row, text=f"  –  {desc}",
                     font=("Segoe UI", 9), fg=self.CLR_MUTED,
                     bg=self.CLR_SURFACE).pack(side=tk.LEFT, pady=2)

        tk.Frame(body, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, pady=6)

        # ── Sekcje
        SECTIONS = [
            ("ntfs",      "🔒  NTFS – Partition Status"),
            ("bitlocker", "🔐  BitLocker – Encryption"),
            ("processes", "⚙️  Processes – Running"),
            ("services",  "🛠  Services – Service Status"),
            ("network",   "🌐  Network – Interfaces and Connections"),
            ("logs",      "📄  Logs – System Events"),
            ("usb",       "🔌  USB – Device History"),
            ("autostart", "🚀  Autostart – Startup Entries"),
            ("drives",    "💾  Drives – Disk Diagnostics"),
            ("databases", "📁  Databases – Engines"),
            ("fslibrary", "📚  FS Library – File Systems"),
        ]

        tk.Label(body, text=_t("Sekcje (opcjonalne nadpisanie):"),
                 font=("Segoe UI", 10, "bold"), fg=self.CLR_TEXT, bg=self.CLR_BG
                 ).pack(anchor=tk.W, pady=(0, 4))

        checks_frame = tk.Frame(body, bg=self.CLR_SURFACE)
        checks_frame.pack(fill=tk.X, pady=(0, 6))

        section_vars = {}
        for sid, slabel in SECTIONS:
            var = tk.BooleanVar(value=True)
            section_vars[sid] = var
            row = tk.Frame(checks_frame, bg=self.CLR_SURFACE)
            row.pack(fill=tk.X, padx=8, pady=1)
            tk.Checkbutton(row, text=slabel, variable=var,
                           font=("Segoe UI", 9), fg=self.CLR_TEXT,
                           bg=self.CLR_SURFACE, selectcolor=self.CLR_BG,
                           activebackground=self.CLR_SURFACE).pack(anchor=tk.W)

        def _sync_type(*_):
            default = self.REPORT_TYPES.get(rtype_var.get(), {}).get("sections", [])
            for sid, var in section_vars.items():
                var.set(sid in default)
        rtype_var.trace_add("write", _sync_type)
        _sync_type()

        sel_row = tk.Frame(body, bg=self.CLR_BG)
        sel_row.pack(fill=tk.X, pady=(2, 8))
        def _all(v):
            for var in section_vars.values(): var.set(v)
        tk.Button(sel_row, text=_t("Zaznacz wszystkie"),
                  font=("Segoe UI", 9), fg=self.CLR_ACCENT, bg=self.CLR_SURFACE,
                  relief=tk.FLAT, bd=0, cursor="hand2", padx=8, pady=2,
                  command=lambda: _all(True)).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(sel_row, text=_t("Odznacz wszystkie"),
                  font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                  relief=tk.FLAT, bd=0, cursor="hand2", padx=8, pady=2,
                  command=lambda: _all(False)).pack(side=tk.LEFT)

        tk.Frame(body, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, pady=6)

        # ── Open after generation
        tk.Checkbutton(body, text="Open Report in Browser After Generation",
                       variable=self._report_autoopen,
                       font=("Segoe UI", 10), fg=self.CLR_TEXT, bg=self.CLR_BG,
                       selectcolor=self.CLR_SURFACE,
                       activebackground=self.CLR_BG).pack(anchor=tk.W, pady=(0, 8))

        # ── Progress bar
        prog_var = tk.StringVar(value="")
        tk.Label(body, textvariable=prog_var,
                 font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_BG,
                 anchor=tk.W).pack(fill=tk.X)
        prog_canvas = tk.Canvas(body, bg=self.CLR_SURFACE, height=6,
                                highlightthickness=0, bd=0)
        prog_canvas.pack(fill=tk.X, pady=(2, 8))
        prog_bar_ref = [None]

        def _update_progress(done, total, label=""):
            frac = done / max(total, 1)
            prog_var.set(f"{'✔' if done == total else '⏳'}  {label}")
            prog_canvas.update_idletasks()
            W2 = prog_canvas.winfo_width()
            if prog_bar_ref[0]:
                prog_canvas.delete(prog_bar_ref[0])
            prog_bar_ref[0] = prog_canvas.create_rectangle(
                0, 0, int(W2 * frac), 6,
                fill=self.CLR_ACCENT if done < total else self.CLR_SUCCESS,
                outline="")

        tk.Frame(body, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, pady=(0, 8))
        btn_row = tk.Frame(body, bg=self.CLR_BG)
        btn_row.pack(fill=tk.X)

        gen_btn = tk.Button(btn_row, text="📋  Generate Report",
                            font=("Segoe UI", 10, "bold"),
                            fg=self.CLR_HEADER_BG, bg=self.CLR_ACCENT,
                            relief=tk.FLAT, padx=16, pady=6, cursor="hand2")
        gen_btn.pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(btn_row, text="Anuluj",
                  font=("Segoe UI", 10), fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                  relief=tk.FLAT, padx=12, pady=6, cursor="hand2",
                  command=win.destroy).pack(side=tk.LEFT)

        def _generate():
            selected = [sid for sid, var in section_vars.items() if var.get()]
            if not selected:
                messagebox.showwarning(_t("Brak sekcji"), _t("Wybierz co najmniej jedną sekcję."), parent=win)
                return
            gen_btn.config(state=tk.DISABLED, text="⏳  Generowanie…")
            prog_var.set("Inicjalizacja…")
            rtype = rtype_var.get()

            def _worker():
                try:
                    path = self._report_collect_and_save(rtype, selected, _update_progress)
                    def _done():
                        prog_var.set(f"✔  Zapisano: {path}")
                        gen_btn.config(state=tk.NORMAL, text="📋  Generuj raport")
                        if self._report_autoopen.get():
                            import webbrowser, os
                            webbrowser.open(f"file:///{os.path.abspath(path)}")
                        messagebox.showinfo(_t("Raport gotowy"),
                                            f"Raport wygenerowany:\n\n{path}", parent=win)
                    self.after(0, _done)
                except Exception as e:
                    def _err():
                        prog_var.set(_t("✘  Błąd: {e}").format(e=e))
                        gen_btn.config(state=tk.NORMAL, text="📋  Generuj raport")
                        messagebox.showerror(_t("Błąd"), str(e), parent=win)
                    self.after(0, _err)

            threading.Thread(target=_worker, daemon=True).start()

        gen_btn.config(command=_generate)

    # ── Main data collection and save function ──────────────────────────────────
    def _report_generate(self, rtype: str, sections: list):
        """Quick generation without wizard – save dialog, then generate."""
        def _worker():
            try:
                path = self._report_collect_and_save(rtype, sections,
                    lambda d, t, l: self._set_status(f"Raport [{d}/{t}]: {l}"))
                def _done():
                    if self._report_autoopen.get():
                        import webbrowser, os
                        webbrowser.open(f"file:///{os.path.abspath(path)}")
                    messagebox.showinfo(_t("Raport gotowy"), f"Zapisano:\n{path}")
                self.after(0, _done)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror(_t("Błąd raportu"), str(e)))
        threading.Thread(target=_worker, daemon=True).start()

    def _report_collect_and_save(self, rtype: str, sections: list, progress_cb) -> str:
        from tkinter import filedialog
        import os
        rinfo = self.REPORT_TYPES.get(rtype, self.REPORT_TYPES["full"])
        depth = rinfo["depth"]
        ts    = time.strftime("%Y%m%d_%H%M%S")
        default_name = f"NTFSecur_{rtype.capitalize()}_{ts}.html"

        path_holder  = [None]
        done_event   = threading.Event()

        def _ask():
            path_holder[0] = filedialog.asksaveasfilename(
                defaultextension=".html",
                initialfile=default_name,
                filetypes=[("HTML", "*.html"), ("All files", "*.*")],
                title=f"Save Report – {rinfo['label']}")
            done_event.set()

        self.after(0, _ask)
        done_event.wait(timeout=120)
        path = path_holder[0]
        if not path:
            raise RuntimeError("Anulowano.")

        total = len(sections)
        data  = {}
        for i, sid in enumerate(sections):
            progress_cb(i, total, f"Zbieranie: {sid}…")
            data[sid] = self._report_gather(sid)

        progress_cb(total, total, "Renderowanie HTML…")
        content = self._report_render_html(rtype, depth, data, sections)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self._set_status(f"✔ Raport zapisany: {os.path.basename(path)}")
        return path

    # ── Zbieranie danych ──────────────────────────────────────────────────────
    def _report_gather(self, section: str) -> dict:
        try:
            if section == "ntfs":
                parts = get_ntfs_partitions()
                states = {p['drive']: self.secure_states.get(p['drive'],
                          tk.BooleanVar(value=False)).get() for p in parts}
                locked = sum(1 for v in states.values() if v)
                return {"partitions": parts, "states": states,
                        "locked": locked, "total": len(parts)}
            elif section == "bitlocker":
                parts = get_ntfs_partitions()
                bl = []
                for p in parts:
                    st = get_bitlocker_status(p['drive'])
                    bl.append({"drive": p['drive'], "label": p['label'],
                               "size": p['size'], "status": st})
                enc = sum(1 for x in bl if x['status'].get('protection') == 'ON')
                return {"items": bl, "encrypted": enc, "total": len(bl)}
            elif section == "processes":
                procs = get_processes()
                running = sum(1 for p in procs if p.get('status','') in ('Running','S','R'))
                return {"items": procs, "count": len(procs), "running": running}
            elif section == "services":
                svcs = get_services()
                running = sum(1 for s in svcs if s.get('status','').lower() in ('running','active','+'))
                stopped = len(svcs) - running
                return {"items": svcs, "count": len(svcs), "running": running, "stopped": stopped}
            elif section == "network":
                info = get_network_info()
                if isinstance(info, list): info = info[0] if info else {}
                return {"info": info}
            elif section == "logs":
                logs = get_logs()
                errors = sum(1 for l in logs if l.get('level') == 'ERROR')
                warns  = sum(1 for l in logs if l.get('level') == 'WARN')
                infos  = sum(1 for l in logs if l.get('level') == 'INFO')
                return {"items": logs, "count": len(logs),
                        "errors": errors, "warns": warns, "infos": infos}
            elif section == "usb":
                db = get_usb_db()
                devices = db.get_all_devices("", "last_seen DESC") or []
                return {"items": devices, "count": len(devices)}
            elif section == "autostart":
                entries = self._ast_get_startup_entries()
                by_type = {}
                for e in entries:
                    t = e.get('type', 'Inne')
                    by_type[t] = by_type.get(t, 0) + 1
                return {"items": entries, "count": len(entries), "by_type": by_type}
            elif section == "drives":
                drives = self._drv_get_drives() if hasattr(self, '_drv_get_drives') else []
                return {"items": drives, "count": len(drives)}
            elif section == "databases":
                return {"items": list(DB_LIBRARY), "count": len(DB_LIBRARY)}
            elif section == "fslibrary":
                return {"items": list(FS_LIBRARY), "count": len(FS_LIBRARY)}
        except Exception as ex:
            return {"error": str(ex)}
        return {}

    # ── HTML renderer ─────────────────────────────────────────────────────────
    def _report_render_html(self, rtype: str, depth: str, data: dict, sections: list) -> str:
        ts    = time.strftime("%Y-%m-%d %H:%M:%S")
        rinfo = self.REPORT_TYPES.get(rtype, self.REPORT_TYPES["full"])

        # ── fetch dialog settings (with defaults) ──────────────────────────────
        def _bv(attr, default=True):
            v = getattr(self, attr, None)
            return v.get() if v is not None else default
        def _sv(attr, default=""):
            v = getattr(self, attr, None)
            return v.get() if v is not None else default

        dark       = _bv("_report_dark_theme",  True)
        graphics   = _bv("_report_graphics",    True)
        show_toc   = _bv("_report_toc",         True)
        show_ts    = _bv("_report_timestamp",   True)
        show_host  = _bv("_report_hostname",    True)
        show_logo  = _bv("_report_logo",        True)
        compact    = _bv("_report_compact",     False)
        page_break = _bv("_report_page_break",  False)
        author     = _sv("_report_author",      __author__)
        company    = _sv("_report_company",     "")
        notes      = _sv("_report_notes",       "")
        classif_v  = getattr(self, "_report_classif_var", None)
        classif    = classif_v.get() if classif_v else "Internal"

        # if charts disabled → summary mode (no SVG/CSS donuts)
        eff_depth = "summary" if not graphics else depth

        SECTION_META = {
            "ntfs":      ("\U0001f512", "NTFS \u2013 Partition Status"),
            "bitlocker": ("\U0001f510", "BitLocker \u2013 Encryption"),
            "processes": ("\u2699\ufe0f",  "Processes"),
            "services":  ("\U0001f527",  "System Services"),
            "network":   ("\U0001f310", "Network"),
            "logs":      ("\U0001f4c4", "System Logs"),
            "usb":       ("\U0001f50c", "USB \u2013 History"),
            "autostart": ("\U0001f680", "Autostart"),
            "drives":    ("\U0001f4be", "Drives \u2013 Diagnostics"),
            "databases": ("\U0001f4c1", "Databases"),
            "fslibrary": ("\U0001f4da", "FS Library \u2013 File Systems"),
        }

        # ── CSS theme colour variables ─────────────────────────────────────────
        if dark:
            css_v = (":root{--bg:#181e2a;--sf:#222d40;--sf2:#2a364d;--ac:#50e8ff;"
                     "--ac2:#2e9ef0;--tx:#f4f8ff;--mu:#8aaace;--bd:#3a4e6a;"
                     "--er:#ff6875;--ok:#3dffa8;--wn:#ffd166;--hd:#0e1622;}")
        else:
            css_v = (":root{--bg:#f4f7fb;--sf:#ffffff;--sf2:#e8eef5;--ac:#0078d7;"
                     "--ac2:#005a9e;--tx:#1a1d24;--mu:#5a6a80;--bd:#c8d4e0;"
                     "--er:#c0392b;--ok:#27ae60;--wn:#d68910;--hd:#1a2a4a;}")

        sp  = "20px" if compact else "40px"
        pad = "14px 20px" if compact else "28px 36px"
        pbk = ".section{page-break-before:always;}" if page_break else ""

        CSS = (css_v +
               "*{box-sizing:border-box;margin:0;padding:0;}"
               "body{font-family:\"Segoe UI\",Arial,sans-serif;background:var(--bg);color:var(--tx);display:flex;min-height:100vh;}"
               "#sidebar{width:220px;min-height:100vh;background:var(--hd);padding:20px 0;position:sticky;top:0;height:100vh;overflow-y:auto;border-right:1px solid var(--bd);flex-shrink:0;}"
               ".sidebar-logo{padding:0 16px 14px;font-size:12px;font-weight:700;color:var(--ac);letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid var(--bd);}"
               ".nav-link{display:block;padding:9px 16px;color:var(--mu);text-decoration:none;font-size:12px;border-left:3px solid transparent;transition:all .12s;}"
               ".nav-link:hover{color:var(--ac);background:var(--sf2);border-left-color:var(--ac);}"
               ".sidebar-meta{padding:16px;font-size:11px;color:var(--bd);border-top:1px solid var(--bd);margin-top:16px;line-height:1.7;}"
               f"#main{{flex:1;padding:{pad};max-width:1100px;}}"
               ".rpt-header{margin-bottom:24px;overflow:hidden;}"
               ".rpt-header h1{font-size:20px;color:var(--ac);font-weight:700;}"
               ".rpt-header .meta{color:var(--mu);font-size:12px;margin-top:6px;line-height:2;}"
               ".rpt-badge{display:inline-block;padding:3px 12px;border-radius:20px;font-size:11px;font-weight:700;margin-left:10px;vertical-align:middle;}"
               ".classif-badge{float:right;padding:4px 14px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:1px;}"
               f".section{{margin-bottom:{sp};scroll-margin-top:20px;}}"
               ".section h2{font-size:15px;color:var(--ac2);border-bottom:1px solid var(--bd);padding-bottom:8px;margin-bottom:16px;}"
               ".toc{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px 20px;margin-bottom:28px;}"
               ".toc h3{font-size:12px;color:var(--mu);font-weight:700;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;}"
               ".toc-links{display:flex;flex-wrap:wrap;gap:8px;}"
               ".toc a{color:var(--ac2);font-size:12px;text-decoration:none;padding:3px 10px;background:var(--sf2);border-radius:20px;border:1px solid var(--bd);}"
               ".toc a:hover{color:var(--ac);border-color:var(--ac);}"
               ".summary-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:32px;}"
               ".kpi-grid{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;}"
               ".kpi{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px 18px;min-width:110px;flex:1;}"
               ".kpi .kv{font-size:26px;font-weight:700;line-height:1;}"
               ".kpi .kl{font-size:11px;color:var(--mu);margin-top:4px;}"
               ".pbar-wrap{margin:10px 0 4px;}"
               ".pbar-label{display:flex;justify-content:space-between;font-size:12px;color:var(--mu);margin-bottom:4px;}"
               ".pbar-track{background:var(--sf2);border-radius:20px;height:16px;overflow:hidden;position:relative;}"
               ".pbar-fill{height:100%;border-radius:20px;transition:width .4s;display:flex;align-items:center;justify-content:flex-end;padding-right:6px;font-size:10px;font-weight:700;color:#000;}"
               ".chart-row{display:flex;gap:24px;flex-wrap:wrap;margin-bottom:16px;align-items:center;}"
               ".donut-wrap{position:relative;width:120px;height:120px;flex-shrink:0;}"
               ".donut-wrap svg{width:100%;height:100%;}"
               ".donut-center{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;line-height:1.2;}"
               ".donut-pct{font-size:20px;font-weight:700;}"
               ".donut-sub{font-size:10px;color:var(--mu);}"
               ".legend{display:flex;flex-direction:column;gap:6px;}"
               ".leg-item{display:flex;align-items:center;gap:8px;font-size:12px;}"
               ".leg-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}"
               ".hbar-chart{width:100%;margin-bottom:12px;}"
               ".hbar-row{display:grid;grid-template-columns:140px 1fr 60px;align-items:center;gap:8px;margin-bottom:6px;}"
               ".hbar-name{font-size:12px;color:var(--mu);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}"
               ".hbar-track{background:var(--sf2);border-radius:10px;height:14px;overflow:hidden;}"
               ".hbar-fill{height:100%;border-radius:10px;}"
               ".hbar-val{font-size:11px;color:var(--mu);}"
               "table{width:100%;border-collapse:collapse;font-size:12px;margin-top:12px;}"
               "th{background:var(--sf2);color:var(--mu);text-align:left;padding:7px 10px;border-bottom:1px solid var(--bd);font-weight:600;font-size:11px;}"
               "td{padding:6px 10px;border-bottom:1px solid var(--sf2);vertical-align:top;}"
               "tr:nth-child(even) td{background:var(--sf);}"
               "tr:hover td{background:var(--sf2);}"
               ".badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;}"
               ".b-ok{background:rgba(61,255,168,.15);color:var(--ok);}"
               ".b-er{background:rgba(255,104,117,.15);color:var(--er);}"
               ".b-wn{background:rgba(255,209,102,.15);color:var(--wn);}"
               ".b-ac{background:rgba(80,232,255,.15);color:var(--ac);}"
               ".alert{padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:12px;}"
               ".alert-danger{background:rgba(255,104,117,.1);border:1px solid var(--er);color:var(--er);}"
               ".alert-warn{background:rgba(255,209,102,.1);border:1px solid var(--wn);color:var(--wn);}"
               ".alert-ok{background:rgba(61,255,168,.1);border:1px solid var(--ok);color:var(--ok);}"
               ".empty{color:var(--mu);font-style:italic;padding:10px 0;font-size:13px;}"
               ".rpt-footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--bd);font-size:11px;color:var(--mu);line-height:2;}"
               "@media(max-width:768px){body{flex-direction:column;}#sidebar{width:100%;height:auto;min-height:unset;position:relative;}}"
               "@media print{#sidebar{display:none;}#main{padding:12px;max-width:100%;}}"
               + pbk)

        # ── klasyfikacja ─────────────────────────────────────────────────────
        CLASSIF_CLR = {
            "Public":       ("#27ae60", "#d5f5e3"),
            "Internal":     ("#2e9ef0", "#d6eaf8"),
            "Confidential": ("#e67e22", "#fdebd0"),
            "Restricted":   ("#c0392b", "#fadbd8"),
        }
        cc, cb = CLASSIF_CLR.get(classif, ("#8aaace", "#2a364d"))
        classif_badge = (f'<span class="classif-badge" style="background:{cb};color:{cc};border:1px solid {cc}44">'
                         f'\U0001f512 {classif}</span>')

        # ── buduj sekcje ─────────────────────────────────────────────────────
        nav_html  = ""
        toc_links = ""
        body_html = ""
        for sid in sections:
            icon, title = SECTION_META.get(sid, ("\U0001f4cb", sid))
            nav_html  += f'<a href="#{sid}" class="nav-link">{icon} {title}</a>\n'
            toc_links += f'<a href="#{sid}">{icon} {title}</a>\n'
            d = data.get(sid, {})
            body_html += f'<section id="{sid}" class="section">\n'
            body_html += f'<h2>{icon} {title}</h2>\n'
            if "error" in d:
                body_html += f'<div class="alert alert-danger">\u26a0 B\u0142\u0105d: {d["error"]}</div>\n'
            else:
                body_html += self._rpt_section(sid, d, eff_depth)
            body_html += '</section>\n'

        # ── TOC ──────────────────────────────────────────────────────────────
        toc_block = ""
        if show_toc and len(sections) > 1:
            toc_block = (f'<div class="toc"><h3>\U0001f4cb Spis tre\u015bci</h3>'
                         f'<div class="toc-links">{toc_links}</div></div>')

        summary_html = self._rpt_summary_bar(data, sections) if len(sections) > 1 else ""

        TYPE_BADGE_COLOR = {
            "quick":    "#ffd166",
            "normal":   "#2e9ef0",
            "full":     "#50e8ff",
            "detailed": "#3dffa8",
        }
        badge_col = TYPE_BADGE_COLOR.get(rtype, "#50e8ff")

        # ── header meta ─────────────────────────────────────────────────────────
        meta_parts = []
        if show_host:
            meta_parts.append(f'Komputer: <strong>{platform.node()}</strong>')
        meta_parts.append(f'System: <strong>{platform.system()} {platform.release()} ({platform.machine()})</strong>')
        if show_ts:
            meta_parts.append(f'Data: <strong>{ts}</strong>')
        if author:
            meta_parts.append(f'Autor: <strong>{author}</strong>')
        if company:
            meta_parts.append(f'Firma: <strong>{company}</strong>')
        meta_html = ' &nbsp;\u00b7&nbsp; '.join(meta_parts)

        logo_html = ('<div style="float:right;font-size:28px;color:var(--ac);opacity:.55;margin-top:-4px">'
                     '\u2B21</div>' if show_logo else "")

        graphics_note = ('<div style="font-size:10px;color:var(--mu);margin-top:6px">'
                         '\u26a0 Wykresy wy\u0142\u0105czone \u2013 tryb tekstowy</div>'
                         if not graphics else "")

        # ── stopka ───────────────────────────────────────────────────────────
        footer_parts = [f'{__product__} v{__version__}', f'Wygenerowano: {ts}']
        if notes:
            footer_parts.append(f'Notatki: {notes}')
        footer_html = ('<div class="rpt-footer">'
                       + ' &nbsp;&nbsp;|&nbsp;&nbsp; '.join(footer_parts)
                       + '</div>')

        # ── sidebar meta ──────────────────────────────────────────────────────
        sb = [f'Typ: <strong style="color:var(--ac)">{rinfo["label"]}</strong>', rinfo["desc"]]
        if show_ts:
            sb.append(f'Wygenerowano:<br><strong>{ts}</strong>')
        if show_host:
            sb.append(platform.node())
        sb += [f'{platform.system()} {platform.release()}',
               f'{__product__}<br>v{__version__}']
        sidebar_meta = "<br>".join(sb)

        # ── assemble HTML ───────────────────────────────────────────────────────
        label_esc = rinfo['label'].replace('"', '&quot;')
        return (f'<!DOCTYPE html>\n<html lang="pl">\n<head>\n'
                f'<meta charset="UTF-8">\n'
                f'<meta name="viewport" content="width=device-width,initial-scale=1.0">\n'
                f'<title>NTFSecur \u2013 Raport {label_esc} \u2013 {ts}</title>\n'
                f'<style>{CSS}</style>\n</head>\n<body>\n'
                f'<nav id="sidebar">\n'
                f'  <div class="sidebar-logo">\U0001f4cb Raporty</div>\n'
                f'  {nav_html}'
                f'  <div class="sidebar-meta">{sidebar_meta}</div>\n'
                f'</nav>\n<main id="main">\n'
                f'  <div class="rpt-header">\n'
                f'    {logo_html}{classif_badge}\n'
                f'    <h1>\U0001f4cb Raport systemowy\n'
                f'      <span class="rpt-badge" style="background:{badge_col}22;color:{badge_col};border:1px solid {badge_col}44">\n'
                f'        {rinfo["label"]}\n'
                f'      </span>\n'
                f'    </h1>\n'
                f'    <div class="meta">{meta_html}</div>{graphics_note}\n'
                f'  </div>\n'
                f'  {toc_block}\n'
                f'  {summary_html}\n'
                f'  {body_html}\n'
                f'  {footer_html}\n'
                f'</main>\n</body>\n</html>')


    # ── Pasek podsumowania ────────────────────────────────────────────────────
    def _rpt_summary_bar(self, data: dict, sections: list) -> str:
        cards = ""
        defs = [
            ("ntfs",      lambda d: (d.get('locked',0), d.get('total',1), "Partycji zablok.", "var(--er)","var(--ok)"),
             ),
            ("bitlocker", lambda d: (d.get('encrypted',0), d.get('total',1), "Zaszyfrowanych", "var(--ok)","var(--er)"),
             ),
            ("processes", lambda d: (d.get('running',0), d.get('count',1), "Active Processes", "var(--ac)","var(--mu)"),
             ),
            ("services",  lambda d: (d.get('running',0), d.get('count',1), "Active Services", "var(--ok)","var(--er)"),
             ),
            ("logs",      lambda d: (d.get('errors',0), d.get('count',1), "Log Errors", "var(--er)","var(--ok)"),
             ),
            ("usb",       lambda d: (d.get('count',0), max(d.get('count',1),1), "USB Devices", "var(--ac2)","var(--mu)"),
             ),
        ]
        for sid, fn in defs:
            if sid not in sections:
                continue
            d = data.get(sid, {})
            if "error" in d:
                continue
            val, total, label, col_hi, col_lo = fn(d)
            pct = round(val / max(total, 1) * 100)
            cards += f"""
<div class="kpi" style="border-top:3px solid {col_hi}">
  <div class="kv" style="color:{col_hi}">{val}<span style="font-size:14px;color:var(--mu);font-weight:400"> / {total}</span></div>
  <div class="kl">{label}</div>
  <div class="pbar-wrap" style="margin-top:8px">
    <div class="pbar-track">
      <div class="pbar-fill" style="width:{pct}%;background:{col_hi}">{pct}%</div>
    </div>
  </div>
</div>"""
        return f'<div class="kpi-grid" style="margin-bottom:28px">{cards}</div>' if cards else ""

    # ── Renderery sekcji ──────────────────────────────────────────────────────
    def _rpt_section(self, sid: str, d: dict, depth: str) -> str:
        """Dispatcher – selects the appropriate renderer for report depth."""
        show_table = (depth == "full")
        show_charts = (depth in ("charts", "full"))

        if sid == "ntfs":       return self._rpt_ntfs(d, show_charts, show_table)
        if sid == "bitlocker":  return self._rpt_bitlocker(d, show_charts, show_table)
        if sid == "processes":  return self._rpt_processes(d, show_charts, show_table)
        if sid == "services":   return self._rpt_services(d, show_charts, show_table)
        if sid == "network":    return self._rpt_network(d, show_table)
        if sid == "logs":       return self._rpt_logs(d, show_charts, show_table)
        if sid == "usb":        return self._rpt_usb(d, show_charts, show_table)
        if sid == "autostart":  return self._rpt_autostart(d, show_charts, show_table)
        if sid == "drives":     return self._rpt_drives(d, show_table)
        if sid == "databases":  return self._rpt_databases(d, show_table)
        if sid == "fslibrary":  return self._rpt_fslibrary(d, show_table)
        return ""

    # ─ helpers ────────────────────────────────────────────────────────────────
    def _rpt_donut(self, val: int, total: int, label: str,
                   col_fill="#50e8ff", col_bg="#2a364d") -> str:
        """Pure-CSS/SVG donut chart."""
        pct   = val / max(total, 1)
        r     = 44
        circ  = 2 * 3.14159 * r
        dash  = pct * circ
        gap   = circ - dash
        pct_s = f"{round(pct*100)}%"
        return f"""
<div class="donut-wrap">
  <svg viewBox="0 0 100 100">
    <circle cx="50" cy="50" r="{r}" fill="none" stroke="{col_bg}" stroke-width="10"/>
    <circle cx="50" cy="50" r="{r}" fill="none" stroke="{col_fill}" stroke-width="10"
            stroke-dasharray="{dash:.1f} {gap:.1f}"
            stroke-linecap="round"
            transform="rotate(-90 50 50)"/>
  </svg>
  <div class="donut-center">
    <div class="donut-pct" style="color:{col_fill}">{pct_s}</div>
    <div class="donut-sub">{label}</div>
  </div>
</div>"""

    def _rpt_pbar(self, label: str, val: int, total: int, color: str = "var(--ac)") -> str:
        pct = round(val / max(total, 1) * 100)
        return f"""
<div class="pbar-wrap">
  <div class="pbar-label"><span>{label}</span><span>{val} / {total} &nbsp;({pct}%)</span></div>
  <div class="pbar-track">
    <div class="pbar-fill" style="width:{pct}%;background:{color}">{pct}%</div>
  </div>
</div>"""

    def _rpt_hbars(self, items: list, max_val: int, color: str = "var(--ac2)") -> str:
        """Horizontal bars. items = list of (name, value)"""
        rows = ""
        for name, val in items[:12]:
            pct = round(val / max(max_val, 1) * 100)
            rows += f"""
<div class="hbar-row">
  <div class="hbar-name" title="{name}">{name[:22]}</div>
  <div class="hbar-track"><div class="hbar-fill" style="width:{pct}%;background:{color}"></div></div>
  <div class="hbar-val">{val} ({pct}%)</div>
</div>"""
        return f'<div class="hbar-chart">{rows}</div>'

    # ─ NTFS ───────────────────────────────────────────────────────────────────
    def _rpt_ntfs(self, d: dict, charts: bool, table: bool) -> str:
        parts   = d.get("partitions", [])
        states  = d.get("states", {})
        locked  = d.get("locked", 0)
        total   = d.get("total", len(parts))
        unlocked = total - locked

        html = ""
        if charts:
            html += '<div class="chart-row">'
            html += self._rpt_donut(locked, total, "zablok.",
                                    "#ff6875" if locked else "#3dffa8")
            html += '<div class="legend">'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#ff6875"></div>Zablokowane (Read-Only): <strong>{locked}</strong></div>'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#3dffa8"></div>Available (Read-Write): <strong>{unlocked}</strong></div>'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#8aaace"></div>Total Partitions: <strong>{total}</strong></div>'
            html += '</div></div>'
            html += self._rpt_pbar("Partycje zablokowane", locked, total, "#ff6875")
            html += self._rpt_pbar("Available Partitions", unlocked, total, "#3dffa8")
        else:
            pct = round(locked / max(total, 1) * 100)
            html += f'<div class="kpi-grid"><div class="kpi"><div class="kv">{locked}/{total}</div><div class="kl">Zablokowanych ({pct}%)</div></div></div>'

        if total == 0:
            return html + '<p class="empty">Brak partycji NTFS.</p>'
        if locked == total:
            html += '<div class="alert alert-ok">✔ All partitions are in Read-Only mode (secure).</div>'
        elif locked == 0:
            html += '<div class="alert alert-warn">⚠ No partitions are secured.</div>'

        if table:
            rows = ""
            for p in parts:
                drv = p.get("drive","?")
                lk  = states.get(drv, False)
                badge = '<span class="badge b-er">🔒 READ-ONLY</span>' if lk \
                        else '<span class="badge b-ok">✔ READ-WRITE</span>'
                rows += f"<tr><td><strong>{drv}</strong></td><td>{p.get('label','—')}</td>" \
                        f"<td>{p.get('size','—')}</td><td>{badge}</td></tr>"
            html += f"""<table><thead><tr><th>Dysk</th><th>Etykieta</th>
<th>Rozmiar</th><th>Stan</th></tr></thead><tbody>{rows}</tbody></table>"""
        return html

    # ─ BitLocker ──────────────────────────────────────────────────────────────
    def _rpt_bitlocker(self, d: dict, charts: bool, table: bool) -> str:
        items = d.get("items", [])
        enc   = d.get("encrypted", 0)
        total = d.get("total", len(items))
        not_enc = total - enc

        html = ""
        if charts:
            html += '<div class="chart-row">'
            html += self._rpt_donut(enc, total, "zaszyfrowanych",
                                    "#3dffa8" if enc == total else "#ff6875")
            html += '<div class="legend">'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#3dffa8"></div>Zaszyfrowane: <strong>{enc}</strong></div>'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#ff6875"></div>Niezaszyfrowane: <strong>{not_enc}</strong></div>'
            html += '</div></div>'
            html += self._rpt_pbar("Encrypted drives", enc, total, "#3dffa8")
        else:
            pct = round(enc / max(total, 1) * 100)
            html += f'<div class="kpi-grid"><div class="kpi"><div class="kv">{enc}/{total}</div><div class="kl">Zaszyfrowanych ({pct}%)</div></div></div>'

        if total == 0:
            return html + '<p class="empty">Brak partycji.</p>'
        if not_enc > 0:
            html += f'<div class="alert alert-warn">⚠ {not_enc} drive(s) without BitLocker encryption!</div>'
        else:
            html += '<div class="alert alert-ok">✔ All drives encrypted.</div>'

        if table:
            rows = ""
            for it in items:
                st = it.get("status", {})
                if st.get("error"):
                    badge = f'<span class="badge b-wn">⚠ {st["error"][:24]}</span>'
                elif st.get("protection") == "ON":
                    badge = '<span class="badge b-ok">🔐 ZASZYFROWANY</span>'
                else:
                    badge = '<span class="badge b-er">⚠ UNENCRYPTED</span>'
                rows += f"<tr><td><strong>{it['drive']}</strong></td><td>{it.get('label','—')}</td>" \
                        f"<td>{it.get('size','—')}</td><td>{badge}</td>" \
                        f"<td>{st.get('status','—')}</td></tr>"
            html += f"""<table><thead><tr><th>Dysk</th><th>Etykieta</th>
<th>Size</th><th>Status</th><th>Details</th></tr></thead><tbody>{rows}</tbody></table>"""
        return html

    # ─ Procesy ────────────────────────────────────────────────────────────────
    def _rpt_processes(self, d: dict, charts: bool, table: bool) -> str:
        cnt     = d.get("count", 0)
        running = d.get("running", 0)
        other   = cnt - running

        html = ""
        if charts:
            html += '<div class="chart-row">'
            html += self._rpt_donut(running, cnt, "aktywnych", "#50e8ff")
            html += '<div class="legend">'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#50e8ff"></div>Aktywne: <strong>{running}</strong></div>'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#8aaace"></div>Other: <strong>{other}</strong></div>'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#2a364d"></div>Total: <strong>{cnt}</strong></div>'
            html += '</div></div>'
            html += self._rpt_pbar("Procesy aktywne", running, cnt, "#50e8ff")
            # Top 10 processes by memory
            items = d.get("items", [])
            def _mem_mb(p):
                m = p.get("mem","0").replace("MB","").replace("GB","").replace("KB","").strip()
                try: return float(m)
                except: return 0
            top = sorted(items, key=_mem_mb, reverse=True)[:10]
            if top:
                max_m = _mem_mb(top[0]) or 1
                bars = [(p.get("name","?")[:22], int(_mem_mb(p))) for p in top]
                html += "<h3 style='margin:14px 0 8px;font-size:13px;color:var(--mu)'>Top 10 Processes by Memory</h3>"
                html += self._rpt_hbars(bars, int(max_m), "#2e9ef0")
        else:
            pct = round(running / max(cnt, 1) * 100)
            html += f'<div class="kpi-grid"><div class="kpi"><div class="kv">{cnt}</div><div class="kl">Processes ({pct}% active)</div></div></div>'

        if table:
            rows = ""
            for p in d.get("items", [])[:300]:
                sc = "b-ok" if p.get("status","") in ("Running","S","R") else "b-ac"
                rows += f"<tr><td>{p.get('pid','')}</td><td>{p.get('name','')}</td>" \
                        f"<td>{p.get('mem','')}</td>" \
                        f"<td><span class=\"badge {sc}\">{p.get('status','')}</span></td></tr>"
            html += f"""<table><thead><tr><th>PID</th><th>Nazwa</th>
<th>Memory</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>"""
        return html

    # ─ Services ─────────────────────────────────────────────────────────────────
    def _rpt_services(self, d: dict, charts: bool, table: bool) -> str:
        cnt     = d.get("count", 0)
        running = d.get("running", 0)
        stopped = d.get("stopped", cnt - running)
        r_pct   = round(running / max(cnt, 1) * 100)

        html = ""
        if charts:
            html += '<div class="chart-row">'
            html += self._rpt_donut(running, cnt, "aktywnych", "#3dffa8")
            html += '<div class="legend">'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#3dffa8"></div>Uruchomione: <strong>{running}</strong> ({r_pct}%)</div>'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#ff6875"></div>Zatrzymane: <strong>{stopped}</strong> ({100-r_pct}%)</div>'
            html += '</div></div>'
            html += self._rpt_pbar("Uruchomione", running, cnt, "#3dffa8")
            html += self._rpt_pbar("Zatrzymane",  stopped, cnt, "#ff6875")
        else:
            html += f'<div class="kpi-grid">' \
                    f'<div class="kpi"><div class="kv" style="color:var(--ok)">{running}</div><div class="kl">Uruchomione ({r_pct}%)</div></div>' \
                    f'<div class="kpi"><div class="kv" style="color:var(--er)">{stopped}</div><div class="kl">Zatrzymane</div></div>' \
                    f'</div>'

        if table:
            rows = ""
            for s in d.get("items", []):
                run = s.get('status','').lower() in ('running','active','+')
                badge = '<span class="badge b-ok">● Running</span>' if run \
                        else f'<span class="badge b-er">● {s.get("status","?")}</span>'
                rows += f"<tr><td>{s.get('name','')}</td><td>{badge}</td>" \
                        f"<td>{s.get('type','—')}</td></tr>"
            html += f"""<table><thead><tr><th>Service Name</th>
<th>Status</th><th>Typ</th></tr></thead><tbody>{rows}</tbody></table>"""
        return html

    # ─ Network ──────────────────────────────────────────────────────────────────
    def _rpt_network(self, d: dict, table: bool) -> str:
        info = d.get("info", {})
        if isinstance(info, list): info = info[0] if info else {}
        html = '<div class="kpi-grid">'
        for lbl, val in [("Hostname", info.get("hostname","?")),
                         ("IP (primary)", info.get("ip","?")),
                         ("System", f"{platform.system()} {platform.release()}")]:
            html += f'<div class="kpi"><div class="kv" style="font-size:14px;color:var(--ac)">{val}</div><div class="kl">{lbl}</div></div>'
        html += '</div>'
        if info.get("connections") and table:
            crows = "".join(
                f"<tr><td>{c.get('proto','')}</td><td>{c.get('local','')}</td>"
                f"<td>{c.get('state','')}</td></tr>"
                for c in info["connections"])
            html += f"""<h3 style="margin:12px 0 8px;font-size:13px;color:var(--mu)">Aktywne porty</h3>
<table><thead><tr><th>Proto</th><th>Adres lokalny</th><th>Stan</th></tr></thead>
<tbody>{crows}</tbody></table>"""
        return html

    # ─ Logi ───────────────────────────────────────────────────────────────────
    def _rpt_logs(self, d: dict, charts: bool, table: bool) -> str:
        cnt    = d.get("count", 0)
        errors = d.get("errors", 0)
        warns  = d.get("warns",  0)
        infos  = d.get("infos",  0)

        html = ""
        if charts:
            html += '<div class="chart-row">'
            html += self._rpt_donut(errors, cnt, "errors", "#ff6875")
            html += '<div class="legend">'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#ff6875"></div>ERROR: <strong>{errors}</strong> ({round(errors/max(cnt,1)*100)}%)</div>'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#ffd166"></div>WARN: <strong>{warns}</strong> ({round(warns/max(cnt,1)*100)}%)</div>'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#3dffa8"></div>INFO: <strong>{infos}</strong> ({round(infos/max(cnt,1)*100)}%)</div>'
            html += f'<div class="leg-item"><div class="leg-dot" style="background:#8aaace"></div>Total: <strong>{cnt}</strong></div>'
            html += '</div></div>'
            html += self._rpt_pbar("ERROR", errors, cnt, "#ff6875")
            html += self._rpt_pbar("WARN",  warns,  cnt, "#ffd166")
            html += self._rpt_pbar("INFO",  infos,  cnt, "#3dffa8")
        else:
            e_pct = round(errors / max(cnt, 1) * 100)
            html += f'<div class="kpi-grid">' \
                    f'<div class="kpi"><div class="kv">{cnt}</div><div class="kl">Total Entries</div></div>' \
                    f'<div class="kpi"><div class="kv" style="color:var(--er)">{errors}</div><div class="kl">ERROR ({e_pct}%)</div></div>' \
                    f'<div class="kpi"><div class="kv" style="color:var(--wn)">{warns}</div><div class="kl">WARN</div></div>' \
                    f'</div>'

        if errors > 0:
            html += f'<div class="alert alert-danger">⚠ Detected {errors} errors in system logs.</div>'
        elif warns > 0:
            html += f'<div class="alert alert-warn">⚠ {warns} warnings in logs.</div>'
        else:
            html += '<div class="alert alert-ok">✔ No errors in logs.</div>'

        if table:
            COLORS = {"ERROR":"b-er","WARN":"b-wn","INFO":"b-ok"}
            rows = ""
            for entry in d.get("items",[])[:400]:
                lvl = entry.get("level","INFO")
                rows += f"<tr><td><span class=\"badge {COLORS.get(lvl,'b-ac')}\">{lvl}</span></td>" \
                        f"<td>{entry.get('date','')}</td>" \
                        f"<td>{entry.get('source','')}</td>" \
                        f"<td>{entry.get('message','')}</td></tr>"
            html += f"""<table><thead><tr><th>Poziom</th><th>Data/Czas</th>
<th>Source</th><th>Message</th></tr></thead><tbody>{rows}</tbody></table>"""
        return html

    # ─ USB ────────────────────────────────────────────────────────────────────
    def _rpt_usb(self, d: dict, charts: bool, table: bool) -> str:
        items = d.get("items", [])
        cnt   = d.get("count", 0)

        html = f'<div class="kpi-grid"><div class="kpi"><div class="kv" style="color:var(--ac2)">{cnt}</div>' \
               f'<div class="kl">Devices in History</div></div>'

        total_gb = sum(
            dev.get("total_bytes", 0) / 1024**3
            for dev in items if dev.get("total_bytes")
        )
        html += f'<div class="kpi"><div class="kv" style="color:var(--ac)">{total_gb:.1f} GB</div>' \
                f'<div class="kl">Total Capacity</div></div></div>'

        if charts and items:
            # Bars – top 10 by capacity
            bars = []
            for dev in sorted(items, key=lambda x: x.get("total_bytes",0), reverse=True)[:10]:
                gb = round(dev.get("total_bytes",0)/1024**3, 1)
                bars.append((dev.get("name","?"), gb))
            if bars:
                html += "<h3 style='margin:12px 0 8px;font-size:13px;color:var(--mu)'>Top 10 Devices by Capacity</h3>"
                html += self._rpt_hbars(bars, int(bars[0][1]) or 1, "#2e9ef0")

        if not items:
            return html + '<p class="empty">Brak historii USB.</p>'

        if table:
            rows = ""
            for dev in items:
                gb = round(dev.get("total_bytes",0)/1024**3, 2) if dev.get("total_bytes") else 0
                rows += f"<tr><td>{dev.get('name','?')}</td>" \
                        f"<td>{dev.get('serial','—')}</td>" \
                        f"<td>{dev.get('manufacturer','—')}</td>" \
                        f"<td>{dev.get('filesystem','—')}</td>" \
                        f"<td>{gb} GB</td>" \
                        f"<td>{dev.get('connect_count','—')}</td>" \
                        f"<td>{dev.get('last_seen','—')}</td></tr>"
            html += f"""<table><thead><tr><th>Nazwa</th><th>Serial</th>
<th>Vendor</th><th>FS</th><th>Size</th><th>Connections</th>
<th>Ostatnie</th></tr></thead><tbody>{rows}</tbody></table>"""
        return html

    # ─ Autostart ──────────────────────────────────────────────────────────────
    def _rpt_autostart(self, d: dict, charts: bool, table: bool) -> str:
        cnt     = d.get("count", 0)
        by_type = d.get("by_type", {})

        html = f'<div class="kpi-grid"><div class="kpi"><div class="kv" style="color:var(--wn)">{cnt}</div>' \
               f'<div class="kl">Autostart Entries</div></div></div>'

        if cnt > 10:
            html += f'<div class="alert alert-warn">⚠ Found {cnt} autostart entries – review the list.</div>'
        else:
            html += '<div class="alert alert-ok">✔ Number of autostart entries is normal.</div>'

        if charts and by_type:
            total_types = sum(by_type.values()) or 1
            bars = sorted(by_type.items(), key=lambda x: x[1], reverse=True)
            html += "<h3 style='margin:12px 0 8px;font-size:13px;color:var(--mu)'>Entries by Type</h3>"
            html += self._rpt_hbars([(k, v) for k, v in bars],
                                     max(v for _, v in bars), "#ffd166")

        if table and d.get("items"):
            rows = ""
            for e in d.get("items", []):
                rows += f"<tr><td>{e.get('name','')}</td>" \
                        f"<td style='word-break:break-all'>{e.get('command','')}</td>" \
                        f"<td>{e.get('type','')}</td></tr>"
            html += f"""<table><thead><tr><th>Nazwa</th>
<th>Command / Path</th><th>Type</th></tr></thead><tbody>{rows}</tbody></table>"""
        return html

    # ── Nowe renderery sekcji raportu ────────────────────────────────────────

    def _rpt_drives(self, d: dict, table: bool) -> str:
        cnt = d.get("count", 0)
        html = (
            f'<div class="kpi-grid">'
            f'<div class="kpi"><div class="kv" style="color:var(--ac)">{cnt}</div>'
            f'<div class="kl">Detected Drives</div></div></div>'
        )
        if cnt == 0:
            html += '<div class="alert alert-warn">⚠ No drives detected or no access.</div>'
        else:
            html += '<div class="alert alert-ok">✔ Drives available.</div>'
        if table and d.get("items"):
            rows = ""
            for drv in d["items"]:
                size_gb = round(drv.get("total", 0) / 1024**3, 1) if drv.get("total") else "N/A"
                free_gb = round(drv.get("free", 0) / 1024**3, 1) if drv.get("free") else "N/A"
                rows += (
                    f"<tr><td>{drv.get('drive','?')}</td>"
                    f"<td>{drv.get('label','')}</td>"
                    f"<td>{drv.get('fstype','')}</td>"
                    f"<td>{size_gb} GB</td>"
                    f"<td>{free_gb} GB</td></tr>"
                )
            html += (
                "<table><thead><tr>"
                "<th>Drive</th><th>Label</th><th>File System</th>"
                "<th>Rozmiar</th><th>Wolne</th>"
                f"</tr></thead><tbody>{rows}</tbody></table>"
            )
        return html

    def _rpt_databases(self, d: dict, table: bool) -> str:
        cnt = d.get("count", 0)
        html = (
            f'<div class="kpi-grid">'
            f'<div class="kpi"><div class="kv" style="color:var(--ac2)">{cnt}</div>'
            f'<div class="kl">Database Engines in Library</div></div></div>'
        )
        if table and d.get("items"):
            rows = ""
            for row in d["items"]:
                # row = (name, type, license, port, os, features, notes)
                name, dbtype, lic, port, opsys, features, notes = row
                rows += (
                    f"<tr><td><strong>{name}</strong></td>"
                    f"<td>{dbtype}</td><td>{lic}</td>"
                    f"<td>{port}</td><td>{opsys}</td>"
                    f"<td style='font-size:11px'>{notes}</td></tr>"
                )
            html += (
                "<table><thead><tr>"
                "<th>Nazwa</th><th>Typ</th><th>Licencja</th>"
                "<th>Port</th><th>Systemy</th><th>Opis</th>"
                f"</tr></thead><tbody>{rows}</tbody></table>"
            )
        else:
            # summary without table
            types = {}
            for row in d.get("items", []):
                t = row[1].split("–")[0].strip().split("/")[0].strip()
                types[t] = types.get(t, 0) + 1
            bars = sorted(types.items(), key=lambda x: x[1], reverse=True)
            if bars:
                html += "<h3 style='margin:12px 0 8px;font-size:13px;color:var(--mu)'>Breakdown by Type</h3>"
                html += self._rpt_hbars(bars, max(v for _, v in bars), "var(--ac2)")
        return html

    def _rpt_fslibrary(self, d: dict, table: bool) -> str:
        cnt = d.get("count", 0)
        html = (
            f'<div class="kpi-grid">'
            f'<div class="kpi"><div class="kv" style="color:var(--ok)">{cnt}</div>'
            f'<div class="kl">File Systems in Library</div></div></div>'
        )
        if table and d.get("items"):
            rows = ""
            for row in d["items"]:
                # row = (name, type, max_vol, max_file, os_support, features, notes)
                name, fstype, max_vol, max_file, opsys, features, notes = row
                rows += (
                    f"<tr><td><strong>{name}</strong></td>"
                    f"<td>{fstype}</td><td>{max_vol}</td>"
                    f"<td>{max_file}</td><td>{opsys}</td>"
                    f"<td style='font-size:11px'>{notes}</td></tr>"
                )
            html += (
                "<table><thead><tr>"
                "<th>System</th><th>Type</th><th>Max volume</th>"
                "<th>Max file</th><th>OS support</th><th>Description</th>"
                f"</tr></thead><tbody>{rows}</tbody></table>"
            )
        else:
            types = {}
            for row in d.get("items", []):
                t = row[1]
                types[t] = types.get(t, 0) + 1
            bars = sorted(types.items(), key=lambda x: x[1], reverse=True)
            if bars:
                html += "<h3 style='margin:12px 0 8px;font-size:13px;color:var(--mu)'>Breakdown by Type</h3>"
                html += self._rpt_hbars(bars, max(v for _, v in bars), "var(--ok)")
        return html

    # ─────────────────────────────────────────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════════════
    #  REPORT SETTINGS – tabbed dialog
    # ══════════════════════════════════════════════════════════════════════════

    def _report_settings_dialog(self):
        """Report settings window with tabs: Appearance / Content / Metadata / Export / Advanced."""
        win = tk.Toplevel(self)
        win.title("🎨  Report Settings")
        win.configure(bg=self.CLR_BG)
        win.resizable(True, False)
        win.grab_set()
        win.update_idletasks()
        W, H = 700, 610
        x = self.winfo_x() + (self.winfo_width()  - W) // 2
        y = self.winfo_y() + (self.winfo_height() - H) // 2
        win.geometry(f"{W}x{H}+{x}+{y}")

        # ── header ──────────────────────────────────────────────────────────────
        tk.Frame(win, bg=self.CLR_ACCENT, height=3).pack(fill=tk.X)
        hdr = tk.Frame(win, bg=self.CLR_HEADER_BG)
        hdr.pack(fill=tk.X)
        hdr_inner = tk.Frame(hdr, bg=self.CLR_HEADER_BG)
        hdr_inner.pack(fill=tk.X, padx=16, pady=10)
        tk.Label(hdr_inner, text="🎨", font=("Segoe UI", 20),
                 fg=self.CLR_ACCENT, bg=self.CLR_HEADER_BG).pack(side=tk.LEFT, padx=(0,10))
        col = tk.Frame(hdr_inner, bg=self.CLR_HEADER_BG)
        col.pack(side=tk.LEFT)
        tk.Label(col, text=_t("HTML Report Settings"),
                 font=("Segoe UI", 12, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_HEADER_BG).pack(anchor=tk.W)
        tk.Label(col, text="Configure appearance, content, metadata, and report export",
                 font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_HEADER_BG).pack(anchor=tk.W)

        # ── tab bar ────────────────────────────────────────────────────────────
        tab_bar = tk.Frame(win, bg=self.CLR_SURFACE2)
        tab_bar.pack(fill=tk.X)
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X)

        scroll_outer = tk.Frame(win, bg=self.CLR_BG)
        scroll_outer.pack(fill=tk.BOTH, expand=True)
        tab_canvas = tk.Canvas(scroll_outer, bg=self.CLR_BG, highlightthickness=0)
        tab_vsb = ttk.Scrollbar(scroll_outer, orient=tk.VERTICAL, command=tab_canvas.yview)
        tab_canvas.configure(yscrollcommand=tab_vsb.set)
        tab_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        tab_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        content_area = tk.Frame(tab_canvas, bg=self.CLR_BG)
        cwin_id = tab_canvas.create_window((0,0), window=content_area, anchor="nw")
        def _on_frame_cfg(e):
            tab_canvas.configure(scrollregion=tab_canvas.bbox("all"))
            tab_canvas.itemconfig(cwin_id, width=tab_canvas.winfo_width())
        content_area.bind("<Configure>", _on_frame_cfg)
        tab_canvas.bind("<Configure>", lambda e: tab_canvas.itemconfig(cwin_id, width=e.width))
        def _on_mousewheel(e): tab_canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        tab_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        TABS = [
            ("appearance", "🎨 Appearance"),
            ("graphics",   "📊 Graphics"),
            ("content",    "📋 Content"),
            ("meta",       "ℹ️  Metadata"),
            ("export",     "💾 Eksport"),
            ("advanced",   "⚙️  Advanced"),
        ]
        tab_frames = {}
        tab_btns   = {}
        active_tab = [None]

        def _switch_tab(tid):
            active_tab[0] = tid
            for k, btn in tab_btns.items():
                if k == tid:
                    btn.configure(bg=self.CLR_BG, fg=self.CLR_ACCENT,
                                  font=("Segoe UI", 10, "bold"), relief=tk.SUNKEN)
                else:
                    btn.configure(bg=self.CLR_SURFACE2, fg=self.CLR_MUTED,
                                  font=("Segoe UI", 10), relief=tk.FLAT)
            for k, frm in tab_frames.items():
                frm.pack_forget() if k != tid else frm.pack(fill=tk.BOTH, expand=True, padx=20, pady=14)
            tab_canvas.yview_moveto(0)

        for tid, tlabel in TABS:
            btn = tk.Button(tab_bar, text=tlabel,
                            font=("Segoe UI", 10), fg=self.CLR_MUTED,
                            bg=self.CLR_SURFACE2, relief=tk.FLAT, bd=0,
                            padx=14, pady=8, cursor="hand2",
                            activebackground=self.CLR_BG,
                            activeforeground=self.CLR_ACCENT,
                            command=lambda t=tid: _switch_tab(t))
            btn.pack(side=tk.LEFT)
            tab_btns[tid] = btn
            tab_frames[tid] = tk.Frame(content_area, bg=self.CLR_BG)

        def _lbl(parent, text, bold=False, muted=False):
            fg = self.CLR_MUTED if muted else self.CLR_TEXT
            f  = ("Segoe UI", 10, "bold") if bold else ("Segoe UI", 10)
            tk.Label(parent, text=text, font=f, fg=fg, bg=self.CLR_BG).pack(anchor=tk.W, pady=(8,2))

        def _sep(parent):
            tk.Frame(parent, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, pady=6)

        def _chk(parent, text, var, desc=""):
            row = tk.Frame(parent, bg=self.CLR_BG)
            row.pack(fill=tk.X, pady=2)
            tk.Checkbutton(row, text=text, variable=var,
                           font=("Segoe UI", 10), fg=self.CLR_TEXT,
                           bg=self.CLR_BG, selectcolor=self.CLR_SURFACE,
                           activebackground=self.CLR_BG, activeforeground=self.CLR_ACCENT
                           ).pack(side=tk.LEFT)
            if desc:
                tk.Label(row, text=f"  — {desc}", font=("Segoe UI", 9),
                         fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT)

        def _entry_row(parent, label, var, width=32):
            row = tk.Frame(parent, bg=self.CLR_BG)
            row.pack(fill=tk.X, pady=3)
            tk.Label(row, text=label, font=("Segoe UI", 10),
                     fg=self.CLR_MUTED, bg=self.CLR_BG, width=22, anchor=tk.W
                     ).pack(side=tk.LEFT)
            tk.Entry(row, textvariable=var, font=("Segoe UI", 10),
                     bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                     insertbackground=self.CLR_ACCENT,
                     relief=tk.FLAT, bd=4, width=width
                     ).pack(side=tk.LEFT)

        def _radio_group(parent, label, var, options):
            _lbl(parent, label, bold=True)
            for val, lbl_t, desc_t in options:
                row = tk.Frame(parent, bg=self.CLR_BG)
                row.pack(fill=tk.X, pady=2)
                tk.Radiobutton(row, text=lbl_t, variable=var, value=val,
                               font=("Segoe UI", 10), fg=self.CLR_TEXT,
                               bg=self.CLR_BG, selectcolor=self.CLR_SURFACE,
                               activebackground=self.CLR_BG
                               ).pack(side=tk.LEFT)
                tk.Label(row, text=f"  — {desc_t}", font=("Segoe UI", 9),
                         fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT)

        # ══════════════════════════════════════════════════════
        # TAB 1: Appearance
        # ══════════════════════════════════════════════════════
        frm_app = tab_frames["appearance"]

        _lbl(frm_app, "Motyw raportu", bold=True)
        _chk(frm_app, "Motyw ciemny (Dark)", self._report_dark_theme,
             "background #181e2a — default")
        _chk(frm_app, "Compact Layout", self._report_compact,
             "smaller spacing, more content on screen")
        _chk(frm_app, "Page Breaks (print)", self._report_page_break,
             "page-break-before for each section when printing")

        _sep(frm_app)
        _lbl(frm_app, "Kolor akcentu", bold=True)
        ACCENT_PRESETS = [
            ("#50e8ff", "Cyan (default)"),
            ("#7c6af7", "Fiolet"),
            ("#2ecc71", "Zielony"),
            ("#e74c3c", "Czerwony"),
            ("#f39c12", "Orange"),
            ("#0078d7", "Niebieski (Windows)"),
        ]
        acc_row = tk.Frame(frm_app, bg=self.CLR_BG)
        acc_row.pack(fill=tk.X, pady=4)
        accent_swatches = {}

        def _set_accent(color, btn_ref):
            self._report_accent_color.set(color)
            for c, b in accent_swatches.items():
                b.configure(relief=tk.SUNKEN if c == color else tk.RAISED,
                            bd=3 if c == color else 1)
            _refresh_preview()

        for hex_c, name in ACCENT_PRESETS:
            swatch = tk.Button(acc_row, bg=hex_c, width=3, height=1,
                               relief=tk.RAISED, bd=1, cursor="hand2",
                               activebackground=hex_c)
            swatch.configure(command=lambda c=hex_c, b=swatch: _set_accent(c, b))
            swatch.pack(side=tk.LEFT, padx=3)
            accent_swatches[hex_c] = swatch
        tk.Label(acc_row, text="  Custom hex:", font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(8,2))
        tk.Entry(acc_row, textvariable=self._report_accent_color,
                 font=("Segoe UI", 9), bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                 insertbackground=self.CLR_ACCENT, relief=tk.FLAT, bd=3, width=10
                 ).pack(side=tk.LEFT)

        _sep(frm_app)
        _radio_group(frm_app, "Rozmiar czcionki", self._report_font_size, [
            ("small",  "Small",   "12px — more content"),
            ("medium", "Medium",  "14px — default"),
            ("large",  "Large",   "16px — better contrast"),
        ])

        _sep(frm_app)
        _lbl(frm_app, "Theme Preview", muted=True)
        prev = tk.Frame(frm_app, bg=self.CLR_SURFACE, padx=12, pady=10)
        prev.pack(fill=tk.X, pady=4)

        def _refresh_preview(*_):
            bg  = "#181e2a" if self._report_dark_theme.get() else "#f0f4f8"
            acc = self._report_accent_color.get() or "#50e8ff"
            tx  = "#f4f8ff" if self._report_dark_theme.get() else "#1a1d24"
            mu  = "#6b7a99" if self._report_dark_theme.get() else "#888"
            for w in prev.winfo_children():
                w.destroy()
            hdr_p = tk.Frame(prev, bg=bg)
            hdr_p.pack(fill=tk.X, pady=(0,4))
            tk.Label(hdr_p, text="NTFSecur Report", font=("Segoe UI", 11, "bold"),
                     fg=acc, bg=bg).pack(side=tk.LEFT)
            tk.Label(hdr_p, text="  2025-01-01 12:00", font=("Segoe UI", 9),
                     fg=mu, bg=bg).pack(side=tk.LEFT)
            tk.Frame(prev, bg=acc, height=2).pack(fill=tk.X, pady=2)
            kpi = tk.Frame(prev, bg=bg)
            kpi.pack(fill=tk.X)
            for lbl, val, col in [("Partycje", "8", acc), ("Szyfrowanie", "75%", "#2ecc71"), ("Procesy", "142", mu)]:
                card = tk.Frame(kpi, bg="#222d40" if self._report_dark_theme.get() else "#dde8f0",
                                padx=8, pady=4)
                card.pack(side=tk.LEFT, padx=4, pady=2)
                tk.Label(card, text=val, font=("Segoe UI", 14, "bold"), fg=col,
                         bg=card["bg"]).pack()
                tk.Label(card, text=lbl, font=("Segoe UI", 8), fg=mu,
                         bg=card["bg"]).pack()

        self._report_dark_theme.trace_add("write",   _refresh_preview)
        self._report_accent_color.trace_add("write", _refresh_preview)
        _refresh_preview()

        # ══════════════════════════════════════════════════════
        # TAB 2: Grafika
        # ══════════════════════════════════════════════════════
        frm_gfx = tab_frames["graphics"]

        _lbl(frm_gfx, "Elementy graficzne", bold=True)
        _chk(frm_gfx, "Generuj wykresy i grafiki", self._report_graphics,
             "donut charts, progress bars, KPI visualizations")
        _chk(frm_gfx, "Logo / Icon in Header", self._report_logo,
             "⬡ symbol in top-right corner of header")
        _chk(frm_gfx, "Karta podsumowania (Summary Card)", self._report_show_summary,
             "KPI block at the start of the report with key indicators")
        _chk(frm_gfx, "Alerts and Warnings", self._report_show_alerts,
             "coloured ⚠/✔ blocks at data anomalies")

        _sep(frm_gfx)
        _lbl(frm_gfx, "Chart Types (CSS/SVG — no external libraries)", muted=True)

        chart_info = [
            ("🍩 Donut Chart",    "Status BitLocker, ochrona NTFS — % szyfrowania/blokady"),
            ("📊 Bar Chart",      "Processes, services, autostart — type comparison"),
            ("🔵 Progress Bar",   "Encryption in progress, disk usage"),
            ("🃏 KPI Cards",      "Counters and key indicators in cards"),
            ("🚦 Status Badge",   "Coloured labels ONLINE/OFFLINE/WARN/OK"),
        ]
        for icon_name, desc in chart_info:
            row = tk.Frame(frm_gfx, bg=self.CLR_SURFACE, padx=10, pady=4)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=icon_name, font=("Segoe UI", 10, "bold"),
                     fg=self.CLR_ACCENT, bg=self.CLR_SURFACE, width=20, anchor=tk.W
                     ).pack(side=tk.LEFT)
            tk.Label(row, text=desc, font=("Segoe UI", 9),
                     fg=self.CLR_TEXT2, bg=self.CLR_SURFACE).pack(side=tk.LEFT)

        _sep(frm_gfx)
        _lbl(frm_gfx, "Eksport grafiki", bold=True)
        _chk(frm_gfx, "Embed graphics inline (self-contained HTML)", tk.BooleanVar(value=True),
             "the .html file works without an internet connection")

        # ══════════════════════════════════════════════════════
        # TAB 3: Content
        # ══════════════════════════════════════════════════════
        frm_con = tab_frames["content"]

        _lbl(frm_con, "Elementy raportu", bold=True)
        _chk(frm_con, "Table of Contents (TOC)", self._report_toc,
             "section list with links at the start of the report")
        _chk(frm_con, "Data i godzina generowania", self._report_timestamp,
             "visible in header and footer")
        _chk(frm_con, "Nazwa komputera (hostname)", self._report_hostname,
             "displayed in report header")
        _chk(frm_con, "Stopka raportu", self._report_show_footer,
             "bottom bar with author, company and version")

        _sep(frm_con)
        _radio_group(frm_con, "Data Depth", tk.StringVar(value="charts"), [
            ("summary", "Summary",      "numbers and alerts only, no charts"),
            ("charts",  "Charts",       "visualizations + summary tables"),
            ("full",    "Full",         "everything + complete raw data tables"),
        ])

        _sep(frm_con)
        _lbl(frm_con, "Limit wierszy w tabelach", bold=True)
        limit_row = tk.Frame(frm_con, bg=self.CLR_BG)
        limit_row.pack(fill=tk.X, pady=4)
        tk.Label(limit_row, text=_t("Maksimum wierszy:"), font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG, width=22, anchor=tk.W
                 ).pack(side=tk.LEFT)
        tk.Spinbox(limit_row, from_=10, to=10000, increment=50,
                   textvariable=self._report_table_limit,
                   font=("Segoe UI", 10), width=8,
                   bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                   insertbackground=self.CLR_ACCENT, relief=tk.FLAT
                   ).pack(side=tk.LEFT)
        tk.Label(limit_row, text="  (0 = bez limitu)",
                 font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_BG
                 ).pack(side=tk.LEFT)

        _sep(frm_con)
        _lbl(frm_con, "Default Report Type (for Ctrl+Shift+3 etc.)", bold=True)
        _radio_group(frm_con, "", self._report_default_type, [
            ("quick",    "⚡ Quick",      "4 sections — key indicators"),
            ("normal",   "📊 Normal",     "6 sections — overview with charts"),
            ("full",     "📋 Full",       "11 sections — all sections"),
            ("detailed", "🔬 Detailed",   "11 sections + complete tables"),
        ])

        # ══════════════════════════════════════════════════════
        # TAB 4: Metadane
        # ══════════════════════════════════════════════════════
        frm_meta = tab_frames["meta"]

        _lbl(frm_meta, "Informacje o autorze raportu", bold=True)
        _entry_row(frm_meta, "Autor:", self._report_author)
        _entry_row(frm_meta, "Firma / organizacja:", self._report_company)

        _sep(frm_meta)
        _lbl(frm_meta, "Custom Report Footer", bold=True)
        _entry_row(frm_meta, "Tekst stopki:", self._report_footer_text, width=36)
        tk.Label(frm_meta, text="  Leave blank to use the default footer (author + version)",
                 font=("Segoe UI", 8), fg=self.CLR_MUTED, bg=self.CLR_BG
                 ).pack(anchor=tk.W, padx=4)

        _sep(frm_meta)
        _lbl(frm_meta, "Notatki / komentarz w raporcie", bold=True)
        notes_frame = tk.Frame(frm_meta, bg=self.CLR_BG)
        notes_frame.pack(fill=tk.X, pady=4)
        notes_txt = tk.Text(notes_frame, height=4, font=("Segoe UI", 10),
                            bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                            insertbackground=self.CLR_ACCENT,
                            relief=tk.FLAT, bd=4, wrap=tk.WORD)
        notes_txt.pack(fill=tk.X, pady=2)
        notes_txt.insert("1.0", self._report_notes.get())

        def _save_notes(*_):
            self._report_notes.set(notes_txt.get("1.0", tk.END).strip())
        notes_txt.bind("<FocusOut>", _save_notes)

        _sep(frm_meta)
        _lbl(frm_meta, "Klasyfikacja raportu", bold=True)
        classif_var = getattr(self, "_report_classif_var", None)
        if classif_var is None:
            classif_var = tk.StringVar(value="Internal")
            self._report_classif_var = classif_var

        CLASSIF = [
            ("Public",       "🟢", "Publicly available report"),
            ("Internal",     "🔵", "For internal use only"),
            ("Confidential", "🟠", "Poufny — nie do dystrybucji"),
            ("Restricted",   "🔴", "Restricted — for administrators only"),
        ]
        for cls, dot, desc in CLASSIF:
            row = tk.Frame(frm_meta, bg=self.CLR_BG)
            row.pack(fill=tk.X, pady=2)
            tk.Radiobutton(row, text=f"{dot}  {cls}", variable=classif_var, value=cls,
                           font=("Segoe UI", 10), fg=self.CLR_TEXT,
                           bg=self.CLR_BG, selectcolor=self.CLR_SURFACE,
                           activebackground=self.CLR_BG
                           ).pack(side=tk.LEFT)
            tk.Label(row, text=f"  — {desc}", font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT)

        # ══════════════════════════════════════════════════════
        # TAB 5: Eksport
        # ══════════════════════════════════════════════════════
        frm_exp = tab_frames["export"]

        _radio_group(frm_exp, "Output File Format", self._report_format, [
            ("html", "HTML", "full report in browser, CSS/SVG charts — recommended"),
            ("txt",  "TXT",  "plain-text, bez grafiki, lekki eksport"),
        ])

        _sep(frm_exp)
        _lbl(frm_exp, "Target Report Directory", bold=True)
        dir_row = tk.Frame(frm_exp, bg=self.CLR_BG)
        dir_row.pack(fill=tk.X, pady=4)
        dir_var = tk.StringVar(value=AppPaths.REPORT_DIR)
        tk.Entry(dir_row, textvariable=dir_var, font=("Segoe UI", 9),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                 insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=46).pack(side=tk.LEFT, padx=(0,6))

        def _browse_dir():
            from tkinter import filedialog
            d = filedialog.askdirectory(initialdir=dir_var.get(),
                                        title="Select Reports Folder")
            if d:
                dir_var.set(d)
        tk.Button(dir_row, text="…", font=("Segoe UI", 9, "bold"),
                  fg=self.CLR_HEADER_BG, bg=self.CLR_ACCENT,
                  relief=tk.FLAT, padx=8, pady=3, cursor="hand2",
                  command=_browse_dir).pack(side=tk.LEFT)

        _sep(frm_exp)
        _lbl(frm_exp, "Filename pattern", bold=True)
        fname_var = getattr(self, "_report_fname_pattern",
                            tk.StringVar(value="NTFSecur_{type}_{date}.html"))
        self._report_fname_pattern = fname_var
        _entry_row(frm_exp, "Wzorzec nazwy:", fname_var, width=34)
        tk.Label(frm_exp,
                 text=_t("Zmienne: {type}  {date}  {time}  {host}  {user}"),
                 font=("Segoe UI", 8), fg=self.CLR_MUTED,
                 bg=self.CLR_BG).pack(anchor=tk.W, padx=4)

        _sep(frm_exp)
        _lbl(frm_exp, "Opcje po wygenerowaniu", bold=True)
        _chk(frm_exp, "Open in Browser Automatically", self._report_autoopen)
        _chk(frm_exp, "Copy Path to Clipboard", self._report_copy_to_clip,
             "path to file is copied to clipboard after generation")

        # ══════════════════════════════════════════════════════
        # TAB 6: Zaawansowane
        # ══════════════════════════════════════════════════════
        frm_adv = tab_frames["advanced"]

        _lbl(frm_adv, "Opcje zaawansowane", bold=True)
        _lbl(frm_adv,
             "The following options affect the report engine and HTML behaviour.", muted=True)

        _sep(frm_adv)
        _lbl(frm_adv, "Performance and Limits", bold=True)

        timeout_var = tk.IntVar(value=30)
        t_row = tk.Frame(frm_adv, bg=self.CLR_BG)
        t_row.pack(fill=tk.X, pady=3)
        tk.Label(t_row, text=_t("Timeout zbierania danych (s):"),
                 font=("Segoe UI", 10), fg=self.CLR_MUTED,
                 bg=self.CLR_BG, width=30, anchor=tk.W).pack(side=tk.LEFT)
        tk.Spinbox(t_row, from_=5, to=120, increment=5, textvariable=timeout_var,
                   font=("Segoe UI", 10), width=6,
                   bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                   insertbackground=self.CLR_ACCENT, relief=tk.FLAT
                   ).pack(side=tk.LEFT)

        _sep(frm_adv)
        _lbl(frm_adv, "HTML / CSS", bold=True)
        minify_var = tk.BooleanVar(value=False)
        _chk(frm_adv, "Minify HTML (remove whitespace)", minify_var,
             "smaller output file")
        embed_fonts_var = tk.BooleanVar(value=False)
        _chk(frm_adv, "Include system fonts as fallback", embed_fonts_var,
             "Segoe UI → Arial → sans-serif in CSS")

        _sep(frm_adv)
        _lbl(frm_adv, "Debugowanie", bold=True)
        debug_html_var = tk.BooleanVar(value=False)
        _chk(frm_adv, "Zapisz HTML z komentarzami debugowania", debug_html_var,
             "inserts <!-- section: ... --> in HTML source")
        save_raw_var = tk.BooleanVar(value=False)
        _chk(frm_adv, "Save raw JSON data alongside report", save_raw_var,
             ".json file with data collected before rendering")

        _sep(frm_adv)
        _lbl(frm_adv, "Security", bold=True)
        sanitize_var = tk.BooleanVar(value=True)
        _chk(frm_adv, "Sanitize input data (HTML escape)", sanitize_var,
             "characters <>&\" are escaped — prevents XSS in the report")
        _chk(frm_adv, "Add X-Content-Type header in meta", tk.BooleanVar(value=True),
             "meta http-equiv in HTML report header")

        _sep(frm_adv)
        # Reset to defaults
        def _reset_all():
            self._report_dark_theme.set(True)
            self._report_compact.set(False)
            self._report_page_break.set(False)
            self._report_graphics.set(True)
            self._report_logo.set(True)
            self._report_timestamp.set(True)
            self._report_hostname.set(True)
            self._report_toc.set(True)
            self._report_show_summary.set(True)
            self._report_show_alerts.set(True)
            self._report_show_footer.set(True)
            self._report_accent_color.set("#50e8ff")
            self._report_font_size.set("medium")
            self._report_table_limit.set(100)
            self._report_default_type.set("full")
            self._report_format.set("html")
            self._report_autoopen.set(True)
            self._report_copy_to_clip.set(False)
            _refresh_preview()
        tk.Button(frm_adv, text="↺  Restore All Settings to Defaults",
                  font=("Segoe UI", 10), fg=self.CLR_WARN,
                  bg=self.CLR_SURFACE, relief=tk.FLAT, padx=14, pady=6,
                  cursor="hand2", command=_reset_all
                  ).pack(anchor=tk.W, pady=8)

        # ── Przyciski dolne ───────────────────────────────────────────────────
        tab_canvas.unbind_all("<MouseWheel>")
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, side=tk.BOTTOM)
        btn_row = tk.Frame(win, bg=self.CLR_HEADER_BG)
        btn_row.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Button(btn_row, text="✔  Save and close",
                  font=("Segoe UI", 10, "bold"),
                  fg=self.CLR_HEADER_BG, bg=self.CLR_ACCENT,
                  relief=tk.FLAT, padx=16, pady=7, cursor="hand2",
                  command=lambda: (_save_notes(), win.destroy())
                  ).pack(side=tk.LEFT, padx=10, pady=8)
        tk.Button(btn_row, text="Anuluj",
                  font=("Segoe UI", 10), fg=self.CLR_MUTED,
                  bg=self.CLR_HEADER_BG, relief=tk.FLAT, padx=12, pady=7,
                  cursor="hand2", command=win.destroy
                  ).pack(side=tk.LEFT)
        tk.Label(btn_row,
                 text=_t("Ustawienia stosowane przy kolejnym generowaniu raportu."),
                 font=("Segoe UI", 9), fg=self.CLR_BORDER,
                 bg=self.CLR_HEADER_BG).pack(side=tk.RIGHT, padx=12)

        _switch_tab("appearance")


    # ══════════════════════════════════════════════════════════════════════════
    #  HANDBOOK – user manual with tabbed chapters
    # ══════════════════════════════════════════════════════════════════════════
    def _menu_handbook(self):
        """Full user handbook with search and thematic tabs."""
        win = tk.Toplevel(self)
        win.title("📖  Handbook – NTFSecur User Manual")
        win.configure(bg=self.CLR_BG)
        win.resizable(True, True)
        win.minsize(920, 640)
        win.update_idletasks()
        W, H = 1060, 720
        x = max(0, self.winfo_x() + (self.winfo_width()  - W) // 2)
        y = max(0, self.winfo_y() + (self.winfo_height() - H) // 2)
        win.geometry(f"{W}x{H}+{x}+{y}")

        # ── header ──────────────────────────────────────────────────────────────
        tk.Frame(win, bg=self.CLR_ACCENT, height=3).pack(fill=tk.X)
        hdr = tk.Frame(win, bg=self.CLR_HEADER_BG)
        hdr.pack(fill=tk.X)
        hdr_inner = tk.Frame(hdr, bg=self.CLR_HEADER_BG)
        hdr_inner.pack(fill=tk.X, padx=16, pady=10)
        tk.Label(hdr_inner, text="📖", font=("Segoe UI", 22),
                 fg=self.CLR_ACCENT, bg=self.CLR_HEADER_BG).pack(side=tk.LEFT, padx=(0,10))
        title_col = tk.Frame(hdr_inner, bg=self.CLR_HEADER_BG)
        title_col.pack(side=tk.LEFT)
        tk.Label(title_col, text=_t("Handbook – User Manual"),
                 font=("Segoe UI", 13, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_HEADER_BG).pack(anchor=tk.W)
        tk.Label(title_col, text=f"{__product__}  v{__version__}  ·  {__copyright__}",
                 font=("Segoe UI", 9), fg=self.CLR_MUTED,
                 bg=self.CLR_HEADER_BG).pack(anchor=tk.W)

        # ── pasek wyszukiwania ────────────────────────────────────────────────
        search_bar = tk.Frame(win, bg=self.CLR_SURFACE2)
        search_bar.pack(fill=tk.X)
        tk.Label(search_bar, text="🔍", font=("Segoe UI", 12),
                 fg=self.CLR_MUTED, bg=self.CLR_SURFACE2).pack(side=tk.LEFT, padx=(12,4))
        search_var = tk.StringVar()
        search_ent = tk.Entry(search_bar, textvariable=search_var,
                              font=("Segoe UI", 10),
                              bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                              insertbackground=self.CLR_ACCENT,
                              relief=tk.FLAT, bd=4, width=36)
        search_ent.pack(side=tk.LEFT, padx=4, pady=6)
        tk.Label(search_bar, text=_t("Search the handbook…  (Enter)"),
                 font=("Segoe UI", 9), fg=self.CLR_MUTED,
                 bg=self.CLR_SURFACE2).pack(side=tk.LEFT, padx=4)
        search_result_var = tk.StringVar(value="")
        tk.Label(search_bar, textvariable=search_result_var,
                 font=("Segoe UI", 9, "bold"), fg=self.CLR_SUCCESS,
                 bg=self.CLR_SURFACE2).pack(side=tk.RIGHT, padx=12)
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X)

        # ── two-panel layout: sidebar (tabs) + content ──────────────────────────
        body = tk.Frame(win, bg=self.CLR_BG)
        body.pack(fill=tk.BOTH, expand=True)

        # SIDEBAR
        sidebar_wrap = tk.Frame(body, bg=self.CLR_SURFACE, width=218)
        sidebar_wrap.pack(side=tk.LEFT, fill=tk.Y)
        sidebar_wrap.pack_propagate(False)
        tk.Frame(sidebar_wrap, bg=self.CLR_BORDER_LT, width=1).pack(side=tk.RIGHT, fill=tk.Y)

        sb_canvas = tk.Canvas(sidebar_wrap, bg=self.CLR_SURFACE, highlightthickness=0, width=217)
        sb_vsb = ttk.Scrollbar(sidebar_wrap, orient=tk.VERTICAL, command=sb_canvas.yview)
        sb_canvas.configure(yscrollcommand=sb_vsb.set)
        sb_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        sb_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sidebar = tk.Frame(sb_canvas, bg=self.CLR_SURFACE)
        sb_canvas.create_window((0,0), window=sidebar, anchor="nw")
        sidebar.bind("<Configure>", lambda e: sb_canvas.configure(
            scrollregion=sb_canvas.bbox("all")))

        tk.Label(sidebar, text="  CHAPTERS",
                 font=("Segoe UI", 8, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_SURFACE
                 ).pack(anchor=tk.W, padx=8, pady=(10,4))

        # CONTENT PANEL
        content_panel = tk.Frame(body, bg=self.CLR_BG)
        content_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        txt_wrap = tk.Frame(content_panel, bg=self.CLR_BG)
        txt_wrap.pack(fill=tk.BOTH, expand=True)
        txt_sb = ttk.Scrollbar(txt_wrap, orient=tk.VERTICAL)
        txt = tk.Text(txt_wrap, font=("Segoe UI", 10),
                      bg=self.CLR_BG, fg=self.CLR_TEXT,
                      relief=tk.FLAT, bd=0, wrap=tk.WORD,
                      padx=28, pady=18, cursor="arrow",
                      yscrollcommand=txt_sb.set,
                      state=tk.DISABLED)
        txt_sb.config(command=txt.yview)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt_sb.pack(side=tk.RIGHT, fill=tk.Y)

        # Tagi formatowania
        txt.tag_configure("h1",    font=("Segoe UI", 17, "bold"), foreground=self.CLR_ACCENT,   spacing1=10, spacing3=6)
        txt.tag_configure("h2",    font=("Segoe UI", 13, "bold"), foreground=self.CLR_ACCENT2,  spacing1=12, spacing3=4)
        txt.tag_configure("h3",    font=("Segoe UI", 11, "bold"), foreground=self.CLR_TEXT,     spacing1=8,  spacing3=2)
        txt.tag_configure("body",  font=("Segoe UI", 10),         foreground=self.CLR_TEXT2,    spacing1=2,  spacing3=2)
        txt.tag_configure("code",  font=("Courier New", 9),       foreground=self.CLR_SUCCESS,  background=self.CLR_SURFACE)
        txt.tag_configure("warn",  font=("Segoe UI", 10),         foreground=self.CLR_WARN,     spacing1=2)
        txt.tag_configure("ok",    font=("Segoe UI", 10),         foreground=self.CLR_SUCCESS)
        txt.tag_configure("kw",    font=("Segoe UI", 10, "bold"), foreground=self.CLR_ACCENT)
        txt.tag_configure("muted", font=("Segoe UI", 9),          foreground=self.CLR_MUTED)
        txt.tag_configure("tip",   font=("Segoe UI", 10, "italic"),foreground="#a0c8ff", spacing1=2)
        txt.tag_configure("found_bg", background="#1a3a10", foreground=self.CLR_SUCCESS)
        txt.tag_configure("sep_line", font=("Segoe UI", 4), foreground=self.CLR_BORDER)

        def W(tag, text):
            txt.config(state=tk.NORMAL)
            txt.insert(tk.END, text, tag)
            txt.config(state=tk.DISABLED)

        def HR():
            W("sep_line", "\n" + "─" * 80 + "\n")

        def TIP(text):
            W("tip", f"💡 {text}\n")

        # ── CHAPTER CONTENT ─────────────────────────────────────────────────────
        CHAPTERS = {}
        def ch(cid, title, fn, group=None):
            CHAPTERS[cid] = (title, fn, group)

        # ─────────────────────────── INTRO ───────────────────────────────────
        def make_intro():
            W("h1", "🔒 NTFSecur – System Management Panel\n")
            W("muted", f"{_t('Wersja')} {__version__}  ·  {__author__}  ·  {__copyright__}\n\n")
            W("body",
              "NTFSecur is a Windows desktop application (.exe) for comprehensive management of "
              "NTFS partition security, BitLocker encryption, system monitoring "
              "and USB device management. Written in Python 3 + tkinter, "
              "it requires no additional system dependencies — "
              "it runs as a standalone .exe file.\n\n")
            W("h2", "System Requirements\n")
            reqs = [
                ("Operating System", "Windows 10/11 (64-bit) — full functionality\n  Linux — partial support (monitoring, USB, logs)"),
                ("Permissions",      "User account — read-only mode\n  Administrator — NTFSecur, BitLocker, services, processes"),
                ("Python",            "3.9+ (embedded in .exe — no separate installation required)"),
                ("RAM",               "~50 MB during operation, ~120 MB during report generation"),
                ("Disk",              "~25 MB (.exe) + data in %LOCALAPPDATA%\\polsoft.ITS\\"),
            ]
            for key, val in reqs:
                W("kw", f"  {key}:  ")
                W("body", f"{val}\n")
            HR()
            W("h2", "Running as Administrator\n")
            W("body", "Right-click ")
            W("code", "NTFSecur.exe")
            W("body", " → ")
            W("code", "Run as administrator")
            W("body", "\nor in short: Right-click shortcut → Properties → Advanced → ✔ Run as administrator.\n\n")
            W("warn", "⚠  Without administrator privileges, NTFSecur, BitLocker\n"
                      "   and service management are unavailable or restricted.\n"
                      "   Status visible in window header (green ✔ ADMIN / orange ⚠ USER).\n")
            HR()
            W("h2", "Application Files and Folders\n")
            try:
                base = AppPaths.BASE
            except Exception:
                base = "%LOCALAPPDATA%\\polsoft.ITS\\NTFSecur"
            paths = [
                ("settings.json",   "Configuration and user preferences"),
                ("NTFSecur.log",    "Application activity log"),
                ("error.log",       "Error and exception log"),
                ("usb_history.db",  "SQLite USB device history database"),
                ("report/",         "Folder with generated HTML reports"),
            ]
            for fname, desc in paths:
                W("code", f"  {fname:<22}")
                W("body", f"  {desc}\n")
            W("muted", f"\n  Base folder: {base}\n")

        # ──────────────────────────── INTERFEJS ──────────────────────────────
        def make_interface():
            W("h1", "🖥️ User Interface\n")
            W("body", "The application window consists of four fixed zones:\n\n")

            W("h2", "① Header Bar\n")
            W("body", "The top bar contains the logo and application name. On the right side:\n")
            W("body", "  • Privilege status: green ")
            W("ok", "✔ ADMIN")
            W("body", " or orange ")
            W("warn", "⚠ USER\n")
            W("body", "  • 🔒/🔓 Window size lock button\n\n")
            TIP("Click the lock icon to lock the window at its current size — useful when working with multiple monitors.")

            W("h2", "② Menu Bar\n")
            menus = [
                ("File",     "Application settings, theme, log export, exit"),
                ("Modules",  "Quick switching between 12 modules"),
                ("NTFSecur", "Bulk operations: Lock/Unlock all partitions"),
                ("Processes","Refresh process list, terminate selected"),
                ("Services", "Service Start/Stop/Restart, filtering"),
                ("Network",  "Refresh network data, connection test"),
                ("Logs",     "Log filtering, clear view"),
                ("Reports",  "Generate aggregate and partial reports, settings"),
                ("Help",     "Handbook (F1), About, check privileges"),
            ]
            for menu, desc in menus:
                W("kw", f"  {menu:<12}")
                W("body", f"  {desc}\n")

            W("h2", "③ Sidebar Panel\n")
            W("body", "List of 12 module buttons. Clicking switches the active module "
                      "in the main content area. Active module highlighted with accent colour.\n")
            W("body", "Keyboard shortcuts: ")
            W("code", "Ctrl+1")
            W("body", " … ")
            W("code", "Ctrl+9")
            W("body", " (subsequent modules in sidebar order)\n\n")

            W("h2", "④ Status Bar (Footer)\n")
            W("body", "The bottom bar displays the current status of the last operation:\n")
            W("ok", "  ✔ Success")
            W("body", " — operation completed successfully\n")
            W("warn", "  ⚠ Warning")
            W("body", " — attention required, but operation completed\n")
            W("body", "  ✘ Error — operation failed (details in log)\n\n")

            W("h2", "Themes and Customisation\n")
            W("body", "Theme switching: ")
            W("code", "File → Theme: Dark / Light")
            W("body", " or shortcut ")
            W("code", "Ctrl+T")
            W("body", ". Theme is saved and restored on next launch.\n")
            TIP("Light Theme recommended for daytime or print use. Dark Theme reduces eye strain during extended sessions.")

        # ─────────────────────────── MODULES ─────────────────────────────────
        def make_modules():
            W("h1", "📦 Module Overview\n")
            W("body", "The application contains 12 modules accessible from the side panel.\n\n")
            modules_info = [
                ("🔒 NTFSecur",    "Ctrl+1", "NTFS partition write protection (diskpart). Requires administrator."),
                ("🔐 BitLocker",   "Ctrl+2", "Full BitLocker encryption management: enable/disable, PIN, recovery keys."),
                ("💾 Drives",      "Ctrl+3", "Media diagnostics: SMART, chkdsk/fsck, wipe, data recovery."),
                ("🚀 Autostart",   "Ctrl+4", "Autostart entries from registry, Startup folders, and scheduled tasks."),
                ("📊 Processes",   "Ctrl+5", "Process list with PID, memory, status. Filtering and KILL."),
                ("🌐 Network",     "Ctrl+6", "Network interfaces, IP, hostname, connection test, ipconfig/ip addr."),
                ("🔧 Services",    "Ctrl+7", "System services: Start/Stop/Restart, filtering, statuses."),
                ("📋 Logs",        "Ctrl+8", "System events: wevtutil (Win) / journalctl (Linux)."),
                ("🔌 USB",         "Ctrl+9", "Live USB monitoring, history in SQLite, CSV/HTML export."),
                ("📁 Databases",   "—",      "Reference library of 18+ database engines."),
                ("📚 FS Library",  "—",      "Library of 24+ file systems with technical parameters."),
                ("📦 USB Mass DB", "—",      "Database of 24+ USB Mass Storage devices with protocols and speeds."),
            ]
            for name, shortcut, desc in modules_info:
                W("h3", f"{name}  ")
                if shortcut != "—":
                    W("code", shortcut)
                W("body", f"\n  {desc}\n\n")

        # ─────────────────────────── NTFSECUR ────────────────────────────────
        def make_ntfsecur():
            W("h1", "🔒 NTFSecur – NTFS Partition Protection\n")
            W("body",
              "Main application feature — sets write protection (read-only) "
              "on NTFS partitions using the system tool ")
            W("code", "diskpart")
            W("body", " (Windows) or ")
            W("code", "blockdev --setro")
            W("body", " (Linux).\n\n")

            W("h2", "How does SECURE ON / OFF work?\n")
            W("kw", "  SECURE ON  ")
            W("code", "attributes volume set readonly\n")
            W("body", "  The partition becomes read-only. No process can "
                      "write data. The file system remains unchanged.\n"
                      "  The operation is immediate and survives system restarts.\n\n")
            W("kw", "  SECURE OFF  ")
            W("code", "attributes volume clear readonly\n")
            W("body", "  Full write access is restored.\n\n")
            W("warn", "⚠  REQUIRES ADMINISTRATOR privileges.\n"
                      "   The change is permanent until manually changed again.\n\n")
            HR()

            W("h2", "Partition Panel\n")
            W("body", "Each partition card shows:\n"
                      "  • Drive letter and label (e.g. C:\\  Windows)\n"
                      "  • Total size and free space\n"
                      "  • File system type (NTFS/exFAT/FAT32)\n"
                      "  • Current protection status (ON/OFF)\n"
                      "  • SECURE ON/OFF button\n"
                      "  • 🔐 button to open the BitLocker panel for this drive\n\n")
            TIP("The card colour turns green when the partition is secured (SECURE ON).")

            W("h2", "Bulk Operations (NTFSecur menu)\n")
            W("kw", "  Lock all partitions\n")
            W("body", "  Sets SECURE ON on all NTFS partitions simultaneously.\n"
                      "  Operation requires confirmation.\n\n")
            W("kw", "  Unlock all partitions\n")
            W("body", "  Removes protection from all NTFS partitions.\n\n")
            W("warn", "⚠  Locking the system drive (C:\\) may prevent "
                      "the system from writing temporary files. Use with caution.\n")

        # ─────────────────────────── BITLOCKER ───────────────────────────────
        def make_bitlocker():
            W("h1", "🔐 BitLocker – Encryption Management\n")
            W("body",
              "The BitLocker panel provides full drive encryption management "
              "via tools ")
            W("code", "manage-bde")
            W("body", " and PowerShell. Available as a module (list) or panel for a specific drive.\n\n")
            W("warn", "⚠  BitLocker is available exclusively on Windows Pro/Enterprise/Education.\n"
                      "   Windows Home does not support BitLocker encryption.\n\n")

            W("h2", "Operations Available from Panel\n")
            ops = [
                ("Enable encryption",  "manage-bde -on",                 "Starts encryption — may take minutes to hours"),
                ("Disable encryption", "manage-bde -off",                "Decrypts drive — time depends on size"),
                ("Lock drive",         "manage-bde -lock",               "Locks access to the encrypted drive"),
                ("Unlock with password","manage-bde -unlock -Password",  "Unlocks with the given password"),
                ("Unlock with key",    "manage-bde -unlock -rk",         "Unlocks with recovery key (48 digits)"),
                ("Suspend protection", "manage-bde -protectors -disable","Disables protection for N restarts"),
                ("Resume protection",  "manage-bde -protectors -enable", "Restores active protection"),
                ("Get keys",           "manage-bde -protectors -get",    "Displays protector IDs and recovery keys"),
                ("Save key",           "export .txt",                    "Saves recovery key to a text file"),
                ("Backup to AD",       "Backup-BitLockerKeyProtector",   "Archives key in Active Directory"),
                ("Add password",       "-protectors -add -Password",     "Adds a password protector to the drive"),
                ("Add TPM",            "-protectors -add -Tpm",          "Adds a TPM protector"),
                ("Add recovery key",   "-protectors -add -RecoveryPassword","Generates a new 48-digit key"),
                ("Change PIN",         "manage-bde -changepin",          "Changes the TPM+PIN protector PIN"),
                ("Wipe free space",    "manage-bde -wipefreespace",      "Securely overwrites free space"),
            ]
            for op, cmd, desc in ops:
                W("kw", f"  {op:<25}")
                W("code", f"  {cmd}\n")
                W("body", f"    {desc}\n\n")

        # ─────────────────────────── DRIVES ──────────────────────────────────
        def make_drives():
            W("h1", "💾 Drives – Disk Diagnostics\n")
            W("body",
              "The Drives module offers comprehensive media diagnostics with a tabbed "
              "interface split into 6 operating modes.\n\n")

            tabs_desc = [
                ("📋 Scan",         "Detects physical and logical disks, reads parameters (size, free space, FS, serial, model). The ⟳ Scan Drives button runs a full scan."),
                ("🏥 SMART",        "Reads SMART attributes for HDDs and SSDs: temperature, read/write errors, operating hours, reallocated sectors. Requires admin rights and WMI (Windows)."),
                ("🔧 FS Repair",    "Runs chkdsk /f /r (Windows) or fsck (Linux) for the selected volume. Displays the result in the log panel. Requires unmounting the volume."),
                ("💣 Wipe",         "Secure drive erase: overwrite with zeros (1 pass), random data (3 passes) or DoD 5220.22-M standard (7 passes). IRREVERSIBLE."),
                ("🔄 Recovery",     "Scan drive for deleted files (basic — based on file system analysis). Option to export list of found files."),
                ("🔁 Regeneration", "Media regeneration tools: surface fill, sequential read/write test, random access test. Results exported to report."),
            ]
            for tab_name, desc in tabs_desc:
                W("h3", f"{tab_name}\n")
                W("body", f"  {desc}\n\n")

            W("warn", "⚠  The Wipe operation is irreversible. Data will be permanently destroyed.\n"
                      "   Make a backup before use.\n")
            TIP("SMART is only available for physical drives with direct WMI access — virtual volumes (VHD, RAMdisk) have no SMART attributes.")

        # ─────────────────────────── AUTOSTART ───────────────────────────────
        def make_autostart():
            W("h1", "🚀 Autostart – Startup Entries\n")
            W("body",
              "The Autostart module displays and manages entries launched at system "
              "startup from various Windows locations.\n\n")
            W("h2", "Scanned Locations\n")
            locs = [
                ("Registry HKCU\\Run",      "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                ("Registry HKCU\\RunOnce",  "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
                ("Registry HKLM\\Run",      "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                ("Registry HKLM\\RunOnce",  "HKEY_LOCAL_MACHINE\\...\\RunOnce"),
                ("Folder Startup (User)",   "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                ("Folder Startup (System)", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                ("Scheduled Tasks",         "Windows Task Scheduler — tasks with @startup trigger"),
            ]
            for name, path in locs:
                W("kw", f"  {name:<28}")
                W("code", f"  {path}\n")
            W("body", "\n")
            W("h2", "Drive Scan (autorun.inf)\n")
            W("body", "The button ")
            W("code", "🔍 SCAN DRIVES")
            W("body", " searches all volumes for ")
            W("code", "autorun.inf")
            W("body", " — a technique used by USB malware.\n\n")
            TIP("A large number of autostart entries can slow down system startup. Select unnecessary entries and remove them using the button in the entry row.")

        # ─────────────────────────── PROCESY ─────────────────────────────────
        def make_processes():
            W("h1", "📊 Processes – Process Monitor\n")
            W("body", "The Processes module displays the list of active system processes.\n\n")
            W("h2", "Table Columns\n")
            cols = [
                ("PID",      "Process identifier assigned by the operating system"),
                ("Name",     "Executable file name of the process"),
                ("Memory",   "RAM usage in MB"),
                ("Status",   "Running / Sleeping / Zombie (Linux) or no data (Windows)"),
            ]
            for col, desc in cols:
                W("kw", f"  {col:<12}")
                W("body", f"  {desc}\n")
            W("body", "\n")
            W("h2", "Operations\n")
            W("body", "  • Type a name fragment in the filter field to narrow the list in real time\n"
                      "  • Click ")
            W("code", "KILL")
            W("body", " next to a process to terminate it (")
            W("code", "taskkill /F /PID")
            W("body", " on Windows, ")
            W("code", "kill -9")
            W("body", " on Linux)\n"
                      "  • ⟳ REFRESH button or Processes menu → Refresh\n\n")
            W("warn", "⚠  Terminating system processes (lsass.exe, winlogon.exe, etc.) "
                      "may cause system instability or a blue screen.\n")

        # ──────────────────────────── NETWORK ────────────────────────────────
        def make_network():
            W("h1", "🌐 Network – Network Interfaces\n")
            W("body", "The Network module displays network configuration information and tests connections.\n\n")
            W("h2", "Displayed Information\n")
            info_items = [
                ("Hostname",       "Computer name on the network"),
                ("IP (primary)",   "Primary IPv4 address of the outgoing interface"),
                ("System",         "Operating system version"),
                ("Architecture",   "x86 / x64 / ARM"),
                ("Connection test","Ping to Google DNS (8.8.8.8) and Cloudflare (1.1.1.1)"),
                ("Raw data",       "Full output of ipconfig (Windows) or ip addr (Linux)"),
            ]
            for key, desc in info_items:
                W("kw", f"  {key:<22}")
                W("body", f"  {desc}\n")
            W("body", "\n")
            TIP("Connection test uses ping with a 1-second timeout. OFFLINE result may indicate ICMP filtering by firewall — not necessarily no internet.")

        # ─────────────────────────── SERVICES ────────────────────────────────
        def make_services():
            W("h1", "🔧 Services – System Services\n")
            W("body", "The Services module manages Windows and Linux system services.\n\n")
            W("h2", "Data Collection\n")
            W("body", "Windows: ")
            W("code", "sc query type= all state= all\n")
            W("body", "Linux:   ")
            W("code", "systemctl list-units --type=service --all\n\n")
            W("h2", "Operations from Services Menu\n")
            W("body", "  • ")
            W("kw", "Start service")
            W("body", " — ")
            W("code", "sc start <nazwa>")
            W("body", " / ")
            W("code", "systemctl start\n")
            W("body", "  • ")
            W("kw", "Stop service")
            W("body", " — ")
            W("code", "sc stop <nazwa>")
            W("body", " / ")
            W("code", "systemctl stop\n")
            W("body", "  • ")
            W("kw", "Restart")
            W("body", " — ")
            W("code", "sc stop + sc start\n")
            W("body", "  • Filtering — type a name fragment in the filter field\n\n")
            W("warn", "⚠  Stopping critical Windows services (e.g. Winmgmt, EventLog, RpcSs) "
                      "may destabilize the system. Use with caution.\n")

        # ──────────────────────────── LOGI ───────────────────────────────────
        def make_logs():
            W("h1", "📋 Logs – System Events\n")
            W("body", "The Logs module collects events from the system journal.\n\n")
            W("h2", "Data Sources\n")
            W("body", "Windows: ")
            W("code", "wevtutil qe System /c:200 /rd:true /f:text\n")
            W("body", "Linux:   ")
            W("code", "journalctl -n 200 --no-pager\n\n")
            W("h2", "Level Colouring\n")
            W("ok",   "  ✔ INFO")
            W("body", "   — informational events\n")
            W("warn", "  ⚠ WARN")
            W("body", "   — warnings\n")
            W("body", "  ✘ ERROR  — critical errors (highlighted in red)\n\n")
            W("h2", "Filtering and Export\n")
            W("body", "  • Text filter: type a phrase to show matching events\n"
                      "  • Export: Logs menu → Export logs to TXT file\n"
                      "  • Clear view: Logs menu → Clear view\n")
            TIP("Application logs (NTFSecur.log / error.log) are a separate system — available in the Logs module by selecting the 'Application' source.")

        # ──────────────────────────── USB ────────────────────────────────────
        def make_usb():
            W("h1", "🔌 USB – Monitoring and History\n")
            W("body",
              "The USB module provides real-time monitoring of connected "
              "USB Mass Storage devices and a history database.\n\n")

            tabs_usb = [
                ("Live",       "Currently connected USB devices: name, letter, FS, size, free, serial, vendor. ⟳ REFRESH button refreshes the list."),
                ("History",    "All devices ever seen by the application, stored in SQLite database. Columns: first/last date, connection count, serial, vendor. CSV export."),
                ("Events",     "Log of last 200 USB events (DETECTED) with exact timestamp, event type, drive letter and serial."),
                ("Statistics",  "KPI cards: total devices, events, most-connected device, largest media. HTML report generation button."),
            ]
            for tab, desc in tabs_usb:
                W("h2", f"Tab: {tab}\n")
                W("body", f"  {desc}\n\n")

            W("h2", "Database File\n")
            W("body", "Data stored in SQLite: ")
            W("code", "usb_history.db")
            W("body", "\nTables: ")
            W("code", "devices")
            W("body", " (devices) and ")
            W("code", "events")
            W("body", " (events)\n\n")
            TIP("USB History fills automatically when you click ⟳ REFRESH in the Live tab or open the USB module. The database is local — not synchronised with the network.")

        # ─────────────────────────── RAPORTY ─────────────────────────────────
        def make_reports():
            W("h1", "📊 HTML Report System\n")
            W("body",
              "NTFSecur generates standalone HTML reports with full system diagnostics. "
              "Files are saved in the report/ folder next to the application.\n\n")

            W("h2", "Aggregate Report Types\n")
            types = [
                ("⚡ Quick",        "Ctrl+Shift+1", "4 sections",  "Key indicators and alerts — quick overview"),
                ("📊 Normal",       "Ctrl+Shift+2", "6 sections",  "Overview with charts and statistics"),
                ("📋 Full",         "Ctrl+Shift+3", "11 sections", "All sections with charts and summaries"),
                ("🔬 Detailed",     "Ctrl+Shift+4", "11 sections", "All sections + complete data tables"),
            ]
            for name, shortcut, sections, desc in types:
                W("kw", f"  {name:<18}")
                W("code", f"{shortcut:<16}")
                W("muted", f" ({sections})\n")
                W("body", f"    {desc}\n\n")

            W("h2", "Partial Reports\n")
            W("body", "Menu ")
            W("code", "Reports → Partial Report…")
            W("body", " — generates a detailed report for one section:\n"
                      "  NTFSecur  ·  BitLocker  ·  Processes  ·  Services  ·  Network\n"
                      "  Logs  ·  USB  ·  Autostart  ·  Drives  ·  Databases  ·  FS Library\n\n")

            W("h2", "Advanced Wizard  ")
            W("code", "Ctrl+Shift+R\n")
            W("body",
              "  • Report type selection (Quick/Normal/Full/Detailed)\n"
              "  • Precise section selection with checkboxes\n"
              "  • Data collection progress bar\n"
              "  • Automatic opening after generation\n\n")

            W("h2", "Report Settings  ")
            W("code", "Reports → Report Settings…\n\n")
            settings_tabs = [
                ("🎨 Appearance",  "Theme (dark/light), accent colour (6 presets + custom hex), font size, compact layout, live preview"),
                ("📊 Graphics",    "Enable/disable charts (donut, bars, KPI), logo in header, summary card, alerts and warnings"),
                ("📋 Content",     "Table of contents, timestamp, hostname, footer, data depth, row limit in tables, default report type"),
                ("ℹ️  Metadata",   "Author, company, custom footer, notes, classification (Public/Internal/Confidential/Restricted)"),
                ("💾 Export",      "Format (HTML/TXT), target folder, filename pattern ({type} {date} {time} {host} {user}), auto-open, copy path"),
                ("⚙️  Advanced",    "Timeout, HTML minification, font fallback, debug comments, JSON data save, HTML sanitization"),
            ]
            for tab, desc in settings_tabs:
                W("h3", f"Tab: {tab}\n")
                W("body", f"  {desc}\n\n")

            TIP("Settings are applied at the next report generation — no application restart required.")

        # ─────────────────────────── BAZY DANYCH ─────────────────────────────
        def make_databases():
            W("h1", "📁 Databases – Database Library\n")
            W("body",
              "The Databases module is a built-in reference library containing "
              "18+ popular database engines with technical data.\n\n")
            W("h2", "Available Information\n")
            cols = [
                ("Name",        "Full name of the database engine"),
                ("Type",        "Relational / NoSQL / NewSQL / Graph / Time-series / Columnar"),
                ("License",     "Open Source / Commercial / Cloud-only"),
                ("Default port","Listening port (e.g. 5432 for PostgreSQL, 3306 MySQL)"),
                ("OS Support",  "Windows / Linux / macOS / Cloud"),
                ("Features",    "Description of key features and use cases"),
            ]
            for col, desc in cols:
                W("kw", f"  {col:<20}")
                W("body", f"  {desc}\n")
            W("body", "\n")
            W("h2", "Filtering\n")
            W("body", "Type a name fragment in the search field to narrow the list. "
                      "Click a row to see engine details.\n")
            TIP("The library is static (built into the application). No internet connection required.")

        # ─────────────────────────── FS LIBRARY ──────────────────────────────
        def make_fslibrary():
            W("h1", "📚 FS Library – File System Library\n")
            W("body",
              "FS Library contains technical data on 24+ file systems "
              "used in personal computers, servers, and embedded devices.\n\n")
            W("h2", "Technical Data for Each System\n")
            cols = [
                ("Max volume",   "Maximum volume size (e.g. 256 TB for NTFS)"),
                ("Max file",     "Maximum size of a single file"),
                ("OS Support",   "Operating systems: Windows / Linux / macOS / BSD / other"),
                ("Type",        "Journaling / COW / Extent-based / FAT / other"),
                ("Features",    "Compression, deduplication, snapshots, encryption, POSIX ACL, etc."),
            ]
            for col, desc in cols:
                W("kw", f"  {col:<18}")
                W("body", f"  {desc}\n")
            W("body", "\n")
            W("body", "Example systems in the library: NTFS, ext4, Btrfs, ZFS, APFS, exFAT, "
                      "FAT32, XFS, ReiserFS, HPFS, VMFS, F2FS and more.\n")

        # ─────────────────────────── USB MASS DB ─────────────────────────────
        def make_usbmassdb():
            W("h1", "📦 USB Mass DB – USB Device Database\n")
            W("body",
              "USB Mass DB is a reference library of 24+ USB Mass Storage devices "
              "with technical data, transfer speeds, and protocols.\n\n")
            W("h2", "Data for Each Device\n")
            cols = [
                ("Vendor",       "Company name and device model"),
                ("Speed",        "Max read/write speed in MB/s"),
                ("Protocol",     "BOT (Bulk-Only Transfer) / UAS (USB Attached SCSI) / Thunderbolt 3"),
                ("Interface",   "USB 2.0 / USB 3.2 Gen 1 / USB 3.2 Gen 2 / USB4 / TB3"),
                ("Features",     "Hardware encryption, durability, portability, size"),
            ]
            for col, desc in cols:
                W("kw", f"  {col:<18}")
                W("body", f"  {desc}\n")
            W("body", "\n")
            W("h2", "Filter by Protocol\n")
            W("body", "Tabs: ")
            W("code", "All  BOT  UAS  TB3")
            W("body", "\nSwitch the view to devices of that protocol class.\n")

        # ─────────────────────────── SHORTCUTS ───────────────────────────────
        def make_shortcuts():
            W("h1", "⌨️ Keyboard Shortcuts\n")
            groups = [
                ("Navigation", [
                    ("F1",           "Open this Handbook"),
                    ("F5",           "Refresh current module"),
                    ("Ctrl+1…9",     "Switch to module 1–9 (sidebar order)"),
                    ("Ctrl+T",       "Toggle Dark / Light theme"),
                    ("Alt+F4",       "Close application"),
                ]),
                ("Reports", [
                    ("Ctrl+Shift+1", "Generate Quick report"),
                    ("Ctrl+Shift+2", "Generate Normal report"),
                    ("Ctrl+Shift+3", "Generate Full report"),
                    ("Ctrl+Shift+4", "Generate Detailed report"),
                    ("Ctrl+Shift+R", "Open Report Wizard (advanced)"),
                ]),
                ("Handbook", [
                    ("F1",           "Open Handbook"),
                    ("Ctrl+F",       "Focus the search field"),
                    ("Enter",        "Search"),
                    ("Escape",       "Close window"),
                ]),
            ]
            for group_name, items in groups:
                W("h2", f"{group_name}\n")
                for key, desc in items:
                    W("code", f"  {key:<22}")
                    W("body", f"  {desc}\n")
                W("body", "\n")

        # ──────────────────────────── FAQ ─────────────────────────────────────
        def make_faq():
            W("h1", "❓ FAQ – Frequently Asked Questions\n")
            faq = [
                ("Why doesn't SECURE ON work?",
                 "The application requires administrator privileges. Right-click NTFSecur.exe → "
                 "'Run as administrator'. Status visible in header (✔ ADMIN / ⚠ USER)."),
                ("Do NTFSecur changes survive a restart?",
                 "Yes — diskpart sets the volume read-only attribute permanently. "
                 "You must manually click SECURE OFF to restore write access."),
                ("BitLocker shows 'Unavailable' or 'N/A'.",
                 "BitLocker requires Windows Pro/Enterprise/Education. "
                 "Home does not support BitLocker. Check version: Settings → System → About."),
                ("USB History is empty.",
                 "The database is created on first run. "
                 "Click ⟳ REFRESH in the Live tab — devices will appear in History."),
                ("Report does not open automatically.",
                 "Uncheck 'Open After Generation' in Report Settings → Export "
                 "and open the file manually from the report/ folder."),
                ("Processes/Services not visible.",
                 "On Linux, ps/systemctl may require sudo. "
                 "On Windows, check access to tasklist/sc."),
                ("How to export USB history to CSV?",
                 "USB module → History tab → '💾 EXPORT CSV' button."),
                ("Where are the configuration files?",
                 f"All in: {AppPaths.BASE if hasattr(AppPaths,'BASE') else '%LOCALAPPDATA%\\polsoft.ITS'}\n"
                 "  settings.json   — application settings\n"
                 "  NTFSecur.log    — activity log\n"
                 "  error.log       — error log\n"
                 "  usb_history.db  — USB history database"),
                ("How to change the report save folder?",
                 "Reports menu → Report Settings… → Export tab → "
                 "the '…' button next to the Target Folder field."),
                ("Why does the report contain only basic data?",
                 "Check Report Settings → Content → Data Depth. "
                 "Select 'Full' to include all data tables."),
            ]
            for q, a in faq:
                W("h3", f"❓  {q}\n")
                W("body", f"  {a}\n\n")

        # ─────────────────────────── O APLIKACJI ─────────────────────────────
        def make_about():
            W("h1", "ℹ️ About\n\n")
            W("kw",  "Product:         ")
            W("body", f"{__product__}\n")
            W("kw",  "Version:         ")
            W("body", f"{__version__}\n")
            W("kw",  "Author:          ")
            W("body", f"{__author__}\n")
            W("kw",  "E-mail:          ")
            W("body", f"{__email__}\n")
            W("kw",  "GitHub:          ")
            W("body", f"{__github__}\n")
            W("kw",  "Copyright:       ")
            W("body", f"{__copyright__}\n\n")
            HR()
            W("h2", "Technology Stack\n")
            stack = [
                ("Python 3.9+",        "Programming language — embedded in .exe"),
                ("tkinter / ttk",      "GUI framework — native Windows/Linux interface"),
                ("SQLite3",            "USB history database — built into Python"),
                ("threading",          "Asynchronous operations — non-blocking UI"),
                ("subprocess",         "Calls: diskpart, manage-bde, powershell, tasklist"),
                ("PyInstaller",        "Packaging to .exe — one file, zero dependencies"),
            ]
            for tech, desc in stack:
                W("kw", f"  {tech:<22}")
                W("body", f"  {desc}\n")
            W("body", "\n")
            HR()
            W("h2", "License\n")
            W("body",
              "All rights reserved. Software intended exclusively "
              "for use by authorised users and system administrators. "
              "Redistribution without the author's written consent is prohibited.\n")

        # ── chapter registration ────────────────────────────────────────────────
        CHAPTER_GROUPS = [
            ("GENERAL", [
                ("intro",       "📋 Introduction",        make_intro),
                ("interface",   "🖥️  Interface",            make_interface),
                ("modules",     "📦 Modules – Overview",  make_modules),
            ]),
            ("MODULES", [
                ("ntfsecur",    "🔒 NTFSecur",            make_ntfsecur),
                ("bitlocker",   "🔐 BitLocker",           make_bitlocker),
                ("drives",      "💾 Drives",              make_drives),
                ("autostart",   "🚀 Autostart",           make_autostart),
                ("processes",   "📊 Processes",           make_processes),
                ("network",     "🌐 Network",             make_network),
                ("services",    "🔧 Services",            make_services),
                ("logs",        "📋 Logs",                make_logs),
                ("usb",         "🔌 USB",                 make_usb),
                ("databases",   "📁 Databases",           make_databases),
                ("fslibrary",   "📚 FS Library",          make_fslibrary),
                ("usbmassdb",   "📦 USB Mass DB",         make_usbmassdb),
            ]),
            ("TOOLS", [
                ("reports",     "📊 Reports",             make_reports),
                ("shortcuts",   "⌨️  Keyboard Shortcuts",  make_shortcuts),
                ("faq",         "❓ FAQ",                  make_faq),
                ("about",       "ℹ️  About",               make_about),
            ]),
        ]

        for group_name, items in CHAPTER_GROUPS:
            # group header
            tk.Label(sidebar, text=f"  {group_name}",
                     font=("Segoe UI", 7, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE
                     ).pack(anchor=tk.W, padx=8, pady=(10,2))
            for cid, title, fn in items:
                CHAPTERS[cid] = (title, fn)

        # ── active tab + switching ──────────────────────────────────────────────
        active_ch = [None]
        ch_btns   = {}

        def _show_chapter(cid):
            if active_ch[0] == cid:
                return
            active_ch[0] = cid
            for k, b in ch_btns.items():
                if k == cid:
                    b.configure(bg=self.CLR_GLOW, fg=self.CLR_ACCENT,
                                font=("Segoe UI", 10, "bold"), relief=tk.SUNKEN)
                else:
                    b.configure(bg=self.CLR_SURFACE, fg=self.CLR_TEXT2,
                                font=("Segoe UI", 10), relief=tk.FLAT)
            txt.config(state=tk.NORMAL)
            txt.delete("1.0", tk.END)
            txt.config(state=tk.DISABLED)
            CHAPTERS[cid][1]()
            txt.config(state=tk.NORMAL)
            txt.see("1.0")
            txt.config(state=tk.DISABLED)
            search_result_var.set("")

        # generate buttons after CHAPTERS is populated
        for group_name, items in CHAPTER_GROUPS:
            tk.Label(sidebar, text=f"  {group_name}",
                     font=("Segoe UI", 7, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE
                     ).pack(anchor=tk.W, padx=8, pady=(10,2))
            for cid, title, fn in items:
                b = tk.Button(sidebar, text=f"  {title}",
                              font=("Segoe UI", 10), fg=self.CLR_TEXT2,
                              bg=self.CLR_SURFACE, relief=tk.FLAT, bd=0,
                              padx=6, pady=5, anchor=tk.W, cursor="hand2",
                              activebackground=self.CLR_GLOW,
                              activeforeground=self.CLR_ACCENT,
                              command=lambda c=cid: _show_chapter(c))
                b.pack(fill=tk.X, padx=4, pady=1)
                ch_btns[cid] = b

        # ── wyszukiwarka ──────────────────────────────────────────────────────
        def _do_search(*_):
            q = search_var.get().strip().lower()
            if not q:
                search_result_var.set("")
                return
            hits = []
            for cid, (title, fn) in CHAPTERS.items():
                txt.config(state=tk.NORMAL)
                txt.delete("1.0", tk.END)
                txt.config(state=tk.DISABLED)
                fn()
                raw = txt.get("1.0", tk.END).lower()
                if q in raw:
                    hits.append(cid)
            if hits:
                search_result_var.set(f"✔ Found in {len(hits)} chapter(s)")
                _show_chapter(hits[0])
                txt.config(state=tk.NORMAL)
                start = "1.0"
                while True:
                    idx = txt.search(q, start, nocase=True, stopindex=tk.END)
                    if not idx:
                        break
                    end = f"{idx}+{len(q)}c"
                    txt.tag_add("found_bg", idx, end)
                    start = end
                txt.config(state=tk.DISABLED)
            else:
                search_result_var.set("✘ Not Found")
                if active_ch[0]:
                    _show_chapter(active_ch[0])

        search_var.trace_add("write", _do_search)
        search_ent.bind("<Return>", _do_search)
        win.bind("<Escape>", lambda e: win.destroy())
        win.bind("<Control-f>", lambda e: (search_ent.focus_set(), search_ent.select_range(0, tk.END)))

        # ── dolny pasek ───────────────────────────────────────────────────────
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, side=tk.BOTTOM)
        bot = tk.Frame(win, bg=self.CLR_HEADER_BG)
        bot.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(bot,
                 text=f"NTFSecur v{__version__}  ·  F1 — Handbook  ·  Ctrl+F — {_t('Szukaj')}  ·  Esc — {_t('Zamknij')}",
                 font=("Segoe UI", 9), fg=self.CLR_BORDER,
                 bg=self.CLR_HEADER_BG).pack(side=tk.LEFT, padx=12, pady=6)
        tk.Button(bot, text=_t("Zamknij"),
                  font=("Segoe UI", 10, "bold"),
                  fg=self.CLR_HEADER_BG, bg=self.CLR_ACCENT,
                  relief=tk.FLAT, padx=14, pady=4, cursor="hand2",
                  command=win.destroy).pack(side=tk.RIGHT, padx=12, pady=6)

        _show_chapter("intro")


    def _menu_about(self):
        win = tk.Toplevel(self)
        win.title(_t("O programie"))
        win.configure(bg=self.CLR_SURFACE)
        win.resizable(False, False)
        win.grab_set()

        # Centre window
        win.update_idletasks()
        w, h = 400, 280
        x = self.winfo_x() + (self.winfo_width()  - w) // 2
        y = self.winfo_y() + (self.winfo_height() - h) // 2
        win.geometry(f"{w}x{h}+{x}+{y}")

        tk.Frame(win, bg=self.CLR_ACCENT, height=3).pack(fill=tk.X)
        tk.Label(win, text="⬡", font=("Segoe UI", 36, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_SURFACE).pack(pady=(18, 4))
        tk.Label(win, text=__product__, font=("Segoe UI", 13, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack()
        tk.Label(win, text=f"{_t('Wersja')} {__version__}",
                 font=("Segoe UI", 10), fg=self.CLR_MUTED, bg=self.CLR_SURFACE).pack(pady=2)
        tk.Frame(win, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=30, pady=10)
        tk.Label(win, text=f"{_t('Autor:')} {__author__}",
                 font=("Segoe UI", 10), fg=self.CLR_TEXT2, bg=self.CLR_SURFACE).pack()
        tk.Label(win, text=f"{_t('E-mail:')} {__email__}",
                 font=("Segoe UI", 10), fg=self.CLR_TEXT2, bg=self.CLR_SURFACE).pack()
        tk.Label(win, text=__copyright__,
                 font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_SURFACE).pack(pady=(8, 0))
        tk.Button(win, text=_t("Zamknij"), font=("Segoe UI", 10, "bold"),
                  fg=self.CLR_HEADER_BG, bg=self.CLR_ACCENT,
                  relief=tk.FLAT, padx=20, pady=6,
                  cursor="hand2", command=win.destroy).pack(pady=16)

    def _menu_check_admin(self):
        if is_admin():
            messagebox.showinfo(_t("Uprawnienia administratora"),
                                _t("✔  Aplikacja działa z uprawnieniami ADMINISTRATORA.\n\n")
                                + _t("Wszystkie operacje systemowe są dostępne."))
        else:
            messagebox.showwarning(_t("Uprawnienia użytkownika"),
                                   _t("⚠  Aplikacja działa BEZ uprawnień administratora.\n\n")
                                   + _t("Niektóre funkcje (NTFSecur, zarządzanie usługami)\n")
                                   + _t("wymagają ponownego uruchomienia jako Administrator."))

    # ══════════════════════════════════════════════════════════════════════════
    #  AERO GLASS + 3D ENGINE
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _hex_to_rgb(h):
        h = h.lstrip("#")
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

    @staticmethod
    def _rgb_to_hex(r, g, b):
        r = max(0, min(255, int(r)))
        g = max(0, min(255, int(g)))
        b = max(0, min(255, int(b)))
        return f"#{r:02x}{g:02x}{b:02x}"

    def _lerp_color(self, c1, c2, t):
        t = max(0.0, min(1.0, t))
        r1, g1, b1 = self._hex_to_rgb(c1)
        r2, g2, b2 = self._hex_to_rgb(c2)
        return self._rgb_to_hex(r1+(r2-r1)*t, g1+(g2-g1)*t, b1+(b2-b1)*t)

    def _brighten(self, col, amt):
        """Lighten a color by amt (0..1)."""
        return self._lerp_color(col, "#FFFFFF", amt)

    def _darken(self, col, amt):
        """Darken a color by amt (0..1)."""
        return self._lerp_color(col, "#000000", amt)

    def _draw_aero_gradient(self, canvas, w, h, top_col, bot_col, steps=40, x0=0, tags=None):
        """Smooth vertical gradient band."""
        sh  = max(1, h / steps)
        kw  = {"tags": tags} if tags else {}
        for i in range(steps + 1):
            t   = i / steps
            col = self._lerp_color(top_col, bot_col, t)
            y0  = int(i * sh)
            y1  = int((i+1) * sh) + 1
            canvas.create_rectangle(x0, y0, x0+w, y1, fill=col, outline=col, **kw)

    def _draw_aero_gradient_offset(self, canvas, w, y_start, y_end, top_col, bot_col, steps=20):
        """Vertical gradient between y_start..y_end."""
        span = max(1, y_end - y_start)
        sh   = span / steps
        for i in range(steps + 1):
            t   = i / steps
            col = self._lerp_color(top_col, bot_col, t)
            y0  = y_start + int(i * sh)
            y1  = y_start + int((i+1) * sh) + 1
            canvas.create_rectangle(0, y0, w, y1, fill=col, outline=col)

    def _draw_3d_gloss(self, canvas, x0, y0, x1, y1, base_col, gloss_frac=0.48, steps=20):
        """Flat top highlight strip (replaces former 3D gloss bubble)."""
        rim = self._lerp_color("#FFFFFF", base_col, 0.35)
        canvas.create_line(x0+2, y0+1, x1-2, y0+1, fill=rim, width=1)

    def _draw_3d_bevel(self, canvas, x0, y0, x1, y1,
                       highlight=None, shadow=None, thickness=2):
        """Flat border (replaces former 3D raised bevel)."""
        border = highlight or "#6A9AC8"
        for k in range(thickness):
            canvas.create_rectangle(x0+k, y0+k, x1-k, y1-k,
                                    outline=border, fill="")

    def _draw_3d_inset(self, canvas, x0, y0, x1, y1,
                       highlight=None, shadow=None, thickness=1):
        """Flat inset border (replaces former sunken 3D bevel)."""
        border = shadow or "#06090F"
        for k in range(thickness):
            canvas.create_rectangle(x0+k, y0+k, x1-k, y1-k,
                                    outline=border, fill="")

    def _draw_rounded_rect(self, canvas, x0, y0, x1, y1, r, fill, outline="", width=0):
        """Draw a rounded rectangle using polygon approximation."""
        # Build 4 arcs at corners
        pts = []
        import math
        corners = [
            (x0+r, y0+r, 180, 270),
            (x1-r, y0+r, 270, 360),
            (x1-r, y1-r,   0,  90),
            (x0+r, y1-r,  90, 180),
        ]
        segs = 8
        for (cx, cy, a_start, a_end) in corners:
            for s in range(segs+1):
                ang = math.radians(a_start + (a_end-a_start)*s/segs)
                pts += [cx + r*math.cos(ang), cy + r*math.sin(ang)]
        canvas.create_polygon(pts, fill=fill, outline=outline, width=width, smooth=True)

    def _draw_aero_glass_panel(self, canvas, x0, y0, x1, y1, base_col,
                               radius=6, bevel=2, title_frac=0.46):
        """
        Full Aero glass panel with:
          - deep gradient background (cool blue-tinted)
          - 3D raised bevel
          - strong top gloss bubble (Windows 7 Aero style)
          - inner shadow inset
          - subtle blue sheen overlay
        """
        W, H = x1-x0, y1-y0
        # 1) Deep Aero background gradient — darker, more saturated blue
        top_c = self._brighten(base_col, 0.12)
        bot_c = self._darken(base_col,  0.28)
        self._draw_aero_gradient(canvas, W, H, top_c, bot_c, steps=40, x0=x0)
        # 1b) Subtle gold-tint overlay scanlines (flat shimmer)
        for y in range(int(H * 0.60)):
            t = y / max(1, int(H * 0.60))
            alpha = (1.0 - t) * 0.06
            if alpha > 0.01 and y % 3 == 0:
                tint = self._lerp_color(base_col, "#1060C0", alpha)
                canvas.create_line(x0+bevel, y0+y, x1-bevel, y0+y, fill=tint)
        # 2) Gloss bubble — stronger, wider (Aero hallmark)
        self._draw_3d_gloss(canvas, x0, y0, x1, y1, base_col,
                            gloss_frac=max(title_frac, 0.52), steps=18)
        # 3) Outer bevel (raised) — brighter highlights
        self._draw_3d_bevel(canvas, x0, y0, x1, y1,
                            highlight=self._brighten(base_col, 0.50),
                            shadow   =self._darken(base_col, 0.65),
                            thickness=bevel)
        # 4) Inner highlight (1px inset from bevel)
        ofs = bevel
        canvas.create_line(x0+ofs, y0+ofs, x1-ofs, y0+ofs,
                           fill=self._brighten(base_col, 0.28), width=1)
        canvas.create_line(x0+ofs, y0+ofs, x0+ofs, y1-ofs,
                           fill=self._brighten(base_col, 0.28), width=1)

    def _build_header(self):
        """
        Animated 3-D header banner:
          • Parallax depth-layer gradient redrawn on resize
          • Animated particle stream (floating cyan dots)
          • 3-D extruded text title (depth shadow stack)
          • Rotating 3-D hexagon logo with face + edge shading
          • Animated glowing bottom accent line (wave)
          • Animated shimmer/scan sweep across the banner
          • Admin badge with pulsing status glow
          • Pin button unchanged
        """
        import math, random

        HDR_H = 100
        BASE  = "#05080F"
        MID   = "#0A1428"
        TOP   = "#112040"
        GLOW  = "#082050"

        # ── Shadow strips ────────────────────────────────────────────────────
        for col in ("#000000", "#020408", "#040810"):
            tk.Frame(self, bg=col, height=1).pack(fill=tk.X, side=tk.TOP)

        hdr_canvas = tk.Canvas(self, height=HDR_H, highlightthickness=0, bd=0, bg=BASE)
        hdr_canvas.pack(fill=tk.X, side=tk.TOP)

        # ── Animation state ──────────────────────────────────────────────────
        anim = {
            "t":         0.0,     # global time counter
            "sweep_x":   -300,    # shimmer sweep X
            "logo_angle": 0.0,    # hex rotation angle (degrees)
            "wave_phase": 0.0,    # bottom wave phase
            "particles":  [],     # list of {x,y,vx,vy,r,alpha}
            "title_glow": 0.0,    # title glow pulse 0..1
            "title_dir":  1,
            "badge_pulse": 0.0,
            "badge_dir":   1,
        }

        # Seed particles
        def _init_particles(W):
            anim["particles"] = []
            for _ in range(28):
                anim["particles"].append({
                    "x":     random.uniform(0, W),
                    "y":     random.uniform(0, HDR_H),
                    "vx":    random.uniform(0.2, 0.8),
                    "vy":    random.uniform(-0.15, 0.15),
                    "r":     random.uniform(1.0, 2.5),
                    "alpha": random.uniform(0.2, 0.9),
                    "da":    random.uniform(0.005, 0.015) * random.choice([-1, 1]),
                })

        _W_last = [0]

        # ── Static depth-layer background (redrawn on resize) ────────────────
        def _draw_bg(W, H):
            hdr_canvas.delete("bg")
            # Layer 0: base deep gradient (3 zones for 3-D depth illusion)
            for y in range(H):
                t = y / max(1, H)
                if t < 0.45:
                    col = self._lerp_color(BASE, MID,  t / 0.45)
                elif t < 0.72:
                    col = self._lerp_color(MID,  TOP, (t - 0.45) / 0.27)
                else:
                    col = self._lerp_color(TOP, GLOW,  (t - 0.72) / 0.28)
                hdr_canvas.create_line(0, y, W, y, fill=col, tags="bg")
            # Layer 1: perspective grid lines (receding to vanishing point)
            VP_X, VP_Y = W // 2, -HDR_H * 2
            n_lines = 10
            for i in range(n_lines + 1):
                t   = i / n_lines
                bx  = int(t * W)
                col = self._lerp_color("#0A1830", BASE, abs(t - 0.5) * 1.8)
                hdr_canvas.create_line(VP_X, VP_Y, bx, H, fill=col, width=1, tags="bg")
            # Layer 2: horizontal depth bands
            for band in range(4):
                t   = (band + 1) / 5
                by  = int(H * t)
                col = self._lerp_color(self.CLR_ACCENT, BASE, 0.88 + band * 0.03)
                hdr_canvas.create_line(0, by, W, by, fill=col, tags="bg")
            # Layer 3: vignette edges (top + bottom darker)
            for y in range(12):
                a   = (1 - y / 12) * 0.7
                col = self._lerp_color(BASE, "#000000", a)
                hdr_canvas.create_line(0, y, W, y, fill=col, tags="bg")
            for y in range(8):
                a   = (1 - y / 8) * 0.5
                col = self._lerp_color(BASE, "#000000", a)
                hdr_canvas.create_line(0, H - 1 - y, W, H - 1 - y, fill=col, tags="bg")

        # ── 3-D extruded text ────────────────────────────────────────────────
        TITLE    = "SYSTEM MANAGEMENT PANEL"
        SUBTITLE = "polsoft.ITS\u2122   \u00b7   Professional System Management Centre   \u00b7   NTFSecur"
        DEPTH    = 5          # extrusion depth (px)
        TX, TY   = 104, HDR_H // 2 - 14
        SX, SY   = 104, HDR_H // 2 + 16

        def _draw_title_3d(W, glow_t):
            hdr_canvas.delete("title")
            # Extrusion layers (back to front)
            for d in range(DEPTH, 0, -1):
                fade = d / DEPTH
                ec   = self._lerp_color(self.CLR_ACCENT2, "#000000", 0.55 + fade * 0.35)
                hdr_canvas.create_text(TX + d, TY + d, text=TITLE,
                                       font=("Segoe UI", 15, "bold"),
                                       fill=ec, anchor=tk.W, tags="title")
            # Glow halo behind text
            gc = self._lerp_color(self.CLR_ACCENT, BASE, 0.60 - glow_t * 0.18)
            hdr_canvas.create_text(TX + 1, TY + 1, text=TITLE,
                                   font=("Segoe UI", 15, "bold"),
                                   fill=gc, anchor=tk.W, tags="title")
            # Front face (bright)
            fc = self._lerp_color(self.CLR_TEXT, self.CLR_ACCENT, glow_t * 0.35)
            hdr_canvas.create_text(TX, TY, text=TITLE,
                                   font=("Segoe UI", 15, "bold"),
                                   fill=fc, anchor=tk.W, tags="title")
            # Subtitle
            hdr_canvas.create_text(SX + 1, SY + 1, text=SUBTITLE,
                                   font=("Segoe UI", 8),
                                   fill=self._darken(self.CLR_MUTED, 0.4),
                                   anchor=tk.W, tags="title")
            hdr_canvas.create_text(SX, SY, text=SUBTITLE,
                                   font=("Segoe UI", 8),
                                   fill=self.CLR_MUTED, anchor=tk.W, tags="title")

        # ── 3-D rotating hexagon logo ────────────────────────────────────────
        LOGO_CX, LOGO_CY = 60, HDR_H // 2
        LOGO_R  = 30
        LOGO_RZ = 10   # Z-radius for 3-D depth effect

        def _draw_logo_3d(angle):
            hdr_canvas.delete("logo")
            a_rad = math.radians(angle)
            # Back-face shadow offset
            for d in range(4, 0, -1):
                pts_s = []
                for i in range(6):
                    a = math.radians(60 * i - 30) + a_rad
                    # Perspective squeeze on X based on angle
                    sx = math.cos(a) * LOGO_R * (0.82 + 0.18 * math.cos(a_rad))
                    sy = math.sin(a) * LOGO_R
                    pts_s += [LOGO_CX + sx + d, LOGO_CY + sy + d]
                col = self._lerp_color(self.CLR_ACCENT2, "#000000", 0.55 + d * 0.1)
                hdr_canvas.create_polygon(pts_s, fill=col, outline="", tags="logo")
            # Face fill with angular shading (light from top-left)
            pts = []
            for i in range(6):
                a  = math.radians(60 * i - 30) + a_rad
                sx = math.cos(a) * LOGO_R * (0.82 + 0.18 * math.cos(a_rad))
                sy = math.sin(a) * LOGO_R
                pts += [LOGO_CX + sx, LOGO_CY + sy]
            hdr_canvas.create_polygon(pts, fill=self.CLR_GLOW,
                                      outline=self.CLR_ACCENT, width=2, tags="logo")
            # Inner highlight triangle (3-D face light)
            hi_pts = []
            for i in [0, 1, 5]:
                a  = math.radians(60 * i - 30) + a_rad
                sx = math.cos(a) * LOGO_R * 0.55
                sy = math.sin(a) * LOGO_R * 0.55
                hi_pts += [LOGO_CX + sx, LOGO_CY + sy]
            hdr_canvas.create_polygon(hi_pts,
                                      fill=self._lerp_color(self.CLR_ACCENT, self.CLR_GLOW, 0.55),
                                      outline="", tags="logo")
            # Inner accent ring
            inner_pts = []
            for i in range(6):
                a  = math.radians(60 * i - 30) + a_rad
                sx = math.cos(a) * (LOGO_R * 0.46)
                sy = math.sin(a) * (LOGO_R * 0.46)
                inner_pts += [LOGO_CX + sx, LOGO_CY + sy]
            hdr_canvas.create_polygon(inner_pts,
                                      fill=self.CLR_ACCENT, outline="", tags="logo")
            # Centre dot
            hdr_canvas.create_oval(LOGO_CX - 4, LOGO_CY - 4,
                                   LOGO_CX + 4, LOGO_CY + 4,
                                   fill=self.CLR_TEXT, outline="", tags="logo")

        # ── Shimmer sweep ────────────────────────────────────────────────────
        def _draw_sweep(W, H, sx):
            hdr_canvas.delete("sweep")
            if sx < -80 or sx > W + 80:
                return
            sw = 60
            for dx in range(sw):
                t   = dx / sw
                # bell curve peak at centre of sweep band
                bell = math.exp(-((t - 0.5) ** 2) / 0.06)
                col  = self._lerp_color(BASE, self.CLR_ACCENT, bell * 0.18)
                hdr_canvas.create_line(sx + dx, 0, sx + dx, H,
                                       fill=col, tags="sweep")

        # ── Animated wave accent line ────────────────────────────────────────
        def _draw_wave(W, H, phase):
            hdr_canvas.delete("wave")
            pts = []
            for x in range(0, W + 4, 4):
                y = H - 3 + int(2.5 * math.sin(x * 0.025 + phase))
                pts.extend([x, y])
            if len(pts) >= 4:
                hdr_canvas.create_line(pts, fill=self.CLR_ACCENT2,
                                       width=1, smooth=True, tags="wave")
            pts2 = []
            for x in range(0, W + 4, 4):
                y = H - 1 + int(1.5 * math.sin(x * 0.030 + phase + 1.2))
                pts2.extend([x, y])
            if len(pts2) >= 4:
                hdr_canvas.create_line(pts2, fill=self.CLR_ACCENT,
                                       width=2, smooth=True, tags="wave")

        # ── Animated particles ───────────────────────────────────────────────
        def _draw_particles(W, H):
            hdr_canvas.delete("part")
            for p in anim["particles"]:
                # Move
                p["x"]     = (p["x"] + p["vx"]) % (W + 20)
                p["y"]     = max(2, min(H - 2, p["y"] + p["vy"]))
                if p["y"] <= 2 or p["y"] >= H - 2:
                    p["vy"] *= -1
                p["alpha"] = max(0.1, min(1.0, p["alpha"] + p["da"]))
                if p["alpha"] <= 0.1 or p["alpha"] >= 0.95:
                    p["da"] *= -1
                r   = p["r"]
                col = self._lerp_color(BASE, self.CLR_ACCENT, p["alpha"] * 0.7)
                hdr_canvas.create_oval(p["x"] - r, p["y"] - r,
                                       p["x"] + r, p["y"] + r,
                                       fill=col, outline="", tags="part")

        # ── Admin badge ──────────────────────────────────────────────────────
        admin_on  = is_admin()
        badge_col = self.CLR_SUCCESS if admin_on else self.CLR_DANGER

        adm_c = tk.Canvas(hdr_canvas, width=96, height=34,
                          bg=BASE, highlightthickness=0, bd=0)

        def _draw_badge(pulse_t=0.0):
            adm_c.delete("all")
            W2, H2 = 96, 34
            adm_c.create_rectangle(0, 0, W2, H2,
                                   fill=self._lerp_color(BASE, badge_col, 0.08),
                                   outline=self._lerp_color(badge_col, BASE, 0.4 - pulse_t * 0.2),
                                   width=1)
            # Pulsing glow border
            if pulse_t > 0.3:
                adm_c.create_rectangle(1, 1, W2 - 1, H2 - 1,
                                       fill="", outline=self._lerp_color(badge_col, BASE, 0.6 - pulse_t * 0.3),
                                       width=1)
            dot_r = int(3 + pulse_t * 2)
            adm_c.create_oval(8 - dot_r, H2 // 2 - dot_r,
                               8 + dot_r, H2 // 2 + dot_r,
                               fill=self._lerp_color(badge_col, self.CLR_TEXT, pulse_t * 0.4),
                               outline="")
            badge_text = "ADMIN" if admin_on else "USER"
            adm_c.create_text(54, H2 // 2, text=badge_text,
                               font=("Segoe UI", 9, "bold"),
                               fill=self._lerp_color(badge_col, self.CLR_TEXT, pulse_t * 0.3),
                               anchor=tk.CENTER)

        _draw_badge()
        hdr_canvas.create_window(0, HDR_H // 2, window=adm_c,
                                 anchor=tk.E, tags="adm_badge")

        # ── Pin button ───────────────────────────────────────────────────────
        pin_c = tk.Canvas(hdr_canvas, width=42, height=42,
                          bg=BASE, highlightthickness=0, bd=0, cursor="hand2")
        hdr_canvas.create_window(0, HDR_H // 2, window=pin_c,
                                 anchor=tk.E, tags="pin_btn")

        def _draw_pin(active, hover=False):
            pin_c.delete("all")
            W2, H2 = 42, 42
            CX, CY = W2 // 2, H2 // 2

            # ── Paleta kolorów ────────────────────────────────────────────────
            ACCENT     = self.CLR_ACCENT
            RED_BASE   = "#BB1A1A"
            RED_MID    = "#DD2828"
            RED_BRIGHT = "#FF4040"
            RED_RIM    = "#FF7070"
            RED_SHEEN  = "#FFB0B0"
            GOLD       = "#D4A840"
            GOLD_BR    = "#FFD060"
            STEEL_TOP  = "#E8F0F8"
            STEEL_MID  = "#A8B8C8"
            STEEL_DK   = "#506070"
            STEEL_SHD  = "#283040"
            W_HL       = "#FFFFFF"

            lp = self._lerp_color

            # ── Wybór trybu ───────────────────────────────────────────────────
            if active:
                btn_top  = lp(RED_MID,    BASE, 0.05)
                btn_bot  = lp(RED_BASE,   BASE, 0.25)
                rim_col  = lp(RED_BRIGHT, BASE, 0.30)
                glow_col = lp(RED_BRIGHT, BASE, 0.55)
            elif hover:
                btn_top  = lp(ACCENT,     BASE, 0.12)
                btn_bot  = lp(ACCENT,     BASE, 0.30)
                rim_col  = lp(ACCENT,     BASE, 0.45)
                glow_col = lp(ACCENT,     BASE, 0.65)
            else:
                btn_top  = lp("#1C2E48",  BASE, 0.0)
                btn_bot  = lp("#0C1A2C",  BASE, 0.0)
                rim_col  = lp(STEEL_DK,   BASE, 0.40)
                glow_col = ""

            # ── Zewnętrzny cień (drop shadow) ─────────────────────────────────
            for i in range(4, 0, -1):
                alpha = 0.12 * i
                pin_c.create_oval(2+i, 3+i, W2-1, H2-1,
                                  fill=lp("#000000", BASE, 1.0-alpha*0.6), outline="")

            # ── Glow ring (active / hover) ────────────────────────────────────
            if glow_col:
                pin_c.create_oval(0, 0, W2, H2, fill="", outline=glow_col, width=3)
                pin_c.create_oval(1, 1, W2-1, H2-1, fill="", outline=lp(glow_col, BASE, 0.5), width=1)

            # ── Główne ciało przycisku — wielowarstwowy gradient 3D ──────────
            # Warstwa 1: ciemna podstawa (dół / cień)
            pin_c.create_oval(3, 3, W2-3, H2-3, fill=btn_bot, outline="")
            # Warstwa 2: jaśniejszy obszar środkowy (góra)
            pin_c.create_oval(3, 3, W2-3, CY+4,
                              fill=btn_top, outline="")
            # Warstwa 3: obramowanie metaliczne
            pin_c.create_oval(3, 3, W2-3, H2-3,
                              fill="", outline=rim_col, width=1)

            # ── Reflex — rozjaśnienie górnej-lewej ćwiartki ───────────────────
            hl_col = lp(STEEL_TOP, btn_top, 0.82)
            pin_c.create_oval(5, 5, W2-12, CY-1, fill=hl_col, outline="")
            pin_c.create_oval(5, 5, W2-18, CY-6,
                              fill=lp(W_HL, btn_top, 0.90), outline="")

            # ── Wewnętrzny ring (bevel) ───────────────────────────────────────
            pin_c.create_oval(5, 5, W2-5, H2-5, fill="",
                              outline=lp(STEEL_TOP, btn_top, 0.82), width=1)
            pin_c.create_oval(6, 6, W2-6, H2-6, fill="",
                              outline=lp(STEEL_DK,  btn_bot, 0.55), width=1)

            # ════════════════════════════════════════════════════════════════
            #  IKONA PINEZKI — kompletny model 3D
            # ════════════════════════════════════════════════════════════════
            PX, PY = CX, CY + 2

            # Aktywny / hover -> jaśniejsza pinezka; normalny -> ciemniejsza
            if active:
                h_col  = RED_BRIGHT
                h_rim  = RED_RIM
                h_sheen= RED_SHEEN
                n_top  = STEEL_TOP
                n_mid  = STEEL_MID
                n_dk   = STEEL_DK
                n_shd  = STEEL_SHD
            elif hover:
                h_col  = lp(RED_MID, RED_BRIGHT, 0.6)
                h_rim  = lp(RED_MID, RED_RIM, 0.5)
                h_sheen= lp(RED_MID, RED_SHEEN, 0.4)
                n_top  = lp(STEEL_MID, STEEL_TOP, 0.5)
                n_mid  = STEEL_MID
                n_dk   = lp(STEEL_DK,  STEEL_MID, 0.3)
                n_shd  = STEEL_SHD
            else:
                h_col  = RED_BASE
                h_rim  = RED_MID
                h_sheen= lp(RED_MID, RED_SHEEN, 0.25)
                n_top  = STEEL_MID
                n_mid  = lp(STEEL_DK, STEEL_MID, 0.4)
                n_dk   = STEEL_DK
                n_shd  = self._darken(STEEL_SHD, 0.4)

            # -- Trzonek (shaft) — cień pod -----------------------------------
            pin_c.create_rectangle(PX-3, PY-3, PX+4, PY+9,
                                   fill=lp(n_shd, BASE, 0.3), outline="")
            # -- Trzonek — lewa ścianka (ciemniejsza) -------------------------
            pin_c.create_rectangle(PX-2, PY-4, PX,   PY+8,
                                   fill=n_dk, outline="")
            # -- Trzonek — prawa ścianka (jaśniejsza) -------------------------
            pin_c.create_rectangle(PX,   PY-4, PX+2, PY+8,
                                   fill=n_mid, outline="")
            # -- Trzonek — górna ścianka (reflex) -----------------------------
            pin_c.create_line(PX-2, PY-4, PX+2, PY-4,
                              fill=n_top, width=1)
            # -- Trzonek — lewa krawędź (połysk) ------------------------------
            pin_c.create_line(PX-2, PY-3, PX-2, PY+7,
                              fill=lp(n_top, n_dk, 0.4), width=1)

            # -- Ostrze igły — cień -------------------------------------------
            pin_c.create_polygon(PX-1, PY+8, PX+2, PY+8, PX+1, PY+14,
                                 fill=lp(n_shd, BASE, 0.25), outline="")
            # -- Ostrze igły — lewa ścianka -----------------------------------
            pin_c.create_polygon(PX-1, PY+7, PX+1, PY+7, PX, PY+13,
                                 fill=n_dk, outline="")
            # -- Ostrze igły — prawa ścianka (reflex) -------------------------
            pin_c.create_polygon(PX+1, PY+7, PX+2, PY+7, PX+1, PY+11,
                                 fill=n_top, outline="")

            # -- Główka pinezki (disc) — zewnętrzny cień ----------------------
            pin_c.create_oval(PX-9, PY-16, PX+10, PY-4,
                              fill=lp(n_shd, BASE, 0.3), outline="")
            # -- Główka — warstwa dolna (cień wewnętrzny po bokach) -----------
            pin_c.create_oval(PX-8, PY-16, PX+8, PY-5,
                              fill=lp(h_col, BASE, 0.15), outline="")
            # -- Główka — główny dysk (kolor) ---------------------------------
            pin_c.create_oval(PX-8, PY-17, PX+8, PY-6,
                              fill=h_col, outline=h_rim, width=1)
            # -- Główka — gradient (góra jaśniejsza, dół ciemniejszy) ---------
            pin_c.create_oval(PX-7, PY-17, PX+7, PY-11,
                              fill=lp(h_col, "#ffffff", 0.18), outline="")
            # -- Główka — połysk (lewy górny półksiężyc) ----------------------
            pin_c.create_oval(PX-6, PY-16, PX+1, PY-11,
                              fill=lp(h_sheen, h_col, 0.45), outline="")
            # -- Główka — jasny punkt (specular highlight) --------------------
            pin_c.create_oval(PX-5, PY-15, PX-2, PY-13,
                              fill=lp(W_HL, h_sheen, 0.55), outline="")
            # -- Główka — złoty ring dekoracyjny (active) ---------------------
            if active:
                pin_c.create_oval(PX-8, PY-17, PX+8, PY-6,
                                  fill="", outline=GOLD_BR, width=1)
                pin_c.create_oval(PX-7, PY-16, PX+7, PY-7,
                                  fill="", outline=lp(GOLD, BASE, 0.4), width=1)


        _draw_pin(self._topmost_on)
        self._pin_canvas  = pin_c
        self._draw_pin_fn = _draw_pin

        # ── Language toggle button (EN / PL) ─────────────────────────────────
        lang_c = tk.Canvas(hdr_canvas, width=52, height=42,
                           bg=BASE, highlightthickness=0, bd=0, cursor="hand2")
        hdr_canvas.create_window(0, HDR_H // 2, window=lang_c,
                                 anchor=tk.E, tags="lang_btn")

        def _draw_lang(hover=False):
            lang_c.delete("all")
            is_en = (get_locale() == "en")
            W2, H2 = 52, 42
            CX, CY = W2 // 2, H2 // 2

            ACCENT   = self.CLR_ACCENT
            ACCENT2  = self.CLR_ACCENT2
            MUTED    = self.CLR_MUTED
            TEXT_BRT = self.CLR_TEXT
            W_HL     = "#FFFFFF"
            lp = self._lerp_color

            # ── Kolory trybu ─────────────────────────────────────────────────
            if hover:
                body_top = lp(ACCENT, BASE, 0.18)
                body_bot = lp(ACCENT, BASE, 0.35)
                rim_out  = lp(ACCENT, BASE, 0.40)
                rim_in   = lp(ACCENT, BASE, 0.70)
            else:
                body_top = lp("#1A2C44", BASE, 0.0)
                body_bot = lp("#0D1C30", BASE, 0.0)
                rim_out  = lp(MUTED, BASE, 0.45)
                rim_in   = lp(MUTED, BASE, 0.75)

            # ── Drop shadow ───────────────────────────────────────────────────
            for i in range(4, 0, -1):
                pin_c_shd = lp("#000000", BASE, 1.0 - 0.10*i)
                lang_c.create_oval(1+i, 2+i, W2-1, H2-1,
                                   fill=pin_c_shd, outline="")

            # ── Zewnętrzny glow (hover) ───────────────────────────────────────
            if hover:
                lang_c.create_oval(0, 0, W2, H2, fill="",
                                   outline=lp(ACCENT, BASE, 0.55), width=2)

            # ── Główne ciało przycisku (zaokrąglony prostokąt z owali) ────────
            # Tło — ciemna podstawa
            lang_c.create_oval(2, 2, W2-2, H2-2, fill=body_bot, outline="")
            # Jaśniejsza górna połowa (efekt 3D)
            lang_c.create_oval(2, 2, W2-2, CY+3, fill=body_top, outline="")
            # Obramowanie zewnętrzne
            lang_c.create_oval(2, 2, W2-2, H2-2, fill="", outline=rim_out, width=1)
            # Wewnętrzny bevel (jasny)
            lang_c.create_oval(4, 4, W2-4, H2-4, fill="",
                               outline=lp(W_HL, body_top, 0.88), width=1)
            # Wewnętrzny bevel (ciemny, dolny)
            lang_c.create_oval(5, 5, W2-5, H2-5, fill="",
                               outline=lp("#000000", body_bot, 0.75), width=1)

            # ── Reflex — połysk górny-lewy ────────────────────────────────────
            lang_c.create_oval(5, 5, W2-22, CY-1,
                               fill=lp(W_HL, body_top, 0.88), outline="")
            lang_c.create_oval(6, 5, W2-26, CY-5,
                               fill=lp(W_HL, body_top, 0.94), outline="")

            # ── Aktywny segment (wytłoczona kapsuła po stronie aktywnej) ──────
            act_col  = lp(ACCENT, body_top, 0.30)
            act_rim  = lp(ACCENT, body_top, 0.55)
            act_sheen= lp(W_HL,   act_col,  0.85)
            if is_en:
                # Lewa połowa wytłoczona
                lang_c.create_oval( 3,  3, 30, H2-3, fill=act_col, outline="")
                lang_c.create_oval( 3,  3, 30, CY+1, fill=lp(act_col, W_HL, 0.12), outline="")
                lang_c.create_oval( 3,  3, 30, H2-3, fill="", outline=act_rim, width=1)
                # Połysk aktywnej strony
                lang_c.create_oval( 5,  5, 22, CY-2, fill=act_sheen, outline="")
            else:
                # Prawa połowa wytłoczona
                lang_c.create_oval(22,  3, W2-3, H2-3, fill=act_col, outline="")
                lang_c.create_oval(22,  3, W2-3, CY+1, fill=lp(act_col, W_HL, 0.12), outline="")
                lang_c.create_oval(22,  3, W2-3, H2-3, fill="", outline=act_rim, width=1)
                lang_c.create_oval(24,  5, W2-5, CY-2, fill=act_sheen, outline="")

            # ── Pionowy separator z efektem 3D ───────────────────────────────
            sep_x = 26
            lang_c.create_line(sep_x-1, 7, sep_x-1, H2-7,
                               fill=lp("#000000", body_bot, 0.55), width=1)
            lang_c.create_line(sep_x,   7, sep_x,   H2-7,
                               fill=lp(MUTED, body_bot, 0.50), width=1)
            lang_c.create_line(sep_x+1, 7, sep_x+1, H2-7,
                               fill=lp(W_HL,  body_top, 0.80), width=1)

            # ── Etykiety EN / PL ──────────────────────────────────────────────
            def _label(x, text, is_active):
                font_act = ("Segoe UI", 9, "bold")
                font_dim = ("Segoe UI", 8)
                col_act  = lp(ACCENT, W_HL, 0.25)
                col_dim  = lp(MUTED,  body_bot, 0.25)
                if is_active:
                    # Cień tekstu (głębia 3D)
                    lang_c.create_text(x+1, CY+2, text=text, font=font_act,
                                       fill=lp("#000000", body_bot, 0.4),
                                       anchor=tk.CENTER)
                    # Właściwy tekst z połyskiem
                    lang_c.create_text(x, CY, text=text, font=font_act,
                                       fill=col_act, anchor=tk.CENTER)
                    # Drobny highlight pod tekstem (reflex od tła)
                    lang_c.create_text(x, CY-1, text=text, font=font_act,
                                       fill=lp(W_HL, col_act, 0.92),
                                       anchor=tk.CENTER)
                else:
                    lang_c.create_text(x, CY, text=text, font=font_dim,
                                       fill=col_dim, anchor=tk.CENTER)

            _label(13, "EN", is_en)
            _label(39, "PL", not is_en)

            # ── Wskaźnik aktywności — świecąca kreska pod etykietą ───────────
            ind_y = H2 - 6
            if is_en:
                for ix in range(7, 20):
                    t = abs((ix - 13) / 6)
                    c = lp(ACCENT, body_bot, max(0.0, 1.0 - t))
                    lang_c.create_line(ix, ind_y, ix, ind_y+2, fill=c, width=1)
            else:
                for ix in range(33, 46):
                    t = abs((ix - 39) / 6)
                    c = lp(ACCENT, body_bot, max(0.0, 1.0 - t))
                    lang_c.create_line(ix, ind_y, ix, ind_y+2, fill=c, width=1)

        _draw_lang()
        self._lang_canvas   = lang_c
        self._draw_lang_fn  = _draw_lang

        def _toggle_language(e=None):
            new_locale = "en" if get_locale() == "pl" else "pl"
            set_locale(new_locale)
            _draw_lang()
            # Cancel running sidebar animation jobs first so they don't
            # fire on already-destroyed canvases during rebuild.
            for job_attr in ("_sb_scan_job", "_sb_pulse_job"):
                job = getattr(self, job_attr, None)
                if job:
                    self.after_cancel(job)
                    setattr(self, job_attr, None)
            # Short delay so any already-queued after() callbacks can
            # run (they will exit via winfo_exists guard) before we
            # destroy the widgets.
            self.after(80, self._rebuild_ui_for_locale)

        lang_c.bind("<Button-1>", _toggle_language)
        lang_c.bind("<Enter>",    lambda e: _draw_lang(True))
        lang_c.bind("<Leave>",    lambda e: _draw_lang(False))

        def _reposition_widgets(e=None):
            W = hdr_canvas.winfo_width() or 1400
            # Right → left: pin_btn | adm_badge | lang_btn
            hdr_canvas.coords("pin_btn",   W - 10,  HDR_H // 2)   # rightmost
            hdr_canvas.coords("adm_badge", W - 62,  HDR_H // 2)   # left of pin
            hdr_canvas.coords("lang_btn",  W - 170, HDR_H // 2)   # leftmost

        # ── Master animation tick (60 fps target) ────────────────────────────
        def _tick():
            W = hdr_canvas.winfo_width()  or 1400
            H = hdr_canvas.winfo_height() or HDR_H

            # Re-seed particles on first run or resize
            if W != _W_last[0] or not anim["particles"]:
                _draw_bg(W, H)
                _init_particles(W)
                _W_last[0] = W

            anim["t"]          += 1
            anim["logo_angle"]  = (anim["logo_angle"] + 0.6) % 360
            anim["wave_phase"]  = (anim["wave_phase"] + 0.04) % (2 * math.pi)
            anim["sweep_x"]    += 3
            if anim["sweep_x"] > W + 120:
                anim["sweep_x"] = -120

            anim["title_glow"] += 0.025 * anim["title_dir"]
            if anim["title_glow"] >= 1.0:
                anim["title_dir"] = -1
            elif anim["title_glow"] <= 0.0:
                anim["title_dir"] =  1

            anim["badge_pulse"] += 0.04 * anim["badge_dir"]
            if anim["badge_pulse"] >= 1.0:
                anim["badge_dir"] = -1
            elif anim["badge_pulse"] <= 0.0:
                anim["badge_dir"] =  1

            # Draw order: particles → sweep → logo → title → wave → badge
            _draw_particles(W, H)
            _draw_sweep(W, H, anim["sweep_x"])
            _draw_logo_3d(anim["logo_angle"])
            _draw_title_3d(W, anim["title_glow"])
            _draw_wave(W, H, anim["wave_phase"])
            _draw_badge(anim["badge_pulse"])
            _reposition_widgets()

            self._hdr_anim_job = self.after(22, _tick)   # ~45 fps

        # Initial static draw then start animation
        def _on_first_configure(e=None):
            W = hdr_canvas.winfo_width()  or 1400
            H = hdr_canvas.winfo_height() or HDR_H
            _draw_bg(W, H)
            _init_particles(W)
            _W_last[0] = W
            _draw_logo_3d(0)
            _draw_title_3d(W, 0.0)
            _reposition_widgets()
            hdr_canvas.unbind("<Configure>")
            hdr_canvas.bind("<Configure>", lambda e: _draw_bg(
                hdr_canvas.winfo_width(), hdr_canvas.winfo_height()))
            self._hdr_anim_job = self.after(100, _tick)

        hdr_canvas.bind("<Configure>", _on_first_configure)
        self.after(40, lambda: _on_first_configure())

        # ── Toggle topmost ───────────────────────────────────────────────────
        def _toggle_topmost(e=None):
            self._topmost_on = not self._topmost_on
            self.attributes("-topmost", self._topmost_on)
            _draw_pin(self._topmost_on)
            if hasattr(self, "_menu_topmost_var"):
                self._menu_topmost_var.set(self._topmost_on)
            get_settings().set("window_topmost", self._topmost_on)
            get_settings().save()

        _tip_win = [None]
        def _tip_show(e):
            if _tip_win[0]: return
            _tip_win[0] = tk.Toplevel(pin_c)
            _tip_win[0].wm_overrideredirect(True)
            _tip_win[0].wm_geometry(f"+{e.x_root+14}+{e.y_root+24}")
            state = "W\u0141\u0104CZONE" if self._topmost_on else "WY\u0141\u0104CZONE"
            frm = tk.Frame(_tip_win[0], bg="#0A1828",
                           highlightbackground=self.CLR_ACCENT, highlightthickness=1)
            frm.pack()
            tk.Label(frm, text=f"\U0001f4cc  Zawsze na wierzchu: {state}",
                     font=("Segoe UI", 8, "bold"),
                     bg="#0A1828", fg=self.CLR_ACCENT, padx=12, pady=6).pack()

        def _tip_hide(e):
            if _tip_win[0]:
                _tip_win[0].destroy()
                _tip_win[0] = None

        pin_c.bind("<Button-1>", _toggle_topmost)
        pin_c.bind("<Enter>", lambda e: (_draw_pin(self._topmost_on, True),  _tip_show(e)))
        pin_c.bind("<Leave>", lambda e: (_draw_pin(self._topmost_on, False), _tip_hide(e)))

    def _rebuild_ui_for_locale(self):
        """Rebuild menu, sidebar and active panel after a locale switch.

        Called 80 ms after the language toggle so that any already-queued
        animation after() callbacks have a chance to run and exit via their
        winfo_exists() guard before we destroy the underlying widgets.
        """
        # 1. Rebuild menu bar (all cascade labels and item labels)
        try:
            self._build_menubar()
        except Exception:
            pass

        # 2. Rebuild sidebar (module name labels + header animation canvases)
        try:
            body_frame = self._body_frame
            # Destroy old sidebar widgets (everything that is NOT content_frame)
            for widget in list(body_frame.winfo_children()):
                if widget is not self.content_frame:
                    widget.destroy()
            self._sidebar_buttons = {}
            self._build_sidebar(body_frame)
            # Re-pack content_frame to the right of the fresh sidebar
            self.content_frame.pack_forget()
            self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        except Exception:
            pass

        # 3. Rebuild the active panel content
        try:
            self._switch_module(self._active_module)
        except Exception:
            pass

    def _build_body(self):
        body = tk.Frame(self, bg=self.CLR_BG)
        body.pack(fill=tk.BOTH, expand=True)
        self._body_frame = body   # keep reference for language toggle rebuild

        self._build_sidebar(body)

        self.content_frame = tk.Frame(body, bg=self.CLR_BG)
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.content_frame.columnconfigure(0, weight=1)

    def _build_sidebar(self, parent):
        """Animated sidebar with slide-in entrance, pulse on active, ripple on click."""
        SB_W    = 232
        SB_BASE = "#08101E"

        sb_outer = tk.Frame(parent, bg="#000000", width=SB_W)
        sb_outer.pack(side=tk.LEFT, fill=tk.Y)
        sb_outer.pack_propagate(False)  # Fix: sidebar does not shrink below SB_W

        sb_bg = tk.Canvas(sb_outer, width=SB_W, highlightthickness=0, bd=0,
                          bg=SB_BASE)
        sb_bg.pack(fill=tk.BOTH, expand=True)

        # ── Animated scanline background ─────────────────────────────────────
        self._sb_scan_offset = 0

        def _draw_sb_bg(e=None):
            H = sb_bg.winfo_height() or 900
            sb_bg.delete("bg")
            off = self._sb_scan_offset
            for y in range(H):
                t   = y / max(1, H)
                tt  = 4 * t * (1 - t)
                base = self._lerp_color("#08101E", "#102030", tt * 0.20)
                # subtle moving scanline shimmer
                scan_t = ((y + off) % 80) / 80
                if scan_t < 0.04:
                    base = self._lerp_color(base, self.CLR_ACCENT, 0.04 - scan_t)
                sb_bg.create_line(0, y, SB_W, y, fill=base, tags="bg")
            # right border
            sb_bg.create_line(SB_W-2, 0, SB_W-2, H,
                              fill=self._lerp_color(self.CLR_BORDER, "#000000", 0.6),
                              width=1, tags="bg")
            sb_bg.create_line(SB_W-1, 0, SB_W-1, H, fill="#000000", width=1, tags="bg")

        # sb_bg Configure bind set at end of _build_sidebar
        self.after(10, _draw_sb_bg)

        # ── Animate scanlines ────────────────────────────────────────────────
        def _tick_scanlines():
            if not sb_bg.winfo_exists():
                return
            self._sb_scan_offset = (self._sb_scan_offset + 1) % 80
            _draw_sb_bg()
            self._sb_scan_job = self.after(60, _tick_scanlines)
        self._sb_scan_job = self.after(800, _tick_scanlines)

        # ── Header with animated accent dot ─────────────────────────────────
        HDR_H = 48
        # Layout frame sits on top of sb_bg canvas (same parent sb_outer)
        # using place to cover full area, then uses pack internally
        layout_frame = tk.Frame(sb_outer, bg=SB_BASE)
        layout_frame.place(x=0, y=0, relwidth=1.0, relheight=1.0)

        # Header canvas inside layout_frame
        sb_hdr_c = tk.Canvas(layout_frame, width=SB_W, height=HDR_H,
                              highlightthickness=0, bd=0, bg="#06101C")
        sb_hdr_c.pack(side=tk.TOP, fill=tk.X)

        self._sb_hdr_pulse = 0.0
        self._sb_hdr_dir   = 1

        def _draw_sb_hdr():
            sb_hdr_c.delete("all")
            W, H = SB_W, HDR_H
            # flat dark bg with bottom accent line
            sb_hdr_c.create_rectangle(0, 0, W, H, fill="#06101C", outline="")
            sb_hdr_c.create_line(0, H-1, W, H-1,
                                 fill=self._lerp_color(self.CLR_ACCENT, "#000000", 0.35),
                                 width=2)
            # Pulsing dot
            p = self._sb_hdr_pulse
            dot_col = self._lerp_color(self.CLR_ACCENT, self.CLR_ACCENT2, p)
            r = int(4 + p * 2)
            sb_hdr_c.create_oval(14-r, H//2-r, 14+r, H//2+r,
                                 fill=self._lerp_color(dot_col, "#000000", 0.3),
                                 outline="")
            sb_hdr_c.create_oval(14-3, H//2-3, 14+3, H//2+3,
                                 fill=dot_col, outline="")
            sb_hdr_c.create_text(26, H//2, text=_t("NAWIGACJA"),
                                 font=("Segoe UI", 9, "bold"),
                                 fill=self.CLR_ACCENT, anchor=tk.W)

        def _pulse_hdr():
            if not sb_hdr_c.winfo_exists():
                return
            self._sb_hdr_pulse += 0.05 * self._sb_hdr_dir
            if self._sb_hdr_pulse >= 1.0:
                self._sb_hdr_dir = -1
            elif self._sb_hdr_pulse <= 0.0:
                self._sb_hdr_dir = 1
            _draw_sb_hdr()
            self._sb_pulse_job = self.after(40, _pulse_hdr)

        _draw_sb_hdr()
        self._sb_pulse_job = self.after(500, _pulse_hdr)

        # ── Button container ─────────────────────────────────────────────────
        FTR_H = 30
        btn_frame = tk.Frame(layout_frame, bg=SB_BASE)
        btn_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # ── Pack sidebar normally (stable layout) ────────────────────────────
        # Note: slide animation via place() interferes with pack geometry manager.
        # Instead we use a fade-in via opacity simulation: start with narrow width.
        def _grow_sidebar(step=0, total=10):
            t   = step / total
            ease = 1.0 - (1.0 - t) ** 3
            w   = max(4, int(SB_W * ease))
            sb_outer.configure(width=w)
            if step < total:
                self.after(20, lambda: _grow_sidebar(step + 1, total))
            else:
                sb_outer.configure(width=SB_W)

        self.after(80, _grow_sidebar)

        # Build buttons immediately (stagger is in intro animation per-button)
        for mod_id, icon, label, _ in self.MODULES:
            self._build_sidebar_btn(btn_frame, mod_id, icon, label)

        # ── Footer ───────────────────────────────────────────────────────────
        footer_c = tk.Canvas(layout_frame, width=SB_W, height=FTR_H,
                              highlightthickness=0, bd=0, bg="#060E18")
        footer_c.pack(side=tk.BOTTOM, fill=tk.X)

        def _draw_sb_footer():
            footer_c.delete("all")
            footer_c.create_rectangle(0, 0, SB_W, FTR_H, fill="#060E18", outline="")
            footer_c.create_line(0, 0, SB_W, 0,
                                 fill=self._lerp_color(self.CLR_BORDER, "#000000", 0.5),
                                 width=1)
            ver_text = f"v{__version__}  ·  polsoft.ITS™"
            footer_c.create_text(SB_W // 2, FTR_H // 2, text=ver_text,
                                 font=("Segoe UI", 7), fill=self.CLR_MUTED,
                                 anchor=tk.CENTER)

        _draw_sb_footer()
        self.after(15, _draw_sb_footer)
        sb_bg.bind("<Configure>", _draw_sb_bg)

    def _build_sidebar_btn(self, sidebar, mod_id, icon, label):
        """Animated nav button: hover fade, accent bar slide, ripple on click, active pulse."""
        BTN_H = 44
        BTN_W = 232
        ACC_W = 3

        C_NORM_BG  = "#0C1828"
        C_HOVER_BG = "#13243E"
        C_ACTV_BG  = "#0F2040"
        C_PRESS_BG = "#09141E"
        C_SEP      = "#080F1A"

        wrap = tk.Frame(sidebar, bg=C_SEP, height=BTN_H + 1)
        wrap.pack(fill=tk.X)
        wrap.pack_propagate(False)

        c = tk.Canvas(wrap, width=BTN_W, height=BTN_H,
                      highlightthickness=0, bd=0, cursor="hand2", bg=C_NORM_BG)
        c.place(x=0, y=0, width=BTN_W, height=BTN_H)

        # ── Per-button animation state ────────────────────────────────────────
        state_obj = {
            "hover_t":    0.0,   # 0..1 hover fade progress
            "hover_dir":  0,     # +1 fade in, -1 fade out
            "hover_job":  None,
            "pulse_t":    0.0,   # active accent pulse
            "pulse_dir":  1,
            "pulse_job":  None,
            "ripple_r":   0,     # ripple radius (0 = inactive)
            "ripple_x":   BTN_W // 2,
            "ripple_y":   BTN_H // 2,
            "ripple_job": None,
            "bar_h":      0,     # accent bar height (slide-in animation)
            "bar_job":    None,
            "intro_x":    BTN_W, # slide-in from right
            "intro_done": False,
        }

        def _draw(s=None):
            if not c.winfo_exists():
                return
            if s is None:
                s = state_obj
            c.delete("all")

            is_active = (self._active_module == mod_id)
            ht        = s["hover_t"]

            # ── Background ────────────────────────────────────────────────
            if is_active:
                bg = self._lerp_color(C_ACTV_BG, C_HOVER_BG, ht * 0.4)
            else:
                bg = self._lerp_color(C_NORM_BG, C_HOVER_BG, ht)
            c.configure(bg=bg)
            c.create_rectangle(0, 0, BTN_W, BTN_H, fill=bg, outline="")

            # ── Ripple ────────────────────────────────────────────────────
            rr = s["ripple_r"]
            if rr > 0:
                alpha = max(0.0, 1.0 - rr / 60)
                rc = self._lerp_color(self.CLR_ACCENT, bg, 1.0 - alpha * 0.25)
                c.create_oval(s["ripple_x"]-rr, s["ripple_y"]-rr,
                              s["ripple_x"]+rr, s["ripple_y"]+rr,
                              outline=rc, width=2)

            # ── Left accent bar (animated height) ─────────────────────────
            bh = s["bar_h"]
            if is_active and bh > 0:
                pt = s["pulse_t"]
                bar_c = self._lerp_color(self.CLR_ACCENT, self.CLR_ACCENT2, pt * 0.3)
                top = (BTN_H - bh) // 2
                c.create_rectangle(0, top, ACC_W, top + bh, fill=bar_c, outline="")
            elif not is_active and ht > 0:
                c.create_rectangle(0, 0, 1, BTN_H,
                                   fill=self._lerp_color(C_NORM_BG, self.CLR_BORDER_LT, ht),
                                   outline="")

            # ── Icon ──────────────────────────────────────────────────────
            icon_x = ACC_W + 16
            if is_active:
                fg = self._lerp_color(self.CLR_ACCENT2, self.CLR_ACCENT,
                                      0.5 + s["pulse_t"] * 0.5)
            elif ht > 0:
                fg = self._lerp_color(self.CLR_MUTED, self.CLR_TEXT, ht)
            else:
                fg = self.CLR_MUTED
            c.create_text(icon_x, BTN_H // 2, text=icon,
                          font=("Segoe UI", 13), fill=fg, anchor=tk.W)

            # ── Label ─────────────────────────────────────────────────────
            lbl_x  = icon_x + 30
            weight = "bold" if is_active else ""
            c.create_text(lbl_x, BTN_H // 2, text=label,
                          font=("Segoe UI", 10, weight), fill=fg, anchor=tk.W)

            # ── Active dot (pulsing) ───────────────────────────────────────
            if is_active:
                pt  = s["pulse_t"]
                dr  = int(3 + pt * 2)
                dc  = self._lerp_color(self.CLR_ACCENT, self.CLR_ACCENT2, pt)
                dx  = BTN_W - 14
                dy  = BTN_H // 2
                # outer glow ring
                c.create_oval(dx - dr - 2, dy - dr - 2, dx + dr + 2, dy + dr + 2,
                              outline=self._lerp_color(dc, bg, 0.65), width=1)
                # solid dot
                c.create_oval(dx - 3, dy - 3, dx + 3, dy + 3, fill=dc, outline="")

            # ── Separator ─────────────────────────────────────────────────
            c.create_line(ACC_W + 10, BTN_H - 1, BTN_W - 10, BTN_H - 1,
                          fill=C_SEP, width=1)

        # ── Hover fade animation ──────────────────────────────────────────────
        def _tick_hover():
            if not c.winfo_exists(): return
            state_obj["hover_t"] = max(0.0, min(1.0,
                state_obj["hover_t"] + 0.12 * state_obj["hover_dir"]))
            _draw()
            if 0.0 < state_obj["hover_t"] < 1.0:
                state_obj["hover_job"] = c.after(14, _tick_hover)
            else:
                state_obj["hover_job"] = None

        def _start_hover(direction):
            state_obj["hover_dir"] = direction
            if state_obj["hover_job"] is None:
                state_obj["hover_job"] = c.after(0, _tick_hover)

        # ── Ripple animation ─────────────────────────────────────────────────
        def _tick_ripple():
            if not c.winfo_exists(): return
            state_obj["ripple_r"] += 5
            _draw()
            if state_obj["ripple_r"] < 65:
                state_obj["ripple_job"] = c.after(16, _tick_ripple)
            else:
                state_obj["ripple_r"]   = 0
                state_obj["ripple_job"] = None
                _draw()

        def _start_ripple(x, y):
            state_obj["ripple_r"] = 1
            state_obj["ripple_x"] = x
            state_obj["ripple_y"] = y
            if state_obj["ripple_job"]:
                c.after_cancel(state_obj["ripple_job"])
            state_obj["ripple_job"] = c.after(0, _tick_ripple)

        # ── Accent bar slide-in ───────────────────────────────────────────────
        def _tick_bar(target=BTN_H):
            if not c.winfo_exists(): return
            state_obj["bar_h"] = min(target,
                state_obj["bar_h"] + int(target * 0.18) + 2)
            _draw()
            if state_obj["bar_h"] < target:
                state_obj["bar_job"] = c.after(14, lambda: _tick_bar(target))
            else:
                state_obj["bar_h"]   = target
                state_obj["bar_job"] = None

        def _tick_bar_out():
            if not c.winfo_exists(): return
            state_obj["bar_h"] = max(0,
                state_obj["bar_h"] - int(BTN_H * 0.22) - 2)
            _draw()
            if state_obj["bar_h"] > 0:
                state_obj["bar_job"] = c.after(12, _tick_bar_out)
            else:
                state_obj["bar_job"] = None

        # ── Active pulse ─────────────────────────────────────────────────────
        def _tick_pulse():
            if not c.winfo_exists(): return
            state_obj["pulse_t"] += 0.04 * state_obj["pulse_dir"]
            if state_obj["pulse_t"] >= 1.0:
                state_obj["pulse_dir"] = -1
            elif state_obj["pulse_t"] <= 0.0:
                state_obj["pulse_dir"] = 1
            _draw()
            if self._active_module == mod_id:
                state_obj["pulse_job"] = c.after(30, _tick_pulse)
            else:
                state_obj["pulse_t"]   = 0.0
                state_obj["pulse_job"] = None
                _draw()

        def _start_pulse():
            if state_obj["pulse_job"] is None:
                state_obj["pulse_job"] = c.after(0, _tick_pulse)

        def _stop_pulse():
            if state_obj["pulse_job"]:
                c.after_cancel(state_obj["pulse_job"])
                state_obj["pulse_job"] = None
                state_obj["pulse_t"]   = 0.0

        # ── Intro fade-in (bg color from black to normal) ────────────────────
        def _tick_intro(step=0, total=8):
            if not c.winfo_exists(): return
            if step < total:
                t    = step / total
                ease = 1.0 - (1.0 - t) ** 2
                # Temporarily dim the background to simulate fade-in
                dim  = self._lerp_color("#000000", C_NORM_BG, ease)
                c.configure(bg=dim)
                c.after(20, lambda: _tick_intro(step + 1, total))
            else:
                c.configure(bg=C_NORM_BG)
                state_obj["intro_done"] = True
                _draw()

        c.after(10, _tick_intro)

        _draw()
        self._sidebar_buttons[mod_id] = (c, c, c)
        c._draw = _draw

        # Store refs for activation callbacks
        c._start_bar    = _tick_bar
        c._stop_bar     = _tick_bar_out
        c._start_pulse  = _start_pulse
        c._stop_pulse   = _stop_pulse

        def _click(e):
            _start_ripple(e.x, e.y)
            self.after(60, lambda: self._switch_module(mod_id))

        def _enter(e):
            _start_hover(1)

        def _leave(e):
            _start_hover(-1)

        c.bind("<Button-1>", _click)
        c.bind("<Enter>",    _enter)
        c.bind("<Leave>",    _leave)

    def _switch_module(self, mod_id: str):
        # ── Deactivate previous ───────────────────────────────────────────────
        if self._active_module in self._sidebar_buttons:
            c, _, _ = self._sidebar_buttons[self._active_module]
            if hasattr(c, "_stop_pulse"):
                c._stop_pulse()
            if hasattr(c, "_stop_bar"):
                c._stop_bar()
            if hasattr(c, "_draw"):
                c._draw()

        self._active_module = mod_id
        if hasattr(self, "_cfg"):
            self._cfg.set("last_module", mod_id)
            self._cfg.save()

        # ── Activate new — animate accent bar slide-in + pulse ────────────────
        if mod_id in self._sidebar_buttons:
            c, _, _ = self._sidebar_buttons[mod_id]
            if hasattr(c, "_start_bar"):
                c._start_bar()
            if hasattr(c, "_start_pulse"):
                c._start_pulse()
            if hasattr(c, "_draw"):
                c._draw()

        # Rebuild content — destroy children and reset grid weights
        for w in self.content_frame.winfo_children():
            w.destroy()
        self.content_frame.columnconfigure(0, weight=1)
        # Reset row weights so next module starts clean
        for _r in range(8):
            self.content_frame.rowconfigure(_r, weight=0, minsize=0)

        method_map = {m[0]: m[3] for m in self.MODULES}
        method = method_map.get(mod_id)
        if method:
            try:
                getattr(self, method)()
            except Exception as exc:
                log_error(f"Module load error: {exc}", exc)
                tk.Label(self.content_frame,
                         text=f"\u26a0  Module load error:\n{exc}",
                         font=("Segoe UI", 11), fg=self.CLR_DANGER,
                         bg=self.CLR_BG, justify=tk.LEFT
                         ).pack(padx=30, pady=30, anchor=tk.W)
                self._set_status(f"\u2718 Module error: {exc}")

    def _build_footer(self):
        # Separator — side=tk.BOTTOM so pack order works correctly
        FTR_H = 36
        ftr_c = tk.Canvas(self, height=FTR_H, highlightthickness=0, bd=0)
        ftr_c.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Frame(self, bg="#000000",           height=1).pack(fill=tk.X, side=tk.BOTTOM)
        tk.Frame(self, bg=self.CLR_BORDER_LT, height=1).pack(fill=tk.X, side=tk.BOTTOM)

        def _draw_footer(e=None):
            W = ftr_c.winfo_width() or 1400
            ftr_c.delete("all")
            # 3D glass panel
            self._draw_aero_glass_panel(ftr_c, 0, 0, W, FTR_H,
                                        base_col="#060C1A", bevel=1, title_frac=0.50)
            # Top accent stripe — double line
            ftr_c.create_line(0, 0, W, 0, fill=self.CLR_ACCENT, width=1)
            ftr_c.create_line(0, 1, W, 1,
                              fill=self._lerp_color(self.CLR_ACCENT, "#060C1A", 0.60), width=1)
            # Status indicator dot
            txt = getattr(self, "_ftr_status_text", _t("Gotowy."))
            dot_col = (self.CLR_DANGER if txt.startswith("✘")
                       else self.CLR_SUCCESS if txt.startswith("✔")
                       else self.CLR_ACCENT if txt.startswith("⏳")
                       else self.CLR_MUTED)
            for rr in range(4, 0, -1):
                t = (4-rr)/4
                gc = self._lerp_color(dot_col, "#060C1A", 0.2+t*0.7)
                ftr_c.create_oval(10-rr, FTR_H//2-rr, 10+rr, FTR_H//2+rr, fill=gc, outline="")
            # Status text — brighter and more readable
            ftr_c.create_text(22, FTR_H//2+1, text=txt,
                              font=("Segoe UI", 9), fill="#000000",
                              anchor=tk.W, tags="status_shadow")
            ftr_c.create_text(22, FTR_H//2, text=txt,
                              font=("Segoe UI", 9), fill=self.CLR_TEXT2,
                              anchor=tk.W, tags="status_text")
            # Copyright — separator | bezpośrednio przed 2026©, wyrównany do prawej
            txt_x = W - 96
            ftr_c.create_text(txt_x, FTR_H//2,
                              text="| " + __copyright__,
                              font=("Segoe UI", 8), fill=self.CLR_BORDER_LT, anchor=tk.E)

        ftr_c.bind("<Configure>", _draw_footer)
        self.after(10, _draw_footer)

        self._ftr_canvas = ftr_c
        self._ftr_status_text = _t("Gotowy.")

        def _set_status_aero(text: str):
            self._ftr_status_text = text
            try:
                ftr_c.itemconfig("status_text",   text=text)
                ftr_c.itemconfig("status_shadow", text=text)
            except Exception:
                pass

        self._set_status = _set_status_aero
        self.status_bar  = type("FakeLabel", (), {
            "configure": lambda self, **kw: _set_status_aero(kw.get("text", ""))
        })()

    def _make_module_header(self, title, subtitle, description):
        self.content_frame.columnconfigure(0, weight=1)
        self.content_frame.rowconfigure(0, weight=0)
        self.content_frame.rowconfigure(1, weight=0)
        self.content_frame.rowconfigure(2, weight=0)

        MH_H = 80   # powiększony banner — odkrywa pełny opis
        mh_c = tk.Canvas(self.content_frame, height=MH_H,
                          highlightthickness=0, bd=0)
        mh_c.grid(row=0, column=0, sticky="ew")

        def _draw_mh(e=None):
            W = mh_c.winfo_width() or 1000
            mh_c.delete("all")
            # 3D glass panel full width
            self._draw_aero_glass_panel(mh_c, 0, 0, W, MH_H,
                                        base_col="#162234", bevel=2, title_frac=0.48)
            # Left accent glow strip
            for x in range(6):
                t   = x / 6
                col = self._lerp_color(self.CLR_ACCENT, "#162234", t*0.80+0.12)
                mh_c.create_line(x, 0, x, MH_H, fill=col)
            # Bottom accent
            mh_c.create_line(0, MH_H-2, W, MH_H-2, fill=self.CLR_ACCENT, width=1)
            mh_c.create_line(0, MH_H-1, W, MH_H-1, fill="#000000",       width=1)
            # Title — lekko odsunięty od lewej krawędzi akcentowej
            tx = 28
            mh_c.create_text(tx+1, 24, text=title,
                             font=("Segoe UI", 16, "bold"), fill="#000000", anchor=tk.W)
            mh_c.create_text(tx,   23, text=title,
                             font=("Segoe UI", 16, "bold"), fill=self.CLR_ACCENT, anchor=tk.W)
            # Subtitle — poniżej tytułu, odsunięty od lewej
            mh_c.create_text(tx+1, 45, text=subtitle,
                             font=("Segoe UI", 10), fill="#000000", anchor=tk.W)
            mh_c.create_text(tx,   44, text=subtitle,
                             font=("Segoe UI", 10), fill=self.CLR_TEXT2, anchor=tk.W)
            # Description — na dole bannera, z większym wcięciem
            mh_c.create_text(tx+1, MH_H-10, text=description,
                             font=("Segoe UI", 8), fill="#000000", anchor=tk.W)
            mh_c.create_text(tx,   MH_H-11, text=description,
                             font=("Segoe UI", 8), fill=self.CLR_MUTED, anchor=tk.W)

        mh_c.bind("<Configure>", _draw_mh)
        self.after(8, _draw_mh)

        # Separator below header
        tk.Frame(self.content_frame, bg=self.CLR_BORDER, height=1).grid(
            row=2, column=0, sticky="ew", padx=0)

    def _make_scrollable(self, row=3):
        """Build canvas + GlassScrollbar, return inner frame."""
        self.content_frame.rowconfigure(row, weight=1)

        wrap = tk.Frame(self.content_frame, bg=self.CLR_BG)
        wrap.grid(row=row, column=0, sticky="nsew", padx=8, pady=6)
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        canvas = tk.Canvas(wrap, bg=self.CLR_BG, highlightthickness=0)
        sb     = GlassScrollbar(wrap, command=canvas.yview, width=10)
        inner  = tk.Frame(canvas, bg=self.CLR_BG)

        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        cid = canvas.create_window((0, 0), window=inner, anchor=tk.NW)
        canvas.configure(yscrollcommand=sb.set)
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(cid, width=e.width))

        canvas.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns", padx=(2, 0))

        self._attach_mousewheel(canvas)

        return inner

    def _attach_mousewheel(self, canvas: tk.Canvas):
        """Attaches MouseWheel handling to canvas with automatic detach on destroy."""
        def _wheel(e):
            if canvas.winfo_exists():
                canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        # Detach previous handler (if any) before attaching a new one
        try:
            canvas.unbind_all("<MouseWheel>")
        except Exception:
            pass
        canvas.bind_all("<MouseWheel>", _wheel)
        canvas.bind("<Destroy>", lambda e: canvas.unbind_all("<MouseWheel>"))

    def _table_header(self, parent, cols):
        TH_H = 34
        c = tk.Canvas(parent, height=TH_H, highlightthickness=0, bd=0)
        c.grid(row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=(0,1))

        def _draw_th(e=None):
            W = c.winfo_width() or 800
            c.delete("all")
            base = "#192840"
            # Glass panel gradient
            for y in range(TH_H):
                t   = y / TH_H
                if t < 0.45:
                    col = self._lerp_color(self._brighten(base,0.22), base, t/0.45)
                else:
                    col = self._lerp_color(base, self._darken(base,0.25), (t-0.45)/0.55)
                c.create_line(0, y, W, y, fill=col)
            # Gloss
            gh = int(TH_H*0.42)
            for y in range(gh):
                t = y/max(1,gh); ease=t*t
                gcol = self._lerp_color(self._lerp_color("#FFFFFF",base,0.74),base,ease)
                c.create_line(1,y,W-1,y, fill=gcol)
            # Bevel
            c.create_line(0,0,W,0, fill=self._brighten(base,0.4), width=1)
            c.create_line(0,TH_H-2,W,TH_H-2, fill=self.CLR_ACCENT, width=1)
            c.create_line(0,TH_H-1,W,TH_H-1, fill="#000000", width=1)
            # Column labels
            x = 12
            for text, width in cols:
                # Shadow
                c.create_text(x+1, TH_H//2+1, text=text,
                              font=("Segoe UI",9,"bold"), fill="#000000", anchor=tk.W)
                c.create_text(x, TH_H//2, text=text,
                              font=("Segoe UI",9,"bold"), fill=self.CLR_ACCENT, anchor=tk.W)
                x += width * 7 + 20

        c.bind("<Configure>", _draw_th)
        self.after(5, _draw_th)

    def _ctrl_bar(self, row=3):
        """Aero glass control bar with subtle separator line."""
        CTRL_H = 52
        bar_c = tk.Canvas(self.content_frame, height=CTRL_H,
                          highlightthickness=0, bd=0)
        bar_c.grid(row=row, column=0, sticky="ew", padx=0, pady=0)

        def _draw_ctrl(e=None):
            W = bar_c.winfo_width() or 1000
            bar_c.delete("all")
            base = self.CLR_BG
            for y in range(CTRL_H):
                t   = y / CTRL_H
                col = self._lerp_color(self._brighten(base,0.04), base, t)
                bar_c.create_line(0, y, W, y, fill=col)
            # Top separator
            bar_c.create_line(0,0,W,0, fill=self._brighten(base,0.18), width=1)
            # Bottom separator
            bar_c.create_line(0,CTRL_H-1,W,CTRL_H-1, fill=self._darken(base,0.25), width=1)

        bar_c.bind("<Configure>", _draw_ctrl)
        self.after(5, _draw_ctrl)

        # Inner frame for buttons, placed with padding
        inner = tk.Frame(bar_c, bg=self.CLR_BG)
        win_id = bar_c.create_window(12, CTRL_H//2, window=inner, anchor=tk.W)
        def _ctrl_resize(e=None):
            _draw_ctrl(e)
            if e:
                bar_c.itemconfigure(win_id, width=max(1, e.width - 24))
        bar_c.bind("<Configure>", _ctrl_resize)
        return inner

    def _flat_btn(self, parent, text, bg, command, fg=None, padx=16, pady=7):
        """Aero 3D glass button rendered on Canvas."""
        fg = fg or self.CLR_HEADER_BG
        BTN_H = 34
        # Measure approx width from text length
        BTN_W = max(80, len(text) * 8 + padx * 2 + 16)

        c = tk.Canvas(parent, width=BTN_W, height=BTN_H,
                      highlightthickness=0, bd=0, cursor="hand2")

        def _draw(state="normal"):
            c.delete("all")
            if state == "press":
                top_c = self._darken(bg, 0.18)
                bot_c = self._darken(bg, 0.05)
                rim_h = self._darken(bg, 0.4)
                rim_s = self._brighten(bg, 0.2)
                tx_c  = fg
            elif state == "hover":
                top_c = self._brighten(bg, 0.18)
                bot_c = bg
                rim_h = self._brighten(bg, 0.45)
                rim_s = self._darken(bg, 0.35)
                tx_c  = fg
            else:
                top_c = self._brighten(bg, 0.08)
                bot_c = self._darken(bg, 0.12)
                rim_h = self._brighten(bg, 0.35)
                rim_s = self._darken(bg, 0.45)
                tx_c  = fg

            # Body gradient
            for y in range(BTN_H):
                t   = y / BTN_H
                col = self._lerp_color(top_c, bot_c, t)
                c.create_line(0, y, BTN_W, y, fill=col)

            # Gloss bubble top 42%
            gh = int(BTN_H * 0.42)
            for y in range(gh):
                t    = y / max(1, gh)
                ease = t * t
                gcol = self._lerp_color(
                    self._lerp_color("#FFFFFF", top_c, 0.72), top_c, ease)
                c.create_line(1, y, BTN_W-1, y, fill=gcol)

            # 3D bevel
            self._draw_3d_bevel(c, 0, 0, BTN_W, BTN_H,
                                highlight=rim_h, shadow=rim_s, thickness=2)
            # Inner highlight
            c.create_line(2, 2, BTN_W-2, 2,
                          fill=self._brighten(top_c, 0.25), width=1)

            # Label with drop-shadow
            cx, cy = BTN_W//2, BTN_H//2
            c.create_text(cx+1, cy+1, text=text,
                          font=("Segoe UI", 9, "bold"), fill="#000000", anchor=tk.CENTER)
            c.create_text(cx, cy, text=text,
                          font=("Segoe UI", 9, "bold"), fill=tx_c, anchor=tk.CENTER)

        _draw("normal")

        c.bind("<Enter>",           lambda e: _draw("hover"))
        c.bind("<Leave>",           lambda e: _draw("normal"))
        c.bind("<ButtonPress-1>",   lambda e: _draw("press"))
        c.bind("<ButtonRelease-1>", lambda e: (_draw("hover"), command()))
        return c

    def _make_row_card(self, parent, cols, col_widths, even=True, accent=None):
        """
        Render a single data row as a mini Aero glass card.
        cols: list of strings, col_widths: list of pixel widths.
        Returns the outer frame so caller can bind events.
        """
        ROW_H = 32
        BASE  = self._brighten(self.CLR_SURFACE, 0.03) if even else self.CLR_SURFACE

        outer = tk.Frame(parent, bg=self.CLR_BG)
        outer.pack(fill=tk.X, padx=8, pady=1)

        c = tk.Canvas(outer, height=ROW_H, highlightthickness=0, bd=0, cursor="hand2")
        c.pack(fill=tk.X)

        def _draw(hover=False):
            c.delete("all")
            W = c.winfo_width() or 800
            bg2 = self._brighten(BASE,0.06) if hover else BASE
            for y in range(ROW_H):
                t   = y/ROW_H
                col = self._lerp_color(self._brighten(bg2,0.05), bg2, t)
                c.create_line(0, y, W, y, fill=col)
            # Gloss top 35%
            if hover:
                gh=int(ROW_H*0.35)
                for y in range(gh):
                    t=y/max(1,gh); ease=t*t
                    gcol=self._lerp_color(self._lerp_color("#FFFFFF",bg2,0.84),bg2,ease)
                    c.create_line(0,y,W,y,fill=gcol)
            # Bottom separator
            c.create_line(0,ROW_H-1,W,ROW_H-1, fill=self._darken(BASE,0.3), width=1)
            # Left accent if provided
            if accent:
                c.create_line(0,0,0,ROW_H, fill=accent, width=3)
            # Text columns
            x = 10 + (3 if accent else 0)
            for i,(text,w) in enumerate(zip(cols, col_widths)):
                fg = self.CLR_ACCENT if i==0 else self.CLR_TEXT2
                c.create_text(x+1,ROW_H//2+1, text=str(text),
                              font=("Segoe UI",9), fill="#000000", anchor=tk.W)
                c.create_text(x,  ROW_H//2,   text=str(text),
                              font=("Segoe UI",9), fill=fg,        anchor=tk.W)
                x += w

        _draw()
        c.bind("<Configure>", lambda e: _draw(False))
        c.bind("<Enter>",     lambda e: _draw(True))
        c.bind("<Leave>",     lambda e: _draw(False))
        return outer, c

    # ─────────────────────────────────────────────────────────────────────────
    #  Module: NTFSecur
    # ─────────────────────────────────────────────────────────────────────────
    def _show_ntfsecur(self):
        self._make_module_header(
            "NTFSecur", _t("Zabezpieczenia partycji NTFS"),
            _t("Zarządzaj ochroną zapisu na woluminach NTFS.\n") +
            _t("  WŁ  → partycja zablokowana (tylko odczyt, brak zapisu)\n") +
            _t("  WYŁ → partycja w pełni dostępna (odczyt + zapis)")
        )
        self.partition_container = self._make_scrollable(3)
        self._load_partitions()

    def _load_partitions(self):
        if not hasattr(self, 'partition_container') or not self.partition_container.winfo_exists():
            return
        self._set_status(_t("Skanowanie partycji NTFS…"))
        for w in self.partition_container.winfo_children():
            w.destroy()

        partitions = get_ntfs_partitions()
        if not partitions:
            tk.Label(self.partition_container, text="No NTFS partitions detected.",
                     font=("Courier New", 11), fg=self.CLR_MUTED, bg=self.CLR_BG
                     ).pack(pady=40)
            self._set_status(_t("Nie znaleziono partycji NTFS."))
            return

        for part in partitions:
            self._build_partition_card(self.partition_container, part)
        self._set_status(_t("Znaleziono {count} partycję/partycji NTFS. Gotowy.").format(count=len(partitions)))

    def _build_partition_card(self, parent, partition: dict):
        drive = partition['drive']
        label = partition['label']
        size  = partition['size']

        var = tk.BooleanVar(value=False)
        self.secure_states[drive] = var
        CARD_BASE = "#172438"

        # ── Outer wrapper with 3D shadow ─────────────────────────────────────
        outer = tk.Frame(parent, bg="#000000", bd=0)
        outer.pack(fill=tk.X, padx=6, pady=3)

        # Canvas card with full Aero glass rendering
        CARD_H = 82
        card_c = tk.Canvas(outer, height=CARD_H, highlightthickness=0, bd=0)
        card_c.pack(fill=tk.X, padx=1, pady=(1,2))

        strip_col = [self.CLR_MUTED]   # mutable for state updates

        def _draw_card(e=None):
            W = card_c.winfo_width() or 700
            card_c.delete("bg")
            # Gradient body — deeper, richer blues
            for y in range(CARD_H):
                t   = y / CARD_H
                if t < 0.40:
                    col = self._lerp_color(self._brighten(CARD_BASE, 0.16), CARD_BASE, t/0.40)
                else:
                    col = self._lerp_color(CARD_BASE, self._darken(CARD_BASE, 0.28), (t-0.40)/0.60)
                card_c.create_line(0, y, W, y, fill=col, tags="bg")
            # Gloss — brighter, higher coverage
            gh = int(CARD_H * 0.45)
            for y in range(gh):
                t=y/max(1,gh)
                ease = 1.0 - (1.0-t)**2.5
                gcol=self._lerp_color(self._lerp_color("#FFFFFF",CARD_BASE,0.74),CARD_BASE,ease)
                card_c.create_line(7, y, W-1, y, fill=gcol, tags="bg")
            # 3D bevel — brighter highlights
            card_c.create_line(0, 0, W, 0, fill=self._brighten(CARD_BASE, 0.45), width=1, tags="bg")
            card_c.create_line(0, 1, W, 1, fill=self._brighten(CARD_BASE, 0.22), width=1, tags="bg")
            card_c.create_line(0, 0, 0, CARD_H, fill=self._brighten(CARD_BASE, 0.30), width=1, tags="bg")
            card_c.create_line(0, CARD_H-1, W, CARD_H-1, fill=self._darken(CARD_BASE, 0.55), width=1, tags="bg")
            card_c.create_line(W-1, 0, W-1, CARD_H, fill=self._darken(CARD_BASE, 0.45), width=1, tags="bg")
            # Left accent strip — wider glow (8px gradient)
            for x in range(10):
                t=x/10
                col=self._lerp_color(strip_col[0], CARD_BASE, t*0.7)
                card_c.create_line(x, 0, x, CARD_H, fill=col, tags="bg")
            # Bright top-left specular corner pip
            card_c.create_oval(1, 1, 8, CARD_H//3,
                               fill=self._brighten(strip_col[0], 0.4), outline="", tags="bg")

        card_c.bind("<Configure>", _draw_card)
        self.after(6, _draw_card)

        # ── Content inside card via place() ─────────────────────────────────
        inner = tk.Frame(card_c, bg=CARD_BASE)
        card_c.create_window(8, 0, window=inner, anchor=tk.NW,
                             width=9999, height=CARD_H, tags="inner_win")
        # resize inner when card resizes — use itemconfig on the canvas window
        _inner_win_id = card_c.find_all()  # placeholder; real id captured below
        def _resize_inner(e=None):
            W = card_c.winfo_width() or 700
            # Update the canvas window width so inner frame fills card properly
            try:
                card_c.itemconfig("inner_win", width=max(1, W - 8))
            except Exception:
                pass
        card_c.bind("<Configure>", lambda e: (_draw_card(e), _resize_inner(e)))
        self.after(50, _resize_inner)

        info_f = tk.Frame(inner, bg=CARD_BASE)
        info_f.pack(side=tk.LEFT, fill=tk.Y, padx=(12,0), pady=10)

        tk.Label(info_f, text=drive,
                 font=("Segoe UI", 13, "bold"),
                 fg=self.CLR_TEXT, bg=CARD_BASE).pack(anchor=tk.W)
        tk.Label(info_f, text=f"{label}  ·  NTFS  ·  {size}",
                 font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=CARD_BASE).pack(anchor=tk.W, pady=(2,0))

        # Status badge
        status_f = tk.Frame(inner, bg=CARD_BASE)
        status_f.pack(side=tk.LEFT, fill=tk.Y, expand=True, pady=10)

        status_lbl = tk.Label(status_f, text=_t("⬤  ODBLOKOWANY"),
                              font=("Segoe UI", 9, "bold"),
                              fg=self.CLR_SUCCESS, bg=CARD_BASE,
                              width=18, anchor=tk.CENTER)
        status_lbl.pack(expand=True)
        self.status_labels[drive] = status_lbl

        # Buttons column
        btn_f = tk.Frame(inner, bg=CARD_BASE)
        btn_f.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=8)

        # --- Secure toggle Canvas button ---
        SEC_W, SEC_H = 118, 32
        sec_c = tk.Canvas(btn_f, width=SEC_W, height=SEC_H,
                          highlightthickness=0, bd=0, cursor="hand2")
        sec_c.pack()
        self.toggle_buttons[drive] = sec_c

        btn_state = [False]   # locked=True / unlocked=False

        def _draw_sec(locked=False, hover=False, working=False):
            sec_c.delete("all")
            if working:
                bg2="#2A2208"; tc=self.CLR_WARN; txt=_t("⏳  PRACUJE…")
            elif locked:
                bg2="#300808" if not hover else "#3E0A0A"
                tc=self.CLR_DANGER; txt=_t("🔒  ZABLOKOWANY")
            else:
                bg2="#071610" if not hover else "#0B1E16"
                tc=self.CLR_SUCCESS; txt=_t("🔓  ODBLOKOWANY")
            # Gradient
            for y in range(SEC_H):
                t=y/SEC_H
                t_e = 1.0 - (1.0-t)**1.8
                col_y=self._lerp_color(self._brighten(bg2,0.18),self._darken(bg2,0.20),t_e)
                sec_c.create_line(0,y,SEC_W,y,fill=col_y)
            # Gloss
            gh=int(SEC_H*0.48)
            for y in range(gh):
                t=y/max(1,gh)
                ease = 1.0 - (1.0-t)**2.5
                gcol=self._lerp_color(self._lerp_color("#FFFFFF",bg2,0.70),bg2,ease)
                sec_c.create_line(1,y,SEC_W-1,y,fill=gcol)
            # Bevel
            self._draw_3d_bevel(sec_c, 0, 0, SEC_W, SEC_H,
                                highlight=self._brighten(tc, 0.35),
                                shadow=self._darken(tc, 0.60), thickness=2)
            # Inner bright top rim
            sec_c.create_line(2, 2, SEC_W-2, 2, fill=self._brighten(tc, 0.2), width=1)
            # Text with shadow
            sec_c.create_text(SEC_W//2+1, SEC_H//2+1, text=txt,
                              font=("Segoe UI", 8, "bold"), fill="#000000", anchor=tk.CENTER)
            sec_c.create_text(SEC_W//2, SEC_H//2, text=txt,
                              font=("Segoe UI", 8, "bold"), fill=tc, anchor=tk.CENTER)

        _draw_sec(False)

        def _do_toggle():
            _draw_sec(working=True)
            def t(): self._toggle_secure(drive, strip_col, _draw_sec, _draw_card)
            self.after(10, t)

        sec_c.bind("<Enter>",           lambda e: _draw_sec(btn_state[0], hover=True))
        sec_c.bind("<Leave>",           lambda e: _draw_sec(btn_state[0], hover=False))
        sec_c.bind("<ButtonPress-1>",   lambda e: _draw_sec(btn_state[0], working=True))
        sec_c.bind("<ButtonRelease-1>", lambda e: _do_toggle())

        # Store extra refs for _apply_result
        sec_c._btn_state = btn_state
        sec_c._draw_sec  = _draw_sec

        # --- BitLocker Canvas button ---
        BL_W, BL_H = 118, 28
        bl_c = tk.Canvas(btn_f, width=BL_W, height=BL_H,
                         highlightthickness=0, bd=0, cursor="hand2")
        bl_c.pack(pady=(6,0))

        def _draw_bl(hover=False):
            bl_c.delete("all")
            bg2="#0A1C34" if not hover else "#14284A"
            tc=self.CLR_ACCENT2
            for y in range(BL_H):
                t=y/BL_H
                t_e = 1.0 - (1.0-t)**1.8
                col_y=self._lerp_color(self._brighten(bg2,0.14),self._darken(bg2,0.18),t_e)
                bl_c.create_line(0,y,BL_W,y,fill=col_y)
            gh=int(BL_H*0.48)
            for y in range(gh):
                t=y/max(1,gh)
                ease = 1.0 - (1.0-t)**2.5
                gcol=self._lerp_color(self._lerp_color("#FFFFFF",bg2,0.76),bg2,ease)
                bl_c.create_line(1,y,BL_W-1,y,fill=gcol)
            self._draw_3d_bevel(bl_c, 0, 0, BL_W, BL_H,
                                highlight=self._brighten(tc, 0.30),
                                shadow=self._darken(tc, 0.65), thickness=1)
            bl_c.create_line(2, 2, BL_W-2, 2, fill=self._brighten(tc, 0.18), width=1)
            bl_c.create_text(BL_W//2+1, BL_H//2+1, text="🔐  BitLocker",
                             font=("Segoe UI", 8, "bold"), fill="#000000", anchor=tk.CENTER)
            bl_c.create_text(BL_W//2, BL_H//2, text="🔐  BitLocker",
                             font=("Segoe UI", 8, "bold"), fill=tc, anchor=tk.CENTER)

        _draw_bl()
        bl_c.bind("<Enter>",           lambda e: _draw_bl(True))
        bl_c.bind("<Leave>",           lambda e: _draw_bl(False))
        bl_c.bind("<ButtonRelease-1>", lambda e: self._open_bitlocker_panel(drive))

    def _toggle_secure(self, drive, strip_col, draw_sec_fn, draw_card_fn):
        """Called from card; strip_col is a mutable [color] list."""
        var       = self.secure_states[drive]
        new_state = not var.get()

        if not is_admin():
            messagebox.showwarning(_t("Niewystarczające uprawnienia"),
                                   _t("Wymagane uprawnienia administratora.") + "\n"
                                   + _t("do zmiany ustawień ochrony zapisu NTFS.\n\n") +
                                   _t("Uruchom ponownie aplikację jako Administrator."))
            draw_sec_fn(var.get())
            return

        self._set_status(_t("Stosowanie NTFSecur na {drive}…").format(drive=drive))

        def worker():
            success, message = set_ntfs_readonly(drive, new_state)
            self.after(0, lambda: self._apply_result(
                drive, strip_col, draw_sec_fn, draw_card_fn,
                new_state, success, message))
        threading.Thread(target=worker, daemon=True).start()

    def _apply_result(self, drive, strip_col, draw_sec_fn, draw_card_fn,
                      new_state, success, message):
        lbl = self.status_labels[drive]
        sec_c = self.toggle_buttons[drive]
        if success:
            self.secure_states[drive].set(new_state)
            if new_state:
                strip_col[0] = self.CLR_DANGER
                lbl.configure(text=_t("🔒  ZABLOKOWANY"), fg=self.CLR_DANGER)
                sec_c._btn_state[0] = True
                draw_sec_fn(True)
            else:
                strip_col[0] = self.CLR_SUCCESS
                lbl.configure(text=_t("⬤  ODBLOKOWANY"),   fg=self.CLR_SUCCESS)
                sec_c._btn_state[0] = False
                draw_sec_fn(False)
            draw_card_fn()
            self._set_status(f"✔ {message}")
        else:
            draw_sec_fn(var.get() if hasattr(self.secure_states.get(drive, None),"get") else False)
            self._set_status(f"✘ Error: {message}")
            messagebox.showerror(_t("Błąd NTFSecur"), message)

    def _open_bitlocker_panel(self, drive: str):
        BitLockerPanel(self, drive)

    # ─────────────────────────────────────────────────────────────────────────
    #  Module: Drives – Diagnostics · Repair · Recovery · Regeneration
    # ─────────────────────────────────────────────────────────────────────────
    def _show_drives(self):
        # Lekki header jak w pozostałych modułach (bez bannera graficznego)
        self._module_header("💾", _t("Dyski"),
                            _t("Diagnostyka · Naprawa · Odzyskiwanie · Regeneracja"))

        # row=1: jeden pasek zakładek, row=2: treść
        self.content_frame.rowconfigure(1, weight=0)
        self.content_frame.rowconfigure(2, weight=1)

        # ── Jeden pasek wszystkich 6 zakładek — kompaktowy ────────────────────
        tab_outer = tk.Frame(self.content_frame, bg=self.CLR_SURFACE2)
        tab_outer.pack(fill=tk.X, padx=0, pady=0)
        tk.Frame(tab_outer, bg=self.CLR_BORDER_LT, height=1).pack(fill=tk.X, side=tk.TOP)
        tk.Frame(tab_outer, bg=self.CLR_BORDER,    height=1).pack(fill=tk.X, side=tk.BOTTOM)
        tab_bar = tk.Frame(tab_outer, bg=self.CLR_SURFACE2)
        tab_bar.pack(fill=tk.X, padx=4, pady=2)

        # Tab content area
        tab_content = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tab_content.pack(fill=tk.BOTH, expand=True)
        tab_content.columnconfigure(0, weight=1)
        tab_content.rowconfigure(0, weight=1)

        self._drv_tabs: dict = {}
        self._drv_active_tab = tk.StringVar(value="scan")

        TABS = [
            ("scan",     _t("🔍 Skan")),
            ("smart",    "📊 SMART"),
            ("repair",   "🛠 Repair"),
            ("recovery", "♻️ Recovery"),
            ("wipe",     "🧹 Wipe"),
            ("regen",    "⚡ Regen"),
        ]

        def _switch(tid):
            self._drv_active_tab.set(tid)
            for k, (btn, frm) in self._drv_tabs.items():
                if k == tid:
                    btn.configure(
                        bg=self.CLR_BG,
                        fg=self.CLR_ACCENT,
                        font=("Segoe UI", 9, "bold"),
                        relief=tk.SUNKEN)
                    frm.tkraise()
                else:
                    btn.configure(
                        bg=self.CLR_SURFACE2,
                        fg=self.CLR_TEXT2,
                        font=("Segoe UI", 9),
                        relief=tk.FLAT)

        for tid, tlabel in TABS:
            btn = tk.Button(tab_bar, text=tlabel,
                            font=("Segoe UI", 9), fg=self.CLR_TEXT2,
                            bg=self.CLR_SURFACE2,
                            relief=tk.FLAT, bd=1,
                            padx=8, pady=2, cursor="hand2",
                            activebackground=self.CLR_GLOW,
                            activeforeground=self.CLR_ACCENT,
                            command=lambda t=tid: _switch(t))
            btn.pack(side=tk.LEFT, padx=2, pady=2)

            frm = tk.Frame(tab_content, bg=self.CLR_BG)
            frm.grid(row=0, column=0, sticky="nsew")
            frm.columnconfigure(0, weight=1)
            frm.rowconfigure(0, weight=1)
            frm.rowconfigure(1, weight=0)
            frm.rowconfigure(2, weight=1)

            self._drv_tabs[tid] = (btn, frm)

        # Build each tab
        self._drv_build_scan()
        self._drv_build_smart()
        self._drv_build_repair()
        self._drv_build_recovery()
        self._drv_build_wipe()
        self._drv_build_regen()

        _switch("scan")


    # ── Sekcja: Backup sterowników (wywoływana z _render_backup) ──────────────
    def _render_driver_backup_section(self, parent_frame):
        """
        Kopia zapasowa sterowników Windows.
        Logika oparta na polsoft.ITS™ Driver Backup Utility (Backup.bat):
          %userprofile%\\.polsoft\\backup\\DriverBackup\\   <- folder eksportu
          %userprofile%\\.polsoft\\backup\\DriverBackup-Win.zip <- archiwum
        Metody: DISM /export-driver  lub  pnputil /export-driver
        Na końcu: Compress-Archive PowerShell → ZIP
        """
        import os as _os, math as _math

        frm = parent_frame
        frm.rowconfigure(0, weight=0)
        frm.rowconfigure(1, weight=0)
        frm.rowconfigure(2, weight=1)

        # ── Ścieżki zgodne z Backup.bat ──────────────────────────────────────
        BACKUP_ROOT = _os.path.join(_os.path.expanduser("~"), ".polsoft", "backup")
        BACKUP_DIR  = _os.path.join(BACKUP_ROOT, "DriverBackup")
        ZIP_FILE    = _os.path.join(BACKUP_ROOT, "DriverBackup-Win.zip")

        # ── Kolory ───────────────────────────────────────────────────────────
        BG      = self.CLR_BG
        SURF    = self.CLR_SURFACE2
        ACCENT  = self.CLR_ACCENT
        ACCENT2 = self.CLR_ACCENT2
        MUTED   = self.CLR_MUTED
        DANGER  = self.CLR_DANGER
        SUCCESS = self.CLR_SUCCESS
        BORDER  = self.CLR_BORDER
        TEXT    = self.CLR_TEXT
        TEXT2   = self.CLR_TEXT2
        lp      = self._lerp_color

        # ══════════════════════════════════════════════════════════════════════
        #  ROW 0 — Hero banner z informacjami
        # ══════════════════════════════════════════════════════════════════════
        BANNER_H = 72
        banner_c = tk.Canvas(frm, height=BANNER_H, highlightthickness=0, bd=0)
        banner_c.grid(row=0, column=0, sticky="ew")

        def _draw_banner(e=None):
            W = banner_c.winfo_width() or 900
            banner_c.delete("all")
            BASE = "#0D1F36"
            # Gradient tła
            for y in range(BANNER_H):
                t   = y / BANNER_H
                tt  = 4*t*(1-t)
                col = lp(self._brighten(BASE, 0.14), BASE, t)
                banner_c.create_line(0, y, W, y, fill=col)
            # Lewy pasek akcentowy — szerszy, z rozbłyskiem
            for x in range(8):
                t   = x / 8
                col = lp(ACCENT, BASE, t*0.85 + 0.05)
                banner_c.create_line(x, 0, x, BANNER_H, fill=col)
            # Górny połysk gloss
            gh = BANNER_H // 2
            for y in range(gh):
                t   = y / max(1, gh)
                gc  = lp(lp("#FFFFFF", BASE, 0.80), BASE, t)
                banner_c.create_line(10, y, W, y, fill=gc)
            # Linia dolna akcentowa
            banner_c.create_line(0, BANNER_H-2, W, BANNER_H-2, fill=ACCENT,   width=1)
            banner_c.create_line(0, BANNER_H-1, W, BANNER_H-1, fill="#000000", width=1)
            # Ikona + tytuł
            banner_c.create_text(19, 22, text="💾",
                                 font=("Segoe UI Emoji", 20), fill=ACCENT, anchor=tk.W)
            banner_c.create_text(58, 16, text=_t("Kopia zapasowa sterowników"),
                                 font=("Segoe UI", 13, "bold"), fill=ACCENT, anchor=tk.W)
            banner_c.create_text(58, 34, text="polsoft.ITS™  ·  Driver Backup Utility",
                                 font=("Segoe UI", 9), fill=TEXT2, anchor=tk.W)
            # Ścieżki — prawa strona
            path_y = 18
            for label, val in (("Folder:", BACKUP_DIR), ("ZIP:", ZIP_FILE)):
                banner_c.create_text(W-10, path_y,
                                     text=f"{label}  {val}",
                                     font=("Courier New", 8), fill=MUTED,
                                     anchor=tk.E)
                path_y += 16

        banner_c.bind("<Configure>", _draw_banner)
        self.after(8, _draw_banner)

        # ══════════════════════════════════════════════════════════════════════
        #  ROW 1 — Panel sterowania: przyciski + progress canvas
        # ══════════════════════════════════════════════════════════════════════
        ctrl_outer = tk.Frame(frm, bg=SURF)
        ctrl_outer.grid(row=1, column=0, sticky="ew")
        tk.Frame(ctrl_outer, bg=self._brighten(BORDER, 0.18), height=1).pack(fill=tk.X, side=tk.TOP)
        tk.Frame(ctrl_outer, bg=BORDER, height=1).pack(fill=tk.X, side=tk.BOTTOM)
        ctrl_f = tk.Frame(ctrl_outer, bg=SURF)
        ctrl_f.pack(fill=tk.X, padx=14, pady=8)

        _running = [False]

        # ── Progress canvas (pełna szerokość, rysowany dynamicznie) ──────────
        prog_outer = tk.Frame(ctrl_f, bg=SURF)
        prog_outer.pack(fill=tk.X, pady=(0, 6))

        PB_H = 22
        pb_lbl_var = ["", 0, "idle"]   # [text, pct, state]
        pb_c = tk.Canvas(prog_outer, height=PB_H, highlightthickness=0, bd=0, bg=SURF)
        pb_c.pack(fill=tk.X)

        def _draw_pb(e=None):
            W   = pb_c.winfo_width() or 860
            pct = pb_lbl_var[1]
            state = pb_lbl_var[2]
            label = pb_lbl_var[0]
            pb_c.delete("all")

            # Tło toru
            TRACK_BG = self._darken(SURF, 0.40)
            pb_c.create_rectangle(0, 0, W, PB_H,
                                  fill=TRACK_BG, outline=lp(BORDER, SURF, 0.3), width=1)
            # Wewnętrzny cień toru
            pb_c.create_rectangle(1, 1, W-1, PB_H//2,
                                  fill=self._darken(TRACK_BG, 0.18), outline="")

            if pct > 0:
                fw = max(4, int((W-2) * min(pct,100) / 100))
                col = (DANGER  if state == "error"
                       else SUCCESS if state == "done"
                       else ACCENT  if state == "running"
                       else ACCENT2)
                col_br = self._brighten(col, 0.25)
                col_dk = self._darken(col, 0.20)
                # Gradient fill — ciemny → jasny → kolor
                for x in range(fw):
                    t   = x / max(1, fw)
                    c2  = lp(col_br, col_dk, t)
                    pb_c.create_line(x+1, 1, x+1, PB_H-1, fill=c2)
                # Górny połysk gloss
                gh = PB_H // 2
                for y in range(gh):
                    t  = y / max(1, gh)
                    gc = lp(lp("#FFFFFF", col, 0.50), col, t**0.7)
                    pb_c.create_line(1, y+1, fw, y+1, fill=gc)
                # Prawy brzeg wypełnienia — jasna linia
                pb_c.create_line(fw, 1, fw, PB_H-1,
                                 fill=self._brighten(col, 0.40), width=1)
                # Obramowanie wypełnienia
                pb_c.create_rectangle(1, 1, fw, PB_H-1,
                                      fill="", outline=self._brighten(col, 0.28), width=1)

            # Tekst procentowy na pasku
            pct_str = f"{pct:.0f}%" if pct > 0 else ""
            pb_c.create_text(W//2+1, PB_H//2+1, text=pct_str,
                             font=("Segoe UI", 8, "bold"), fill="#000000", anchor=tk.CENTER)
            pb_c.create_text(W//2,   PB_H//2,   text=pct_str,
                             font=("Segoe UI", 8, "bold"), fill="#FFFFFF", anchor=tk.CENTER)
            # Etykieta po prawej stronie toru
            if label:
                pb_c.create_text(W-6, PB_H//2+1, text=label,
                                 font=("Segoe UI", 8), fill="#000000", anchor=tk.E)
                pb_c.create_text(W-6, PB_H//2,   text=label,
                                 font=("Segoe UI", 8), fill=TEXT2, anchor=tk.E)

        pb_c.bind("<Configure>", _draw_pb)
        self.after(10, _draw_pb)

        def _set_pb(pct, label="", state="idle"):
            pb_lbl_var[0] = label
            pb_lbl_var[1] = pct
            pb_lbl_var[2] = state
            _draw_pb()

        # ── Badge statusu ─────────────────────────────────────────────────────
        status_row = tk.Frame(ctrl_f, bg=SURF)
        status_row.pack(fill=tk.X)

        SBW, SBH = 120, 26
        status_c = tk.Canvas(status_row, width=SBW, height=SBH,
                             highlightthickness=0, bd=0, bg=SURF)
        status_c.pack(side=tk.LEFT, padx=(0, 12))

        _status_state = ["idle"]

        def _draw_status(state="idle"):
            _status_state[0] = state
            status_c.delete("all")
            INFO = {
                "idle":    (MUTED,   _t("○  Oczekuje")),
                "running": (ACCENT,  _t("⏳  W toku…")),
                "zip":     (ACCENT2, _t("🗜  Pakowanie ZIP…")),
                "done":    (SUCCESS, _t("✔  Backup gotowy")),
                "error":   (DANGER,  _t("✘  Błąd")),
            }
            col, txt = INFO.get(state, (MUTED, "?"))
            bg2 = lp(col, SURF, 0.82)
            # Tło z gradientem
            status_c.create_rectangle(0, 0, SBW, SBH,
                                      fill=bg2, outline=col, width=1)
            status_c.create_rectangle(1, 1, SBW-1, SBH//2,
                                      fill=lp("#FFFFFF", bg2, 0.91), outline="")
            # Cień tekstu
            status_c.create_text(SBW//2+1, SBH//2+1, text=txt,
                                 font=("Segoe UI", 9, "bold"),
                                 fill=self._darken(col, 0.45), anchor=tk.CENTER)
            status_c.create_text(SBW//2, SBH//2, text=txt,
                                 font=("Segoe UI", 9, "bold"),
                                 fill=col, anchor=tk.CENTER)

        _draw_status("idle")

        # ── Przyciski metod (wzorowane na BAT: opcja 1 = DISM, opcja 2 = PnPUtil) ──
        btn_grp = tk.Frame(status_row, bg=SURF)
        btn_grp.pack(side=tk.LEFT)

        # ── Animacja pulsująca podczas eksportu ───────────────────────────────
        _anim = [0, None]

        def _anim_tick():
            if not _running[0]:
                return
            phase = (_anim[0] % 60) / 60
            # Oscylacja sin dla realistycznego postępu (5%–90%)
            t   = 0.5 - 0.5 * _math.cos(phase * _math.pi * 2)
            pct = 5 + 85 * t
            state_now = _status_state[0]
            label = ("Eksportowanie sterowników (DISM)…"
                     if state_now == "running" else
                     "Eksportowanie sterowników (PnPUtil)…"
                     if state_now == "running" else
                     "Pakowanie do ZIP…" if state_now == "zip" else "")
            _set_pb(pct, label, state_now)
            _anim[0] += 1
            _anim[1] = self.after(80, _anim_tick)

        def _start_anim(state):
            _running[0] = True
            _draw_status(state)
            _anim[0] = 0
            _anim_tick()

        def _stop_anim():
            _running[0] = False
            if _anim[1]:
                try: self.after_cancel(_anim[1])
                except: pass

        # ── Log ──────────────────────────────────────────────────────────────
        log_txt = self._drv_log_box(frm, row=2)

        def _log(msg, tag=""):
            self._drv_log(log_txt, msg, tag)

        def _clear():
            self._drv_clear(log_txt)

        # ══════════════════════════════════════════════════════════════════════
        #  Główna procedura — odzwierciedla logikę Backup.bat
        # ══════════════════════════════════════════════════════════════════════
        def _do_backup(method: str):
            """
            Odpowiednik sekcji :DISM / :PNPUTIL / :ZIP z Backup.bat.
            method = "dism" | "pnputil"
            """
            if _running[0]:
                return
            _clear()
            _log("══════════════════════════════════════════════════", "hdr")
            _log(f"  polsoft.ITS™  Driver Backup  [{method.upper()}]", "hdr")
            _log("══════════════════════════════════════════════════", "hdr")
            _log("")
            _set_pb(0, "Przygotowanie folderów…", "idle")
            _draw_status("running")

            def worker():
                import os as _o
                try:
                    # --- Prepare folders (jak w BAT: mkdir jeśli nie istnieje) ---
                    _o.makedirs(BACKUP_DIR, exist_ok=True)
                    self.after(0, lambda: _log(f"✔  Folder: {BACKUP_DIR}", "ok"))
                    self.after(0, lambda: _set_pb(3, "Folder przygotowany…", "running"))

                    # --- Wybór komendy (opcja 1 = DISM, opcja 2 = PnPUtil) ---
                    if method == "dism":
                        # :DISM → dism /online /export-driver /destination:"%BACKUP_DIR%"
                        cmd = ["dism", "/online", "/export-driver",
                               f"/destination:{BACKUP_DIR}"]
                        self.after(0, lambda: _log(
                            f"  CMD: dism /online /export-driver /destination:\"{BACKUP_DIR}\"", "muted"))
                    else:
                        # :PNPUTIL → pnputil /export-driver * "%BACKUP_DIR%"
                        cmd = ["pnputil", "/export-driver", "*", BACKUP_DIR]
                        self.after(0, lambda: _log(
                            f"  CMD: pnputil /export-driver * \"{BACKUP_DIR}\"", "muted"))

                    self.after(0, lambda: _log(""))
                    self.after(0, lambda m=method: _start_anim("running"))

                    kw = {"creationflags": subprocess.CREATE_NO_WINDOW} \
                         if sys.platform == "win32" else {}
                    proc = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, errors="replace", **kw)

                    for line in proc.stdout:
                        l = line.rstrip()
                        if not l:
                            continue
                        lo = l.lower()
                        tag = ("err"  if any(w in lo for w in ("error","fail","blad","nie pow")) else
                               "ok"   if any(w in lo for w in ("export","added","ok","success","skopiow","driver package","plik")) else
                               "warn" if any(w in lo for w in ("warn","skip","pominię","uwaga")) else "")
                        self.after(0, lambda x=l, t=tag: _log(x, t))

                    proc.wait()
                    rc = proc.returncode

                    self.after(0, _stop_anim)

                    # --- errorlevel 1 → błąd (jak w BAT: if errorlevel 1 goto MENU) ---
                    if rc not in (0, 1):   # DISM może zwracać 1 przy częściowym sukcesie
                        self.after(0, lambda: _set_pb(100, f"✘  Eksport zakończony błędem (kod {rc})", "error"))
                        self.after(0, lambda: _draw_status("error"))
                        self.after(0, lambda: _log(f"\n✘  {method.upper()} zakończył się kodem: {rc}", "err"))
                        self.after(0, lambda: self._set_status(f"✘ Backup sterowników nieudany (kod {rc})"))
                        return

                    self.after(0, lambda: _log(f"\n✔  Eksport sterowników zakończony (kod: {rc})", "ok"))

                    # ─── :ZIP → powershell Compress-Archive ──────────────────
                    # Odpowiednik sekcji :ZIP z Backup.bat
                    self.after(0, lambda: _draw_status("zip"))
                    self.after(0, lambda: _set_pb(5, "Tworzenie archiwum ZIP…", "zip"))
                    self.after(0, lambda: _log("\n── Tworzenie archiwum ZIP ──", "hdr"))

                    # if exist "%ZIP_FILE%" del "%ZIP_FILE%"
                    if _o.path.exists(ZIP_FILE):
                        _o.remove(ZIP_FILE)
                        self.after(0, lambda: _log(f"  Usunięto stary ZIP.", "muted"))

                    # powershell -command "Compress-Archive -Path '%BACKUP_DIR%\*' -DestinationPath '%ZIP_FILE%' -Force"
                    ps_cmd = (
                        f"Compress-Archive -Path '{BACKUP_DIR}\\*' "
                        f"-DestinationPath '{ZIP_FILE}' -Force"
                    )
                    self.after(0, lambda: _log(f"  CMD: powershell Compress-Archive…", "muted"))

                    self.after(0, lambda: _start_anim("zip"))

                    if sys.platform == "win32":
                        zip_cmd = ["powershell", "-NoProfile", "-NonInteractive",
                                   "-Command", ps_cmd]
                    else:
                        zip_cmd = ["zip", "-r", ZIP_FILE, BACKUP_DIR]

                    r2 = subprocess.run(zip_cmd, capture_output=True, text=True,
                                        errors="replace",
                                        **({"creationflags": subprocess.CREATE_NO_WINDOW}
                                           if sys.platform == "win32" else {}))

                    self.after(0, _stop_anim)

                    # --- if errorlevel 1 (ZIP) ---
                    if r2.returncode != 0:
                        self.after(0, lambda: _set_pb(100, "✘  Nie udało się utworzyć ZIP", "error"))
                        self.after(0, lambda: _draw_status("error"))
                        self.after(0, lambda: _log(f"✘  ZIP error: {r2.stderr or r2.stdout}", "err"))
                        self.after(0, lambda: self._set_status("✘ Błąd tworzenia ZIP"))
                        return

                    # --- [OK] Backup zakończony pomyślnie ---
                    try:
                        size_mb  = _o.path.getsize(ZIP_FILE) / 1024 / 1024
                        size_str = f"{size_mb:.1f} MB"
                    except Exception:
                        size_str = "?"

                    try:
                        n_files = sum(len(fs) for _, _, fs in _o.walk(BACKUP_DIR))
                        n_str   = f"{n_files} plików"
                    except Exception:
                        n_str   = ""

                    self.after(0, lambda: _set_pb(100, f"✔  Backup gotowy — {size_str}", "done"))
                    self.after(0, lambda: _draw_status("done"))
                    self.after(0, lambda: _log(""))
                    self.after(0, lambda: _log("══════════════════════════════════", "hdr"))
                    self.after(0, lambda: _log("  ✔  Backup zakończony pomyślnie!", "ok"))
                    self.after(0, lambda s=size_str: _log(f"  Plik ZIP:  {ZIP_FILE}", "ok"))
                    self.after(0, lambda s=size_str: _log(f"  Rozmiar:  {s}", "ok"))
                    if n_str:
                        self.after(0, lambda n=n_str: _log(f"  Sterowniki: {n}", "ok"))
                    self.after(0, lambda: _log("══════════════════════════════════", "hdr"))
                    self.after(0, lambda s=size_str: self._set_status(f"✔ Backup sterowników — {s}"))

                except Exception as ex:
                    self.after(0, _stop_anim)
                    self.after(0, lambda e=ex: _set_pb(0, f"Błąd: {e}", "error"))
                    self.after(0, lambda: _draw_status("error"))
                    self.after(0, lambda e=ex: _log(f"✘  {e}", "err"))
                    self.after(0, lambda: self._set_status("✘ Błąd backupu sterowników"))
                finally:
                    _running[0] = False

            threading.Thread(target=worker, daemon=True).start()

        # ── Przyciski (opcja 1 / opcja 2 z BAT menu) ─────────────────────────
        self._flat_btn(btn_grp, _t("💾 DISM"), self.CLR_ACCENT2,
                       lambda: _do_backup("dism"),
                       fg=self.CLR_TEXT, padx=10, pady=4).pack(side=tk.LEFT, padx=(0, 5))

        self._flat_btn(btn_grp, _t("🔌 PnPUtil"), "#1A3A5C",
                       lambda: _do_backup("pnputil"),
                       fg=TEXT2, padx=10, pady=4).pack(side=tk.LEFT, padx=(0, 5))

        def _open_folder():
            import os as _o
            _o.makedirs(BACKUP_DIR, exist_ok=True)
            if sys.platform == "win32":
                subprocess.Popen(["explorer", BACKUP_DIR],
                                 **{"creationflags": subprocess.CREATE_NO_WINDOW})
            _log(f"ℹ️  {_t('Otwarto')}: {BACKUP_DIR}", "muted")

        self._flat_btn(btn_grp, _t("📂 Folder"), self.CLR_SURFACE2,
                       _open_folder, fg=TEXT2, padx=10, pady=4).pack(side=tk.LEFT)

        # ── Info startowe w logu ──────────────────────────────────────────────
        _log("polsoft.ITS™  Driver Backup Utility", "hdr")
        _log(f"  {_t('Wersja GUI')} — {_t('bazuje na Backup.bat')}", "muted")
        _log("")
        _log(f"  {_t('Metody eksportu')}:", "muted")
        _log("  • DISM (1)    → dism /online /export-driver", "muted")
        _log("  • PnPUtil (2) → pnputil /export-driver * <folder>", "muted")
        _log("")
        _log(f"  {_t('Folder docelowy')} : {BACKUP_DIR}", "muted")
        _log(f"  {_t('Archiwum ZIP')}    : {ZIP_FILE}", "muted")
        _log("")
        _log(f"  {_t('Kliknij przycisk aby rozpocząć backup.')}", "muted")



    # ── Pomocnicze ─────────────────────────────────────────────────────────────
    def _drv_get_drives(self) -> list:
        drives = []
        if sys.platform == "win32":
            # ── Metoda 1: PowerShell Get-PSDrive (działa na Win10/11) ──────────
            try:
                ps = (
                    "Get-PSDrive -PSProvider FileSystem | "
                    "Select-Object -Property Name,Root,Used,Free,Description | "
                    "ConvertTo-Json"
                )
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                    capture_output=True, text=True, timeout=10,
                    **_no_window_kwargs())
                if result.returncode == 0 and result.stdout.strip():
                    import json as _json
                    data = _json.loads(result.stdout.strip())
                    if isinstance(data, dict):
                        data = [data]
                    for d in data:
                        name = str(d.get("Name", "")).strip()
                        if not name:
                            continue
                        path = f"{name}:"
                        root = str(d.get("Root", path)).strip().rstrip("\\")
                        desc = str(d.get("Description", "")).strip()
                        used = d.get("Used") or 0
                        free = d.get("Free") or 0
                        total = (used + free) if (used or free) else 0
                        size_gb = f"{round(total / (1024**3), 1)} GB" if total else "?"
                        dtype = "Removable" if name.upper() not in ("C","D","E","F","G","H") else "Fixed"
                        label = f"{path}  ({desc or 'No label'})  [{dtype}]"
                        drives.append({"label": label, "path": path,
                                       "size": size_gb, "type": dtype})
            except Exception:
                pass

            # ── Metoda 2: fsutil (fallback) ──────────────────────────────────
            if not drives:
                try:
                    import string
                    for letter in string.ascii_uppercase:
                        path = f"{letter}:"
                        if os.path.exists(path + "\\"):
                            try:
                                total, _, free = os.statvfs(path + "\\").f_blocks, 0, 0
                            except Exception:
                                pass
                            try:
                                import ctypes as _ct
                                free_b  = _ct.c_ulonglong(0)
                                total_b = _ct.c_ulonglong(0)
                                _ct.windll.kernel32.GetDiskFreeSpaceExW(
                                    path + "\\",
                                    _ct.byref(_ct.c_ulonglong(0)),
                                    _ct.byref(total_b),
                                    _ct.byref(free_b))
                                size_gb = f"{round(total_b.value / (1024**3), 1)} GB"
                            except Exception:
                                size_gb = "?"
                            drives.append({
                                "label": f"{path}  [Drive]",
                                "path":  path,
                                "size":  size_gb,
                                "type":  "Fixed",
                            })
                except Exception:
                    pass

            # ── Metoda 3: statyczny fallback ─────────────────────────────────
            if not drives:
                drives = [
                    {"label": "C:  (System)  [Fixed]",      "path": "C:", "size": "237 GB", "type": "Fixed"},
                    {"label": "D:  (Data)  [Fixed]",         "path": "D:", "size": "465 GB", "type": "Fixed"},
                    {"label": "E:  (USB Drive)  [Removable]","path": "E:", "size": "16 GB",  "type": "Removable"},
                ]
        else:
            try:
                result = subprocess.run(
                    ["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,MODEL", "-J"],
                    capture_output=True, text=True, timeout=10)
                for dev in json.loads(result.stdout).get("blockdevices", []):
                    nm = dev.get("name", "")
                    drives.append({"label": f"/dev/{nm}  ({dev.get('model','?')})",
                                   "path": f"/dev/{nm}",
                                   "size": dev.get("size", "?"),
                                   "type": dev.get("type", "disk")})
            except Exception:
                drives = [
                    {"label": "/dev/sda  (HDD)",    "path": "/dev/sda",    "size": "500 GB", "type": "disk"},
                    {"label": "/dev/sdb  (USB)",    "path": "/dev/sdb",    "size": "16 GB",  "type": "disk"},
                    {"label": "/dev/mmcblk0  (SD)", "path": "/dev/mmcblk0","size": "32 GB",  "type": "disk"},
                ]
        return drives

    def _drv_selector(self, parent, attr, row=0) -> tk.StringVar:
        """Drive selector row — returns StringVar."""
        hdr = tk.Frame(parent, bg=self.CLR_SURFACE2)
        hdr.grid(row=row, column=0, sticky="ew", padx=0, pady=0)
        tk.Frame(hdr, bg=self.CLR_BORDER_LT, height=1).pack(fill=tk.X)
        inner = tk.Frame(hdr, bg=self.CLR_SURFACE2)
        inner.pack(fill=tk.X, padx=16, pady=8)

        tk.Label(inner, text="💾  Drive / Device:",
                 font=("Segoe UI", 10, "bold"),
                 fg=self.CLR_TEXT2, bg=self.CLR_SURFACE2).pack(side=tk.LEFT)

        drives = self._drv_get_drives()
        setattr(self, f"_drv_list_{attr}", drives)
        labels = [d["label"] for d in drives]
        var = tk.StringVar(value=labels[0] if labels else "No drives found")

        style = ttk.Style()
        style.configure("Drv.TCombobox",
                        fieldbackground=self.CLR_SURFACE,
                        background=self.CLR_SURFACE,
                        foreground=self.CLR_TEXT,
                        selectbackground=self.CLR_ACCENT2,
                        font=("Segoe UI", 10))
        cb = ttk.Combobox(inner, textvariable=var, values=labels,
                          state="readonly", width=50,
                          style="Drv.TCombobox",
                          font=("Segoe UI", 10))
        cb.pack(side=tk.LEFT, padx=(12, 0))
        tk.Frame(hdr, bg=self.CLR_BORDER, height=1).pack(fill=tk.X)
        return var

    def _drv_path(self, attr: str, var: tk.StringVar) -> str:
        label = var.get()
        lst = getattr(self, f"_drv_list_{attr}", [])
        for d in lst:
            if d["label"] == label:
                return d["path"]
        return label.split()[0]

    def _drv_log_box(self, parent, row=2) -> tk.Text:
        """Dark log area with highlighting."""
        parent.rowconfigure(row, weight=1)
        wrap = tk.Frame(parent, bg=self.CLR_BORDER_LT, padx=1, pady=1)
        wrap.grid(row=row, column=0, sticky="nsew", padx=14, pady=(4, 12))
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        inner = tk.Frame(wrap, bg=self.CLR_BG)
        inner.pack(fill=tk.BOTH, expand=True)
        inner.columnconfigure(0, weight=1)
        inner.rowconfigure(0, weight=1)

        txt = tk.Text(inner, bg="#101820", fg="#50E8FF",
                      font=("Courier New", 10), relief=tk.FLAT,
                      insertbackground=self.CLR_ACCENT,
                      wrap=tk.WORD, bd=0, highlightthickness=0,
                      padx=12, pady=10)
        sb = GlassScrollbar(inner, command=txt.yview, width=10)
        txt.configure(yscrollcommand=sb.set)
        txt.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns", padx=(2, 0))

        txt.tag_configure("ok",   foreground="#3DFFA8",
                          font=("Courier New", 10, "bold"))
        txt.tag_configure("err",  foreground="#FF6875",
                          font=("Courier New", 10, "bold"))
        txt.tag_configure("warn", foreground="#FFD166")
        txt.tag_configure("hdr",  foreground="#50E8FF",
                          font=("Courier New", 11, "bold"))
        txt.tag_configure("muted",foreground="#6A8CB0")
        return txt

    def _drv_log(self, txt: tk.Text, msg: str, tag: str = ""):
        txt.configure(state=tk.NORMAL)
        txt.insert(tk.END, msg + "\n", tag or "")
        txt.see(tk.END)
        txt.configure(state=tk.DISABLED)

    def _drv_clear(self, txt: tk.Text):
        txt.configure(state=tk.NORMAL)
        txt.delete("1.0", tk.END)
        txt.configure(state=tk.DISABLED)

    def _drv_ctrl(self, parent, row=1) -> tk.Frame:
        """Button bar — with 3D underline."""
        wrap = tk.Frame(parent, bg=self.CLR_SURFACE2)
        wrap.grid(row=row, column=0, sticky="ew", padx=0, pady=0)
        tk.Frame(wrap, bg=self.CLR_BORDER, height=1).pack(fill=tk.X)
        ctrl = tk.Frame(wrap, bg=self.CLR_SURFACE2)
        ctrl.pack(fill=tk.X, padx=14, pady=7)
        tk.Frame(wrap, bg=self.CLR_BORDER_LT, height=1).pack(fill=tk.X, side=tk.BOTTOM)
        return ctrl

    def _drv_run_cmd(self, cmd: list, txt: tk.Text, on_done=None):
        def worker():
            try:
                kw = {"creationflags": subprocess.CREATE_NO_WINDOW} \
                     if sys.platform == "win32" else {}
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, errors="replace", **kw)
                for line in proc.stdout:
                    l = line.rstrip()
                    lo = l.lower()
                    tag = ("err"  if any(w in lo for w in ("error","fail","bad","corrupt","nie")) else
                           "warn" if any(w in lo for w in ("warn","caution","old","uwaga")) else
                           "ok"   if any(w in lo for w in ("ok","pass","good","healthy","success",
                                                            "fixed","repaired","naprawiono")) else "")
                    self.after(0, lambda x=l, t=tag: self._drv_log(txt, x, t))
                proc.wait()
                rc = proc.returncode
                self.after(0, lambda: self._drv_log(
                    txt, f"\n── Finished (code: {rc}) ──",
                    "ok" if rc == 0 else "err"))
                if on_done:
                    self.after(0, on_done)
            except FileNotFoundError as e:
                self.after(0, lambda e=e: self._drv_log(
                    txt, f"✘  Tool not found: {e}", "err"))
            except Exception as e:
                self.after(0, lambda e=e: self._drv_log(
                    txt, f"✘  Error: {e}", "err"))
        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _is_system_drive(path: str) -> bool:
        """Returns True if path is the system drive — safe verification."""
        p = path.strip().upper()
        if sys.platform == "win32":
            # Exact "C:" or "C:\" only — does not block e.g. /dev/sdc
            return p == "C:" or p.startswith("C:\\") or p.startswith("C:/")
        else:
            # Na Linux blokuje /dev/sda oraz punkty montowania /
            SYSTEM_DEVS = {"/dev/sda", "/dev/nvme0n1", "/dev/mmcblk0"}
            p_lower = path.strip().lower()
            return p_lower in SYSTEM_DEVS or p_lower == "/"

    # ── TAB: Scan ───────────────────────────────────────────────────────────
    def _drv_build_scan(self):
        _, frm = self._drv_tabs["scan"]
        self._drv_scan_var = self._drv_selector(frm, "scan", row=0)
        ctrl = self._drv_ctrl(frm, row=1)
        self._drv_scan_log = self._drv_log_box(frm, row=2)

        self._flat_btn(ctrl, "🔍  Full Scan", self.CLR_ACCENT2,
                       lambda: self._drv_do_scan(True),
                       fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0, 8))
        self._flat_btn(ctrl, "📋  Drive Info", self.CLR_SURFACE2,
                       self._drv_disk_info,
                       fg=self.CLR_TEXT2).pack(side=tk.LEFT, padx=(0, 8))
        self._flat_btn(ctrl, "⟳  Refresh List", self.CLR_SURFACE2,
                       lambda: self._drv_do_scan(False),
                       fg=self.CLR_MUTED).pack(side=tk.LEFT)

        self._drv_log(self._drv_scan_log,
                      "ℹ  Select a drive and click 'Full Scan' or 'Drive Info'.\n"
                      "   Bad sector scan may take several minutes.", "muted")

    def _drv_do_scan(self, full: bool):
        txt = self._drv_scan_log
        self._drv_clear(txt)
        path = self._drv_path("scan", self._drv_scan_var)
        # Normalize: chkdsk/fsutil want "C:" not "C:\" 
        win_path = path.rstrip("\\") if sys.platform == "win32" else path
        self._set_status(f"Scanning {path}…")
        self._drv_log(txt, f"══ Drive Scan: {path} ══", "hdr")
        if sys.platform == "win32":
            cmd = (["chkdsk", win_path, "/scan", "/perf"] if full
                   else ["fsutil", "fsinfo", "volumeinfo", win_path])
        else:
            cmd = (["sudo", "badblocks", "-v", "-s", path] if full
                   else ["lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,VENDOR,SERIAL", path])
        self._drv_run_cmd(cmd, txt, on_done=lambda: self._set_status(_t("Skanowanie zakończone: {path}").format(path=path)))

    def _drv_disk_info(self):
        txt = self._drv_scan_log
        self._drv_clear(txt)
        path = self._drv_path("scan", self._drv_scan_var)
        self._drv_log(txt, f"══ Drive Info: {path} ══", "hdr")
        self._set_status(f"Pobieranie informacji: {path}…")
        if sys.platform == "win32":
            cmds = [["wmic", "diskdrive", "get",
                     "Model,Size,Status,InterfaceType,MediaType", "/format:list"],
                    ["fsutil", "fsinfo", "ntfsinfo", path.rstrip("\\")]]
        else:
            cmds = [["lsblk", "-o",
                     "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,VENDOR,SERIAL,TRAN", path],
                    ["df", "-h", path]]
        def _seq():
            for cmd in cmds:
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=15, errors="replace")
                    out = r.stdout.strip() or r.stderr.strip()
                    self.after(0, lambda o=out: self._drv_log(txt, o))
                    self.after(0, lambda: self._drv_log(txt, ""))
                except Exception as e:
                    self.after(0, lambda ex=e: self._drv_log(txt, f"✘ {ex}", "err"))
            self.after(0, lambda: self._set_status(f"Informacje pobrane: {path}"))
        threading.Thread(target=_seq, daemon=True).start()

    # ── TAB: SMART ──────────────────────────────────────────────────────────
    def _drv_build_smart(self):
        _, frm = self._drv_tabs["smart"]
        self._drv_smart_var = self._drv_selector(frm, "smart", row=0)
        ctrl = self._drv_ctrl(frm, row=1)
        self._drv_smart_log = self._drv_log_box(frm, row=2)

        self._flat_btn(ctrl, "📊  Health Status", self.CLR_ACCENT2,
                       self._smart_health, fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "📋  All Attributes", self.CLR_SURFACE2,
                       self._smart_all, fg=self.CLR_TEXT2).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "⚡  Short Test", self.CLR_SURFACE2,
                       self._smart_short, fg=self.CLR_ACCENT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "⏱  Long Test", self.CLR_WARN,
                       self._smart_long, fg=self.CLR_HEADER_BG).pack(side=tk.LEFT)

        self._drv_log(self._drv_smart_log,
                      "ℹ  Required: smartmontools (smartctl)\n"
                      "   Windows : https://www.smartmontools.org\n"
                      "   Linux   : sudo apt install smartmontools\n"
                      "\n   Applies to HDD/SSD drives. SD cards and USB drives usually do not support SMART.", "muted")

    def _smart_health(self):
        txt = self._drv_smart_log; self._drv_clear(txt)
        path = self._drv_path("smart", self._drv_smart_var)
        self._drv_log(txt, f"══ SMART – health status: {path} ══", "hdr")
        self._set_status(f"Sprawdzanie SMART: {path}…")
        self._drv_run_cmd(["smartctl", "-H", path], txt,
                          on_done=lambda: self._set_status("SMART gotowy."))

    def _smart_all(self):
        txt = self._drv_smart_log; self._drv_clear(txt)
        path = self._drv_path("smart", self._drv_smart_var)
        self._drv_log(txt, f"══ SMART – all attributes: {path} ══", "hdr")
        self._drv_run_cmd(["smartctl", "-a", path], txt,
                          on_done=lambda: self._set_status("SMART odczytany."))

    def _smart_short(self):
        txt = self._drv_smart_log
        path = self._drv_path("smart", self._drv_smart_var)
        self._drv_log(txt, f"══ SMART – short test: {path} ══", "hdr")
        self._drv_run_cmd(["smartctl", "-t", "short", path], txt,
                          on_done=lambda: self._set_status(_t("Krótki test uruchomiony (~2 min).")))

    def _smart_long(self):
        txt = self._drv_smart_log
        path = self._drv_path("smart", self._drv_smart_var)
        if not messagebox.askyesno(_t("Test SMART (długi)"),
                                   _t("Długi test na {path} może zająć 30–120 min.\nKontynuować?").format(path=path)):
            return
        self._drv_log(txt, f"══ SMART – long test: {path} ══", "hdr")
        self._drv_run_cmd(["smartctl", "-t", "long", path], txt,
                          on_done=lambda: self._set_status(_t("Długi test uruchomiony (w tle).")))

    # ── TAB: Repair / Fix ───────────────────────────────────────────────────
    def _drv_build_repair(self):
        _, frm = self._drv_tabs["repair"]
        self._drv_repair_var = self._drv_selector(frm, "repair", row=0)
        ctrl = self._drv_ctrl(frm, row=1)
        self._drv_repair_log = self._drv_log_box(frm, row=2)

        # Opcje
        opt = tk.Frame(ctrl, bg=self.CLR_SURFACE2)
        opt.pack(side=tk.LEFT, padx=(0, 16))
        self._rep_fix   = tk.BooleanVar(value=True)
        self._rep_spotfix = tk.BooleanVar(value=False)
        for txt, var in [("Auto-repair errors", self._rep_fix),
                         ("SpotFix (bez restartu)", self._rep_spotfix)]:
            tk.Checkbutton(opt, text=txt, variable=var,
                           font=("Segoe UI", 9), fg=self.CLR_TEXT2,
                           bg=self.CLR_SURFACE2, selectcolor=self.CLR_BORDER,
                           activebackground=self.CLR_SURFACE2,
                           activeforeground=self.CLR_ACCENT).pack(side=tk.LEFT, padx=6)

        self._flat_btn(ctrl, "🛠  Check and Repair", self.CLR_ACCENT2,
                       self._rep_run, fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "🔎  Tylko weryfikacja", self.CLR_SURFACE2,
                       self._rep_verify, fg=self.CLR_TEXT2).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "📂  Format FAT32", self.CLR_DANGER,
                       self._rep_format, fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "🗂  Format NTFS", self.CLR_DANGER,
                       self._rep_format_ntfs, fg=self.CLR_TEXT).pack(side=tk.LEFT)

        self._drv_log(self._drv_repair_log,
                      "ℹ  Windows: chkdsk    Linux: fsck\n"
                      "   Repair operations require Administrator / root privileges.\n"
                      "   SpotFix repairs errors online without reboot (Windows only).", "muted")

    def _rep_run(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"),
                                   "Wymagane uprawnienia Administratora / root.")
            return
        txt = self._drv_repair_log; self._drv_clear(txt)
        path = self._drv_path("repair", self._drv_repair_var)
        self._drv_log(txt, f"══ {_t('Sprawdzanie i naprawa: {path}').format(path=path)} ══", "hdr")
        self._set_status(_t("Naprawa systemu plików: {path}…").format(path=path))
        if sys.platform == "win32":
            cmd = ["chkdsk", path.rstrip("\\")]
            cmd.append("/spotfix" if self._rep_spotfix.get()
                       else "/f" if self._rep_fix.get() else "")
            cmd = [c for c in cmd if c]
        else:
            cmd = ["sudo", "fsck", "-y" if self._rep_fix.get() else "-n", path]
        self._drv_run_cmd(cmd, txt, on_done=lambda: self._set_status(_t("Naprawa zakończona.")))

    def _rep_verify(self):
        txt = self._drv_repair_log; self._drv_clear(txt)
        path = self._drv_path("repair", self._drv_repair_var)
        self._drv_log(txt, f"══ {_t('Weryfikacja (tylko odczyt): {path}').format(path=path)} ══", "hdr")
        self._set_status(f"Verifying {path}…")
        cmd = (["chkdsk", path.rstrip("\\")] if sys.platform == "win32"
               else ["sudo", "fsck", "-n", path])
        self._drv_run_cmd(cmd, txt, on_done=lambda: self._set_status(_t("Weryfikacja zakończona.")))

    def _rep_format(self):
        path = self._drv_path("repair", self._drv_repair_var)
        if self._is_system_drive(path):
            messagebox.showerror(_t("Bezpieczeństwo"), _t("Nie można sformatować dysku systemowego!")); return
        if not messagebox.askyesno(_t("Formatuj FAT32"),
                                   _t("⚠  WSZYSTKIE DANE na {path} zostaną USUNIĘTE!\n").format(path=path) +
                                   _t("Format: FAT32.  Kontynuować?"), icon="warning"):
            return
        txt = self._drv_repair_log; self._drv_clear(txt)
        self._drv_log(txt, f"══ Format FAT32: {path} ══", "hdr")
        self._set_status(f"Formatowanie {path} jako FAT32…")
        cmd = (["format", f"{path.rstrip(':\\:')}:", "/FS:FAT32", "/Q", "/Y"]
               if sys.platform == "win32"
               else ["sudo", "mkfs.fat", "-F", "32", path])
        self._drv_run_cmd(cmd, txt, on_done=lambda: self._set_status(_t("Formatowanie zakończone.")))

    def _rep_format_ntfs(self):
        path = self._drv_path("repair", self._drv_repair_var)
        if self._is_system_drive(path):
            messagebox.showerror(_t("Bezpieczeństwo"), _t("Nie można sformatować dysku systemowego!")); return
        if not messagebox.askyesno(_t("Formatuj NTFS"),
                                   _t("⚠  WSZYSTKIE DANE na {path} zostaną USUNIĘTE!\n").format(path=path) +
                                   _t("Format: NTFS.  Kontynuować?"), icon="warning"):
            return
        txt = self._drv_repair_log; self._drv_clear(txt)
        self._drv_log(txt, f"══ Format NTFS: {path} ══", "hdr")
        self._set_status(f"Formatowanie {path} jako NTFS…")
        cmd = (["format", f"{path.rstrip(':\\:')}:", "/FS:NTFS", "/Q", "/Y"]
               if sys.platform == "win32"
               else ["sudo", "mkfs.ntfs", "-f", path])
        self._drv_run_cmd(cmd, txt, on_done=lambda: self._set_status(_t("Formatowanie NTFS zakończone.")))

    # ── TAB: Data Recovery ──────────────────────────────────────────────────
    def _drv_build_recovery(self):
        _, frm = self._drv_tabs["recovery"]
        self._drv_rec_var = self._drv_selector(frm, "rec", row=0)
        ctrl = self._drv_ctrl(frm, row=1)
        self._drv_rec_log = self._drv_log_box(frm, row=2)

        self._flat_btn(ctrl, "♻️  TestDisk", self.CLR_ACCENT2,
                       self._rec_testdisk, fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "🖼  PhotoRec", self.CLR_ACCENT2,
                       self._rec_photorec, fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "📁  extundelete", self.CLR_SURFACE2,
                       self._rec_extundelete, fg=self.CLR_TEXT2).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "🗺  Scan MBR/GPT", self.CLR_SURFACE2,
                       self._rec_scan_parts, fg=self.CLR_ACCENT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "💾  Clone Drive", self.CLR_WARN,
                       self._rec_clone, fg=self.CLR_HEADER_BG).pack(side=tk.LEFT)

        self._drv_log(self._drv_rec_log,
                      "ℹ  Data recovery tools:\n"
                      "   TestDisk / PhotoRec : https://www.cgsecurity.org\n"
                      "   Linux              : sudo apt install testdisk\n"
                      "   extundelete        : sudo apt install extundelete  (tylko Linux ext2/3/4)\n"
                      "\n⚠  For best results work on an unmounted / read-only media.", "muted")

    def _rec_testdisk(self):
        txt = self._drv_rec_log
        path = self._drv_path("rec", self._drv_rec_var)
        self._drv_log(txt, f"══ TestDisk: {path} ══", "hdr")
        self._set_status(f"Uruchamiam TestDisk: {path}…")
        try:
            if sys.platform == "win32":
                subprocess.Popen(["cmd", "/c", "start", "testdisk_win.exe", "/log", path])
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", f"sudo testdisk {path}"])
            self._drv_log(txt, "✔  " + _t("TestDisk uruchomiony w nowym oknie."), "ok")
        except Exception as e:
            self._drv_log(txt, f"✘  testdisk not found: {e}\n"
                          "   Pobierz: https://www.cgsecurity.org", "err")

    def _rec_photorec(self):
        txt = self._drv_rec_log
        path = self._drv_path("rec", self._drv_rec_var)
        self._drv_log(txt, f"══ PhotoRec: {path} ══", "hdr")
        try:
            if sys.platform == "win32":
                subprocess.Popen(["cmd", "/c", "start", "photorec_win.exe", path])
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", f"sudo photorec {path}"])
            self._drv_log(txt, "✔  " + _t("PhotoRec uruchomiony."), "ok")
        except Exception as e:
            self._drv_log(txt, f"✘  {e}\n   Download the TestDisk package (includes PhotoRec).", "err")

    def _rec_extundelete(self):
        txt = self._drv_rec_log; self._drv_clear(txt)
        path = self._drv_path("rec", self._drv_rec_var)
        self._drv_log(txt, f"══ extundelete: {path} ══", "hdr")
        if sys.platform == "win32":
            self._drv_log(txt,
                          "ℹ  extundelete works only on Linux (ext2/3/4).\n"
                          "   On Windows use: Recuva, R-Studio or GetDataBack.", "warn")
            return
        self._set_status(_t("Skanowanie {path} w poszukiwaniu usuniętych plików…").format(path=path))
        self._drv_log(txt, "⚠  Files will be saved to ./RECOVERED_FILES/", "warn")
        self._drv_run_cmd(["sudo", "extundelete", path, "--restore-all"], txt,
                          on_done=lambda: self._set_status("extundelete complete."))

    def _rec_scan_parts(self):
        txt = self._drv_rec_log; self._drv_clear(txt)
        path = self._drv_path("rec", self._drv_rec_var)
        self._drv_log(txt, f"══ {_t('Skan tablicy partycji: {path}').format(path=path)} ══", "hdr")
        self._set_status(_t("Skanowanie tablicy partycji: {path}…").format(path=path))
        if sys.platform == "win32":
            try:
                script = "list disk\nlist volume\nexit\n"
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
                    tf.write(script)
                    tmp = tf.name
                try:
                    r = subprocess.run(["diskpart", "/s", tmp],
                                       capture_output=True, text=True, timeout=20)
                finally:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
                self._drv_log(txt, r.stdout)
            except Exception as e:
                self._drv_log(txt, f"✘ {e}", "err")
        else:
            self._drv_run_cmd(["sudo", "fdisk", "-l", path], txt,
                               on_done=lambda: self._set_status(_t("Skanowanie partycji zakończone.")))

    def _rec_clone(self):
        txt = self._drv_rec_log
        path = self._drv_path("rec", self._drv_rec_var)
        if sys.platform == "win32":
            messagebox.showinfo(_t("Klonowanie dysku"),
                                _t("Klonowanie bloków przez dd nie jest dostępne w Windows.\n\n") +
                                _t("Zalecane narzędzia:\n") +
                                "• Clonezilla (clonezilla.org)\n"
                                "• Macrium Reflect Free\n"
                                "• DriveImage XML")
            self._drv_log(txt, _t("ℹ  Na Windows użyj Clonezilla lub Macrium Reflect."), "warn")
            return
        drives = self._drv_get_drives()
        targets = [d["path"] for d in drives if d["path"] != path]
        if not targets:
            messagebox.showerror(_t("Klonowanie"), _t("Brak dostępnych dysków docelowych."))
            return
        win = tk.Toplevel(self)
        win.title(_t("Klonuj dysk"))
        win.geometry("420x210")
        win.configure(bg=self.CLR_BG)
        win.transient(self); win.grab_set()

        tk.Frame(win, bg=self.CLR_BORDER_LT, height=1).pack(fill=tk.X)
        tk.Label(win, text=f"  Source:  {path}",
                 font=("Segoe UI", 10, "bold"), fg=self.CLR_TEXT,
                 bg=self.CLR_SURFACE2).pack(fill=tk.X, padx=0, pady=(8, 4))
        tk.Label(win, text="  " + _t("Dysk docelowy:"),
                 font=("Segoe UI", 10), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(anchor=tk.W, padx=14)
        tgt_var = tk.StringVar(value=targets[0])
        ttk.Combobox(win, textvariable=tgt_var, values=targets,
                     state="readonly", width=36).pack(padx=14, pady=6)
        tk.Label(win, text="⚠  Data on the target drive will be OVERWRITTEN!",
                 font=("Segoe UI", 9, "bold"), fg=self.CLR_DANGER,
                 bg=self.CLR_BG).pack()
        btn_row = tk.Frame(win, bg=self.CLR_BG)
        btn_row.pack(pady=12)

        def _do():
            tgt = tgt_var.get(); win.destroy()
            self._drv_clear(txt)
            self._drv_log(txt, f"══ Cloning: {path} → {tgt} ══", "hdr")
            self._set_status(_t("Klonowanie {path} → {tgt}…").format(path=path, tgt=tgt))
            self._drv_run_cmd(
                ["sudo", "dd", f"if={path}", f"of={tgt}",
                 "bs=4M", "conv=sync,noerror", "status=progress"],
                txt, on_done=lambda: self._set_status(_t("Klonowanie zakończone.")))

        self._flat_btn(btn_row, _t("▶  KLONUJ"), self.CLR_DANGER,
                       _do, fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=8)
        self._flat_btn(btn_row, "Anuluj", self.CLR_SURFACE2,
                       win.destroy, fg=self.CLR_TEXT2).pack(side=tk.LEFT)

    # ── TAB: Wipe ───────────────────────────────────────────────────────────
    def _drv_build_wipe(self):
        _, frm = self._drv_tabs["wipe"]
        self._drv_wipe_var = self._drv_selector(frm, "wipe", row=0)
        ctrl = self._drv_ctrl(frm, row=1)
        self._drv_wipe_log = self._drv_log_box(frm, row=2)

        passes_f = tk.Frame(ctrl, bg=self.CLR_SURFACE2)
        passes_f.pack(side=tk.LEFT, padx=(0, 16))
        tk.Label(passes_f, text=_t("Przebiegi:"),
                 font=("Segoe UI", 9), fg=self.CLR_MUTED,
                 bg=self.CLR_SURFACE2).pack(side=tk.LEFT)
        self._wipe_passes = tk.StringVar(value="1")
        ttk.Spinbox(passes_f, from_=1, to=35,
                    textvariable=self._wipe_passes,
                    width=4, font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=4)

        self._flat_btn(ctrl, "🧹  Zero-fill", self.CLR_ACCENT2,
                       self._wipe_zero, fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "🔒  " + _t("Bezpieczne kasowanie"), self.CLR_DANGER,
                       self._wipe_secure, fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "🎲  " + _t("Losowe dane"), self.CLR_SURFACE2,
                       self._wipe_random, fg=self.CLR_WARN).pack(side=tk.LEFT)

        self._drv_log(self._drv_wipe_log,
                      "⚠  WARNING: Wipe operations PERMANENTLY destroy ALL data!\n"
                      "   Zero-fill    : fastest — overwrites with zeros (0x00)\n"
                      "   Secure erase : shred (Linux) / cipher /w (Windows)\n"
                      "   Random data  : overwrites with random bytes (good for SSD)", "err")

    def _wipe_zero(self):
        path = self._drv_path("wipe", self._drv_wipe_var)
        if self._is_system_drive(path):
            messagebox.showerror(_t("Bezpieczeństwo"), _t("Nie można wyczyścić dysku systemowego!")); return
        if not messagebox.askyesno(_t("Wypełnienie zerami"),
                                   _t("⚠  WSZYSTKIE DANE na {path} zostaną ZNISZCZONE zerami!\nKontynuować?").format(path=path),
                                   icon="warning"):
            return
        txt = self._drv_wipe_log; self._drv_clear(txt)
        self._drv_log(txt, f"══ Zero-fill: {path} ══", "hdr")
        self._set_status(_t("Wypełnienie zerami: {path}…").format(path=path))
        cmd = (["cipher", "/w:" + path.rstrip(":\\") + ":\\"] if sys.platform == "win32"
               else ["sudo", "dd", "if=/dev/zero", f"of={path}", "bs=4M", "status=progress"])
        self._drv_run_cmd(cmd, txt, on_done=lambda: self._set_status(_t("Wypełnienie zerami zakończone.")))

    def _wipe_secure(self):
        path = self._drv_path("wipe", self._drv_wipe_var)
        if self._is_system_drive(path):
            messagebox.showerror(_t("Bezpieczeństwo"), _t("Nie można wyczyścić dysku systemowego!")); return
        passes = self._wipe_passes.get()
        if not messagebox.askyesno(_t("Bezpieczne kasowanie"),
                                   _t("⚠  BEZPIECZNE KASOWANIE {path}  ({passes} przebieg(ów))\n").format(path=path, passes=passes) +
                                   _t("Wszystkie dane zostaną nieodwracalnie zniszczone!"),
                                   icon="warning"):
            return
        txt = self._drv_wipe_log; self._drv_clear(txt)
        self._drv_log(txt, f"══ {_t('Bezpieczne kasowanie: {path}').format(path=path)} ══", "hdr")
        self._set_status(f"Secure erase: {path}…")
        cmd = (["cipher", "/w:" + path.rstrip(":\\") + ":\\"] if sys.platform == "win32"
               else ["sudo", "shred", f"-n{passes}", "-v", "-z", path])
        self._drv_run_cmd(cmd, txt, on_done=lambda: self._set_status(_t("Bezpieczne kasowanie zakończone.")))

    def _wipe_random(self):
        path = self._drv_path("wipe", self._drv_wipe_var)
        if self._is_system_drive(path):
            messagebox.showerror(_t("Bezpieczeństwo"), _t("Nie można wyczyścić dysku systemowego!")); return
        if not messagebox.askyesno(_t("Losowe dane"),
                                   _t("⚠  Wypełnić {path} losowymi danymi?\nWszystkie istniejące dane zostaną utracone.").format(path=path),
                                   icon="warning"):
            return
        if sys.platform == "win32":
            messagebox.showinfo(_t("Losowe dane"),
                                _t("Wypełnienie losowymi danymi przez dd nie jest dostępne na Windows.\n") +
                                _t("Użyj Eraser lub Cipher z wieloma przebiegami."))
            return
        txt = self._drv_wipe_log; self._drv_clear(txt)
        self._drv_log(txt, f"══ Losowe dane: {path} ══", "hdr")
        self._set_status(_t("Wypełnianie losowymi danymi: {path}…").format(path=path))
        self._drv_run_cmd(["sudo", "dd", "if=/dev/urandom", f"of={path}",
                           "bs=4M", "status=progress"], txt,
                          on_done=lambda: self._set_status(_t("Wypełnienie losowymi danymi zakończone.")))

    # ── TAB: Drive Regeneration ─────────────────────────────────────────────
    def _drv_build_regen(self):
        _, frm = self._drv_tabs["regen"]
        self._drv_regen_var = self._drv_selector(frm, "regen", row=0)
        ctrl = self._drv_ctrl(frm, row=1)
        self._drv_regen_log = self._drv_log_box(frm, row=2)

        self._flat_btn(ctrl, "🔄  Refresh MBR/GPT", self.CLR_ACCENT2,
                       self._regen_mbr, fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, _t("🧲  Napraw sektory (HDD)"), self.CLR_SURFACE2,
                       self._regen_bad_sectors, fg=self.CLR_TEXT2).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "⚡  Trim SSD", self.CLR_SUCCESS,
                       self._regen_trim, fg=self.CLR_HEADER_BG).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "🔋  Reset USB (Reconnect)", self.CLR_WARN,
                       self._regen_usb_reset, fg=self.CLR_HEADER_BG).pack(side=tk.LEFT, padx=(0,8))
        self._flat_btn(ctrl, "📝  Restore Partition Table", self.CLR_DANGER,
                       self._regen_restore_pt, fg=self.CLR_TEXT).pack(side=tk.LEFT)

        self._drv_log(self._drv_regen_log,
                      "ℹ  Drive regeneration tools:\n\n"
                      "   Refresh MBR/GPT       : Rebuilds partition table (bootrec/testdisk)\n"
                      "   Repair sectors         : Attempts to regenerate damaged HDD sectors\n"
                      "   Trim SSD              : Sends TRIM command to SSD (optimisation)\n"
                      "   Reset USB             : Disconnects and reconnects USB via system tools\n"
                      "   Restore table         : TestDisk — interactive partition restore\n\n"
                      "⚠  Regeneration of a damaged medium does not guarantee data recovery.\n"
                      "   Always make a backup before repair!", "muted")

    def _regen_mbr(self):
        txt = self._drv_regen_log; self._drv_clear(txt)
        path = self._drv_path("regen", self._drv_regen_var)
        self._drv_log(txt, f"══ Refreshing MBR/GPT: {path} ══", "hdr")
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia Administratora."))
            return
        self._set_status(_t("Odświeżanie tablicy partycji: {path}…").format(path=path))
        if sys.platform == "win32":
            # Run fixmbr, then fixboot sequentially after completion
            self._drv_run_cmd(
                ["bootrec", "/fixmbr"], txt,
                on_done=lambda: self._drv_run_cmd(
                    ["bootrec", "/fixboot"], txt,
                    on_done=lambda: self._set_status(_t("Odświeżenie MBR/GPT zakończone."))))
        else:
            self._drv_run_cmd(["sudo", "grub-install", path], txt,
                               on_done=lambda: self._set_status(_t("Odświeżenie MBR zakończone.")))

    def _regen_bad_sectors(self):
        txt = self._drv_regen_log; self._drv_clear(txt)
        path = self._drv_path("regen", self._drv_regen_var)
        self._drv_log(txt, f"══ Damaged sector regeneration: {path} ══", "hdr")
        self._drv_log(txt,
                      "ℹ  Attempting sector regeneration via forced read with verification.\n"
                      "   This may take from a few minutes to several hours.\n"
                      "   HDD: some sectors may be reallocated by firmware.", "warn")
        self._set_status(_t("Regeneracja sektorów: {path}…").format(path=path))
        if sys.platform == "win32":
            self._drv_run_cmd(
                ["chkdsk", path.rstrip("\\"), "/r", "/scan"],
                txt, on_done=lambda: self._set_status(_t("Naprawa sektorów zakończona.")))
        else:
            self._drv_run_cmd(
                ["sudo", "badblocks", "-n", "-v", "-s", path],
                txt, on_done=lambda: self._set_status("Badblocks complete."))

    def _regen_trim(self):
        txt = self._drv_regen_log; self._drv_clear(txt)
        path = self._drv_path("regen", self._drv_regen_var)
        self._drv_log(txt, f"══ TRIM SSD: {path} ══", "hdr")
        self._set_status(f"Running TRIM: {path}…")
        if sys.platform == "win32":
            self._drv_run_cmd(
                ["defrag", path.rstrip(":\\") + ":", "/U", "/V", "/L"],
                txt, on_done=lambda: self._set_status("TRIM complete."))
        else:
            # fstrim wymaga punktu montowania
            self._drv_run_cmd(
                ["sudo", "fstrim", "-v", path if "/" in path else "/"],
                txt, on_done=lambda: self._set_status("fstrim complete."))

    def _regen_usb_reset(self):
        txt = self._drv_regen_log; self._drv_clear(txt)
        path = self._drv_path("regen", self._drv_regen_var)
        self._drv_log(txt, f"══ Reset USB: {path} ══", "hdr")
        self._set_status("Resetting USB port…")
        if sys.platform == "win32":
            self._drv_log(txt,
                          "ℹ  On Windows: Physically disconnect and reconnect the USB device.\n"
                          "   Or use: Device Manager → Disable → Enable\n\n"
                          "   Attempting via devcon (if installed):", "warn")
            self._drv_run_cmd(
                ["devcon", "restart", "@USBSTOR\\*"],
                txt, on_done=lambda: self._set_status("USB reset complete."))
        else:
            dev_name = path.split("/")[-1] if "/" in path else path
            self._drv_log(txt,
                          f"ℹ  Attempting reset via echo to sysfs ({dev_name})...\n", "warn")
            def _reset():
                try:
                    for sysf in [f"/sys/bus/usb/devices/{dev_name}/authorized"]:
                        if os.path.exists(sysf):
                            subprocess.run(["sudo", "sh", "-c", f"echo 0 > {sysf}"],
                                           timeout=5)
                            time.sleep(1)
                            subprocess.run(["sudo", "sh", "-c", f"echo 1 > {sysf}"],
                                           timeout=5)
                            self.after(0, lambda: self._drv_log(
                                txt, f"✔  Reset: {sysf}", "ok"))
                            return
                    self.after(0, lambda: self._drv_log(
                        txt, "ℹ  sysfs path not found — disconnect USB physically.", "warn"))
                except Exception as e:
                    self.after(0, lambda e=e: self._drv_log(txt, f"✘ {e}", "err"))
                self.after(0, lambda: self._set_status("USB reset complete."))
            threading.Thread(target=_reset, daemon=True).start()

    def _regen_restore_pt(self):
        txt = self._drv_regen_log; self._drv_clear(txt)
        path = self._drv_path("regen", self._drv_regen_var)
        self._drv_log(txt, f"══ Przywracanie tablicy partycji: {path} ══", "hdr")
        self._drv_log(txt,
                      "ℹ  Starting TestDisk in interactive mode.\n"
                      "   TestDisk will detect and suggest restoring lost partitions.\n"
                      "   Follow the instructions in the terminal window.", "warn")
        self._set_status(f"Uruchamiam TestDisk: {path}…")
        try:
            if sys.platform == "win32":
                subprocess.Popen(["cmd", "/c", "start", "testdisk_win.exe",
                                  "/log", path])
                self._drv_log(txt, "✔  " + _t("TestDisk uruchomiony."), "ok")
            else:
                subprocess.Popen(["x-terminal-emulator", "-e",
                                  f"sudo testdisk {path}"])
                self._drv_log(txt, "✔  " + _t("TestDisk uruchomiony w terminalu."), "ok")
        except Exception as e:
            self._drv_log(txt,
                          f"✘  Error starting TestDisk: {e}\n"
                          "   Run manually: sudo testdisk " + path, "err")
        self._set_status("TestDisk uruchomiony.")

    # ── Theme helpers (v2) ────────────────────────────────────────────────────
    def _load_palette(self, palette: dict):
        """Copy palette dict values into CLR_* instance attributes."""
        self.CLR_BG        = palette["BG"]
        self.CLR_SURFACE   = palette["SURFACE"]
        self.CLR_SURFACE2  = palette["SURFACE2"]
        self.CLR_BORDER    = palette["BORDER"]
        self.CLR_BORDER_LT = palette["BORDER_LT"]
        self.CLR_ACCENT    = palette["ACCENT"]
        self.CLR_ACCENT2   = palette["ACCENT2"]
        self.CLR_DANGER    = palette["DANGER"]
        self.CLR_SUCCESS   = palette["SUCCESS"]
        self.CLR_WARN      = palette["WARN"]
        self.CLR_TEXT      = palette["TEXT"]
        self.CLR_TEXT2     = palette["TEXT2"]
        self.CLR_MUTED     = palette["MUTED"]
        self.CLR_HEADER_BG = palette["HEADER_BG"]
        self.CLR_CARD_TOP  = palette["CARD_TOP"]
        self.CLR_CARD_BOT  = palette["CARD_BOT"]
        self.CLR_GLOW      = palette["GLOW"]

    def _toggle_theme(self):
        """Switch between dark and light mode and rebuild the entire UI."""
        current = self._active_module

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

        self.secure_states    = {}
        self.status_labels    = {}
        self.toggle_buttons   = {}
        self._sidebar_buttons = {}

        self._apply_scrollbar_style()
        self._build_menubar()
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


    # ── Extended menu utils ──────────────────────────────────────────────────
    def _drives_menu_tab(self, tab: str):
        """Switch to Drives module and activate the given tab."""
        self._switch_module("drives")
        def _set_tab():
            if hasattr(self, '_drv_tabs') and tab in self._drv_tabs:
                self._drv_active_tab.set(tab)
                for k, (btn, frm) in self._drv_tabs.items():
                    if k == tab:
                        btn.configure(bg=self.CLR_BG, fg=self.CLR_ACCENT,
                                      font=("Segoe UI", 10, "bold"), relief=tk.SUNKEN)
                        frm.tkraise()
                    else:
                        btn.configure(bg=self.CLR_SURFACE2, fg=self.CLR_TEXT2,
                                      font=("Segoe UI", 10), relief=tk.RAISED)
        self.after(150, _set_tab)

    def _refresh_drives_info(self):
        """Refresh the currently active Drives tab (no-op if module not loaded)."""
        if hasattr(self, '_drv_active_tab') and hasattr(self, '_drv_tabs'):
            tab = self._drv_active_tab.get()
            if tab in self._drv_tabs:
                _, frm = self._drv_tabs[tab]
                build_fn = getattr(self, f"_drv_build_{tab}", None)
                if build_fn:
                    for w in frm.winfo_children():
                        w.destroy()
                    build_fn()

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
        current = self._active_module
        for widget in self.winfo_children():
            widget.destroy()
        self.secure_states    = {}
        self.status_labels    = {}
        self.toggle_buttons   = {}
        self._sidebar_buttons = {}
        self._apply_scrollbar_style()
        self._build_menubar()
        self._build_ui()
        self._build_watermark()
        self._switch_module(current)

    def _refresh_ntfs_from_menu(self):
        """Refresh NTFSecur partitions from menu"""
        self._switch_module("ntfsecur")
        if hasattr(self, '_load_partitions'):
            self._load_partitions()

    def _reset_factory_settings(self):
        """Przywroc ustawienia fabryczne."""
        if not messagebox.askyesno(
                _t("Przywróć ustawienia fabryczne"),
                _t("Spowoduje to przywrócenie WSZYSTKICH ustawień do wartości fabrycznych\n") +
                _t("i ponowne uruchomienie interfejsu.\n\nKontynuować?")):
            return
        get_settings().reset_to_factory()
        messagebox.showinfo(_t("Reset zakończony"),
                            _t("Przywrócono ustawienia fabryczne.\n") +
                            _t("Geometria okna i motyw zostały zresetowane."))
        self._toggle_theme() if not self._is_dark else None
        self._rebuild_ui_keep_module()

    # ── Sidebar + Watermark helpers ───────────────────────────────────────────
    def _update_sidebar(self, active):
        """Update sidebar button highlight to match the active module."""
        for key, (row, accent, lbl) in self._sidebar_buttons.items():
            if key == active:
                row.configure(bg=self.CLR_GLOW)
                accent.configure(bg=self.CLR_ACCENT)
                lbl.configure(bg=self.CLR_GLOW, fg=self.CLR_ACCENT,
                               font=("Segoe UI", 11, "bold"))
            else:
                row.configure(bg=self.CLR_SURFACE)
                accent.configure(bg=self.CLR_SURFACE2)
                lbl.configure(bg=self.CLR_SURFACE, fg=self.CLR_TEXT2,
                               font=("Segoe UI", 11))

    def _build_watermark(self):
        """Place semi-transparent logo watermark in bottom-right corner."""
        self._wm_img = None
        logo_path = resource_path("ntfsecur", "pic", "logo.png")
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


    # ── Module helpers (v2 – lighter) ────────────────────────────────────────
    def _module_header(self, icon, title, subtitle):
        """Lightweight module header using pack — used by newer modules."""
        hdr = tk.Frame(self.content_frame, bg=self.CLR_BG)
        hdr.pack(fill=tk.X, padx=24, pady=(16, 0))
        label_text = f"{icon}  {title}" if icon else title
        tk.Label(hdr, text=label_text, font=("Segoe UI", 18, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(side=tk.LEFT)
        if subtitle:
            tk.Label(hdr, text=f"  {subtitle}", font=("Segoe UI", 10),
                     fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, pady=(5, 0))
        tk.Frame(self.content_frame, bg=self.CLR_BORDER, height=1
                 ).pack(fill=tk.X, padx=16, pady=(8, 0))

    def _scrollable_area(self, parent=None) -> tk.Frame:
        container = parent if parent is not None else self.content_frame
        wrapper = tk.Frame(container, bg=self.CLR_BG)
        wrapper.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        canvas = tk.Canvas(wrapper, bg=self.CLR_BG, highlightthickness=0)
        sb = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=canvas.yview)
        inner = tk.Frame(canvas, bg=self.CLR_BG)

        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        cid = canvas.create_window((0, 0), window=inner, anchor=tk.NW)
        canvas.configure(yscrollcommand=sb.set)
        # Stretch content to canvas width
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(cid, width=e.width))
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        # MouseWheel with auto-detach on destroy
        def _wheel(e):
            if canvas.winfo_exists():
                canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        try:
            canvas.unbind_all("<MouseWheel>")
        except Exception:
            pass
        canvas.bind_all("<MouseWheel>", _wheel)
        canvas.bind("<Destroy>", lambda e: canvas.unbind_all("<MouseWheel>"))
        return inner

    def _action_btn(self, parent, text, color, command):
        return tk.Button(parent, text=text, font=("Segoe UI", 9, "bold"),
                         fg=self.CLR_BG, bg=color,
                         activebackground=self.CLR_ACCENT, activeforeground=self.CLR_BG,
                         relief=tk.FLAT, bd=0, padx=8, pady=4, cursor="hand2",
                         command=command)

    def _col_headers(self, cols_spec):
        cols = tk.Frame(self.content_frame, bg=self.CLR_SURFACE)
        cols.pack(fill=tk.X, padx=8, pady=(4, 0))
        for txt, w in cols_spec:
            tk.Label(cols, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)


    # ══ MODULE: BitLocker (standalone list view) ═════════════════════════════
    def _render_bitlocker(self):
        if sys.platform != "win32":
            self._module_header("", "BitLocker", _t("Szyfrowanie dysków Windows"))
            tk.Label(self.content_frame, 
                    text="BitLocker is only available on Windows Pro/Enterprise editions.",
                    font=("Segoe UI", 12), fg=self.CLR_WARN, bg=self.CLR_BG).pack(pady=40)
            return
        
        self._module_header("", "BitLocker", _t("Zarządzanie szyfrowaniem dysków Windows"))
        tk.Label(self.content_frame,
                text="View and manage BitLocker encryption on all NTFS volumes.",
                font=("Segoe UI", 10), fg=self.CLR_MUTED, bg=self.CLR_BG,
                justify=tk.LEFT).pack(anchor=tk.W, padx=16, pady=(4, 6))
        
        # Toolbar
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=8, pady=4)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                        self._refresh_bitlocker_list).pack(side=tk.LEFT, padx=(0, 8))
        
        self._bitlock_container = self._scrollable_area()
        self._refresh_bitlocker_list()

    def _refresh_bitlocker_list(self):
        """Refresh BitLocker status for all partitions"""
        if not hasattr(self, '_bitlock_container') or not self._bitlock_container.winfo_exists():
            return
        self._set_status("Scanning BitLocker status...")
        for w in self._bitlock_container.winfo_children():
            w.destroy()

        tk.Label(self._bitlock_container, text="Loading…",
                font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)

        # Capture the container reference at the time the thread is started
        container_ref = self._bitlock_container

        def worker():
            partitions = get_ntfs_partitions()
            bl_data = []
            for part in partitions:
                status = get_bitlocker_status(part['drive'])
                bl_data.append({'partition': part, 'status': status})
            # Only schedule UI update if the container widget still exists
            def _safe_display():
                try:
                    if container_ref.winfo_exists():
                        self._display_bitlocker_list(bl_data, container_ref)
                except Exception:
                    pass
            self.after(0, _safe_display)

        threading.Thread(target=worker, daemon=True).start()

    def _display_bitlocker_list(self, bl_data, container=None):
        """Display BitLocker status and controls for all drives"""
        if container is None:
            container = getattr(self, '_bitlock_container', None)
        if container is None or not container.winfo_exists():
            return

        for w in container.winfo_children():
            w.destroy()

        if not bl_data:
            tk.Label(container, text="No NTFS partitions found.",
                    font=("Segoe UI", 12), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=40)
            self._set_status(_t("Nie znaleziono partycji NTFS."))
            return

        for item in bl_data:
            part = item['partition']
            status = item['status']
            self._build_bitlocker_card(container, part, status)

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
            messagebox.showwarning(_t("Niewystarczające uprawnienia"),
                                  _t("Wymagane uprawnienia administratora.") + "\n"
                                  + _t("do zarządzania BitLockerem.\n\n")
                                  + _t("Uruchom ponownie aplikację jako Administrator."))
            return
        
        action_names = {'on': _t('Włącz szyfrowanie'), 'off': _t('Odszyfruj dysk'), 'suspend': _t('Wstrzymaj ochronę')}
        action_name = action_names.get(action, action)
        
        if not messagebox.askyesno(_t("Potwierdź działanie"),
                                  _t("Ta operacja może zająć dużo czasu.\n\n") +
                                  _t("Wykonać: {action_name}\nna {drive}?").format(action_name=action_name, drive=drive)):
            return
        
        self._set_status(f"BitLocker: {action_name} na {drive}...")
        
        def worker():
            ok, msg = control_bitlocker(drive, action)
            self.after(0, lambda: (
                self._set_status(f"{'OK' if ok else 'ERROR'} {msg}"),
                self._refresh_bitlocker_list() if ok else None
            ))
        
        threading.Thread(target=worker, daemon=True).start()


    # ══ MODULE: Autostart ════════════════════════════════════════════════════
    def _render_autostart(self):
        self._module_header("🚀", "Autostart", _t("Zarządzanie programami startowymi i autostart"))

        # ── Tab bar ────────────────────────────────────────────────────────────
        tab_bar = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tab_bar.pack(fill=tk.X, padx=20, pady=(0, 4))

        self._ast_tab = tk.StringVar(value="startup")
        self._ast_tab_btns: dict = {}
        self._ast_tab_frame = tk.Frame(self.content_frame, bg=self.CLR_BG)
        self._ast_tab_frame.pack(fill=tk.BOTH, expand=True)

        TABS = [
            ("startup",  "🚀  Autostart"),
            ("autorun",  _t("💿  Autorun.inf")),
            ("tasks",    _t("⏰  Zaplanowane zadania")),
        ]

        def _switch_ast(tag):
            self._ast_tab.set(tag)
            for t, b in self._ast_tab_btns.items():
                b.config(
                    fg=self.CLR_TEXT if t == tag else self.CLR_MUTED,
                    bg=self.CLR_SURFACE if t == tag else self.CLR_BG,
                    relief=tk.SUNKEN if t == tag else tk.FLAT,
                )
            for w in self._ast_tab_frame.winfo_children():
                w.destroy()
            {"startup": self._ast_render_startup,
             "autorun": self._ast_render_autorun,
             "tasks":   self._ast_render_tasks}[tag](self._ast_tab_frame)

        for tag, label in TABS:
            b = tk.Button(tab_bar, text=label,
                          font=("Segoe UI", 10, "bold"),
                          fg=self.CLR_MUTED, bg=self.CLR_BG,
                          relief=tk.FLAT, bd=0,
                          padx=14, pady=5, cursor="hand2",
                          activeforeground=self.CLR_TEXT,
                          activebackground=self.CLR_SURFACE,
                          command=lambda t=tag: _switch_ast(t))
            b.pack(side=tk.LEFT, padx=(0, 2))
            self._ast_tab_btns[tag] = b

        tk.Frame(self.content_frame, bg=self.CLR_BORDER, height=1).pack(
            fill=tk.X, padx=20, pady=(0, 4))

        _switch_ast("startup")

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _ast_get_startup_entries(self) -> list:
        """Fetch autostart entries from registry and startup folders."""
        entries = []
        if sys.platform == "win32":
            import winreg
            hives = [
                (winreg.HKEY_CURRENT_USER,
                 r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER,
                 r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            hive_names = {
                winreg.HKEY_CURRENT_USER:  "HKCU",
                winreg.HKEY_LOCAL_MACHINE: "HKLM",
            }
            for hive, path in hives:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            entries.append({
                                "name":    name,
                                "command": value,
                                "source":  f"{hive_names.get(hive,'?')}\\...\\{path.split(chr(92))[-1]}",
                                "type":    _t("Rejestr"),
                                "hive":    hive,
                                "regpath": path,
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    pass

            # Foldery startowe
            import os, glob
            startup_dirs = []
            appdata = os.environ.get("APPDATA", "")
            progdata = os.environ.get("ProgramData", "C:\\ProgramData")
            if appdata:
                startup_dirs.append(
                    os.path.join(appdata,
                                 r"Microsoft\Windows\Start Menu\Programs\Startup"))
            startup_dirs.append(
                os.path.join(progdata,
                             r"Microsoft\Windows\Start Menu\Programs\StartUp"))
            for d in startup_dirs:
                for f in glob.glob(os.path.join(d, "*")):
                    entries.append({
                        "name":    os.path.basename(f),
                        "command": f,
                        "source":  d,
                        "type":    _t("Folder startowy"),
                        "hive":    None,
                        "regpath": None,
                    })
        else:
            # Linux: ~/.config/autostart + /etc/xdg/autostart
            import os, glob
            for d in [
                os.path.expanduser("~/.config/autostart"),
                "/etc/xdg/autostart",
                "/etc/init.d",
            ]:
                for f in glob.glob(os.path.join(d, "*.desktop")) + \
                         glob.glob(os.path.join(d, "*")):
                    entries.append({
                        "name":    os.path.basename(f),
                        "command": f,
                        "source":  d,
                        "type":    "XDG / init.d",
                        "hive":    None,
                        "regpath": None,
                    })
        return entries

    def _ast_delete_entry(self, entry: dict, container):
        """Remove autostart entry from registry or folder."""
        if not messagebox.askyesno(
                _t("Usuń autostart"),
                _t("Czy na pewno chcesz usunąć:\n\n{name}\n\n").format(name=entry['name']) +
                                   _t("Źródło: {source}?").format(source=entry['source'])):
            return
        try:
            if entry.get("hive") and entry.get("regpath"):
                import winreg
                key = winreg.OpenKey(entry["hive"], entry["regpath"],
                                     0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, entry["name"])
                winreg.CloseKey(key)
                self._set_status(_t("Usunięto z rejestru: {name}").format(name=entry['name']))
            else:
                import os
                path = entry["command"]
                if os.path.isfile(path):
                    os.remove(path)
                    self._set_status(_t("Plik usunięty: {name}").format(name=entry['name']))
                else:
                    self._set_status(_t("Plik nie znaleziony: {path}").format(path=path))
        except PermissionError:
            messagebox.showerror(_t("Błąd"),
                _t("Brak uprawnień administratora.\n") +
                _t("Uruchom ponownie aplikację jako Administrator."))
            return
        except Exception as e:
            messagebox.showerror(_t("Błąd"), str(e))
            return
        # Refresh view
        for w in container.winfo_children():
            w.destroy()
        self._ast_fill_startup(container)

    def _ast_add_entry(self, container):
        """Dialog dodawania nowego wpisu autostartu (tylko Windows)."""
        if sys.platform != "win32":
            messagebox.showinfo("Informacja", _t("Dodawanie wpisów działa tylko na Windows."))
            return
        win = tk.Toplevel(self)
        win.title(_t("Dodaj wpis autostartu"))
        win.geometry("520x220")
        win.configure(bg=self.CLR_BG)
        win.resizable(False, False)
        win.grab_set()

        def lbl(text, row):
            tk.Label(win, text=text, font=("Segoe UI", 10),
                     fg=self.CLR_MUTED, bg=self.CLR_BG,
                     anchor=tk.W).grid(row=row, column=0, padx=16, pady=6, sticky=tk.W)

        def ent(row):
            e = tk.Entry(win, font=("Segoe UI", 10),
                         bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                         insertbackground=self.CLR_ACCENT,
                         relief=tk.FLAT, bd=4, width=38)
            e.grid(row=row, column=1, padx=(0, 16), pady=6, sticky=tk.EW)
            return e

        win.columnconfigure(1, weight=1)
        lbl(_t("Nazwa wpisu:"), 0)
        lbl("Path / command:", 1)
        lbl(_t("Klucz rejestru:"), 2)

        e_name = ent(0)
        e_cmd  = ent(1)

        import winreg
        reg_options = [
            "HKCU – Run (current user)",
            "HKLM – Run (all users)",
            "HKCU – RunOnce",
            "HKLM – RunOnce",
        ]
        reg_map = {
            "HKCU – Run (current user)": (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run"),
            "HKLM – Run (all users)": (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run"),
            "HKCU – RunOnce": (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            "HKLM – RunOnce": (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        }
        sel = tk.StringVar(value=reg_options[0])
        om = tk.OptionMenu(win, sel, *reg_options)
        om.config(font=("Segoe UI", 9), bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                  activebackground=self.CLR_ACCENT2, bd=0, highlightthickness=0)
        om["menu"].config(bg=self.CLR_SURFACE, fg=self.CLR_TEXT)
        om.grid(row=2, column=1, padx=(0, 16), pady=6, sticky=tk.EW)

        def browse():
            from tkinter import filedialog
            path = filedialog.askopenfilename(
                title=_t("Wybierz plik wykonywalny"),
                filetypes=[("Executables", "*.exe *.bat *.cmd *.ps1 *.vbs"),
                           ("All files", "*.*")])
            if path:
                e_cmd.delete(0, tk.END)
                e_cmd.insert(0, path)

        def save():
            name = e_name.get().strip()
            cmd  = e_cmd.get().strip()
            if not name or not cmd:
                messagebox.showwarning(_t("Błąd"), _t("Nazwa i polecenie są wymagane."),
                                       parent=win)
                return
            hive, path = reg_map[sel.get()]
            try:
                key = winreg.OpenKey(hive, path, 0,
                                     winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, cmd)
                winreg.CloseKey(key)
                self._set_status(_t("Dodano: {name}").format(name=name))
                win.destroy()
                for w in container.winfo_children():
                    w.destroy()
                self._ast_fill_startup(container)
            except PermissionError:
                messagebox.showerror(_t("Błąd"),
                    _t("Brak uprawnień.\nUruchom jako Administrator."), parent=win)
            except Exception as e:
                messagebox.showerror(_t("Błąd"), str(e), parent=win)

        bf = tk.Frame(win, bg=self.CLR_BG)
        bf.grid(row=3, column=0, columnspan=2, pady=12, padx=16, sticky=tk.EW)
        self._action_btn(bf, "📂  BROWSE", self.CLR_SURFACE2, browse).pack(side=tk.LEFT, padx=(0, 8))
        self._action_btn(bf, _t("✔  DODAJ"), self.CLR_SUCCESS, save).pack(side=tk.LEFT)
        self._action_btn(bf, "Anuluj", self.CLR_DANGER,
                         win.destroy).pack(side=tk.RIGHT)

    # ── Tab: Startup entries ──────────────────────────────────────────────────
    def _ast_render_startup(self, parent):
        tb = tk.Frame(parent, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=4, pady=6)

        container = self._scrollable_area(parent)

        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         lambda: [w.destroy() for w in container.winfo_children()]
                         or self._ast_fill_startup(container)).pack(side=tk.LEFT, padx=(0, 8))
        self._action_btn(tb, _t("➕  DODAJ WPIS"), self.CLR_SUCCESS,
                         lambda: self._ast_add_entry(container)).pack(side=tk.LEFT, padx=(0, 8))

        # Column header
        hdr = tk.Frame(parent, bg=self.CLR_SURFACE)
        hdr.pack(fill=tk.X, padx=4, pady=(4, 0))
        hdr.lift()  # ponad scrollable
        for txt, w in [("NAME", 26), ("COMMAND / PATH", 52), ("SOURCE", 20), ("TYPE", 14)]:
            tk.Label(hdr, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

        self._ast_fill_startup(container)

    def _ast_fill_startup(self, container):
        if not container.winfo_exists():
            return
        for w in container.winfo_children():
            w.destroy()
        tk.Label(container, text=_t("Wczytywanie…"),
                 font=("Segoe UI", 10), fg=self.CLR_MUTED,
                 bg=self.CLR_BG).pack(pady=20)

        c = container
        def worker():
            entries = self._ast_get_startup_entries()
            def _done():
                try:
                    if c.winfo_exists():
                        self._ast_show_startup(c, entries)
                except Exception:
                    pass
            self.after(0, _done)
        threading.Thread(target=worker, daemon=True).start()

    def _ast_show_startup(self, container, entries):
        try:
            if not container.winfo_exists():
                return
        except Exception:
            return
        for w in container.winfo_children():
            w.destroy()
        if not entries:
            tk.Label(container, text="No autostart entries.",
                     font=("Segoe UI", 11), fg=self.CLR_MUTED,
                     bg=self.CLR_BG).pack(pady=40)
            self._set_status("Autostart: no entries.")
            return

        TYPE_COLORS = {
            _t("Rejestr"):         self.CLR_ACCENT,
            _t("Folder startowy"): self.CLR_SUCCESS,
            "XDG / init.d":    self.CLR_WARN,
        }
        for i, entry in enumerate(entries):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            row = tk.Frame(container, bg=bg)
            row.pack(fill=tk.X, padx=4, pady=1)

            tk.Label(row, text=entry['name'][:26],
                     font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_TEXT, bg=bg,
                     width=26, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=5)
            tk.Label(row, text=entry['command'][:55],
                     font=("Segoe UI", 9),
                     fg=self.CLR_MUTED, bg=bg,
                     width=52, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=entry['source'][-22:],
                     font=("Segoe UI", 8),
                     fg=self.CLR_ACCENT2, bg=bg,
                     width=20, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=entry['type'],
                     font=("Segoe UI", 8, "bold"),
                     fg=TYPE_COLORS.get(entry['type'], self.CLR_MUTED), bg=bg,
                     width=14, anchor=tk.W).pack(side=tk.LEFT, padx=4)

            self._action_btn(row, "🗑  REMOVE", self.CLR_DANGER,
                             lambda e=entry, c=container: self._ast_delete_entry(e, c)
                             ).pack(side=tk.RIGHT, padx=8)

        self._set_status(f"Autostart: {len(entries)} entry/entries.")

    # ── Tab: Autorun.inf ──────────────────────────────────────────────────────
    def _ast_render_autorun(self, parent):
        tb = tk.Frame(parent, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=4, pady=6)

        self._action_btn(tb, _t("🔍  SKANUJ DYSKI"), self.CLR_ACCENT2,
                         lambda: self._ast_scan_autorun(container)).pack(side=tk.LEFT, padx=(0, 8))

        info = tk.Label(tb,
            text="Scans all drives for autorun.inf files (malicious autorun)",
            font=("Segoe UI", 9), fg=self.CLR_MUTED, bg=self.CLR_BG)
        info.pack(side=tk.LEFT, padx=8)

        tk.Frame(parent, bg=self.CLR_BORDER, height=1).pack(fill=tk.X, padx=4, pady=(4, 0))
        container = self._scrollable_area(parent)

        # Header
        tk.Label(container,
                 text="Click 'SCAN DRIVES' to search for autorun.inf files on all media.",
                 font=("Segoe UI", 10), fg=self.CLR_MUTED, bg=self.CLR_BG,
                 wraplength=600, justify=tk.LEFT).pack(pady=30, padx=20)

    def _ast_scan_autorun(self, container):
        try:
            if not container.winfo_exists():
                return
        except Exception:
            return
        for w in container.winfo_children():
            w.destroy()
        tk.Label(container, text="⏳  Scanning drives…",
                 font=("Segoe UI", 11), fg=self.CLR_ACCENT,
                 bg=self.CLR_BG).pack(pady=30)
        self._set_status("Searching for autorun.inf files…")

        c = container
        def worker():
            import os, glob
            found = []
            if sys.platform == "win32":
                import string
                drives = [f"{d}:\\" for d in string.ascii_uppercase
                          if os.path.exists(f"{d}:\\")]
            else:
                # Only scan actual mount points, not the root filesystem
                drives = [d for d in ["/media", "/mnt", "/run/media"]
                          if os.path.isdir(d)]

            for drive in drives:
                for root, dirs, files in os.walk(drive):
                    for fname in files:
                        if fname.lower() == "autorun.inf":
                            fpath = os.path.join(root, fname)
                            content = ""
                            try:
                                with open(fpath, "r", errors="replace") as fh:
                                    content = fh.read(2048)
                            except Exception:
                                content = "(no access)"
                            found.append({"path": fpath,
                                          "drive": drive,
                                          "content": content})
                    # Do not go deeper than 3 levels
                    depth = root.replace(drive, "").count(os.sep)
                    if depth >= 2:
                        dirs.clear()

            def _done():
                try:
                    if c.winfo_exists():
                        self._ast_show_autorun(c, found)
                except Exception:
                    pass
            self.after(0, _done)

        threading.Thread(target=worker, daemon=True).start()

    def _ast_show_autorun(self, container, found):
        try:
            if not container.winfo_exists():
                return
        except Exception:
            return
        for w in container.winfo_children():
            w.destroy()
        self._set_status(f"Autorun.inf: found {len(found)} file(s).")

        if not found:
            tk.Label(container,
                     text="✔  No autorun.inf files found.\nDrives are clean.",
                     font=("Segoe UI", 12, "bold"),
                     fg=self.CLR_SUCCESS, bg=self.CLR_BG).pack(pady=40)
            return

        tk.Label(container,
                 text=f"⚠  Found {len(found)} autorun.inf file(s):",
                 font=("Segoe UI", 11, "bold"),
                 fg=self.CLR_WARN, bg=self.CLR_BG).pack(anchor=tk.W, padx=8, pady=(8, 4))

        for item in found:
            card = tk.Frame(container, bg=self.CLR_SURFACE,
                            highlightbackground=self.CLR_WARN,
                            highlightthickness=1)
            card.pack(fill=tk.X, padx=8, pady=4)

            hdr = tk.Frame(card, bg=self.CLR_SURFACE)
            hdr.pack(fill=tk.X, padx=10, pady=(8, 4))

            tk.Label(hdr, text=f"📄  {item['path']}",
                     font=("Segoe UI", 10, "bold"),
                     fg=self.CLR_WARN, bg=self.CLR_SURFACE).pack(side=tk.LEFT, fill=tk.X)

            btn_del = tk.Button(hdr, text="🗑  DELETE FILE",
                                font=("Segoe UI", 9, "bold"),
                                fg=self.CLR_HEADER_BG, bg=self.CLR_DANGER,
                                relief=tk.FLAT, padx=8, pady=3, cursor="hand2",
                                command=lambda p=item['path'], c=container:
                                self._ast_delete_autorun(p, c))
            btn_del.pack(side=tk.RIGHT, padx=4)

            btn_view = tk.Button(hdr, text="👁  CONTENTS",
                                 font=("Segoe UI", 9, "bold"),
                                 fg=self.CLR_HEADER_BG, bg=self.CLR_ACCENT2,
                                 relief=tk.FLAT, padx=8, pady=3, cursor="hand2",
                                 command=lambda p=item['path'], c=item['content']:
                                 self._ast_show_autorun_content(p, c))
            btn_view.pack(side=tk.RIGHT, padx=4)

            # Preview first 3 lines
            preview = "\n".join(item['content'].splitlines()[:3])
            if preview:
                tk.Label(card, text=preview,
                         font=("Courier New", 9),
                         fg=self.CLR_TEXT2, bg=self.CLR_SURFACE,
                         justify=tk.LEFT, anchor=tk.W).pack(
                             anchor=tk.W, padx=12, pady=(0, 8))

    def _ast_delete_autorun(self, path: str, container):
        import os
        if not messagebox.askyesno(_t("Usuń autorun.inf"),
                                   _t("Usunąć plik:\n{path}?").format(path=path)):
            return
        try:
            os.remove(path)
            self._set_status(_t("Usunięto: {path}").format(path=path))
            self._ast_scan_autorun(container)
        except PermissionError:
            messagebox.showerror(_t("Błąd"),
                _t("Brak uprawnień. Uruchom jako Administrator."))
        except Exception as e:
            messagebox.showerror(_t("Błąd"), str(e))

    def _ast_show_autorun_content(self, path: str, content: str):
        win = tk.Toplevel(self)
        win.title(f"Contents: {path}")
        win.geometry("620x420")
        win.configure(bg=self.CLR_BG)
        win.resizable(True, True)
        win.minsize(400, 280)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(1, weight=1)

        tk.Label(win, text=path, font=("Segoe UI", 9),
                 fg=self.CLR_MUTED, bg=self.CLR_BG,
                 anchor=tk.W).grid(row=0, column=0, columnspan=2,
                                   sticky="ew", padx=12, pady=(10, 4))

        txt = tk.Text(win, font=("Courier New", 10),
                      bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                      relief=tk.FLAT, wrap=tk.WORD,
                      insertbackground=self.CLR_ACCENT)
        sb  = ttk.Scrollbar(win, orient=tk.VERTICAL, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.grid(row=1, column=0, sticky="nsew", padx=(12, 0), pady=(0, 12))
        sb.grid(row=1, column=1, sticky="ns", padx=(0, 8), pady=(0, 12))
        txt.insert("1.0", content)
        txt.configure(state=tk.DISABLED)

    # ── Tab: Zaplanowane zadania ──────────────────────────────────────────────
    def _ast_render_tasks(self, parent):
        tb = tk.Frame(parent, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=4, pady=6)

        container = self._scrollable_area(parent)

        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         lambda: [w.destroy() for w in container.winfo_children()]
                         or self._ast_load_tasks(container)).pack(side=tk.LEFT, padx=(0, 8))

        hdr = tk.Frame(parent, bg=self.CLR_SURFACE)
        hdr.pack(fill=tk.X, padx=4, pady=(4, 0))
        hdr.lift()
        for txt, w in [(_t("NAZWA ZADANIA"), 34), ("STATUS", 12), (_t("WYZWALACZ"), 22), (_t("OSTATNIE URUCHOMIENIE"), 22)]:
            tk.Label(hdr, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

        self._ast_load_tasks(container)

    def _ast_load_tasks(self, container):
        try:
            if not container.winfo_exists():
                return
        except Exception:
            return
        for w in container.winfo_children():
            w.destroy()
        tk.Label(container, text=_t("Loading tasks…"),
                 font=("Segoe UI", 10), fg=self.CLR_MUTED,
                 bg=self.CLR_BG).pack(pady=20)
        c = container
        def _done():
            try:
                if c.winfo_exists():
                    self._ast_show_tasks(c, self._ast_get_tasks())
            except Exception:
                pass
        threading.Thread(target=lambda: self.after(0, _done), daemon=True).start()

    def _ast_get_tasks(self) -> list:
        tasks = []
        if sys.platform == "win32":
            try:
                result = subprocess.run(
                    ["schtasks", "/query", "/fo", "CSV", "/v"],
                    capture_output=True, text=True, timeout=20,
                    **_no_window_kwargs())
                lines = result.stdout.strip().splitlines()
                if len(lines) > 1:
                    import csv as _csv, io
                    reader = _csv.DictReader(io.StringIO(result.stdout))
                    for row in reader:
                        name   = row.get("TaskName", "").strip().lstrip("\\")
                        status = row.get("Status", "").strip()
                        trig   = row.get("Scheduled Task State", "").strip() or \
                                 row.get("Trigger", "").strip()
                        last   = row.get("Last Run Time", "").strip()
                        if name:
                            tasks.append({"name": name, "status": status,
                                          "trigger": trig, "last_run": last})
            except Exception as e:
                tasks.append({"name": f"Error: {e}", "status": "?",
                              "trigger": "", "last_run": ""})
        else:
            # Linux: crontab -l
            try:
                r = subprocess.run(["crontab", "-l"],
                                   capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        tasks.append({"name": line[:60], "status": "aktywny",
                                      "trigger": "cron", "last_run": ""})
            except Exception:
                pass
            # systemd timers
            try:
                r = subprocess.run(
                    ["systemctl", "list-timers", "--no-pager", "--all"],
                    capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        tasks.append({
                            "name": parts[-1], "status": "timer",
                            "trigger": " ".join(parts[:2]),
                            "last_run": " ".join(parts[4:6]) if len(parts) > 5 else ""
                        })
            except Exception:
                pass
        return tasks

    def _ast_show_tasks(self, container, tasks):
        try:
            if not container.winfo_exists():
                return
        except Exception:
            return
        for w in container.winfo_children():
            w.destroy()
        if not tasks:
            tk.Label(container, text="No scheduled tasks.",
                     font=("Segoe UI", 11), fg=self.CLR_MUTED,
                     bg=self.CLR_BG).pack(pady=40)
            self._set_status("Zadania: brak.")
            return

        STATUS_COLORS = {
            "Ready":    self.CLR_SUCCESS,
            "Running":  self.CLR_ACCENT,
            "Disabled": self.CLR_DANGER,
            "aktywny":  self.CLR_SUCCESS,
            "timer":    self.CLR_ACCENT2,
        }
        for i, task in enumerate(tasks):
            bg = self.CLR_SURFACE if i % 2 == 0 else self.CLR_BG
            row = tk.Frame(container, bg=bg)
            row.pack(fill=tk.X, padx=4, pady=1)

            sc = STATUS_COLORS.get(task['status'], self.CLR_MUTED)

            tk.Label(row, text=task['name'][:36],
                     font=("Segoe UI", 9), fg=self.CLR_TEXT, bg=bg,
                     width=34, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)
            tk.Label(row, text=task['status'][:12],
                     font=("Segoe UI", 9, "bold"), fg=sc, bg=bg,
                     width=12, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=task['trigger'][:24],
                     font=("Segoe UI", 8), fg=self.CLR_MUTED, bg=bg,
                     width=22, anchor=tk.W).pack(side=tk.LEFT, padx=4)
            tk.Label(row, text=task['last_run'][:24],
                     font=("Segoe UI", 8), fg=self.CLR_MUTED, bg=bg,
                     width=22, anchor=tk.W).pack(side=tk.LEFT, padx=4)

            if sys.platform == "win32":
                self._action_btn(
                    row, "⏹  DISABLE", self.CLR_WARN,
                    lambda n=task['name'], c=container:
                    self._ast_toggle_task(n, "disable", c)
                ).pack(side=tk.RIGHT, padx=2)
                self._action_btn(
                    row, "▶  ENABLE", self.CLR_SUCCESS,
                    lambda n=task['name'], c=container:
                    self._ast_toggle_task(n, "enable", c)
                ).pack(side=tk.RIGHT, padx=2)

        self._set_status(f"Tasks: {len(tasks)} entries.")

    def _ast_toggle_task(self, name: str, action: str, container):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"),
                _t("Wymagane uprawnienia administratora."))
            return
        verb = "/enable" if action == "enable" else "/disable"
        try:
            subprocess.run(
                ["schtasks", "/change", "/tn", name, verb],
                capture_output=True, timeout=10, **_no_window_kwargs())
            self._set_status(f"{'Enabled' if action=='enable' else 'Disabled'}: {name}")
        except Exception as e:
            messagebox.showerror(_t("Błąd"), str(e))
        try:
            if container.winfo_exists():
                self._ast_load_tasks(container)
        except Exception:
            pass


    # ══ MODULE: Processes (v2) ═══════════════════════════════════════════════
    def _render_processes(self):
        self._module_header("", "Procesy", _t("Menedżer procesów"))

        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=8, pady=4)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         self._refresh_processes).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(tb, text=_t("Szukaj:"), font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(8, 4))
        self._proc_search = tk.StringVar()
        tk.Entry(tb, textvariable=self._proc_search, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=26).pack(side=tk.LEFT)
        self._proc_search.trace_add("write", lambda *a: self._filter_processes())

        self._col_headers([("PID", 8), ("PROCESS NAME", 42), ("MEMORY", 12), ("STATUS", 10), ("", 12)])
        self._proc_container = self._scrollable_area()
        self._all_procs = []
        self._refresh_processes()

    def _refresh_processes(self):
        if not hasattr(self, '_proc_container') or not self._proc_container.winfo_exists():
            return
        self._set_status("Loading processes…")
        for w in self._proc_container.winfo_children():
            w.destroy()
        tk.Label(self._proc_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)
        c = self._proc_container
        def _done(procs):
            try:
                if c.winfo_exists():
                    self._display_processes(procs)
            except Exception:
                pass
        def _proc_worker():
            result = get_processes()
            self.after(0, lambda: _done(result))
        threading.Thread(target=_proc_worker, daemon=True).start()

    def _display_processes(self, procs):
        if not hasattr(self, '_proc_container') or not self._proc_container.winfo_exists():
            return
        self._all_procs = procs
        self._filter_processes()
        self._set_status(f"Processes: {len(procs)}")

    def _filter_processes(self):
        if not hasattr(self, '_proc_container') or not self._proc_container.winfo_exists():
            return
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
                     fg=self.CLR_TEXT, bg=bg, width=36, anchor=tk.W).pack(side=tk.LEFT, padx=4)
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
            messagebox.showerror(_t("Błąd"), _t("Nieprawidłowy identyfikator procesu."))
            return
        if not messagebox.askyesno(_t("Potwierdź"), _t("Zakończyć proces:\n{name}  (PID {pid})?").format(name=name, pid=pid)):
            return
        self._set_status(_t("Kończenie procesu {pid}…").format(pid=pid))
        def worker():
            ok, msg = kill_process(pid)
            def _done():
                self._set_status(f"{'OK' if ok else 'ERROR'} {msg}")
                if ok and hasattr(self, '_proc_container') and self._proc_container.winfo_exists():
                    self._refresh_processes()
            self.after(0, _done)
        threading.Thread(target=worker, daemon=True).start()


    # ══ MODULE: Network (v2) ═════════════════════════════════════════════════
    def _render_network(self):
        self._module_header("", _t("Sieć"), _t("Informacje sieciowe"))
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=8, pady=4)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         self._refresh_network).pack(side=tk.LEFT)
        self._net_container = self._scrollable_area()
        self._refresh_network()

    def _refresh_network(self):
        if not hasattr(self, '_net_container') or not self._net_container.winfo_exists():
            return
        self._set_status("Fetching network info…")
        for w in self._net_container.winfo_children():
            w.destroy()
        tk.Label(self._net_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)
        c = self._net_container
        def _done(info):
            try:
                if c.winfo_exists():
                    self._display_network(info)
            except Exception:
                pass
        def _worker():
            result = get_network_info()   # runs in background thread
            self.after(0, lambda: _done(result))
        threading.Thread(target=_worker, daemon=True).start()

    def _display_network(self, info):
        if not hasattr(self, '_net_container') or not self._net_container.winfo_exists():
            return
        for w in self._net_container.winfo_children():
            w.destroy()

        # info is a list of interface dicts; primary info is in info[0]
        iface0 = info[0] if info else {}

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

        section(_t("PODSTAWOWE INFORMACJE"))
        kv("Hostname",      iface0.get('hostname', 'N/A'))
        kv("IP (primary)",  iface0.get('ip', 'N/A'), self.CLR_ACCENT)
        kv("System",        platform.system() + " " + platform.release())
        kv(_t("Architektura"), platform.machine())

        section("CONNECTION TEST")
        for name, host in [("Google DNS", "8.8.8.8"), ("Cloudflare", "1.1.1.1")]:
            cmd = ['ping', '-n', '1', '-w', '1000', host] if sys.platform == "win32" \
                  else ['ping', '-c', '1', '-W', '1', host]
            ok, _ = run_cmd(cmd)
            kv(f"{name} ({host})", "ONLINE" if ok else "OFFLINE",
               self.CLR_SUCCESS if ok else self.CLR_DANGER)

        if iface0.get('raw'):
            section(_t("INTERFEJSY SIECIOWE"))
            raw_txt = tk.Text(self._net_container, height=12, font=("Segoe UI", 9),
                          bg=self.CLR_SURFACE, fg=self.CLR_TEXT, relief=tk.FLAT, bd=0,
                          insertbackground=self.CLR_ACCENT)
            raw_txt.pack(fill=tk.X, padx=12, pady=4)
            raw_txt.insert("1.0", iface0['raw'])
            raw_txt.configure(state=tk.DISABLED)

        if iface0.get('connections'):
            section(_t("AKTYWNE PORTY"))
            for conn in iface0['connections']:
                kv(conn.get('proto', ''),
                   f"{conn.get('local', '')}  [{conn.get('state', '')}]")

        self._set_status(f"Network: {iface0.get('hostname','?')} / {iface0.get('ip','?')}")


    # ══ MODULE: Services (v2) ════════════════════════════════════════════════
    def _render_services(self):
        self._module_header("", _t("Usługi"), _t("Kontrola usług systemowych"))
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=8, pady=4)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         self._refresh_services).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(tb, text="Search:", font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT, padx=(8, 4))
        self._svc_search = tk.StringVar()
        tk.Entry(tb, textvariable=self._svc_search, font=("Segoe UI", 10),
                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT, insertbackground=self.CLR_ACCENT,
                 relief=tk.FLAT, bd=4, width=22).pack(side=tk.LEFT)
        self._svc_search.trace_add("write", lambda *a: self._filter_services())

        self._col_headers([("SERVICE NAME", 34), ("STATUS", 12), ("TYPE", 20), ("ACTIONS", 26)])
        self._svc_container = self._scrollable_area()
        self._all_services = []
        self._refresh_services()

    def _refresh_services(self):
        if not hasattr(self, '_svc_container') or not self._svc_container.winfo_exists():
            return
        self._set_status("Loading services…")
        for w in self._svc_container.winfo_children():
            w.destroy()
        tk.Label(self._svc_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)
        c = self._svc_container
        def _done(svcs):
            try:
                if c.winfo_exists():
                    self._display_services(svcs)
            except Exception:
                pass
        def _svc_worker():
            result = get_services()
            self.after(0, lambda: _done(result))
        threading.Thread(target=_svc_worker, daemon=True).start()

    def _display_services(self, svcs):
        if not hasattr(self, '_svc_container') or not self._svc_container.winfo_exists():
            return
        self._all_services = svcs
        self._filter_services()
        self._set_status(f"Services: {len(svcs)}")

    def _filter_services(self):
        if not hasattr(self, '_svc_container') or not self._svc_container.winfo_exists():
            return
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
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora."))
            return
        # Validate service name
        if not name or not all(c.isalnum() or c in '-_.' for c in name):
            messagebox.showerror(_t("Błąd"), _t("Nieprawidłowa nazwa usługi."))
            return
        if not messagebox.askyesno(_t("Potwierdź"),
                                   _t("Wykonać '{act}' na usłudze:\n{name}?").format(act=action.upper(), name=name)):
            return
        self._set_status(_t("Executing {action} → {name}…").format(action=action, name=name))
        def worker():
            ok, msg = control_service(name, action)
            def _done():
                self._set_status(f"{'OK' if ok else 'ERROR'} {msg}")
                if ok and hasattr(self, '_svc_container') and self._svc_container.winfo_exists():
                    self._refresh_services()
            self.after(0, _done)
        threading.Thread(target=worker, daemon=True).start()


    # ══ MODULE: Logs (v2) ════════════════════════════════════════════════════
    def _render_logs(self):
        self._module_header("", _t("Logi"), _t("Logi systemowe"))
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=8, pady=4)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         self._refresh_logs).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(tb, text=_t("Filtr:"), font=("Segoe UI", 10),
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

        self._col_headers([("LEVEL", 8), ("DATE/TIME", 22), ("SOURCE", 22), ("MESSAGE", 60)])
        self._log_container = self._scrollable_area()
        self._all_logs = []
        self._clear_logs_view = lambda: (
            [w.destroy() for w in self._log_container.winfo_children()],
            self._set_status("Log view cleared.")
        ) if hasattr(self, "_log_container") and self._log_container.winfo_exists() else None
        self._refresh_logs()

    def _refresh_logs(self):
        if not hasattr(self, '_log_container') or not self._log_container.winfo_exists():
            return
        self._set_status("Fetching logs…")
        for w in self._log_container.winfo_children():
            w.destroy()
        tk.Label(self._log_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)
        c = self._log_container
        def _done(logs):
            try:
                if c.winfo_exists():
                    self._display_logs(logs)
            except Exception:
                pass
        def _log_worker():
            result = get_logs()
            self.after(0, lambda: _done(result))
        threading.Thread(target=_log_worker, daemon=True).start()

    def _display_logs(self, logs):
        if not hasattr(self, '_log_container') or not self._log_container.winfo_exists():
            return
        self._all_logs = logs
        self._filter_logs()
        self._set_status(f"Entries: {len(logs)}")

    def _filter_logs(self):
        if not hasattr(self, '_log_container') or not self._log_container.winfo_exists():
            return
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


    # ══ MODULE: Database Library ════════════════════════════════════════════
    def _render_databases(self):
        self._module_header("🗄️", _t("Biblioteka baz danych"), _t("Baza wiedzy o silnikach baz danych"))

        # Toolbar with search
        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=8, pady=4)
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
        hdr.pack(fill=tk.X, padx=8, pady=(4, 0))
        for txt, w in [("Engine", 18), (_t("Type"), 20), ("Port", 8),
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
        win.title(f"DB Info – {name}")
        win.geometry("520x260")
        win.configure(bg=self.CLR_BG)
        win.resizable(True, True)
        win.minsize(480, 280)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(5, weight=1)

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

    # ══ MODULE: FS Library ══════════════════════════════════════════════════
    def _render_fslibrary(self):
        self._module_header("📚", _t("Biblioteka FS"), _t("Formaty partycji i systemy plików – baza wiedzy"))

        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=8, pady=4)
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
        hdr.pack(fill=tk.X, padx=8, pady=(4, 0))
        for txt, w in [("FS", 10), (_t("Type"), 12), ("Max Vol", 10),
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
        win.title(f"FS Info – {name}")
        win.geometry("520x240")
        win.configure(bg=self.CLR_BG)
        win.resizable(True, True)
        win.minsize(480, 280)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(5, weight=1)

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

    # ══ MODULE: USB Mass Memory DB ══════════════════════════════════════════
    def _render_usbmass(self):
        self._module_header("🧲", "USB Mass DB", _t("Baza urządzeń masowych USB"))

        tb = tk.Frame(self.content_frame, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=8, pady=4)
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
        hdr.pack(fill=tk.X, padx=8, pady=(4, 0))
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
        win.title(f"USB Info – {vendor}")
        win.geometry("520x270")
        win.configure(bg=self.CLR_BG)
        win.resizable(True, True)
        win.minsize(480, 280)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(5, weight=1)

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
    # ══ MODULE: USB Diagnostics ═════════════════════════════════════════════
    def _render_usb(self):
        self._module_header("🔌", _t("USB – Diagnostyka"), _t("Urządzenia USB + historia (SQLite)"))

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
        if not hasattr(self, '_usb_container') or not self._usb_container.winfo_exists():
            return
        self._set_status("Scanning USB devices…")
        for w in self._usb_container.winfo_children():
            w.destroy()
        tk.Label(self._usb_container, text="Loading…",
                 font=("Segoe UI", 11), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=20)

        c = self._usb_container

        def worker():
            devs = get_usb_devices()
            # Save to DB in background
            try:
                if devs:
                    get_usb_db().record_scan(devs)
            except Exception:
                pass
            def _done():
                try:
                    if c.winfo_exists():
                        self._display_usb(devs, c)
                except Exception:
                    pass
            self.after(0, _done)

        threading.Thread(target=worker, daemon=True).start()

    def _display_usb(self, devices, container=None):
        if container is None:
            container = getattr(self, '_usb_container', None)
        if container is None or not container.winfo_exists():
            return
        for w in container.winfo_children():
            w.destroy()

        if not devices:
            tk.Label(container,
                     text="No USB storage devices connected.",
                     font=("Segoe UI", 12), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(pady=40)
            self._set_status("No USB devices found.")
            return

        for dev in devices:
            self._build_usb_card(container, dev)

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

        # Map display label → SQL ORDER BY string
        self._usb_sort_map = {
            "Last Seen ↓":       "last_seen DESC",
            "First Seen ↓":      "first_seen DESC",
            "Connections ↓":     "connect_count DESC",
            "Name A→Z":          "name ASC",
            "Size ↓":            "total_bytes DESC",
        }
        sort_labels = list(self._usb_sort_map.keys())
        self._usb_hist_order = tk.StringVar(value=sort_labels[0])

        om = tk.OptionMenu(tb, self._usb_hist_order, *sort_labels)
        om.config(font=("Segoe UI", 9), bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                  activebackground=self.CLR_ACCENT2, bd=0, highlightthickness=0)
        om["menu"].config(bg=self.CLR_SURFACE, fg=self.CLR_TEXT, font=("Segoe UI", 9))
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
                       ("FS", 8), ("Size", 10), ("Connections", 8),
                       (_t("First Seen"), 16), (_t("Last Seen"), 16)]:
            tk.Label(hdr, text=txt, font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_MUTED, bg=self.CLR_SURFACE,
                     width=w, anchor=tk.W).pack(side=tk.LEFT, padx=4, pady=4)

        container = self._scrollable_area(parent)
        self._usb_hist_container = container
        self._load_usb_history(container)

    def _load_usb_history(self, container):
        db = get_usb_db()
        search = self._usb_hist_search.get() if hasattr(self, '_usb_hist_search') else ""
        label  = self._usb_hist_order.get()  if hasattr(self, '_usb_hist_order')  else "Last Seen ↓"
        sort_map = getattr(self, '_usb_sort_map', {})
        order  = sort_map.get(label, "last_seen DESC")

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
        win.title(f"USB History – {dev.get('name', '?')}")
        win.geometry("560x420")
        win.configure(bg=self.CLR_BG)
        win.resizable(True, True)
        win.minsize(480, 320)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(3, weight=1)

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
        tk.Label(win, text=_t("Recent Events:"),
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
            lb.insert(tk.END, "  " + _t("No events for this device."))

    def _delete_usb_device(self, device_id: int, container):
        if messagebox.askyesno(_t("Delete"), _t("Remove this device from history?")):
            get_usb_db().delete_device(device_id)
            self._load_usb_history(container)

    def _export_usb_csv(self):
        from tkinter import filedialog
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All", "*.*")],
            initialfile="usb_history.csv",
            title=_t("Export USB History to CSV"))
        if not filepath:
            return
        ok, msg = get_usb_db().export_csv(filepath)
        if ok:
            messagebox.showinfo(_t("Export"), msg)
        else:
            messagebox.showerror(_t("Błąd"), msg)

    def _clear_usb_history(self):
        if messagebox.askyesno(_t("Clear History"), _t("Delete ALL USB device history?\nThis action cannot be undone.")):
            get_usb_db().clear_all()
            if hasattr(self, '_usb_hist_container'):
                self._load_usb_history(self._usb_hist_container)
            self._set_status("USB history cleared.")

    # ─── Events log tab ──────────────────────────────────────────────────────
    def _render_usb_events(self, parent):
        tb = tk.Frame(parent, bg=self.CLR_BG)
        tb.pack(fill=tk.X, padx=0, pady=4)
        tk.Label(tb, text=_t("Last 200 USB Events:"), font=("Segoe UI", 10),
                 fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT)
        self._action_btn(tb, "⟳  REFRESH", self.CLR_ACCENT2,
                         lambda: self._load_usb_events(ev_container)).pack(side=tk.LEFT, padx=8)

        hdr = tk.Frame(parent, bg=self.CLR_SURFACE)
        hdr.pack(fill=tk.X, padx=0, pady=(4, 0))
        for txt, w in [(_t("Time"), 18), (_t("Type"), 10), ("Name", 22),
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
            card.grid(row=0, column=col, padx=8, sticky="nsew")
            grid.columnconfigure(col, weight=1)
            grid.rowconfigure(0, weight=1)

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
<title>NTFSecur – USB Report {ts}</title>
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

    # ══════════════════════════════════════════════════════════════════════════
    #  MODULE: Backup systemu
    # ══════════════════════════════════════════════════════════════════════════

    def _render_backup(self):
        import os, subprocess, threading, time as _time, math as _math

        BACKUP_ROOT = os.path.join(os.path.expanduser("~"), ".polsoft", "backup")
        BACKUP_DIR  = r"C:\.polsoft\backup\windows"
        DRV_DIR     = os.path.join(BACKUP_ROOT, "DriverBackup")
        DRV_ZIP     = os.path.join(BACKUP_ROOT, "DriverBackup-Win.zip")
        if _PACKAGE_LOADED:
            try:
                BACKUP_DIR = AppPaths.BACKUP_DIR
            except Exception:
                pass

        self._module_header("🛡", _t("Backup"), _t("Kopie zapasowe systemu Windows"))

        p = self.content_frame
        p.rowconfigure(0, weight=0)   # toolbar + opcje
        p.rowconfigure(1, weight=0)   # ścieżki
        p.rowconfigure(2, weight=1)   # log

        # ══════════════════════════════════════════════════════════════════════
        #  ROW 0 — Jeden panel ze wszystkimi opcjami (grid 2×N)
        # ══════════════════════════════════════════════════════════════════════
        opts = tk.Frame(p, bg=self.CLR_SURFACE2)
        opts.pack(fill=tk.X, padx=0, pady=0)
        tk.Frame(opts, bg=self.CLR_BORDER_LT, height=1).pack(fill=tk.X, side=tk.TOP)
        tk.Frame(opts, bg=self.CLR_BORDER,    height=1).pack(fill=tk.X, side=tk.BOTTOM)

        inner = tk.Frame(opts, bg=self.CLR_SURFACE2)
        inner.pack(fill=tk.X, padx=16, pady=10)

        # ── helpers ──────────────────────────────────────────────────────────
        _running_drv = [False]
        _anim_state  = [0, None, "idle"]   # [tick, after_id, state]

        def _log(msg, tag=""):
            log_txt.configure(state=tk.NORMAL)
            ts = _time.strftime("%H:%M:%S")
            log_txt.insert(tk.END, f"[{ts}]  {msg}\n", tag or "")
            log_txt.see(tk.END)
            log_txt.configure(state=tk.DISABLED)

        def _run_task(name, func, need_admin=True):
            if need_admin and not is_admin():
                messagebox.showwarning(_t("Brak uprawnień"), _t("Wymagane uprawnienia administratora."))
                return
            self._set_status(f"⏳ {name}…")
            _log(f"▶ {name}")
            def worker():
                try:
                    ok, msg = func()
                except Exception as exc:
                    ok, msg = False, str(exc)
                icon = "✔" if ok else "✘"
                self.after(0, lambda: (self._set_status(f"{icon} {name}"), _log(f"{icon} {name}: {msg[:300]}")))
            threading.Thread(target=worker, daemon=True).start()

        def _run_all():
            if not is_admin():
                messagebox.showwarning(_t("Brak uprawnień"), _t("Wymagane uprawnienia administratora."))
                return
            _log("══════════════════════════════════════════", "hdr")
            _log(f"  🛡  {_t('Wykonaj pełny backup')}", "hdr")
            _log("══════════════════════════════════════════", "hdr")
            self._set_status(f"⏳ {_t('Wykonaj pełny backup')}…")
            def worker():
                tasks = [
                    (_t("Backup plików użytkownika (File History)"), backup_file_history),
                    (_t("Backup rejestru Windows (pełny)"),          backup_registry),
                    (_t("Backup BCD (bootloader)"),                  backup_bcd),
                ]
                all_ok = True
                for name, func in tasks:
                    try:
                        ok, msg = func()
                    except Exception as exc:
                        ok, msg = False, str(exc)
                    icon = "✔" if ok else "✘"
                    if not ok:
                        all_ok = False
                    self.after(0, lambda i=icon, n=name, m=msg: _log(f"{i} {n}: {m[:200]}"))
                final = "✔ " + _t("Wszystkie zadania tworzenia kopii zapasowych zostały ukończone.") \
                        if all_ok else "✘ " + _t("Niektóre zadania zakończyły się błędem – sprawdź log.")
                self.after(0, lambda: (self._set_status(final), _log(final)))
            threading.Thread(target=worker, daemon=True).start()

        def _open_folder(d=None):
            folder = d or BACKUP_DIR
            try:
                os.makedirs(folder, exist_ok=True)
                subprocess.Popen(["explorer", folder])
            except Exception as exc:
                _log(f"✘ {exc}", "err")

        # ── funkcja pomocnicza wiersza opcji ─────────────────────────────────
        def _row(parent, row, icon, label, hint, btns):
            """
            Jeden wiersz: ikona | etykieta + hint | przyciski
            btns = [(text, color, callback), ...]
            """
            # separator poziomy
            if row > 0:
                tk.Frame(parent, bg=self.CLR_BORDER, height=1).grid(
                    row=row*2-1, column=0, columnspan=3, sticky="ew", pady=0)

            lbl_f = tk.Frame(parent, bg=self.CLR_SURFACE2)
            lbl_f.grid(row=row*2, column=0, sticky="w", padx=(0, 20), pady=6)
            tk.Label(lbl_f, text=icon, font=("Segoe UI Emoji", 14),
                     fg=self.CLR_ACCENT, bg=self.CLR_SURFACE2).pack(side=tk.LEFT, padx=(0, 6))
            lbl_inner = tk.Frame(lbl_f, bg=self.CLR_SURFACE2)
            lbl_inner.pack(side=tk.LEFT)
            tk.Label(lbl_inner, text=_t(label), font=("Segoe UI", 9, "bold"),
                     fg=self.CLR_TEXT, bg=self.CLR_SURFACE2).pack(anchor=tk.W)
            if hint:
                tk.Label(lbl_inner, text=hint, font=("Consolas", 7),
                         fg=self.CLR_MUTED, bg=self.CLR_SURFACE2).pack(anchor=tk.W)

            btn_f = tk.Frame(parent, bg=self.CLR_SURFACE2)
            btn_f.grid(row=row*2, column=1, sticky="w", pady=6)
            for txt, col, cmd in btns:
                tk.Button(btn_f, text=txt, command=cmd,
                          font=("Segoe UI", 9, "bold"),
                          fg=self.CLR_BG, bg=col,
                          activebackground=self.CLR_ACCENT,
                          activeforeground=self.CLR_BG,
                          relief=tk.FLAT, bd=0,
                          padx=10, pady=4, cursor="hand2",
                          ).pack(side=tk.LEFT, padx=(0, 6))

        # ── wszystkie wiersze ──────────────────────────────────────────────
        _row(inner, 0,
             "📂", "Backup plików użytkownika (File History)",
             "fhmanagew.exe -backupnow",
             [
                 ("▶ " + _t("Uruchom teraz"),
                  self.CLR_SUCCESS,
                  lambda: _run_task(_t("Backup plików użytkownika (File History)"),
                                    backup_file_history, need_admin=False)),
                 ("⚙ " + _t("Lokalizacja"),
                  self.CLR_ACCENT2,
                  lambda: _run_task(_t("Ręczne wskazanie lokalizacji historii plików"),
                                    backup_file_history_location, need_admin=False)),
             ])

        _row(inner, 1,
             "🗂", "Backup rejestru Windows (pełny)",
             r"reg export HKLM … /y  +  reg export HKCU … /y",
             [
                 ("▶ " + _t("Eksport gałęzi rejestru HKLM") + " + HKCU",
                  self.CLR_ACCENT,
                  lambda: _run_task(_t("Backup rejestru Windows (pełny)"),
                                    backup_registry)),
             ])

        _row(inner, 2,
             "💿", "Backup BCD (bootloader)",
             r"bcdedit /export <BACKUP_DIR>\bcd_backup",
             [
                 ("▶ " + _t("Eksport BCD"),
                  self.CLR_ACCENT,
                  lambda: _run_task(_t("Backup BCD (bootloader)"),
                                    backup_bcd)),
             ])

        _row(inner, 3,
             "🔌", "Backup sterowników Windows",
             "dism /online /export-driver  |  pnputil /export-driver * <folder>",
             [
                 ("▶ " + _t("DISM"),
                  self.CLR_ACCENT2,
                  lambda: _do_drv_backup("dism")),
                 ("▶ " + _t("PnPUtil"),
                  "#1A3A5C",
                  lambda: _do_drv_backup("pnputil")),
                 ("📂 " + _t("Folder"),
                  self.CLR_SURFACE2 if hasattr(self,"CLR_SURFACE2") else self.CLR_SURFACE,
                  lambda: _open_folder(DRV_DIR)),
             ])

        # ── mega-przycisk + folder ────────────────────────────────────────
        tk.Frame(inner, bg=self.CLR_BORDER, height=1).grid(
            row=8, column=0, columnspan=3, sticky="ew", pady=(4, 0))

        action_f = tk.Frame(inner, bg=self.CLR_SURFACE2)
        action_f.grid(row=9, column=0, columnspan=2, sticky="w", pady=(8, 2))
        tk.Button(action_f,
                  text="🛡  " + _t("Wykonaj pełny backup"),
                  command=_run_all,
                  font=("Segoe UI", 10, "bold"),
                  fg=self.CLR_BG, bg=self.CLR_SUCCESS,
                  activebackground=self.CLR_ACCENT,
                  activeforeground=self.CLR_BG,
                  relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2",
                  ).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(action_f,
                  text="📁  " + _t("Otwórz folder kopii zapasowych"),
                  command=lambda: _open_folder(),
                  font=("Segoe UI", 9),
                  fg=self.CLR_TEXT2,
                  bg=self.CLR_SURFACE2 if hasattr(self,"CLR_SURFACE2") else self.CLR_SURFACE,
                  activebackground=self.CLR_BG,
                  relief=tk.FLAT, bd=0,
                  padx=10, pady=6, cursor="hand2",
                  ).pack(side=tk.LEFT)

        # ══════════════════════════════════════════════════════════════════════
        #  ROW 1 — ścieżka docelowa
        # ══════════════════════════════════════════════════════════════════════
        path_f = tk.Frame(p, bg=self.CLR_BG)
        path_f.pack(fill=tk.X, padx=20, pady=(6, 2))
        tk.Label(path_f, text=_t("Folder docelowy kopii zapasowych") + ":  ",
                 font=("Segoe UI", 8), fg=self.CLR_MUTED, bg=self.CLR_BG).pack(side=tk.LEFT)
        tk.Label(path_f, text=BACKUP_DIR,
                 font=("Consolas", 8), fg=self.CLR_ACCENT, bg=self.CLR_BG).pack(side=tk.LEFT)

        # ══════════════════════════════════════════════════════════════════════
        #  ROW 2 — wspólny log (ciemny, jak w sekcji drives)
        # ══════════════════════════════════════════════════════════════════════
        log_wrap = tk.Frame(p, bg=self.CLR_BORDER_LT, padx=1, pady=1)
        log_wrap.pack(fill=tk.BOTH, expand=True, padx=14, pady=(4, 10))
        log_inner = tk.Frame(log_wrap, bg=self.CLR_BG)
        log_inner.pack(fill=tk.BOTH, expand=True)
        log_inner.columnconfigure(0, weight=1)
        log_inner.rowconfigure(0, weight=1)

        log_txt = tk.Text(log_inner, bg="#101820", fg="#50E8FF",
                          font=("Courier New", 9), relief=tk.FLAT,
                          insertbackground=self.CLR_ACCENT,
                          wrap=tk.WORD, bd=0, highlightthickness=0,
                          padx=10, pady=8, state=tk.DISABLED)
        log_sb = GlassScrollbar(log_inner, command=log_txt.yview, width=10)
        log_txt.configure(yscrollcommand=log_sb.set)
        log_txt.grid(row=0, column=0, sticky="nsew")
        log_sb.grid(row=0, column=1, sticky="ns", padx=(2, 0))

        log_txt.tag_configure("ok",    foreground="#3DFFA8", font=("Courier New", 9, "bold"))
        log_txt.tag_configure("err",   foreground="#FF6875", font=("Courier New", 9, "bold"))
        log_txt.tag_configure("warn",  foreground="#FFD166")
        log_txt.tag_configure("hdr",   foreground="#50E8FF", font=("Courier New", 10, "bold"))
        log_txt.tag_configure("muted", foreground="#6A8CB0")

        # ══════════════════════════════════════════════════════════════════════
        #  Logika backup sterowników (inline, używa wspólnego log_txt)
        # ══════════════════════════════════════════════════════════════════════
        def _do_drv_backup(method):
            if _running_drv[0]:
                return
            _running_drv[0] = True
            _log("══════════════════════════════════════════", "hdr")
            _log(f"  🔌  Driver Backup  [{method.upper()}]", "hdr")
            _log("══════════════════════════════════════════", "hdr")
            self._set_status(f"⏳ Driver Backup [{method.upper()}]…")

            def worker():
                try:
                    os.makedirs(DRV_DIR, exist_ok=True)
                    self.after(0, lambda: _log(f"✔  Folder: {DRV_DIR}", "ok"))

                    cmd = (["dism", "/online", "/export-driver", f"/destination:{DRV_DIR}"]
                           if method == "dism" else
                           ["pnputil", "/export-driver", "*", DRV_DIR])
                    self.after(0, lambda: _log(f"  CMD: {' '.join(cmd)}", "muted"))

                    kw = {"creationflags": subprocess.CREATE_NO_WINDOW} \
                         if sys.platform == "win32" else {}
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT,
                                            text=True, errors="replace", **kw)
                    for line in proc.stdout:
                        l = line.rstrip()
                        if not l:
                            continue
                        lo = l.lower()
                        tag = ("err"  if any(w in lo for w in ("error","fail","blad")) else
                               "ok"   if any(w in lo for w in ("export","added","ok","success","driver package")) else
                               "warn" if any(w in lo for w in ("warn","skip")) else "")
                        self.after(0, lambda x=l, t=tag: _log(x, t))
                    proc.wait()
                    rc = proc.returncode

                    if rc not in (0, 1):
                        self.after(0, lambda: (_log(f"✘  Eksport błąd (kod {rc})", "err"),
                                               self._set_status(f"✘ Driver Backup błąd ({rc})")))
                        return

                    self.after(0, lambda: _log("✔  Eksport sterowników OK", "ok"))
                    self.after(0, lambda: _log("\n── Tworzenie ZIP… ──", "hdr"))

                    if os.path.exists(DRV_ZIP):
                        os.remove(DRV_ZIP)

                    ps = (f"Compress-Archive -Path '{DRV_DIR}\\*' "
                          f"-DestinationPath '{DRV_ZIP}' -Force")
                    zip_cmd = (["powershell", "-NoProfile", "-NonInteractive", "-Command", ps]
                               if sys.platform == "win32" else
                               ["zip", "-r", DRV_ZIP, DRV_DIR])
                    r2 = subprocess.run(zip_cmd, capture_output=True, text=True,
                                        errors="replace", **kw)

                    if r2.returncode != 0:
                        self.after(0, lambda: (_log(f"✘  ZIP błąd: {r2.stderr or r2.stdout}", "err"),
                                               self._set_status("✘ ZIP error")))
                        return

                    try:
                        size_str = f"{os.path.getsize(DRV_ZIP)/1024/1024:.1f} MB"
                    except Exception:
                        size_str = "?"
                    self.after(0, lambda: (
                        _log(f"✔  ZIP: {DRV_ZIP}  ({size_str})", "ok"),
                        _log("✔  Driver Backup zakończony pomyślnie!", "ok"),
                        self._set_status(f"✔ Driver Backup — {size_str}"),
                    ))
                except Exception as ex:
                    self.after(0, lambda e=ex: (_log(f"✘  {e}", "err"),
                                                self._set_status(f"✘ {e}")))
                finally:
                    _running_drv[0] = False

            threading.Thread(target=worker, daemon=True).start()

        # info startowe w logu
        _log(_t("Kopia zapasowa systemu") + " — NTFSecur", "hdr")
        _log(f"  {_t('Folder docelowy kopii zapasowych')}: {BACKUP_DIR}", "muted")
        _log(f"  Sterowniki: {DRV_DIR}", "muted")



    def _backup_section(self, parent, title, hint=""):
        """Pomocnicza metoda – nagłówek podsekcji w module Backup."""
        frm = tk.Frame(parent, bg=self.CLR_BG)
        frm.pack(fill=tk.X, padx=16, pady=(8, 2))
        tk.Label(frm, text=title, font=("Segoe UI", 10, "bold"),
                 fg=self.CLR_TEXT, bg=self.CLR_BG).pack(anchor=tk.W)
        if hint:
            tk.Label(frm, text=hint, font=("Consolas", 8),
                     fg=self.CLR_MUTED, bg=self.CLR_BG).pack(anchor=tk.W, padx=4)


# ─────────────────────────────────────────────────────────────────────────────
#  BitLocker Panel – full popup
# ─────────────────────────────────────────────────────────────────────────────
class BitLockerPanel(tk.Toplevel):
    """Modal popup with full BitLocker management for the selected drive."""

    CLR_BG       = "#18202E"
    CLR_SURFACE  = "#222D40"
    CLR_SURFACE2 = "#2A364D"
    CLR_BORDER   = "#3A4E6A"
    CLR_BORDER_LT= "#5A7EA0"
    CLR_ACCENT   = "#50E8FF"
    CLR_ACCENT2  = "#2E9EF0"
    CLR_DANGER   = "#FF6875"
    CLR_SUCCESS  = "#3DFFA8"
    CLR_WARN     = "#FFD166"
    CLR_TEXT     = "#F4F8FF"
    CLR_TEXT2    = "#C8D8F0"
    CLR_MUTED    = "#8AAACE"
    CLR_HEADER   = "#0E1622"
    CLR_BLUE     = "#1A3A5C"

    def __init__(self, parent, drive: str):
        super().__init__(parent)
        self.drive   = drive
        self._parent = parent
        self._status_info: dict = {}

        self.title(f"BitLocker – {drive}")
        self.configure(bg=self.CLR_BG)
        self.resizable(True, True)
        self.minsize(720, 580)

        # Centre relative to parent
        self.update_idletasks()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_x(),     parent.winfo_y()
        w, h   = 800, 640
        self.geometry(f"{w}x{h}+{px + (pw - w)//2}+{py + (ph - h)//2}")

        self.grab_set()
        self._build()
        self._refresh_status()

    # ── Build ─────────────────────────────────────────────────────────────────
    def _build(self):
        # ── Header ──
        hdr = tk.Frame(self, bg=self.CLR_HEADER, height=60)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Frame(self, bg=self.CLR_ACCENT, height=2).pack(fill=tk.X)

        tk.Label(hdr, text="🔐  BitLocker Drive Encryption",
                 font=("Segoe UI", 14, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_HEADER).pack(side=tk.LEFT, padx=20, pady=14)
        tk.Label(hdr, text=f"Drive: {self.drive}",
                 font=("Segoe UI", 11),
                 fg=self.CLR_TEXT2, bg=self.CLR_HEADER).pack(side=tk.LEFT, padx=6, pady=(18,0))

        # ── Status bar (top) ──
        self._status_frame = tk.Frame(self, bg=self.CLR_SURFACE2)
        self._status_frame.pack(fill=tk.X, padx=0, pady=0)
        tk.Frame(self, bg=self.CLR_BORDER, height=1).pack(fill=tk.X)

        self._lbl_protection = tk.Label(self._status_frame, text=_t("Ochrona: …"),
                                        font=("Segoe UI", 10, "bold"),
                                        fg=self.CLR_MUTED, bg=self.CLR_SURFACE2)
        self._lbl_protection.pack(side=tk.LEFT, padx=20, pady=10)

        self._lbl_lock = tk.Label(self._status_frame, text=_t("Blokada: …"),
                                  font=("Segoe UI", 10),
                                  fg=self.CLR_MUTED, bg=self.CLR_SURFACE2)
        self._lbl_lock.pack(side=tk.LEFT, padx=20)

        self._lbl_method = tk.Label(self._status_frame, text=_t("Metoda: …"),
                                    font=("Segoe UI", 10),
                                    fg=self.CLR_MUTED, bg=self.CLR_SURFACE2)
        self._lbl_method.pack(side=tk.LEFT, padx=20)

        self._lbl_pct = tk.Label(self._status_frame, text="",
                                 font=("Segoe UI", 10),
                                 fg=self.CLR_WARN, bg=self.CLR_SURFACE2)
        self._lbl_pct.pack(side=tk.LEFT, padx=10)

        tk.Button(self._status_frame, text="⟳ Refresh",
                  font=("Segoe UI", 9, "bold"),
                  fg=self.CLR_HEADER, bg=self.CLR_ACCENT,
                  relief=tk.FLAT, padx=10, pady=4,
                  cursor="hand2", command=self._refresh_status
                  ).pack(side=tk.RIGHT, padx=14, pady=8)

        # ── Notebook (tabs) ──
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("BL.TNotebook",
                        background=self.CLR_BG, borderwidth=0)
        style.configure("BL.TNotebook.Tab",
                        background=self.CLR_SURFACE, foreground=self.CLR_TEXT2,
                        font=("Segoe UI", 10, "bold"), padding=[14, 6])
        style.map("BL.TNotebook.Tab",
                  background=[("selected", self.CLR_GLOW if hasattr(self,'CLR_GLOW') else "#1A5A80")],
                  foreground=[("selected", self.CLR_ACCENT)])

        nb = ttk.Notebook(self, style="BL.TNotebook")
        nb.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        self._tab_main   = self._make_tab(nb, "🔒 Szyfrowanie")
        self._tab_unlock = self._make_tab(nb, "🔓 Unlock")
        self._tab_keys   = self._make_tab(nb, "🗝 Klucze")
        self._tab_adv    = self._make_tab(nb, "⚙ Advanced")
        self._tab_log    = self._make_tab(nb, "📋 Operation Log")

        nb.add(self._tab_main,   text="🔒  Szyfrowanie")
        nb.add(self._tab_unlock, text="🔓  Unlock")
        nb.add(self._tab_keys,   text="🗝  Klucze & Protektory")
        nb.add(self._tab_adv,    text="⚙  Advanced")
        nb.add(self._tab_log,    text="📋  Operation Log")

        self._build_tab_main()
        self._build_tab_unlock()
        self._build_tab_keys()
        self._build_tab_adv()
        self._build_tab_log()

        # ── Dolny pasek statusu ──
        tk.Frame(self, bg=self.CLR_BORDER, height=1).pack(fill=tk.X)
        self._bot_status = tk.Label(self, text=_t("Gotowy."),
                                    font=("Segoe UI", 9),
                                    fg=self.CLR_MUTED, bg=self.CLR_HEADER, anchor=tk.W)
        self._bot_status.pack(fill=tk.X, padx=16, pady=6)

    def _make_tab(self, nb, title):
        f = tk.Frame(nb, bg=self.CLR_BG)
        f.columnconfigure(0, weight=1)
        f.rowconfigure(99, weight=1)   # ostatni wiersz zbiera nadmiar
        return f

    # ── TAB 1: Szyfrowanie ───────────────────────────────────────────────────
    def _build_tab_main(self):
        p = self._tab_main
        self._section(p, "Enable / Disable BitLocker")

        row = tk.Frame(p, bg=self.CLR_BG)
        row.pack(fill=tk.X, padx=20, pady=(0, 8))

        self._btn(row, "✔ Enable BitLocker\n(+ recovery key)",
                  self.CLR_SUCCESS, self._action_enable).pack(side=tk.LEFT, padx=(0,10))
        self._btn(row, "✘ Disable BitLocker\n(remove encryption)",
                  self.CLR_DANGER, self._action_disable).pack(side=tk.LEFT, padx=(0,10))
        self._btn(row, "⏸ Suspend Protection\n(1 restart)",
                  self.CLR_WARN, self._action_suspend, fg=self.CLR_HEADER).pack(side=tk.LEFT, padx=(0,10))
        self._btn(row, "▶ Resume Protection",
                  self.CLR_ACCENT2, self._action_resume).pack(side=tk.LEFT)

        self._section(p, "Blokowanie partycji")
        row2 = tk.Frame(p, bg=self.CLR_BG)
        row2.pack(fill=tk.X, padx=20, pady=(0, 8))

        self._btn(row2, "🔒 Lock Partition",
                  "#C04060", self._action_lock).pack(side=tk.LEFT, padx=(0,10))
        self._btn(row2, "🔒 Lock (force unmount)",
                  "#8B1A30", self._action_lock_force).pack(side=tk.LEFT)

        self._section(p, "Status Details (raw manage-bde data)")
        self._txt_main = self._text_box(p, height=10)

    # ── TAB 2: Odblokuj ──────────────────────────────────────────────────────
    def _build_tab_unlock(self):
        p = self._tab_unlock
        self._section(p, "Unlock with Password")

        frm = tk.Frame(p, bg=self.CLR_BG)
        frm.pack(fill=tk.X, padx=20, pady=(0,12))

        tk.Label(frm, text="Password:", font=("Segoe UI", 10),
                 fg=self.CLR_TEXT2, bg=self.CLR_BG).grid(row=0, column=0, sticky=tk.W, pady=4)
        self._ent_pwd = tk.Entry(frm, show="•", font=("Segoe UI", 11),
                                 bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                                 insertbackground=self.CLR_ACCENT,
                                 relief=tk.FLAT, width=36)
        self._ent_pwd.grid(row=0, column=1, padx=(10,0), pady=4)

        self._var_show_pwd = tk.BooleanVar(value=False)
        tk.Checkbutton(frm, text=_t("Show password"),
                       variable=self._var_show_pwd,
                       command=lambda: self._ent_pwd.configure(
                           show="" if self._var_show_pwd.get() else "•"),
                       font=("Segoe UI", 9),
                       fg=self.CLR_MUTED, bg=self.CLR_BG,
                       activebackground=self.CLR_BG,
                       selectcolor=self.CLR_SURFACE).grid(row=1, column=1, sticky=tk.W, padx=(10,0))

        self._btn(frm, "🔓 Unlock with Password",
                  self.CLR_ACCENT2, self._action_unlock_pwd
                  ).grid(row=2, column=1, sticky=tk.W, padx=(10,0), pady=(8,0))

        self._section(p, "Odblokuj kluczem odzysku (48-cyfrowy)")
        frm2 = tk.Frame(p, bg=self.CLR_BG)
        frm2.pack(fill=tk.X, padx=20, pady=(0,12))

        tk.Label(frm2, text=_t("Klucz odzysku:"), font=("Segoe UI", 10),
                 fg=self.CLR_TEXT2, bg=self.CLR_BG).grid(row=0, column=0, sticky=tk.W, pady=4)
        self._ent_rk = tk.Entry(frm2, font=("Segoe UI", 11),
                                bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                                insertbackground=self.CLR_ACCENT,
                                relief=tk.FLAT, width=52)
        self._ent_rk.grid(row=0, column=1, padx=(10,0), pady=4)

        tk.Label(frm2, text="Format: 123456-123456-123456-123456-123456-123456-123456-123456",
                 font=("Segoe UI", 8), fg=self.CLR_MUTED, bg=self.CLR_BG
                 ).grid(row=1, column=1, sticky=tk.W, padx=(10,0))

        self._btn(frm2, "🔓 Unlock with Recovery Key",
                  self.CLR_ACCENT2, self._action_unlock_recovery
                  ).grid(row=2, column=1, sticky=tk.W, padx=(10,0), pady=(8,0))

    # ── TAB 3: Klucze & Protektory ───────────────────────────────────────────
    def _build_tab_keys(self):
        p = self._tab_keys
        self._section(p, "Aktualne protektory klucza")

        self._txt_keys = self._text_box(p, height=6)

        row = tk.Frame(p, bg=self.CLR_BG)
        row.pack(fill=tk.X, padx=20, pady=(0, 6))
        self._btn(row, "⟳ Get Protectors",
                  self.CLR_ACCENT, self._action_get_keys).pack(side=tk.LEFT, padx=(0,8))
        self._btn(row, "💾 Save recovery key to file…",
                  self.CLR_BLUE, self._action_save_recovery).pack(side=tk.LEFT, padx=(0,8))
        self._btn(row, "☁ Back Up to AD",
                  self.CLR_BLUE, self._action_backup_ad).pack(side=tk.LEFT)

        self._section(p, "Dodaj protektor")
        row2 = tk.Frame(p, bg=self.CLR_BG)
        row2.pack(fill=tk.X, padx=20, pady=(0,8))

        self._btn(row2, "🔑 Add Password Protector",
                  self.CLR_SURFACE2, self._action_add_pwd_protector,
                  fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._btn(row2, "📦 Add TPM Protector",
                  self.CLR_SURFACE2, self._action_add_tpm,
                  fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._btn(row2, "🆕 Generate Recovery Key",
                  self.CLR_SURFACE2, self._action_add_recovery,
                  fg=self.CLR_TEXT).pack(side=tk.LEFT)

        self._section(p, "Change PIN")
        frm = tk.Frame(p, bg=self.CLR_BG)
        frm.pack(fill=tk.X, padx=20, pady=(0,6))
        tk.Label(frm, text=_t("Stary PIN:"), font=("Segoe UI", 10),
                 fg=self.CLR_TEXT2, bg=self.CLR_BG).grid(row=0, column=0, sticky=tk.W, pady=3)
        self._ent_old_pin = tk.Entry(frm, show="•", font=("Segoe UI", 10),
                                     bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                                     insertbackground=self.CLR_ACCENT,
                                     relief=tk.FLAT, width=24)
        self._ent_old_pin.grid(row=0, column=1, padx=(10,0), pady=3)
        tk.Label(frm, text=_t("Nowy PIN:"), font=("Segoe UI", 10),
                 fg=self.CLR_TEXT2, bg=self.CLR_BG).grid(row=1, column=0, sticky=tk.W, pady=3)
        self._ent_new_pin = tk.Entry(frm, show="•", font=("Segoe UI", 10),
                                     bg=self.CLR_SURFACE, fg=self.CLR_TEXT,
                                     insertbackground=self.CLR_ACCENT,
                                     relief=tk.FLAT, width=24)
        self._ent_new_pin.grid(row=1, column=1, padx=(10,0), pady=3)
        self._btn(frm, "✔ Change PIN",
                  self.CLR_ACCENT2, self._action_change_pin
                  ).grid(row=2, column=1, sticky=tk.W, padx=(10,0), pady=(6,0))

    # ── TAB 4: Zaawansowane ──────────────────────────────────────────────────
    def _build_tab_adv(self):
        p = self._tab_adv
        self._section(p, "Czyszczenie wolnej przestrzeni (Wipe Free Space)")
        tk.Label(p, text=(
            "Encrypts previously unencrypted data in the drive's free space.\n"
            "The operation may take a very long time (hours for large drives)."),
                 font=("Segoe UI", 10), fg=self.CLR_MUTED, bg=self.CLR_BG,
                 justify=tk.LEFT).pack(anchor=tk.W, padx=20, pady=(0,8))
        row = tk.Frame(p, bg=self.CLR_BG)
        row.pack(fill=tk.X, padx=20, pady=(0,10))
        self._btn(row, "🧹 Wipe Free Space",
                  "#8B3A3A", self._action_wipe_free).pack(side=tk.LEFT)

        self._section(p, "Informacje systemowe BitLocker (PowerShell)")
        row2 = tk.Frame(p, bg=self.CLR_BG)
        row2.pack(fill=tk.X, padx=20, pady=(0,8))
        self._btn(row2, "📊 Get PowerShell Data",
                  self.CLR_SURFACE2, self._action_ps_info,
                  fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._btn(row2, "📋 Copy to Clipboard",
                  self.CLR_SURFACE2, self._action_copy_adv,
                  fg=self.CLR_TEXT).pack(side=tk.LEFT)
        self._txt_adv = self._text_box(p, height=12)

    # ── TAB 5: Log operacji ──────────────────────────────────────────────────
    def _build_tab_log(self):
        p = self._tab_log
        self._section(p, "Dziennik wykonanych operacji")
        row = tk.Frame(p, bg=self.CLR_BG)
        row.pack(fill=tk.X, padx=20, pady=(0,6))
        self._btn(row, "🗑 Clear Log",
                  self.CLR_SURFACE2, self._clear_log,
                  fg=self.CLR_TEXT).pack(side=tk.LEFT, padx=(0,8))
        self._btn(row, "💾 Save log to file…",
                  self.CLR_BLUE, self._save_log).pack(side=tk.LEFT)
        self._txt_log = self._text_box(p, height=18)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _section(self, parent, title: str):
        frm = tk.Frame(parent, bg=self.CLR_SURFACE2)
        frm.pack(fill=tk.X, padx=0, pady=(8,0))
        tk.Frame(frm, bg=self.CLR_ACCENT, width=4).pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(frm, text=f"  {title}",
                 font=("Segoe UI", 10, "bold"),
                 fg=self.CLR_ACCENT, bg=self.CLR_SURFACE2
                 ).pack(side=tk.LEFT, padx=8, pady=7)
        tk.Frame(parent, bg=self.CLR_BORDER, height=1).pack(fill=tk.X)

    def _btn(self, parent, text: str, bg: str, cmd, fg=None):
        fg = fg or self.CLR_HEADER
        return tk.Button(parent, text=text,
                         font=("Segoe UI", 9, "bold"),
                         fg=fg, bg=bg,
                         activebackground=self.CLR_ACCENT,
                         activeforeground=self.CLR_HEADER,
                         relief=tk.RAISED, bd=2,
                         padx=12, pady=6,
                         cursor="hand2", command=cmd,
                         wraplength=160, justify=tk.CENTER)

    def _text_box(self, parent, height=8):
        frm = tk.Frame(parent, bg=self.CLR_SURFACE)
        frm.pack(fill=tk.BOTH, expand=True, padx=20, pady=(4, 8))
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(0, weight=1)

        txt = tk.Text(frm, font=("Consolas", 9),
                      bg=self.CLR_SURFACE, fg=self.CLR_TEXT2,
                      insertbackground=self.CLR_ACCENT,
                      relief=tk.FLAT,
                      state=tk.DISABLED, wrap=tk.WORD)
        sb = tk.Scrollbar(frm, command=txt.yview,
                          bg=self.CLR_BORDER, troughcolor=self.CLR_BG)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        txt.pack(fill=tk.BOTH, expand=True)
        return txt

    def _write(self, widget, text: str, append: bool = False):
        widget.configure(state=tk.NORMAL)
        if not append:
            widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.see(tk.END)
        widget.configure(state=tk.DISABLED)

    def _log(self, msg: str):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}]  {msg}\n"
        self._write(self._txt_log, line, append=True)

    def _set_bot(self, text: str):
        self._bot_status.configure(text=text)

    # ── Status refresh ────────────────────────────────────────────────────────
    def _refresh_status(self):
        self._set_bot("Pobieranie statusu BitLocker…")
        def worker():
            info = bl_status(self.drive)
            self.after(0, lambda: self._apply_status(info))
        threading.Thread(target=worker, daemon=True).start()

    def _apply_status(self, info: dict):
        self._status_info = info
        prot  = info.get("protection", "Unknown")
        lock  = info.get("lock_status", "Unknown")
        meth  = info.get("method", "–")
        pct   = info.get("percentage", "–")
        raw   = info.get("raw", "")

        # Kolorowanie ochrony
        if "On" in prot or "1" == prot:
            pc, pt = self.CLR_SUCCESS, f"✔  Ochrona: ON ({prot})"
        elif "Off" in prot or "0" == prot:
            pc, pt = self.CLR_DANGER,  f"✘  Protection: OFF ({prot})"
        else:
            pc, pt = self.CLR_WARN,    f"?  Ochrona: {prot}"
        self._lbl_protection.configure(text=pt, fg=pc)

        lc = self.CLR_DANGER if "Locked" in lock else self.CLR_SUCCESS
        self._lbl_lock.configure(text=f"Blokada: {lock}", fg=lc)
        self._lbl_method.configure(text=f"Metoda: {meth}", fg=self.CLR_TEXT2)
        if pct not in ("–", "100%", "100.0%"):
            self._lbl_pct.configure(text=f"Progress: {pct}")
        else:
            self._lbl_pct.configure(text="")

        if hasattr(self, '_txt_main'):
            self._write(self._txt_main, raw or "(brak danych)")

        kps = info.get("key_protectors", [])
        if hasattr(self, '_txt_keys') and kps:
            self._write(self._txt_keys,
                        "Protektory kluczy:\n" + "\n".join(f"  • {k}" for k in kps))

        status_str = f"Status: {prot} | {lock} | {meth}"
        self._set_bot(status_str)
        self._log(f"Status refreshed: {status_str}")

    # ── Actions ───────────────────────────────────────────────────────────────
    def _run_async(self, label: str, func, *args, on_done=None):
        self._set_bot(f"{label}…")
        self._log(f"▶ {label} ({self.drive})")
        def worker():
            ok, msg = func(*args)
            def done():
                icon = "✔" if ok else "✘"
                self._set_bot(f"{icon} {msg[:120]}")
                self._log(f"{icon} {msg}")
                if on_done:
                    on_done(ok, msg)
                self._refresh_status()
            self.after(0, done)
        threading.Thread(target=worker, daemon=True).start()

    def _action_enable(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        if not messagebox.askyesno("BitLocker – Enable",
                f"Enable BitLocker encryption on {self.drive}?\n\n"
                "The operation may take a long time. A recovery key will be generated."):
            return
        self._run_async("Enabling BitLocker", bl_enable, self.drive, True)

    def _action_disable(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        if not messagebox.askyesno("BitLocker – Disable",
                f"⚠  DISABLE and remove BitLocker encryption on {self.drive}?\n\n"
                "Data will be decrypted. The operation may take a very long time."):
            return
        self._run_async("Disabling BitLocker", bl_disable, self.drive)

    def _action_lock(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        self._run_async("Blokowanie partycji", bl_lock, self.drive, False)

    def _action_lock_force(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        if not messagebox.askyesno("BitLocker – Force Lock",
                f"Force immediate disconnection and locking of {self.drive}?\n"
                "Unsaved data may be lost!"):
            return
        self._run_async("Wymuszanie blokady", bl_lock, self.drive, True)

    def _action_suspend(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        self._run_async("Suspending Protection", bl_suspend, self.drive, 1)

    def _action_resume(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        self._run_async("Resuming Protection", bl_resume, self.drive)

    def _action_unlock_pwd(self):
        pwd = self._ent_pwd.get().strip()
        if not pwd:
            messagebox.showwarning("Password", "Enter a password."); return
        self._run_async("Unlocking with Password", bl_unlock_password, self.drive, pwd)

    def _action_unlock_recovery(self):
        rk = self._ent_rk.get().strip()
        if not rk:
            messagebox.showwarning("Key", "Enter the recovery key."); return
        self._run_async("Unlocking with Key", bl_unlock_recovery, self.drive, rk)

    def _action_get_keys(self):
        self._set_bot("Fetching keys…")
        self._log(f"▶ Fetching protectors ({self.drive})")
        def worker():
            ok, msg = bl_get_recovery_key(self.drive)
            def done():
                self._write(self._txt_keys, msg)
                icon = "✔" if ok else "✘"
                self._set_bot(f"{icon} Protectors retrieved.")
                self._log(f"{icon} Keys: {msg[:120]}")
            self.after(0, done)
        threading.Thread(target=worker, daemon=True).start()

    def _action_save_recovery(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title=f"Save BitLocker Recovery Key – {self.drive}")
        if not path:
            return
        def worker():
            ok, msg = bl_get_recovery_key(self.drive)
            if ok:
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(f"BitLocker Recovery Key – {self.drive}\n")
                        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        f.write(msg)
                    result = f"✔ Key saved: {path}"
                except Exception as e:
                    result = f"✘ Write error: {e}"
            else:
                result = f"✘ {msg}"
            self.after(0, lambda: (self._set_bot(result), self._log(result)))
        threading.Thread(target=worker, daemon=True).start()

    def _action_backup_ad(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        self._run_async("Backing Up Key to AD", bl_backup_recovery_to_ad, self.drive)

    def _action_add_pwd_protector(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        win = tk.Toplevel(self)
        win.title("Add Password Protector")
        win.configure(bg=self.CLR_SURFACE)
        win.resizable(False, False)
        win.grab_set()
        win.geometry(f"360x180+{self.winfo_x()+200}+{self.winfo_y()+200}")

        tk.Label(win, text="New BitLocker Password:", font=("Segoe UI", 10),
                 fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(padx=20, pady=(20,4), anchor=tk.W)
        ent = tk.Entry(win, show="•", font=("Segoe UI", 11),
                       bg=self.CLR_BG, fg=self.CLR_TEXT,
                       insertbackground=self.CLR_ACCENT, relief=tk.FLAT, width=32)
        ent.pack(padx=20, pady=(0,4))
        tk.Label(win, text="Confirm Password:", font=("Segoe UI", 10),
                 fg=self.CLR_TEXT, bg=self.CLR_SURFACE).pack(padx=20, pady=(6,4), anchor=tk.W)
        ent2 = tk.Entry(win, show="•", font=("Segoe UI", 11),
                        bg=self.CLR_BG, fg=self.CLR_TEXT,
                        insertbackground=self.CLR_ACCENT, relief=tk.FLAT, width=32)
        ent2.pack(padx=20, pady=(0,10))

        def do():
            p1, p2 = ent.get(), ent2.get()
            if p1 != p2:
                messagebox.showwarning("Password", "Passwords do not match.", parent=win); return
            if len(p1) < 8:
                messagebox.showwarning("Password", "Password must be at least 8 characters.", parent=win); return
            win.destroy()
            self._run_async("Adding Password Protector", bl_add_password_protector, self.drive, p1)

        tk.Button(win, text="Add", font=("Segoe UI", 10, "bold"),
                  fg=self.CLR_HEADER, bg=self.CLR_ACCENT,
                  relief=tk.FLAT, padx=16, pady=5,
                  cursor="hand2", command=do).pack()

    def _action_add_tpm(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        self._run_async("Adding TPM Protector", bl_add_tpm_protector, self.drive)

    def _action_add_recovery(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        def on_done(ok, msg):
            if ok:
                self._write(self._txt_keys, msg, append=True)
        self._run_async("Generating Recovery Key", bl_add_recovery_protector, self.drive,
                        on_done=on_done)

    def _action_change_pin(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        old = self._ent_old_pin.get()
        new = self._ent_new_pin.get()
        if not old or not new:
            messagebox.showwarning("PIN", "Enter old and new PIN."); return
        self._run_async("Changing PIN", bl_change_pin, self.drive, old, new)

    def _action_ps_info(self):
        self._set_bot("Fetching PowerShell data…")
        self._log(f"▶ PowerShell info ({self.drive})")
        ps = (
            f"Get-BitLockerVolume -MountPoint '{self.drive}' | "
            "Select-Object -Property * | Format-List"
        )
        def worker():
            rc, out, err = bl_run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=20)
            result = out or err or "No data (PowerShell unavailable or insufficient privileges)."
            def done():
                self._write(self._txt_adv, result)
                self._set_bot("✔ PowerShell data retrieved.")
                self._log(f"✔ PowerShell info ({len(result)} chars)")
            self.after(0, done)
        threading.Thread(target=worker, daemon=True).start()

    def _action_copy_adv(self):
        try:
            text = self._txt_adv.get("1.0", tk.END)
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_bot("✔ Copied to clipboard.")
        except Exception as e:
            self._set_bot(f"✘ Copy error: {e}")

    def _action_wipe_free(self):
        if not is_admin():
            messagebox.showwarning(_t("Uprawnienia"), _t("Wymagane uprawnienia administratora.")); return
        if not messagebox.askyesno("Wipe Free Space",
                f"Wipe free space on {self.drive}?\n\n"
                "The operation may take many hours for large drives!"):
            return
        self._run_async("Wiping Free Space", bl_wipe_free_space, self.drive)

    def _clear_log(self):
        self._write(self._txt_log, "")

    def _save_log(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save BitLocker Operation Log")
        if not path:
            return
        try:
            content = self._txt_log.get("1.0", tk.END)
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"BitLocker Operation Log – {self.drive}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(content)
            self._set_bot(f"✔ Log saved: {path}")
        except Exception as e:
            self._set_bot(f"✘ Write error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  Auto-elevation – request UAC on Windows if not already admin
# ─────────────────────────────────────────────────────────────────────────────
def _elevate_if_needed() -> bool:
    """
    On Windows: if the process is not running as Administrator, re-launch
    itself via ShellExecute with 'runas' verb (triggers UAC prompt) and
    exit the current (unprivileged) process.

    Returns True  if already elevated (caller should continue normally).
    Returns False if re-launch was triggered (caller should exit).
    On non-Windows platforms always returns True.
    """
    if sys.platform != "win32":
        return True

    try:
        is_elevated = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_elevated = False

    if is_elevated:
        return True

    # Re-launch with UAC elevation
    try:
        if getattr(sys, "frozen", False):
            # W trybie EXE: uruchom ponownie ten sam EXE z UAC
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, "", None, 1)
        else:
            script = os.path.abspath(__file__)
            # ShellExecute: hwnd, verb, file, params, cwd, show
            ret = ctypes.windll.shell32.ShellExecuteW(
                None,           # parent window handle
                "runas",        # verb – triggers UAC
                sys.executable, # python.exe
                f'"{script}"',  # argument: this script
                None,           # working directory (inherit)
                1,              # SW_SHOWNORMAL
            )
        # ShellExecuteW returns > 32 on success
        if ret <= 32:
            # UAC was denied or failed – show message and continue without admin
            try:
                import tkinter as _tk
                from tkinter import messagebox as _mb
                _r = _tk.Tk(); _r.withdraw()
                _mb.showwarning(
                    "NTFSecur – Insufficient Privileges",
                    "Failed to restart as Administrator.\n"
                    "Some features (NTFSecur, BitLocker, services)\n"
                    "will be unavailable.",
                )
                _r.destroy()
            except Exception:
                pass
            return True   # continue without elevation
    except Exception:
        pass

    return False  # elevated process launched – exit this one


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not _elevate_if_needed():
        # A new elevated process was spawned – exit this unprivileged one
        sys.exit(0)

    try:
        set_locale("en")          # force English UI on every launch
        app = SystemManagementPanel()
        app.mainloop()
    except Exception as _startup_exc:
        import traceback as _tb
        _msg = _tb.format_exc()
        # Write to error log
        try:
            _setup_logging()
            _logging.getLogger("ntfsecur").critical(
                "Fatal startup error:\n%s", _msg)
        except Exception:
            pass
        # Also write to a crash file next to the script
        try:
            # W trybie EXE (frozen) zapisz crash.log obok pliku wykonywalnego
            _crash_dir = os.path.dirname(sys.executable) \
                         if getattr(sys, "frozen", False) else _HERE
            _crash_path = os.path.join(_crash_dir, "crash.log")
            with open(_crash_path, "w", encoding="utf-8") as _cf:
                _cf.write(_msg)
        except Exception:
            pass
        # Show error dialog
        try:
            import tkinter as _tk
            from tkinter import messagebox as _mb
            _r = _tk.Tk(); _r.withdraw()
            _mb.showerror(
                "NTFSecur – Fatal Error",
                f"Program zakończył się z błędem:\n\n{_msg[:1200]}\n\n"
                f"Szczegóły zapisane w crash.log"
            )
            _r.destroy()
        except Exception:
            pass
        sys.exit(1)