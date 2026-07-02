import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.lang import translate_message


STARTUP_KEYS = [
    "Spotify", "Discord", "OneDrive",
    "com.squirrel.Teams.Teams", "Skype",
    "EpicGamesLauncher", "Steam"
]


def clean_user_temp(log, lang=None):
    removed = 0
    for folder in [tempfile.gettempdir(), os.environ.get("TEMP", ""), os.environ.get("TMP", "")]:
        if not folder:
            continue
        for item in Path(folder).glob("*"):
            try:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
                removed += 1
            except Exception:
                pass
    log(translate_message(lang, "clean_user_temp", count=removed))


def clean_system_temp(log, lang=None):
    removed = 0
    system_temp = Path("C:/Windows/Temp")
    if system_temp.exists():
        for item in system_temp.glob("*"):
            try:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
                removed += 1
            except Exception:
                pass
    log(translate_message(lang, "clean_system_temp", count=removed))


def clean_prefetch(log, lang=None):
    removed = 0
    prefetch = Path("C:/Windows/Prefetch")
    if prefetch.exists():
        for item in prefetch.glob("*"):
            try:
                item.unlink()
                removed += 1
            except Exception:
                pass
    log(translate_message(lang, "clean_prefetch", count=removed))


def clean_dns_and_thumbnails(log, lang=None):
    subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
    removed = 0
    thumb_dir = Path(os.environ.get("LocalAppData", "")) / "Microsoft/Windows/Explorer"
    if thumb_dir.exists():
        for f in thumb_dir.glob("thumbcache_*.db"):
            try:
                f.unlink()
                removed += 1
            except Exception:
                pass
    log(translate_message(lang, "clean_dns_and_thumbnails", count=removed))


def clean_startup(log, lang=None):
    disabled = []
    for key in STARTUP_KEYS:
        result = subprocess.run(
            ["reg", "delete",
             r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
             "/v", key, "/f"],
            capture_output=True
        )
        if result.returncode == 0:
            disabled.append(key)
    if disabled:
        log(translate_message(lang, "clean_startup_disabled", items=", ".join(disabled)))
    else:
        log(translate_message(lang, "clean_startup_none"))


def clean_virtual_memory(log, lang=None):
    subprocess.run(
        ["reg", "add",
         r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
         "/v", "ClearPageFileAtShutdown", "/t", "REG_DWORD", "/d", "1", "/f"],
        capture_output=True
    )
    log(translate_message(lang, "clean_virtual_memory"))


def clean_recycle_bin(log, lang=None):
    subprocess.run(
        ["PowerShell", "-Command", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"],
        capture_output=True
    )
    log(translate_message(lang, "clean_recycle_bin"))


def clean_disk(log, lang=None):
    subprocess.run(["cleanmgr", "/sagerun:1"], capture_output=True)
    log(translate_message(lang, "clean_disk"))


ALL_STEPS = [
    clean_user_temp,
    clean_system_temp,
    clean_prefetch,
    clean_dns_and_thumbnails,
    clean_startup,
    clean_virtual_memory,
    clean_recycle_bin,
    clean_disk,
]


def run_cleaning(selected_steps: list[bool], log_callback, progress_callback, lang=None):
    total = sum(selected_steps)
    done = 0
    for i, (run, func) in enumerate(zip(selected_steps, ALL_STEPS)):
        if run:
            try:
                func(log_callback, lang=lang)
            except Exception as e:
                log_callback(translate_message(lang, "clean_error_step", index=i + 1, error=e))
            done += 1
            progress_callback(done / total if total else 0.0)
