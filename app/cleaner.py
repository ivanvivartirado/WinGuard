import os
import shutil
import subprocess
import tempfile
from pathlib import Path


STEPS = [
    "Temporales de usuario",
    "Temporales del sistema",
    "Prefetch",
    "Cache DNS y miniaturas",
    "Programas de inicio innecesarios",
    "Memoria virtual",
    "Papelera de reciclaje",
    "Limpieza de disco",
]

STARTUP_KEYS = [
    "Spotify", "Discord", "OneDrive",
    "com.squirrel.Teams.Teams", "Skype",
    "EpicGamesLauncher", "Steam"
]


def clean_user_temp(log):
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
    log(f"Temporales de usuario: {removed} elementos eliminados.")


def clean_system_temp(log):
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
    log(f"Temporales del sistema: {removed} elementos eliminados.")


def clean_prefetch(log):
    removed = 0
    prefetch = Path("C:/Windows/Prefetch")
    if prefetch.exists():
        for item in prefetch.glob("*"):
            try:
                item.unlink()
                removed += 1
            except Exception:
                pass
    log(f"Prefetch: {removed} archivos eliminados.")


def clean_dns_and_thumbnails(log):
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
    log(f"Cache DNS vaciada. Miniaturas: {removed} archivos eliminados.")


def clean_startup(log):
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
        log(f"Inicio deshabilitado: {', '.join(disabled)}.")
    else:
        log("Inicio: ningún programa innecesario encontrado.")


def clean_virtual_memory(log):
    subprocess.run(
        ["reg", "add",
         r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
         "/v", "ClearPageFileAtShutdown", "/t", "REG_DWORD", "/d", "1", "/f"],
        capture_output=True
    )
    log("Memoria virtual: se limpiará en cada apagado.")


def clean_recycle_bin(log):
    subprocess.run(
        ["PowerShell", "-Command", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"],
        capture_output=True
    )
    log("Papelera de reciclaje vaciada.")


def clean_disk(log):
    subprocess.run(["cleanmgr", "/sagerun:1"], capture_output=True)
    log("Limpieza de disco completada.")


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


def run_cleaning(selected_steps: list[bool], log_callback, progress_callback):
    total = sum(selected_steps)
    done = 0
    for i, (run, func) in enumerate(zip(selected_steps, ALL_STEPS)):
        if run:
            try:
                func(log_callback)
            except Exception as e:
                log_callback(f"Error en paso {i+1}: {e}")
            done += 1
            progress_callback(done / total)
