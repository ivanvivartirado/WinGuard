import subprocess
import os
from pathlib import Path

from app.lang import translate_message


DEFENDER_PATH = Path("C:/Program Files/Windows Defender/MpCmdRun.exe")


def is_defender_available():
    return DEFENDER_PATH.exists()


def run_scan(log_callback, progress_callback, lang=None):
    if not is_defender_available():
        log_callback(translate_message(lang, "defender_not_found"))
        return False

    log_callback(translate_message(lang, "defender_starting"))
    progress_callback(0.0)

    try:
        process = subprocess.Popen(
            [str(DEFENDER_PATH), "-Scan", "-ScanType", "2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        for line in process.stdout:
            line = line.strip()
            if line:
                log_callback(f"[Defender] {line}")

        process.wait()
        progress_callback(1.0)

        if process.returncode == 0:
            log_callback(translate_message(lang, "defender_completed"))
            return True
        elif process.returncode == 2:
            log_callback(translate_message(lang, "defender_threat"))
            return False
        else:
            log_callback(translate_message(lang, "defender_code", code=process.returncode))
            return True

    except Exception as e:
        log_callback(translate_message(lang, "defender_error", error=e))
        return False