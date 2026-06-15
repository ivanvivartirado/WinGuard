import subprocess
import os
from pathlib import Path


DEFENDER_PATH = Path("C:/Program Files/Windows Defender/MpCmdRun.exe")


def is_defender_available():
    return DEFENDER_PATH.exists()


def run_scan(log_callback, progress_callback):
    if not is_defender_available():
        log_callback("Windows Defender no encontrado en este sistema.")
        return False

    log_callback("Iniciando escaneo con Windows Defender...")
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
            log_callback("Escaneo completado. No se encontraron amenazas.")
            return True
        elif process.returncode == 2:
            log_callback("AMENAZA DETECTADA. Abre Windows Defender para más detalles.")
            return False
        else:
            log_callback(f"Escaneo finalizado con código: {process.returncode}")
            return True

    except Exception as e:
        log_callback(f"Error al ejecutar Windows Defender: {e}")
        return False
