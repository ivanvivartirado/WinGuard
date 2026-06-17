import os
from pathlib import Path
from datetime import datetime


def generate_report(log_lines: list[str], scan_result: dict = None):
    desktop = Path(os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"))
    date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = desktop / f"informe_limpieza_{date_str}.txt"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("   INFORME DE LIMPIEZA - WinGuard\n")
        f.write("=" * 50 + "\n")
        f.write(f"Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write("\n")

        f.write("--- LOG DE LIMPIEZA ---\n")
        for line in log_lines:
            f.write(f"  {line}\n")
        f.write("\n")

        if scan_result:
            f.write("--- RESULTADO VIRUSTOTAL ---\n")
            f.write(f"  Malicioso:   {scan_result.get('malicious', 0)}\n")
            f.write(f"  Sospechoso:  {scan_result.get('suspicious', 0)}\n")
            f.write(f"  Limpio:      {scan_result.get('undetected', 0)}\n")
            f.write("\n")

        f.write("=" * 50 + "\n")
        f.write("   Generado por WinGuard - github.com/ivanvivartirado\n")
        f.write("=" * 50 + "\n")

    return str(report_path)
