import os
from pathlib import Path
from datetime import datetime

from app.lang import translate_message


def generate_report(log_lines: list[str], scan_result: dict = None, lang=None):
    desktop = Path(os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"))
    date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = desktop / f"informe_limpieza_{date_str}.txt"

    title = translate_message(lang, "report_title")
    date_label = translate_message(lang, "report_date", date=datetime.now().strftime('%d/%m/%Y %H:%M:%S'))
    log_header = translate_message(lang, "report_log_header")
    vt_header = translate_message(lang, "report_vt_header")
    generated_by = translate_message(lang, "report_generated_by")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write(f"   {title}\n")
        f.write("=" * 50 + "\n")
        f.write(f"{date_label}\n")
        f.write("\n")

        f.write(f"{log_header}\n")
        for line in log_lines:
            f.write(f"  {line}\n")
        f.write("\n")

        if scan_result:
            f.write(f"{vt_header}\n")
            f.write(f"  {translate_message(lang, 'vt_malicious', count=scan_result.get('malicious', 0))}\n")
            f.write(f"  {translate_message(lang, 'vt_suspicious', count=scan_result.get('suspicious', 0))}\n")
            f.write(f"  {translate_message(lang, 'vt_clean', count=scan_result.get('undetected', 0))}\n")
            f.write("\n")

        f.write("=" * 50 + "\n")
        f.write(f"   {generated_by}\n")
        f.write("=" * 50 + "\n")

    return str(report_path)
