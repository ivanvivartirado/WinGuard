import requests
import os
from pathlib import Path
from dotenv import load_dotenv

from app.lang import translate_message

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"~/Pruebas/WinGuard main
❯ python main.py
Traceback (most recent call last):
  File "/home/xibi/Pruebas/WinGuard/main.py", line 4, in <module>
    app = App()
  File "/home/xibi/Pruebas/WinGuard/app/ui.py", line 27, in __init__
    self._build_tabs()
    ~~~~~~~~~~~~~~~~^^
  File "/home/xibi/Pruebas/WinGuard/app/ui.py", line 82, in _build_tabs
    self.tabs.configure(fg_color="#0f172a", border_width=0, corner_radius=22)
    ~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/xibi/.local/lib/python3.14/site-packages/customtkinter/windows/widgets/ctk_tabview.py", line 252, in configure
    self._set_grid_current_tab()
    ~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/home/xibi/.local/lib/python3.14/site-packages/customtkinter/windows/widgets/ctk_tabview.py", line 186, in _set_grid_current_tab
    self._tab_dict[self._current_name].grid(row=3, column=0, sticky="nsew",
    ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^
KeyError: ''~/Pruebas/WinGuard main
❯ python main.py
Traceback (most recent call last):
  File "/home/xibi/Pruebas/WinGuard/main.py", line 4, in <module>
    app = App()
  File "/home/xibi/Pruebas/WinGuard/app/ui.py", line 27, in __init__
    self._build_tabs()
    ~~~~~~~~~~~~~~~~^^
  File "/home/xibi/Pruebas/WinGuard/app/ui.py", line 82, in _build_tabs
    self.tabs.configure(fg_color="#0f172a", border_width=0, corner_radius=22)
    ~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/xibi/.local/lib/python3.14/site-packages/customtkinter/windows/widgets/ctk_tabview.py", line 252, in configure
    self._set_grid_current_tab()
    ~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/home/xibi/.local/lib/python3.14/site-packages/customtkinter/windows/widgets/ctk_tabview.py", line 186, in _set_grid_current_tab
    self._tab_dict[self._current_name].grid(row=3, column=0, sticky="nsew",
    ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^
KeyError: ''

def check_api_key():
    return API_KEY is not None and len(API_KEY) > 0


from app.lang import translate_message


def scan_file(filepath: str, log_callback, progress_callback, lang=None):
    if not check_api_key():
        log_callback(translate_message(lang, "vt_api_missing"))
        return None

    path = Path(filepath)
    if not path.exists():
        log_callback(translate_message(lang, "vt_file_missing", filepath=filepath))
        return None

    log_callback(translate_message(lang, "vt_uploading", name=path.name))
    progress_callback(0.1)

    try:
        # Subir el archivo
        with open(path, "rb") as f:
            response = requests.post(
                f"{BASE_URL}/files",
                headers={"x-apikey": API_KEY},
                files={"file": (path.name, f)}
            )
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]
        log_callback(translate_message(lang, "vt_uploaded", analysis_id=analysis_id))
        progress_callback(0.3)

        # Esperar resultado
        log_callback(translate_message(lang, "vt_waiting"))
        import time
        for i in range(20):
            time.sleep(3)
            result = requests.get(
                f"{BASE_URL}/analyses/{analysis_id}",
                headers={"x-apikey": API_KEY}
            )
            result.raise_for_status()
            data = result.json()["data"]["attributes"]
            status = data.get("status")
            progress_callback(0.3 + (i / 20) * 0.7)

            if status == "completed":
                stats = data["stats"]
                log_callback(translate_message(lang, "vt_result_header"))
                log_callback(translate_message(lang, "vt_malicious", count=stats.get('malicious', 0)))
                log_callback(translate_message(lang, "vt_suspicious", count=stats.get('suspicious', 0)))
                log_callback(translate_message(lang, "vt_clean", count=stats.get('undetected', 0)))
                log_callback(translate_message(lang, "vt_unknown", count=stats.get('type-unsupported', 0)))
                progress_callback(1.0)

                if stats.get("malicious", 0) > 0:
                    log_callback(translate_message(lang, "vt_warning_malicious"))
                elif stats.get("suspicious", 0) > 0:
                    log_callback(translate_message(lang, "vt_warning_suspicious"))
                else:
                    log_callback(translate_message(lang, "vt_clean_result"))

                return stats

        log_callback(translate_message(lang, "vt_timeout"))
        return None

    except requests.exceptions.HTTPError as e:
        log_callback(translate_message(lang, "vt_http_error", error=e))
        return None
    except Exception as e:
        log_callback(translate_message(lang, "vt_unexpected_error", error=e))
        return None
