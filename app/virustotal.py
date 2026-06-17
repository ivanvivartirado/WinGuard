import requests
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"


def check_api_key():
    return API_KEY is not None and len(API_KEY) > 0


def scan_file(filepath: str, log_callback, progress_callback):
    if not check_api_key():
        log_callback("ERROR: No se encontró la API key de VirusTotal en el archivo .env")
        return None

    path = Path(filepath)
    if not path.exists():
        log_callback(f"ERROR: El archivo {filepath} no existe.")
        return None

    log_callback(f"Subiendo archivo a VirusTotal: {path.name}")
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
        log_callback(f"Archivo subido. ID de análisis: {analysis_id}")
        progress_callback(0.3)

        # Esperar resultado
        log_callback("Esperando resultados (puede tardar unos segundos)...")
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
                log_callback("--- Resultado VirusTotal ---")
                log_callback(f"  Malicioso:   {stats.get('malicious', 0)}")
                log_callback(f"  Sospechoso:  {stats.get('suspicious', 0)}")
                log_callback(f"  Limpio:      {stats.get('undetected', 0)}")
                log_callback(f"  Sin datos:   {stats.get('type-unsupported', 0)}")
                progress_callback(1.0)

                if stats.get("malicious", 0) > 0:
                    log_callback("ADVERTENCIA: El archivo es malicioso segun varios motores.")
                elif stats.get("suspicious", 0) > 0:
                    log_callback("PRECAUCION: El archivo es sospechoso segun algunos motores.")
                else:
                    log_callback("El archivo parece limpio.")

                return stats

        log_callback("Tiempo de espera agotado. Intentalo de nuevo mas tarde.")
        return None

    except requests.exceptions.HTTPError as e:
        log_callback(f"Error HTTP: {e}")
        return None
    except Exception as e:
        log_callback(f"Error inesperado: {e}")
        return None
