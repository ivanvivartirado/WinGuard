import customtkinter as ctk
import threading
from app.cleaner import ALL_STEPS, STEPS, run_cleaning
from app.defender import run_scan, is_defender_available
from app.virustotal import scan_file, check_api_key
from app.report import generate_report

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WinGuard")
        self.geometry("750x600")
        self.resizable(False, False)
        self.log_lines = []
        self.vt_result = None

        self._build_header()
        self._build_tabs()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=0)
        header.pack(fill="x", pady=(0, 0))
        ctk.CTkLabel(
            header, text="🛡 WinGuard",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#4fc3f7"
        ).pack(side="left", padx=20, pady=12)
        ctk.CTkLabel(
            header, text="Limpieza y seguridad para Windows",
            font=ctk.CTkFont(size=12),
            text_color="#888"
        ).pack(side="left", padx=0, pady=12)

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=15, pady=15)

        self.tabs.add("Limpieza rápida")
        self.tabs.add("Modo avanzado")
        self.tabs.add("VirusTotal")

        self._build_quick_tab()
        self._build_advanced_tab()
        self._build_vt_tab()

    # ── PESTAÑA 1: Limpieza rápida ──────────────────────────────
    def _build_quick_tab(self):
        tab = self.tabs.tab("Limpieza rápida")

        self.quick_progress = ctk.CTkProgressBar(tab, width=680)
        self.quick_progress.pack(pady=(15, 5))
        self.quick_progress.set(0)

        self.quick_status = ctk.CTkLabel(tab, text="Listo para limpiar.", font=ctk.CTkFont(size=12))
        self.quick_status.pack()

        self.quick_log = ctk.CTkTextbox(tab, width=680, height=300, state="disabled")
        self.quick_log.pack(pady=10)

        btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        btn_frame.pack()

        ctk.CTkButton(
            btn_frame, text="Iniciar limpieza completa",
            width=220, fg_color="#1565c0",
            command=self._run_quick_clean
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_frame, text="Escanear con Defender",
            width=220, fg_color="#2e7d32",
            command=self._run_defender
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_frame, text="Guardar informe",
            width=180, fg_color="#555",
            command=self._save_report
        ).pack(side="left", padx=8)

    def _run_quick_clean(self):
        self._reset_log()
        selected = [True] * len(ALL_STEPS)
        thread = threading.Thread(
            target=run_cleaning,
            args=(selected, self._log, self._set_progress),
            daemon=True
        )
        thread.start()

    def _run_defender(self):
        if not is_defender_available():
            self._log("Windows Defender no disponible en este sistema.")
            return
        thread = threading.Thread(
            target=run_scan,
            args=(self._log, self._set_progress),
            daemon=True
        )
        thread.start()

    # ── PESTAÑA 2: Modo avanzado ────────────────────────────────
    def _build_advanced_tab(self):
        tab = self.tabs.tab("Modo avanzado")

        ctk.CTkLabel(
            tab, text="Selecciona los pasos que quieres ejecutar:",
            font=ctk.CTkFont(size=13)
        ).pack(anchor="w", padx=20, pady=(15, 5))

        self.step_vars = []
        for step in STEPS:
            var = ctk.BooleanVar(value=True)
            self.step_vars.append(var)
            ctk.CTkCheckBox(tab, text=step, variable=var).pack(anchor="w", padx=30, pady=3)

        self.adv_progress = ctk.CTkProgressBar(tab, width=680)
        self.adv_progress.pack(pady=(15, 5))
        self.adv_progress.set(0)

        self.adv_log = ctk.CTkTextbox(tab, width=680, height=180, state="disabled")
        self.adv_log.pack(pady=5)

        ctk.CTkButton(
            tab, text="Ejecutar selección",
            width=220, fg_color="#1565c0",
            command=self._run_advanced_clean
        ).pack(pady=8)

    def _run_advanced_clean(self):
        selected = [var.get() for var in self.step_vars]
        if not any(selected):
            self._log_adv("Selecciona al menos un paso.")
            return
        thread = threading.Thread(
            target=run_cleaning,
            args=(selected, self._log_adv, self._set_adv_progress),
            daemon=True
        )
        thread.start()

    # ── PESTAÑA 3: VirusTotal ───────────────────────────────────
    def _build_vt_tab(self):
        tab = self.tabs.tab("VirusTotal")

        ctk.CTkLabel(
            tab, text="Analiza un archivo con 70+ motores antivirus",
            font=ctk.CTkFont(size=13)
        ).pack(pady=(20, 5))

        if not check_api_key():
            ctk.CTkLabel(
                tab,
                text="API key no configurada. Añade VT_API_KEY en el archivo .env",
                text_color="#e57373",
                font=ctk.CTkFont(size=12)
            ).pack(pady=5)

        self.vt_path_entry = ctk.CTkEntry(tab, width=500, placeholder_text="Ruta del archivo...")
        self.vt_path_entry.pack(pady=8)

        ctk.CTkButton(
            tab, text="Seleccionar archivo",
            width=200, fg_color="#555",
            command=self._browse_file
        ).pack(pady=4)

        self.vt_progress = ctk.CTkProgressBar(tab, width=680)
        self.vt_progress.pack(pady=(15, 5))
        self.vt_progress.set(0)

        self.vt_log = ctk.CTkTextbox(tab, width=680, height=220, state="disabled")
        self.vt_log.pack(pady=5)

        ctk.CTkButton(
            tab, text="Analizar archivo",
            width=220, fg_color="#1565c0",
            command=self._run_vt_scan
        ).pack(pady=8)

    def _browse_file(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename()
        if path:
            self.vt_path_entry.delete(0, "end")
            self.vt_path_entry.insert(0, path)

    def _run_vt_scan(self):
        filepath = self.vt_path_entry.get().strip()
        if not filepath:
            self._log_vt("Selecciona un archivo primero.")
            return
        thread = threading.Thread(
            target=self._vt_thread,
            args=(filepath,),
            daemon=True
        )
        thread.start()

    def _vt_thread(self, filepath):
        self.vt_result = scan_file(filepath, self._log_vt, self._set_vt_progress)

    # ── HELPERS ─────────────────────────────────────────────────
    def _log(self, msg):
        self.log_lines.append(msg)
        self.quick_log.configure(state="normal")
        self.quick_log.insert("end", msg + "\n")
        self.quick_log.see("end")
        self.quick_log.configure(state="disabled")
        self.quick_status.configure(text=msg)

    def _log_adv(self, msg):
        self.adv_log.configure(state="normal")
        self.adv_log.insert("end", msg + "\n")
        self.adv_log.see("end")
        self.adv_log.configure(state="disabled")

    def _log_vt(self, msg):
        self.vt_log.configure(state="normal")
        self.vt_log.insert("end", msg + "\n")
        self.vt_log.see("end")
        self.vt_log.configure(state="disabled")

    def _set_progress(self, val):
        self.quick_progress.set(val)

    def _set_adv_progress(self, val):
        self.adv_progress.set(val)

    def _set_vt_progress(self, val):
        self.vt_progress.set(val)

    def _reset_log(self):
        self.log_lines = []
        self.quick_log.configure(state="normal")
        self.quick_log.delete("1.0", "end")
        self.quick_log.configure(state="disabled")
        self.quick_progress.set(0)

    def _save_report(self):
        path = generate_report(self.log_lines, self.vt_result)
        self._log(f"Informe guardado en: {path}")
