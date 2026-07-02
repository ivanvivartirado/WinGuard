import customtkinter as ctk
import threading
from app.cleaner import ALL_STEPS, run_cleaning
from app.defender import run_scan, is_defender_available
from app.virustotal import scan_file, check_api_key
from app.report import generate_report
from app.lang import LANGUAGES

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.language = "Español"
        self.t = LANGUAGES[self.language]
        self.title(self.t["title"])
        self.geometry("820x670")
        self.minsize(780, 640)
        self.resizable(True, True)
        self.configure(fg_color="#07111f")
        self.log_lines = []
        self.vt_result = None

        self._build_header()
        self._build_tabs()
        self._build_status_bar()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="#111827", corner_radius=20, border_width=1, border_color="#334155")
        header.pack(fill="x", padx=15, pady=(10, 8))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header, text=f"🛡 {self.t['title']}",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#4fc3f7"
        ).grid(row=0, column=0, padx=(20, 10), pady=16, sticky="w")

        title_wrap = ctk.CTkFrame(header, fg_color="transparent")
        title_wrap.grid(row=0, column=1, padx=0, pady=12, sticky="w")
        ctk.CTkLabel(
            title_wrap, text=self.t["subtitle"],
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8"
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_wrap, text=self.t["header_badge"],
            font=ctk.CTkFont(size=11),
            text_color="#38bdf8"
        ).pack(anchor="w", pady=(2, 0))

        self.language_menu = ctk.CTkOptionMenu(
            header,
            values=list(LANGUAGES.keys()),
            command=self._change_language,
            width=140,
            fg_color="#0f172a",
            button_color="#1f2937",
            text_color="#f8fafc",
            dropdown_fg_color="#111827",
        )
        self.language_menu.set(self.language)
        self.language_menu.grid(row=0, column=2, padx=20, pady=16, sticky="e")

    def _change_language(self, choice):
        self.language = choice
        self.t = LANGUAGES[choice]
        self.title(self.t["title"])
        self._rebuild_ui()

    def _rebuild_ui(self):
        for widget in self.winfo_children():
            widget.destroy()
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self, width=760, height=560)
        self.tabs.configure(fg_color="#0f172a", border_width=0, corner_radius=22)
        self.tabs.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        self.tabs.add(self.t["tab_quick"])
        self.tabs.add(self.t["tab_advanced"])
        self.tabs.add(self.t["tab_vt"])

        self._build_quick_tab()
        self._build_advanced_tab()
        self._build_vt_tab()

    def _build_status_bar(self):
        footer = ctk.CTkFrame(self, fg_color="#111827", corner_radius=18, border_width=1, border_color="#334155")
        footer.pack(fill="x", side="bottom", padx=15, pady=(0, 15))
        self.status_bar = ctk.CTkLabel(
            footer,
            text=f"{self.t['status_ready']} | {self.language}",
            font=ctk.CTkFont(size=11),
            text_color="#cbd5e1"
        )
        self.status_bar.pack(side="left", padx=20, pady=10)

    # ── PESTAÑA 1: Limpieza rápida ──────────────────────────────
    def _build_quick_tab(self):
        tab = self.tabs.tab(self.t["tab_quick"])

        card = ctk.CTkFrame(tab, fg_color="#111827", corner_radius=18, border_width=1, border_color="#334155")
        card.pack(fill="both", expand=True, padx=20, pady=10)

        self.quick_progress = ctk.CTkProgressBar(card, height=10)
        self.quick_progress.pack(fill="x", padx=20, pady=(20, 8))
        self.quick_progress.set(0)

        info_frame = ctk.CTkFrame(card, fg_color="#0f172a", corner_radius=16, border_width=1, border_color="#334155")
        info_frame.pack(fill="x", padx=20, pady=(0, 14))
        ctk.CTkLabel(
            info_frame,
            text=self.t["quick_summary"],
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1"
        ).pack(anchor="w", padx=16, pady=14)

        self.quick_status = ctk.CTkLabel(card, text=self.t["status_ready"], font=ctk.CTkFont(size=12), text_color="#cbd5e1")
        self.quick_status.pack(anchor="w", padx=20, pady=(0, 14))

        log_frame = ctk.CTkFrame(card, fg_color="#0f172a", corner_radius=16, border_width=1, border_color="#334155")
        log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        ctk.CTkLabel(log_frame, text=self.t["log_header"], font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=14, pady=(14, 6))
        self.quick_log = ctk.CTkTextbox(log_frame, width=700, height=220, state="disabled", fg_color="#0b1220", border_width=0)
        self.quick_log.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        btn_panel = ctk.CTkFrame(card, fg_color="#0f172a", corner_radius=16, border_width=1, border_color="#334155")
        btn_panel.pack(fill="x", padx=18, pady=(0, 20))

        btn_frame = ctk.CTkFrame(btn_panel, fg_color="transparent")
        btn_frame.pack(padx=12, pady=12)

        defender_available = is_defender_available()

        self.quick_clean_button = ctk.CTkButton(
            btn_frame, text=f"🧹 {self.t['btn_quick_clean']}",
            width=220, height=44,
            fg_color="#2563eb", hover_color="#1d4ed8",
            text_color="#f8fafc", corner_radius=16,
            command=self._run_quick_clean
        )
        self.quick_clean_button.pack(side="left", padx=8)

        self.defender_button = ctk.CTkButton(
            btn_frame, text=f"🛡 {self.t['btn_defender']}",
            width=220, height=44,
            fg_color="#16a34a", hover_color="#15803d",
            text_color="#f8fafc", corner_radius=16,
            command=self._run_defender,
            state="normal" if defender_available else "disabled"
        )
        self.defender_button.pack(side="left", padx=8)

        self.report_button = ctk.CTkButton(
            btn_frame, text=f"📄 {self.t['btn_report']}",
            width=180, height=44,
            fg_color="#334155", hover_color="#475569",
            text_color="#f8fafc", corner_radius=16,
            command=self._save_report
        )
        self.report_button.pack(side="left", padx=8)

        self.clear_button = ctk.CTkButton(
            btn_frame, text=f"🧼 {self.t['btn_clear']}",
            width=120, height=44,
            fg_color="#7c3aed", hover_color="#9333ea",
            text_color="#f8fafc", corner_radius=16,
            command=self._reset_log
        )
        self.clear_button.pack(side="left", padx=8)

        self.quick_buttons = [
            self.quick_clean_button,
            self.defender_button,
            self.report_button,
            self.clear_button,
        ]

    def _run_quick_clean(self):
        self._reset_log()
        self._start_operation(self.quick_buttons, self.quick_status)
        selected = [True] * len(ALL_STEPS)
        thread = threading.Thread(
            target=self._quick_clean_thread,
            args=(selected,),
            daemon=True
        )
        thread.start()

    def _quick_clean_thread(self, selected):
        run_cleaning(selected, self._log, self._set_progress, lang=self.t)
        self._end_operation(self.quick_buttons, self.quick_status, True)

    def _run_defender(self):
        if not is_defender_available():
            self._log(self.t["defender_unavailable"])
            return
        self._reset_log()
        self._start_operation(self.quick_buttons, self.quick_status)
        thread = threading.Thread(
            target=self._defender_thread,
            daemon=True
        )
        thread.start()

    def _defender_thread(self):
        run_scan(self._log, self._set_progress, lang=self.t)
        self._end_operation(self.quick_buttons, self.quick_status, True)

    # ── PESTAÑA 2: Modo avanzado ────────────────────────────────
    def _build_advanced_tab(self):
        tab = self.tabs.tab(self.t["tab_advanced"])

        ctk.CTkLabel(
            tab, text=self.t["select_steps"],
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=20, pady=(15, 5))

        ctk.CTkLabel(
            tab,
            text=self.t["advanced_summary"],
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1"
        ).pack(pady=(0, 12), padx=20, anchor="w")

        card = ctk.CTkFrame(tab, fg_color="#111827", corner_radius=18, border_width=1, border_color="#334155")
        card.pack(fill="both", expand=True, padx=20, pady=10)

        control_frame = ctk.CTkFrame(card, fg_color="transparent")
        control_frame.pack(fill="x", padx=20, pady=(20, 10))
        self.select_all_button = ctk.CTkButton(
            control_frame, text=f"✅ {self.t['btn_select_all']}",
            width=160, height=42, fg_color="#2563eb",
            hover_color="#1d4ed8", text_color="#f8fafc",
            corner_radius=16, command=self._select_all_steps
        )
        self.select_all_button.pack(side="left")
        self.clear_all_button = ctk.CTkButton(
            control_frame, text=f"❌ {self.t['btn_clear_all']}",
            width=160, height=42, fg_color="#475569",
            hover_color="#64748b", text_color="#f8fafc",
            corner_radius=16, command=self._clear_all_steps
        )
        self.clear_all_button.pack(side="left", padx=10)

        steps_frame = ctk.CTkFrame(card, fg_color="#0f172a", corner_radius=16, border_width=1, border_color="#334155")
        steps_frame.pack(fill="x", padx=20, pady=(0, 12))
        steps_frame.grid_columnconfigure(0, weight=1)
        steps_frame.grid_columnconfigure(1, weight=1)
        self.step_vars = []
        steps = self.t["step_names"]
        for index, step in enumerate(steps):
            var = ctk.BooleanVar(value=True)
            self.step_vars.append(var)
            row = index // 2
            column = index % 2
            ctk.CTkCheckBox(steps_frame, text=step, variable=var).grid(row=row, column=column, sticky="w", padx=(18 if column == 0 else 12, 18), pady=6)

        self.adv_progress = ctk.CTkProgressBar(card, height=10)
        self.adv_progress.pack(fill="x", padx=20, pady=(10, 8))
        self.adv_progress.set(0)

        self.adv_status = ctk.CTkLabel(card, text=self.t["status_ready"], font=ctk.CTkFont(size=12), text_color="#cbd5e1")
        self.adv_status.pack(anchor="w", padx=20, pady=(0, 12))

        log_frame = ctk.CTkFrame(card, fg_color="#0f172a", corner_radius=14, border_width=1, border_color="#334155")
        log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        ctk.CTkLabel(log_frame, text=self.t["log_header"], font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=14, pady=(14, 6))
        self.adv_log = ctk.CTkTextbox(log_frame, width=700, height=180, state="disabled", fg_color="#0b1220", border_width=0)
        self.adv_log.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        action_frame = ctk.CTkFrame(card, fg_color="transparent")
        action_frame.pack(fill="x", padx=20, pady=(0, 20))
        self.adv_run_button = ctk.CTkButton(
            action_frame, text=f"▶️ {self.t['btn_run']}",
            width=220, height=44, fg_color="#2563eb",
            hover_color="#1d4ed8", text_color="#f8fafc",
            corner_radius=16, command=self._run_advanced_clean
        )
        self.adv_run_button.pack(side="right")
        self.adv_buttons = [
            self.adv_run_button,
            self.select_all_button,
            self.clear_all_button,
        ]

    def _run_advanced_clean(self):
        selected = [var.get() for var in self.step_vars]
        if not any(selected):
            self._log_adv(self.t["no_steps"])
            self._set_status(self.adv_status, self.t["status_error"])
            return
        self._reset_adv_log()
        self._start_operation(self.adv_buttons, self.adv_status)
        thread = threading.Thread(
            target=self._advanced_thread,
            args=(selected,),
            daemon=True
        )
        thread.start()

    def _advanced_thread(self, selected):
        run_cleaning(selected, self._log_adv, self._set_adv_progress, lang=self.t)
        self._end_operation(self.adv_buttons, self.adv_status, True)

    # ── PESTAÑA 3: VirusTotal ───────────────────────────────────
    def _build_vt_tab(self):
        tab = self.tabs.tab(self.t["tab_vt"])

        ctk.CTkLabel(
            tab, text=self.t["vt_title"],
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(20, 5), anchor="w", padx=20)

        ctk.CTkLabel(
            tab,
            text=self.t["vt_summary"],
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1"
        ).pack(pady=(0, 12), padx=20, anchor="w")

        card = ctk.CTkFrame(tab, fg_color="#111827", corner_radius=18, border_width=1, border_color="#334155")
        card.pack(fill="both", expand=True, padx=20, pady=10)

        has_key = check_api_key()
        if not has_key:
            ctk.CTkLabel(
                card,
                text=self.t["vt_no_key"],
                text_color="#f87171",
                font=ctk.CTkFont(size=12)
            ).pack(pady=(20, 5), padx=20, anchor="w")

        path_frame = ctk.CTkFrame(card, fg_color="#0f172a", corner_radius=16, border_width=1, border_color="#334155")
        path_frame.pack(fill="x", padx=20, pady=(20, 10))
        self.vt_path_entry = ctk.CTkEntry(path_frame, width=460, placeholder_text=self.t["vt_placeholder"], corner_radius=14, fg_color="#0b1220")
        self.vt_path_entry.pack(side="left", padx=(0, 10), fill="x", expand=True)
        self.vt_browse_button = ctk.CTkButton(
            path_frame, text=f"📁 {self.t['btn_browse']}",
            width=160, height=42, fg_color="#475569",
            hover_color="#64748b", text_color="#f8fafc",
            corner_radius=16, command=self._browse_file
        )
        self.vt_browse_button.pack(side="left")

        self.vt_status = ctk.CTkLabel(card, text=self.t["status_ready"], font=ctk.CTkFont(size=12), text_color="#cbd5e1")
        self.vt_status.pack(anchor="w", padx=20, pady=(0, 10))

        self.vt_progress = ctk.CTkProgressBar(card, height=10)
        self.vt_progress.pack(fill="x", padx=20, pady=(0, 10))
        self.vt_progress.set(0)

        log_frame = ctk.CTkFrame(card, fg_color="#0f172a", corner_radius=14, border_width=1, border_color="#334155")
        log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        ctk.CTkLabel(log_frame, text=self.t["log_header"], font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=14, pady=(14, 6))
        self.vt_log = ctk.CTkTextbox(log_frame, width=700, height=180, state="disabled", fg_color="#0b1220", border_width=0)
        self.vt_log.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        action_frame = ctk.CTkFrame(card, fg_color="#0f172a", corner_radius=16, border_width=1, border_color="#334155")
        action_frame.pack(fill="x", padx=20, pady=(0, 20))
        action_frame.pack_propagate(False)
        self.vt_analyze_button = ctk.CTkButton(
            action_frame, text=f"🔎 {self.t['btn_analyze']}",
            width=220, height=44, fg_color="#2563eb",
            hover_color="#1d4ed8", text_color="#f8fafc",
            corner_radius=16, command=self._run_vt_scan,
            state="normal" if has_key else "disabled"
        )
        self.vt_analyze_button.pack(side="right", padx=10, pady=10)
        self.vt_buttons = [self.vt_browse_button, self.vt_analyze_button]

    def _browse_file(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename()
        if path:
            self.vt_path_entry.delete(0, "end")
            self.vt_path_entry.insert(0, path)

    def _run_vt_scan(self):
        filepath = self.vt_path_entry.get().strip()
        if not filepath:
            self._log_vt(self.t["vt_no_file"])
            self._set_status(self.vt_status, self.t["status_error"])
            return
        from pathlib import Path
        path = Path(filepath)
        if not path.exists():
            self._log_vt(self.t["vt_file_not_exists"])
            self._set_status(self.vt_status, self.t["status_error"])
            return
        self._reset_vt_log()
        self._start_operation(self.vt_buttons, self.vt_status)
        thread = threading.Thread(
            target=self._vt_thread,
            args=(str(path),),
            daemon=True
        )
        thread.start()

    def _vt_thread(self, filepath):
        self.vt_result = scan_file(filepath, self._log_vt, self._set_vt_progress, lang=self.t)
        self._end_operation(self.vt_buttons, self.vt_status, self.vt_result is not None)

    def _toggle_buttons(self, buttons, enabled):
        for button in buttons:
            try:
                button.configure(state="normal" if enabled else "disabled")
            except Exception:
                pass

    def _start_operation(self, buttons, status_label):
        self._safe_ui(lambda: self._toggle_buttons(buttons, False))
        self._safe_ui(lambda: self._set_status(status_label, self.t["status_running"]))
        self._safe_ui(lambda: self._set_status(self.status_bar, self.t["status_running"]))

    def _end_operation(self, buttons, status_label, success=True):
        def end():
            self._toggle_buttons(buttons, True)
            if hasattr(self, "defender_button") and not is_defender_available():
                self.defender_button.configure(state="disabled")
            if hasattr(self, "vt_analyze_button") and not check_api_key():
                self.vt_analyze_button.configure(state="disabled")
            text = self.t["status_complete"] if success else self.t["status_error"]
            self._set_status(status_label, text)
            self._set_status(self.status_bar, text)
        self._safe_ui(end)

    def _safe_ui(self, action):
        try:
            self.after(0, action)
        except Exception:
            pass

    # ── HELPERS ─────────────────────────────────────────────────
    def _log(self, msg):
        def update():
            self.log_lines.append(msg)
            self.quick_log.configure(state="normal")
            self.quick_log.insert("end", msg + "\n")
            self.quick_log.see("end")
            self.quick_log.configure(state="disabled")
            self.quick_status.configure(text=msg)
            self.status_bar.configure(text=msg)
        self._safe_ui(update)

    def _log_adv(self, msg):
        def update():
            self.adv_log.configure(state="normal")
            self.adv_log.insert("end", msg + "\n")
            self.adv_log.see("end")
            self.adv_log.configure(state="disabled")
        self._safe_ui(update)

    def _log_vt(self, msg):
        def update():
            self.vt_log.configure(state="normal")
            self.vt_log.insert("end", msg + "\n")
            self.vt_log.see("end")
            self.vt_log.configure(state="disabled")
        self._safe_ui(update)

    def _set_progress(self, val):
        self.quick_progress.set(val)

    def _set_adv_progress(self, val):
        self.adv_progress.set(val)

    def _set_vt_progress(self, val):
        self.vt_progress.set(val)

    def _set_status(self, label, text):
        label.configure(text=text)

    def _reset_adv_log(self):
        self.adv_log.configure(state="normal")
        self.adv_log.delete("1.0", "end")
        self.adv_log.configure(state="disabled")
        self.adv_progress.set(0)
        self._set_status(self.adv_status, self.t["status_ready"])
        self._set_status(self.status_bar, self.t["status_ready"])

    def _reset_vt_log(self):
        self.vt_log.configure(state="normal")
        self.vt_log.delete("1.0", "end")
        self.vt_log.configure(state="disabled")
        self.vt_progress.set(0)
        self._set_status(self.vt_status, self.t["status_ready"])
        self._set_status(self.status_bar, self.t["status_ready"])

    def _select_all_steps(self):
        for var in self.step_vars:
            var.set(True)

    def _clear_all_steps(self):
        for var in self.step_vars:
            var.set(False)

    def _reset_log(self):
        self.log_lines = []
        self.quick_log.configure(state="normal")
        self.quick_log.delete("1.0", "end")
        self.quick_log.configure(state="disabled")
        self.quick_progress.set(0)
        self._set_status(self.quick_status, self.t["status_ready"])
        self._set_status(self.status_bar, f"{self.t['status_ready']} | {self.language}")

    def _save_report(self):
        path = generate_report(self.log_lines, self.vt_result, lang=self.t)
        self._log(f"{self.t['report_saved']} {path}")
