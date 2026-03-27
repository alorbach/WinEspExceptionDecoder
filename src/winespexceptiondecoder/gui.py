from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from tkinter.scrolledtext import ScrolledText

from .analysis import build_report, render_report
from .config import load_config, save_config
from .decoder import auto_detect_gdb, find_gdb_candidates
from .models import DecodeRequest


class DecoderApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("WinEspExceptionDecoder")
        self.root.geometry("1100x760")

        self._config = load_config()
        self._decode_after_id: str | None = None
        self._last_scanned_base_path = self._config.get("elf_scan_base_path", "")
        self._cached_scanned_elf = self._config.get("cached_scanned_elf", "")

        self.elf_var = tk.StringVar(value=self._config.get("elf_path", ""))
        self.elf_base_var = tk.StringVar(value=self._config.get("elf_base_path", ""))
        self.gdb_var = tk.StringVar(value=self._config.get("gdb_path", "") or auto_detect_gdb() or "")
        self.auto_refresh_var = tk.BooleanVar(value=self._config.get("auto_refresh", True))
        self.status_var = tk.StringVar(value="Ready")

        self._build_ui()
        self._restore_window()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        controls = ttk.Frame(self.root, padding=12)
        controls.grid(row=0, column=0, sticky="ew")
        controls.columnconfigure(1, weight=1)

        ttk.Label(controls, text="ELF file").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(controls, textvariable=self.elf_var).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Button(controls, text="Browse", command=self.choose_elf).grid(row=0, column=2, padx=(8, 0), pady=4)

        ttk.Label(controls, text="ELF base path").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(controls, textvariable=self.elf_base_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(controls, text="Browse", command=self.choose_elf_base_path).grid(row=1, column=2, padx=(8, 0), pady=4)

        ttk.Label(controls, text="GDB path").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(controls, textvariable=self.gdb_var).grid(row=2, column=1, sticky="ew", pady=4)

        gdb_buttons = ttk.Frame(controls)
        gdb_buttons.grid(row=2, column=2, sticky="e", padx=(8, 0), pady=4)
        ttk.Button(gdb_buttons, text="Browse", command=self.choose_gdb).grid(row=0, column=0, padx=(0, 4))
        ttk.Button(gdb_buttons, text="Detect", command=self.detect_gdb).grid(row=0, column=1)

        action_row = ttk.Frame(controls)
        action_row.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Checkbutton(action_row, text="Auto refresh", variable=self.auto_refresh_var).grid(row=0, column=0, sticky="w")
        ttk.Button(action_row, text="Decode", command=self.decode_now).grid(row=0, column=1, padx=(12, 0))
        ttk.Button(action_row, text="Clear", command=self.clear_input).grid(row=0, column=2, padx=(8, 0))
        ttk.Label(action_row, textvariable=self.status_var).grid(row=0, column=3, padx=(16, 0), sticky="w")

        panes = ttk.Panedwindow(self.root, orient=tk.VERTICAL)
        panes.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

        input_frame = ttk.Labelframe(panes, text="Pasted Debug Log", padding=8)
        self.input_text = ScrolledText(input_frame, wrap=tk.WORD, height=10, font=("Consolas", 10))
        self.input_text.pack(fill=tk.BOTH, expand=True)
        self.input_text.insert("1.0", self._config.get("raw_log", ""))
        self.input_text.bind("<<Modified>>", self._on_input_modified)
        panes.add(input_frame, weight=1)

        output_frame = ttk.Labelframe(panes, text="Analysis Report", padding=8)
        self.output_text = ScrolledText(output_frame, wrap=tk.WORD, state=tk.DISABLED, height=26, font=("Consolas", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)
        panes.add(output_frame, weight=3)

        if self.input_text.get("1.0", "end").strip():
            self.decode_now()

    def choose_elf(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select ELF file",
            filetypes=[("ELF files", "*.elf"), ("All files", "*.*")],
        )
        if selected:
            self.elf_var.set(selected)
            self._schedule_decode()

    def choose_gdb(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select GDB executable",
            filetypes=[("Executable", "*.exe"), ("All files", "*.*")],
        )
        if selected:
            self.gdb_var.set(selected)
            self._schedule_decode()

    def choose_elf_base_path(self) -> None:
        initial_dir = self.elf_base_var.get().strip() or str(Path.home())
        selected = filedialog.askdirectory(title="Select ELF base path", initialdir=initial_dir)
        if selected:
            self._set_elf_base_path(selected)
            self._schedule_decode()

    def detect_gdb(self) -> None:
        detected = auto_detect_gdb()
        if detected:
            self.gdb_var.set(detected)
            self.status_var.set(f"Detected gdb: {detected}")
        else:
            candidates = find_gdb_candidates()
            self.status_var.set("No gdb detected automatically." if not candidates else f"Found {len(candidates)} candidates.")
        self._schedule_decode()

    def clear_input(self) -> None:
        self.input_text.delete("1.0", tk.END)
        self._set_output("")
        self.status_var.set("Cleared")

    def decode_now(self) -> None:
        base_path = self.elf_base_var.get().strip()
        explicit_elf = self.elf_var.get().strip() or None
        cached_elf_path = None
        if base_path:
            if base_path != self._last_scanned_base_path:
                self._last_scanned_base_path = base_path
                self._cached_scanned_elf = ""
            elif self._cached_scanned_elf:
                cached_elf_path = self._cached_scanned_elf

        request = DecodeRequest(
            raw_log=self.input_text.get("1.0", tk.END).strip(),
            elf_path=explicit_elf,
            elf_base_path=base_path or None,
            cached_elf_path=cached_elf_path,
            gdb_path=self.gdb_var.get().strip() or None,
        )
        report = build_report(request)
        if not explicit_elf and base_path:
            if report.resolved_elf_path:
                self._cached_scanned_elf = report.resolved_elf_path
                self._last_scanned_base_path = base_path
            elif not cached_elf_path:
                self._cached_scanned_elf = ""
        self._set_output(render_report(report))
        if report.resolved_elf_path and not request.elf_path and request.elf_base_path:
            self.status_var.set(f"Decoded {len(report.frames)} frame(s) using {Path(report.resolved_elf_path).name}")
        else:
            self.status_var.set(f"Decoded {len(report.frames)} frame(s)")

    def on_close(self) -> None:
        config = {
            "elf_path": self.elf_var.get().strip(),
            "elf_base_path": self.elf_base_var.get().strip(),
            "elf_scan_base_path": self._last_scanned_base_path,
            "cached_scanned_elf": self._cached_scanned_elf,
            "gdb_path": self.gdb_var.get().strip(),
            "raw_log": self.input_text.get("1.0", tk.END).strip(),
            "auto_refresh": self.auto_refresh_var.get(),
            "geometry": self.root.geometry(),
        }
        save_config(config)
        self.root.destroy()

    def _schedule_decode(self) -> None:
        if not self.auto_refresh_var.get():
            return
        if self._decode_after_id:
            self.root.after_cancel(self._decode_after_id)
        self._decode_after_id = self.root.after(500, self.decode_now)

    def _set_output(self, value: str) -> None:
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", value)
        self.output_text.config(state=tk.DISABLED)

    def _on_input_modified(self, _event) -> None:
        if self.input_text.edit_modified():
            self.input_text.edit_modified(False)
            self._schedule_decode()

    def _restore_window(self) -> None:
        geometry = self._config.get("geometry")
        if geometry:
            self.root.geometry(geometry)

    def _set_elf_base_path(self, value: str) -> None:
        normalized = value.strip()
        current = self.elf_base_var.get().strip()
        self.elf_base_var.set(normalized)
        if normalized != current:
            self._last_scanned_base_path = normalized
            self._cached_scanned_elf = ""


def launch() -> int:
    root = tk.Tk()
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    DecoderApp(root)
    root.mainloop()
    return 0
