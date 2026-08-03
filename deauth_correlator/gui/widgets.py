"""Small Tkinter helpers shared by the GUI tabs."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

PALETTE = {
    "found": "#b3261e",
    "not_found": "#1b5e20",
    "insufficient": "#8a6d00",
    "muted": "#5f6368",
    "panel": "#f6f7f9",
    "accent": "#1a73e8",
}


class ScrollFrame(ttk.Frame):
    """A vertically scrollable frame; content goes in ``.body``."""

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.body = ttk.Frame(canvas)

        window = canvas.create_window((0, 0), window=self.body, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.body.bind("<Configure>",
                       lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(window, width=e.width))
        canvas.bind_all("<MouseWheel>", lambda e: _wheel(canvas, e), add="+")
        self._canvas = canvas


def _wheel(canvas, event) -> None:
    try:
        canvas.yview_scroll(int(-event.delta / 120), "units")
    except tk.TclError:
        pass


class FileList(ttk.Frame):
    """A labelled list of input files with add / add-folder / remove buttons."""

    def __init__(self, master, title: str, hint: str, on_change=None,
                 filetypes=None, allow_dirs: bool = False, height: int = 5):
        super().__init__(master)
        self.on_change = on_change
        self.filetypes = filetypes or [("All files", "*.*")]
        self.allow_dirs = allow_dirs

        ttk.Label(self, text=title, font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 1))
        ttk.Label(self, text=hint, foreground=PALETTE["muted"],
                  wraplength=780, justify="left").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(0, 4))

        self.listbox = tk.Listbox(self, height=height, activestyle="none",
                                  selectmode="extended", exportselection=False)
        self.listbox.grid(row=2, column=0, sticky="nsew")

        scroll = ttk.Scrollbar(self, orient="vertical", command=self.listbox.yview)
        scroll.grid(row=2, column=1, sticky="ns")
        self.listbox.configure(yscrollcommand=scroll.set)

        buttons = ttk.Frame(self)
        buttons.grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 10))
        ttk.Button(buttons, text="Add files…", command=self.add_files).pack(
            side="left")
        if allow_dirs:
            ttk.Button(buttons, text="Add folder…",
                       command=self.add_folder).pack(side="left", padx=(6, 0))
        ttk.Button(buttons, text="Remove selected", command=self.remove_selected).pack(
            side="left", padx=(6, 0))
        ttk.Button(buttons, text="Clear", command=self.clear).pack(
            side="left", padx=(6, 0))

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

    def add_files(self) -> None:
        from tkinter import filedialog
        paths = filedialog.askopenfilenames(filetypes=self.filetypes)
        for path in paths:
            self._append(path)
        self._changed()

    def add_folder(self) -> None:
        from tkinter import filedialog
        path = filedialog.askdirectory()
        if path:
            self._append(path)
            self._changed()

    def remove_selected(self) -> None:
        for index in reversed(self.listbox.curselection()):
            self.listbox.delete(index)
        self._changed()

    def clear(self) -> None:
        self.listbox.delete(0, "end")
        self._changed()

    def paths(self) -> list[str]:
        return list(self.listbox.get(0, "end"))

    def set_paths(self, paths) -> None:
        self.listbox.delete(0, "end")
        for path in paths:
            self._append(path)
        self._changed()

    def _append(self, path: str) -> None:
        if path not in self.paths():
            self.listbox.insert("end", path)

    def _changed(self) -> None:
        if self.on_change:
            self.on_change()


class LabeledEntry(ttk.Frame):
    def __init__(self, master, label: str, width: int = 28, show: str | None = None,
                 hint: str = "", value: str = ""):
        super().__init__(master)
        ttk.Label(self, text=label, width=22, anchor="w").grid(row=0, column=0,
                                                               sticky="w")
        self.var = tk.StringVar(value=value)
        self.entry = ttk.Entry(self, textvariable=self.var, width=width, show=show)
        self.entry.grid(row=0, column=1, sticky="w")
        if hint:
            ttk.Label(self, text=hint, foreground=PALETTE["muted"]).grid(
                row=0, column=2, sticky="w", padx=(8, 0))

    def get(self) -> str:
        return self.var.get().strip()

    def set(self, value) -> None:
        self.var.set("" if value is None else str(value))


class LogPane(ttk.Frame):
    """Read-only text pane used for progress output."""

    def __init__(self, master, height: int = 12):
        super().__init__(master)
        self.text = tk.Text(self, height=height, wrap="word", state="disabled",
                            font=("Consolas", 9))
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.text.tag_configure("error", foreground=PALETTE["found"])
        self.text.tag_configure("ok", foreground=PALETTE["not_found"])
        self.text.tag_configure("muted", foreground=PALETTE["muted"])

    def write(self, message: str, tag: str = "") -> None:
        self.text.configure(state="normal")
        self.text.insert("end", message + "\n", tag or ())
        self.text.see("end")
        self.text.configure(state="disabled")

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")


def make_table(master, columns: list[tuple[str, int]], height: int = 12):
    """A ttk.Treeview with a vertical and horizontal scrollbar."""
    frame = ttk.Frame(master)
    tree = ttk.Treeview(frame, columns=[c for c, _ in columns], show="headings",
                        height=height)
    for name, width in columns:
        tree.heading(name, text=name)
        tree.column(name, width=width, anchor="w", stretch=False)

    vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)

    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)

    tree.tag_configure("hit", background="#fdecea")
    tree.tag_configure("odd", background="#fafafa")
    return frame, tree
