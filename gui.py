"""Dark analyzer picker shown before a scan starts."""

import os


BG = "#1c1c1c"
FG = "#f2f2f2"
MUTED = "#9a9a9a"
ACCENT = "#3d6fbf"
ACCENT_ACTIVE = "#4e82d6"
BTN = "#2e2e2e"
BTN_ACTIVE = "#3c3c3c"
ROW = "#242424"
GREEN = "#3ddc84"
BOX_OFF = "#6e6e6e"


def half_count(n):
    """How many leading tools Select Half checks. Rounds up on an odd count."""
    return (n + 1) // 2


def _paint_check(canvas, checked):
    """Empty gray box, or a large green check when selected."""
    canvas.delete("all")
    if checked:
        canvas.create_rectangle(2, 2, 22, 22, outline=GREEN, width=2)
        canvas.create_line(
            6, 13, 11, 18, 19, 6,
            fill=GREEN,
            width=3,
            capstyle="round",
            joinstyle="round",
        )
    else:
        canvas.create_rectangle(2, 2, 22, 22, outline=BOX_OFF, width=1)


def pick_analyzers(entries, apk_path):
    """Open the picker.

    entries: list of {"id", "filename", "description"}.
    Returns the chosen analyzer ids, or None if the window is closed.
    Raises RuntimeError when tkinter or a display is unavailable.
    """
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError as exc:
        raise RuntimeError(f"tkinter is not available ({exc})") from exc

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise RuntimeError(f"no display ({exc})") from exc

    chosen = {"ids": None}
    checks = []

    root.title("androidsec — select analyzers")
    root.configure(bg=BG)
    root.geometry("680x720")
    root.minsize(520, 480)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("Dark.TFrame", background=BG)
    style.configure("Dark.TButton", background=BTN, foreground=FG, borderwidth=0, padding=(12, 6), font=("DejaVu Sans", 10))
    style.map("Dark.TButton", background=[("active", BTN_ACTIVE), ("pressed", BTN_ACTIVE)])
    style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff", borderwidth=0, padding=(16, 8), font=("DejaVu Sans", 10, "bold"))
    style.map("Accent.TButton", background=[("active", ACCENT_ACTIVE), ("pressed", ACCENT_ACTIVE)])
    style.configure(
        "Dark.Vertical.TScrollbar",
        background=BTN,
        troughcolor=BG,
        bordercolor=BG,
        arrowcolor=FG,
    )

    header = ttk.Frame(root, style="Dark.TFrame", padding=(20, 16, 20, 8))
    header.grid(row=0, column=0, sticky="ew")
    tk.Label(header, text="androidsec", bg=BG, fg=FG, font=("DejaVu Sans", 16, "bold"), anchor="w").pack(fill="x")
    tk.Label(
        header,
        text=os.path.basename(apk_path),
        bg=BG,
        fg=MUTED,
        font=("DejaVu Sans", 10),
        anchor="w",
    ).pack(fill="x", pady=(2, 0))
    tk.Label(
        header,
        text="Choose which analyzers to run.",
        bg=BG,
        fg=FG,
        font=("DejaVu Sans", 11),
        anchor="w",
    ).pack(fill="x", pady=(10, 0))

    buttons = ttk.Frame(root, style="Dark.TFrame", padding=(20, 4, 20, 8))
    buttons.grid(row=1, column=0, sticky="ew")

    def set_all(value):
        for var in checks:
            var.set(value)
        status.set("")

    def select_half():
        keep = half_count(len(checks))
        for index, var in enumerate(checks):
            var.set(index < keep)
        status.set("")

    ttk.Button(buttons, text="Select All", style="Dark.TButton", command=lambda: set_all(True)).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text="Select None", style="Dark.TButton", command=lambda: set_all(False)).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text="Select Half", style="Dark.TButton", command=select_half).pack(side="left")

    list_wrap = ttk.Frame(root, style="Dark.TFrame", padding=(20, 0, 12, 0))
    list_wrap.grid(row=2, column=0, sticky="nsew")
    list_wrap.grid_rowconfigure(0, weight=1)
    list_wrap.grid_columnconfigure(0, weight=1)

    canvas = tk.Canvas(list_wrap, bg=BG, highlightthickness=0, bd=0)
    scrollbar = ttk.Scrollbar(list_wrap, orient="vertical", style="Dark.Vertical.TScrollbar", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.grid(row=0, column=0, sticky="nsew")
    scrollbar.grid(row=0, column=1, sticky="ns")

    rows = tk.Frame(canvas, bg=BG)
    window_id = canvas.create_window((0, 0), window=rows, anchor="nw")

    def _fit_rows(event):
        canvas.itemconfigure(window_id, width=event.width)

    def _fit_scroll(_event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    canvas.bind("<Configure>", _fit_rows)
    rows.bind("<Configure>", _fit_scroll)

    for entry in entries:
        var = tk.BooleanVar(value=False)
        checks.append(var)
        row = tk.Frame(rows, bg=ROW, padx=10, pady=8)
        row.pack(fill="x", pady=3)
        head = tk.Frame(row, bg=ROW)
        head.pack(fill="x")
        box = tk.Canvas(
            head, width=24, height=24, bg=ROW,
            highlightthickness=0, bd=0, cursor="hand2",
        )
        box.pack(side="left")
        name = tk.Label(
            head,
            text=entry["filename"],
            bg=ROW,
            fg=FG,
            font=("DejaVu Sans", 10, "bold"),
            anchor="w",
            cursor="hand2",
        )
        name.pack(side="left", padx=(8, 0))

        def toggle(v=var):
            v.set(not bool(v.get()))
            status.set("")

        def paint(*_args, v=var, c=box):
            _paint_check(c, bool(v.get()))

        var.trace_add("write", paint)
        paint()
        box.bind("<Button-1>", lambda _event, t=toggle: t())
        name.bind("<Button-1>", lambda _event, t=toggle: t())
        tk.Label(
            row,
            text=entry["description"],
            bg=ROW,
            fg=MUTED,
            font=("DejaVu Sans", 9),
            anchor="w",
            justify="left",
            padx=32,
        ).pack(fill="x")

    def _on_wheel(event):
        if getattr(event, "num", None) == 4:
            canvas.yview_scroll(-3, "units")
        elif getattr(event, "num", None) == 5:
            canvas.yview_scroll(3, "units")
        else:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    root.bind_all("<Button-4>", _on_wheel)
    root.bind_all("<Button-5>", _on_wheel)
    root.bind_all("<MouseWheel>", _on_wheel)

    footer = ttk.Frame(root, style="Dark.TFrame", padding=(20, 10, 20, 16))
    footer.grid(row=3, column=0, sticky="ew")
    status = tk.StringVar(value="")
    tk.Label(footer, textvariable=status, bg=BG, fg="#e0a040", font=("DejaVu Sans", 10), anchor="w").pack(fill="x", pady=(0, 8))

    def run_selected():
        ids = [entry["id"] for entry, var in zip(entries, checks) if var.get()]
        if not ids:
            status.set("Select at least one tool.")
            return
        chosen["ids"] = ids
        root.destroy()

    def cancel():
        chosen["ids"] = None
        root.destroy()

    ttk.Button(footer, text="Run Selected", style="Accent.TButton", command=run_selected).pack(anchor="e")
    root.protocol("WM_DELETE_WINDOW", cancel)
    root.bind("<Escape>", lambda _event: cancel())

    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(2, weight=1)
    root.mainloop()
    return chosen["ids"]
