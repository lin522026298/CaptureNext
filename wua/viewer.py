"""Small offline, read-only Tk viewer. No sockets or remote media requests.

The first implementation displays original structured payload as text instead
of rendering untrusted HTML/XML. Media playback/linking is not implemented.
"""
from __future__ import annotations

import json
from pathlib import Path

from .store import ArchiveStore


def format_detail(store, logical_id):
    observations = []
    for row in store.get_observations(logical_id):
        observations.append({key: row[key] for key in (
            "source_id", "snapshot_id", "rule_name", "confidence", "observation_id",
            "db_relative_path", "table_name", "native_locator", "normalized_input",
            "raw_record", "dedupe_evidence", "source_meta", "snapshot_meta")})
    return json.dumps({"observations": observations,
                       "conflicts": store.get_conflicts(logical_id)}, ensure_ascii=False, indent=2)


def launch(path: str | Path):
    import tkinter as tk
    from tkinter import messagebox, ttk
    store = ArchiveStore(path, readonly=True)
    root = tk.Tk()
    root.title("WUA 离线归档查看器 · 只读原型")
    root.geometry("1200x820")
    offset = 0
    filters = {}
    rows = []
    toolbar = ttk.Frame(root, padding=8)
    toolbar.pack(fill="x")
    variables = {}
    for key, label, width in (("search", "全文", 24), ("conversation_id", "会话ID", 24),
                              ("source_id", "来源ID", 18), ("since", "起始日期", 12)):
        ttk.Label(toolbar, text=label).pack(side="left")
        variable = tk.StringVar()
        ttk.Entry(toolbar, textvariable=variable, width=width).pack(side="left", padx=(2, 8))
        variables[key] = variable
    notice = tk.StringVar(value="所有日期按UTC；缺失来源不代表没有消息。媒体尚未关联。")
    ttk.Label(root, textvariable=notice).pack(fill="x", padx=8)
    split = ttk.Panedwindow(root, orient="vertical")
    split.pack(fill="both", expand=True)
    listing = ttk.Frame(split)
    split.add(listing, weight=2)
    tree = ttk.Treeview(listing, columns=("time", "conversation", "sender", "body", "sources", "conflicts"),
                        show="headings", selectmode="browse")
    for key, label, width in (("time", "UTC时间", 175), ("conversation", "会话", 180),
                              ("sender", "发送者", 160), ("body", "正文/结构原文", 470),
                              ("sources", "来源", 50), ("conflicts", "冲突", 50)):
        tree.heading(key, text=label)
        tree.column(key, width=width, stretch=key == "body")
    scroll = ttk.Scrollbar(listing, command=tree.yview)
    tree.configure(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y")
    tree.pack(fill="both", expand=True)
    detail_frame = ttk.Frame(split)
    split.add(detail_frame, weight=1)
    detail = tk.Text(detail_frame, wrap="none", state="disabled")
    detail_scroll = ttk.Scrollbar(detail_frame, command=detail.yview)
    detail_horizontal = ttk.Scrollbar(detail_frame, orient="horizontal", command=detail.xview)
    detail.configure(yscrollcommand=detail_scroll.set)
    detail.configure(xscrollcommand=detail_horizontal.set)
    detail_scroll.pack(side="right", fill="y")
    detail_horizontal.pack(side="bottom", fill="x")
    detail.pack(fill="both", expand=True)

    def set_detail(value):
        detail.configure(state="normal")
        detail.delete("1.0", "end")
        detail.insert("1.0", value)
        detail.configure(state="disabled")

    def load():
        nonlocal rows
        try:
            rows = store.list_messages(limit=100, offset=offset, **filters)
        except (ValueError, TypeError) as exc:
            messagebox.showerror("筛选错误", str(exc), parent=root)
            return
        tree.delete(*tree.get_children())
        for row in rows:
            tree.insert("", "end", iid=row["logical_id"], values=(row["event_time"] or "未知",
                row["conversation_id"] or "未解析", row["sender_id"] or "未解析",
                (row["body_text"] if row["body_text"] is not None else "[正文未解析，展开原始行]").replace("\n", " ↵ "),
                row["source_count"], row["conflict_count"]))
        notice.set(f"只读 · 第 {offset + 1}–{offset + len(rows)} 条 · 日期按UTC · 媒体未关联 · 覆盖仅为已导入观察")
        set_detail("选择消息以展开全部来源、原生字段和判重证据。")

    def search():
        nonlocal filters, offset
        filters = {key: value.get() for key, value in variables.items() if value.get()}
        if "since" in filters and len(filters["since"]) == 10:
            filters["since"] += "T00:00:00+00:00"
        offset = 0
        load()

    def page(direction):
        nonlocal offset
        if direction > 0 and len(rows) < 100:
            return
        offset = max(0, offset + 100 * direction)
        load()

    def selected(_event):
        choice = tree.selection()
        if choice:
            set_detail(format_detail(store, choice[0]))

    ttk.Button(toolbar, text="检索", command=search).pack(side="left")
    ttk.Button(toolbar, text="上一页", command=lambda: page(-1)).pack(side="left", padx=4)
    ttk.Button(toolbar, text="下一页", command=lambda: page(1)).pack(side="left")
    tree.bind("<<TreeviewSelect>>", selected)
    root.bind("<Return>", lambda _event: search())
    try:
        load()
        root.mainloop()
    finally:
        store.close()
