"""Standalone entry point for the offline read-only WUA viewer prototype."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wua.viewer import launch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    archive = args.archive
    if archive is None:
        import tkinter as tk
        from tkinter.filedialog import askopenfilename
        root = tk.Tk()
        root.withdraw()
        chosen = askopenfilename(title="选择 WUA 归档（不会修改）", parent=root,
                                  filetypes=[("WUA SQLite", "*.sqlite *.sqlite3 *.db"), ("All files", "*")])
        root.destroy()
        if not chosen:
            return 0
        archive = Path(chosen)
    try:
        launch(archive)
    except Exception as exc:
        import tkinter as tk
        from tkinter.messagebox import showerror
        root = tk.Tk()
        root.withdraw()
        showerror("无法打开只读归档", f"{type(exc).__name__}: {exc}", parent=root)
        root.destroy()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
