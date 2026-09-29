#!/usr/bin/env python3
"""
lab_gui.py — a Tkinter console for the EDR lab. Standard library only.

    python3 lab_gui.py            # launch
    python3 lab_gui.py --check    # verify the environment without opening a window

"""

from __future__ import annotations

import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter

ROOT = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------- #
# Palette. Dark, because this sits next to a terminal all day.
# --------------------------------------------------------------------------- #
BG = "#1e1f22"
BG2 = "#2b2d30"
BG3 = "#3c3f41"
FG = "#d6d6d6"
FG_DIM = "#9a9a9a"
ACCENT = "#4a9eff"
OK = "#4ec9b0"
WARN = "#dcdcaa"
BAD = "#f48771"
PURPLE = "#c586c0"

VERDICT_COLOUR = {
    "detected": OK,
    "logged_no_rule": WARN,
    "silent": BAD,
    "tamper_positive": PURPLE,
    "inconclusive": FG_DIM,
    "dry_run": FG_DIM,
}
# Verdicts that mean "look at this run before you trust it."
VERDICT_NEEDS_ATTENTION = {"silent", "tamper_positive"}


# =========================================================================== #
# environment probing — each probe answers one question and returns plain
# data. probe_environment() just combines them, so any single check can be
# read (or fixed) without wading through the others.
# =========================================================================== #
def which_all(*names: str) -> dict[str, str | None]:
    return {n: shutil.which(n) for n in names}


def probe_tools() -> dict:
    """External binaries this repo shells out to, and whether PyYAML/transport
    libraries the harness itself imports are actually installed."""
    info: dict = {"tools": which_all("vmrun", "ansible-playbook", "git"), "has_yaml": False,
                  "transports": {}}
    try:
        import yaml  # noqa: F401
        info["has_yaml"] = True
    except ImportError:
        pass
    for mod, label in (("winrm", "pywinrm"), ("paramiko", "paramiko")):
        try:
            __import__(mod)
            info["transports"][label] = True
        except ImportError:
            info["transports"][label] = False
    return info


def probe_required_files() -> list[str]:
    """Files the harness cannot run without. Absence here means 'wrong
    directory' far more often than 'broken install'."""
    required = [
        "harness/run_all.py", "harness/score.py", "harness/report.py",
        "tools/preflight.sh", "tools/isolation_check.py", "tools/minisiem/engine.py",
        "Makefile",
    ]
    return [r for r in required if not os.path.exists(os.path.join(ROOT, r))]


def probe_cases() -> list[str]:
    """Every case file under harness/cases/{windows,linux,baseline}/*.yml."""
    cases_dir = os.path.join(ROOT, "harness", "cases")
    found: list[str] = []
    if os.path.isdir(cases_dir):
        for suite in ("windows", "linux", "baseline"):
            d = os.path.join(cases_dir, suite)
            if os.path.isdir(d):
                found += [os.path.join(d, f) for f in sorted(os.listdir(d))
                          if f.endswith(".yml") and not f.startswith("_")]
    return found


def probe_rules() -> tuple[int, list[str]]:
    """Rule id count (for the headline number) and the rule files themselves
    (for the Rules tab), from rules/windows/ and rules/linux/."""
    rules_dir = os.path.join(ROOT, "rules")
    n_rules = 0
    files: list[str] = []
    for suite in ("windows", "linux"):
        d = os.path.join(rules_dir, suite)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.endswith((".yml", ".yaml")) and not f.startswith("_"):
                path = os.path.join(d, f)
                files.append(path)
                try:
                    n_rules += len(re.findall(r"^id:\s*\S+", open(path).read(), re.M))
                except OSError:
                    pass
    return n_rules, files


def probe_isolation() -> dict | None:
    """Most recent isolation-evidence directory under store/_isolation, with
    its age in days. run_all.py refuses a scored run without this, so the
    GUI has to know the same fact before offering the button."""
    iso_root = os.path.join(ROOT, "store", "_isolation")
    if not os.path.isdir(iso_root):
        return None
    entries = sorted(os.listdir(iso_root))
    if not entries:
        return None
    newest = entries[-1]
    age_days = int((time.time() - os.path.getmtime(os.path.join(iso_root, newest))) / 86400)
    return {"dir": newest, "age_days": age_days}


def probe_environment() -> dict:
    """Work out what this machine can actually do. Runs no case, touches no VM."""
    env: dict = {
        "root": ROOT,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "lab_pass": bool(os.environ.get("LAB_PASS")),
        "problems": [],
        "warnings": [],
    }
    env.update(probe_tools())

    if not env["has_yaml"]:
        env["problems"].append("PyYAML missing — most of the harness cannot run. "
                                "pip install -r requirements.txt")

    env["missing"] = probe_required_files()
    if env["missing"]:
        env["problems"].append(f"{len(env['missing'])} required file(s) missing — "
                                f"is this the repo root? see the Setup tab")

    if not any(env["transports"].values()):
        env["warnings"].append("neither pywinrm nor paramiko installed — offline modes only")

    env["case_files"] = probe_cases()
    env["n_cases"] = len(env["case_files"])

    env["n_rules"], env["rule_files"] = probe_rules()

    env["isolation"] = probe_isolation()
    if env["isolation"] is None:
        env["warnings"].append("no isolation evidence yet — run Preflight (isolation) "
                                "before any scored run")

    return env


# =========================================================================== #
# run history — reads store/<run>/cases/<id>/score.json across EVERY run
# dir, not just the newest. The original console only ever looked at the
# latest run; this is what makes a dashboard and a browsable history possible.
# =========================================================================== #
def scan_all_runs() -> list[dict]:
    """Every run recorded under store/, newest first."""
    store = os.path.join(ROOT, "store")
    runs: list[dict] = []
    if not os.path.isdir(store):
        return runs
    for name in os.listdir(store):
        if not re.match(r"^R\d+", name):
            continue
        run_dir = os.path.join(store, name)
        cases_dir = os.path.join(run_dir, "cases")
        verdicts: dict[str, dict] = {}
        if os.path.isdir(cases_dir):
            for cid in sorted(os.listdir(cases_dir)):
                score_path = os.path.join(cases_dir, cid, "score.json")
                if os.path.isfile(score_path):
                    try:
                        data = json.load(open(score_path))
                        verdicts[cid] = {"verdict": data.get("verdict", "?"),
                                          "reason": data.get("reason", "")}
                    except (OSError, ValueError):
                        pass
        runs.append({
            "run_id": name,
            "dir": run_dir,
            "mtime": os.path.getmtime(run_dir),
            "verdicts": verdicts,
        })
    runs.sort(key=lambda r: r["mtime"], reverse=True)
    return runs


def tally_verdicts(runs: list[dict]) -> Counter:
    counts: Counter = Counter()
    for r in runs:
        for v in r["verdicts"].values():
            counts[v["verdict"]] += 1
    return counts


def last_verdict_by_case(runs: list[dict]) -> dict[str, str]:
    """Most recent verdict per case id, scanning newest-run-first so the
    first hit for a case id is its latest result."""
    out: dict[str, str] = {}
    for r in runs:
        for cid, v in r["verdicts"].items():
            out.setdefault(cid, v["verdict"])
    return out


# =========================================================================== #
# subprocess runner that never blocks the UI
# =========================================================================== #
class Runner:
    """Runs commands on a worker thread and streams output to a queue.

    A GUI that freezes on a 60-second capture window looks broken, and the
    natural reaction is to click Run again — which, for this harness, would
    start a SECOND case against the same VMs and produce evidence from two
    interleaved runs. So everything long-running goes through here, and
    start() refuses outright while something is already in flight.
    """

    def __init__(self, on_line, on_done):
        self.on_line = on_line
        self.on_done = on_done
        self.proc: subprocess.Popen | None = None
        self.busy = False
        self.start_time: float | None = None
        self._q: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        self.root = None
        self.label = ""

    def start(self, argv: list[str], label: str, cwd: str | None = None,
              env_extra: dict | None = None) -> bool:
        if self.busy:
            self.on_line(f"[gui] refusing to start {label}: {self.label} is still running.\n",
                         "warn")
            return False
        self.busy = True
        self.label = label
        self.start_time = time.time()
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        if env_extra:
            env.update(env_extra)

        self._thread = threading.Thread(
            target=self._run, args=(argv, label, cwd or ROOT, env), daemon=True)
        self._thread.start()
        return True

    def _run(self, argv, label, cwd, env):
        # Runs on a worker thread — must not touch a widget, not even to echo
        # the command. Everything goes on the queue; the main thread renders it.
        self._q.put(("line", f"\n$ {' '.join(shlex.quote(a) for a in argv)}\n"))
        rc = None
        try:
            self.proc = subprocess.Popen(
                argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1)
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                self._q.put(("line", line))
            rc = self.proc.wait()
        except FileNotFoundError as exc:
            self._q.put(("line", f"[gui] command not found: {exc}\n"))
            rc = 127
        except Exception as exc:  # noqa: BLE001
            self._q.put(("line", f"[gui] {type(exc).__name__}: {exc}\n"))
            rc = 1
        finally:
            self.proc = None
        self._q.put(("done", (label, rc)))

    def stop(self):
        """Called from the main thread (Stop button), so touching on_line is safe."""
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self._q.put(("line", f"[gui] terminated {self.label}\n"))

    def elapsed(self) -> int:
        if not self.busy or self.start_time is None:
            return 0
        return int(time.time() - self.start_time)

    def _pump(self):
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "line":
                    self.on_line(payload)
                else:
                    label, rc = payload
                    self.busy = False
                    self.start_time = None
                    self.on_done(label, rc)
        except queue.Empty:
            pass
        except Exception:  # noqa: BLE001
            pass
        if self.root is not None:
            self.root.after(60, self._pump)

    def attach(self, root):
        """Bind to a Tk root and begin draining the output queue."""
        self.root = root
        self._pump()


# =========================================================================== #
# the window
# =========================================================================== #
def build_app():  # pragma: no cover - requires a display
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    env = probe_environment()

    root = tk.Tk()
    root.title("EDR Lab — console")
    root.geometry("1360x860")
    root.minsize(1040, 640)
    root.configure(bg=BG)

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(".", background=BG, foreground=FG, fieldbackground=BG2,
                    bordercolor=BG3, lightcolor=BG3, darkcolor=BG)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Dim.TLabel", background=BG, foreground=FG_DIM)
    style.configure("Head.TLabel", background=BG, foreground=FG,
                     font=("TkDefaultFont", 11, "bold"))
    style.configure("TButton", background=BG3, foreground=FG, borderwidth=0, padding=(10, 6))
    style.map("TButton",
              background=[("active", ACCENT), ("disabled", BG2)],
              foreground=[("disabled", "#6a6a6a")])
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=BG2, foreground=FG_DIM, padding=(14, 7))
    style.map("TNotebook.Tab",
              background=[("selected", BG3)],
              foreground=[("selected", FG)])
    style.configure("TCombobox", fieldbackground=BG2, background=BG3, foreground=FG)
    # clam leaves the readonly state unmapped, which renders as a near-white
    # field with invisible text — Combobox is used read-only everywhere here.
    style.map("TCombobox",
              fieldbackground=[("readonly", BG2)],
              foreground=[("readonly", FG)],
              background=[("readonly", BG3)],
              selectbackground=[("readonly", BG2)],
              selectforeground=[("readonly", FG)])
    style.configure("Treeview", background=BG2, fieldbackground=BG2,
                    foreground=FG, rowheight=24, borderwidth=0)
    style.configure("Treeview.Heading", background=BG3, foreground=FG, relief="flat")
    style.map("Treeview", background=[("selected", ACCENT)],
              foreground=[("selected", "#ffffff")])

    # ---- layout: left = cases, right = tabs -------------------------------
    outer = ttk.Frame(root)
    outer.pack(fill="both", expand=True, padx=10, pady=(10, 0))

    left = ttk.Frame(outer, width=350)
    left.pack(side="left", fill="y", padx=(0, 10))
    left.pack_propagate(False)

    case_header = ttk.Frame(left)
    case_header.pack(fill="x")
    case_title = ttk.Label(case_header, text="CASES", style="Head.TLabel")
    case_title.pack(side="left", fill="x", expand=True)
    case_panel_expanded = True

    def toggle_case_panel():
        nonlocal case_panel_expanded
        case_panel_expanded = not case_panel_expanded
        if case_panel_expanded:
            left.configure(width=350)
            case_title.pack(side="left", fill="x", expand=True)
            case_content.pack(fill="both", expand=True)
            case_panel_toggle.configure(text="‹")
        else:
            case_content.pack_forget()
            case_title.pack_forget()
            left.configure(width=34)
            case_panel_toggle.configure(text="›")

    case_panel_toggle = ttk.Button(case_header, text="‹", width=2,
                                   command=toggle_case_panel)
    case_panel_toggle.pack(side="right", padx=(4, 0))

    case_content = ttk.Frame(left)
    case_content.pack(fill="both", expand=True)
    filt = ttk.Frame(case_content)
    filt.pack(fill="x", pady=(6, 6))
    suite_var = tk.StringVar(value="all")
    ttk.Combobox(filt, textvariable=suite_var, state="readonly", width=10,
                 values=["all", "windows", "linux", "baseline"]).pack(side="left")
    search_var = tk.StringVar()
    ttk.Entry(filt, textvariable=search_var, width=16).pack(side="left", padx=(6, 0), fill="x",
                                                             expand=True)

    case_tree = ttk.Treeview(case_content, columns=("suite", "phase", "last"),
                              show="tree headings",
                              selectmode="browse")
    case_tree.heading("#0", text="case")
    case_tree.heading("suite", text="suite")
    case_tree.heading("phase", text="phase")
    case_tree.heading("last", text="last")
    case_tree.column("#0", width=170, stretch=True)
    case_tree.column("suite", width=64, anchor="center")
    case_tree.column("phase", width=42, anchor="center")
    case_tree.column("last", width=90, anchor="center")
    case_tree.pack(fill="both", expand=True)
    for verdict, colour in VERDICT_COLOUR.items():
        case_tree.tag_configure(f"v_{verdict}", foreground=colour)

    case_info = tk.Text(case_content, height=7, bg=BG2, fg=FG_DIM, insertbackground=FG,
                         relief="flat", wrap="word", font=("TkFixedFont", 9), padx=8, pady=6)
    case_info.pack(fill="x", pady=(6, 0))
    case_info.insert("end", "Case Details:\nSelect a case to view its details.")
    case_info.configure(state="disabled")

    right = ttk.Frame(outer)
    right.pack(side="left", fill="both", expand=True)

    nb = ttk.Notebook(right)
    nb.pack(fill="both", expand=True)

    # Declared here so the Report/Evidence header bars (built below, before
    # their text widgets exist) and the refresh logic (built further down,
    # after the widgets exist) share the same StringVars/Comboboxes.
    report_run_var = tk.StringVar()
    ev_run_var = tk.StringVar()
    analysis_run_var = tk.StringVar()
    analysis_case_var = tk.StringVar()
    analysis_source_var = tk.StringVar()
    report_run_menu = None  # assigned inside the Report tab's header()
    ev_run_menu = None      # assigned inside the Evidence tab's header()

    def text_tab(title, header=None):
        """header(frame), if given, is called (and packed) before the text
        widget itself — so a run-selector bar ends up above the text, not
        fighting it for space after the fact."""
        frame = ttk.Frame(nb)
        nb.add(frame, text=title)
        if header is not None:
            header(frame)
        txt = tk.Text(frame, bg=BG2, fg=FG, insertbackground=FG, relief="flat",
                       wrap="none", font=("TkFixedFont", 9), padx=10, pady=8,
                       selectbackground=ACCENT)
        ys = ttk.Scrollbar(frame, orient="vertical", command=txt.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        xs.pack(side="bottom", fill="x")
        txt.pack(side="left", fill="both", expand=True)
        for tag, colour in (("ok", OK), ("warn", WARN), ("bad", BAD),
                             ("cmd", ACCENT), ("dim", FG_DIM), ("purple", PURPLE)):
            txt.tag_configure(tag, foreground=colour)
        return frame, txt

    # ---- Dashboard tab (new: aggregates every run, not just the latest) ---
    dash_frame = ttk.Frame(nb)
    nb.add(dash_frame, text="Dashboard")

    dash_cards = ttk.Frame(dash_frame)
    dash_cards.pack(fill="x", padx=10, pady=(10, 6))

    def stat_card(parent, col):
        card = tk.Frame(parent, bg=BG2, height=94, highlightthickness=1,
                        highlightbackground=BG3)
        card.pack_propagate(False)
        card.grid(row=0, column=col, sticky="ew",
                  padx=(0 if col == 0 else 7, 0))
        parent.grid_columnconfigure(col, weight=1)
        value_lbl = tk.Label(card, text="—", bg=BG2, fg=FG,
                             font=("TkDefaultFont", 18, "bold"))
        value_lbl.pack(anchor="w", padx=10, pady=(7, 0))
        caption_lbl = tk.Label(card, text="", bg=BG2, fg=FG_DIM,
                               font=("TkDefaultFont", 9), anchor="w", justify="left")
        caption_lbl.pack(anchor="w", padx=10, pady=(0, 6))
        return value_lbl, caption_lbl

    card_cases_val, card_cases_cap = stat_card(dash_cards, 0)
    card_rules_val, card_rules_cap = stat_card(dash_cards, 1)
    card_runs_val, card_runs_cap = stat_card(dash_cards, 2)
    card_rate_val, card_rate_cap = stat_card(dash_cards, 3)

    dash_sections = ttk.Frame(dash_frame)
    dash_sections.pack(fill="both", expand=True, padx=10, pady=(6, 10))
    dash_sections.columnconfigure(0, weight=1, minsize=165)
    dash_sections.columnconfigure(2, weight=3, minsize=390)
    dash_sections.rowconfigure(0, weight=1)

    verdict_panel = ttk.Frame(dash_sections)
    verdict_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
    ttk.Label(verdict_panel, text="CASES", style="Head.TLabel").pack(
        anchor="w", pady=(0, 2))
    ttk.Label(verdict_panel, text="all recorded runs", style="Dim.TLabel").pack(
        anchor="w", pady=(0, 6))
    dash_verdict_frame = ttk.Frame(verdict_panel)
    dash_verdict_frame.pack(fill="x")

    ttk.Separator(dash_sections, orient="vertical").grid(row=0, column=1, sticky="ns")

    recent_panel = ttk.Frame(dash_sections)
    recent_panel.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
    recent_header = ttk.Frame(recent_panel)
    recent_header.pack(fill="x", pady=(0, 4))
    ttk.Label(recent_header, text="RECENT RUNS", style="Head.TLabel").pack(side="left")
    ttk.Label(recent_header, text="attention = silent or tamper_positive",
              style="Dim.TLabel").pack(side="right")
    recent_table_frame = ttk.Frame(recent_panel)
    recent_table_frame.pack(fill="both", expand=True, padx=4)
    recent_table_frame.grid_columnconfigure(0, weight=1)
    recent_table_frame.grid_rowconfigure(0, weight=1)
    style.configure("Dashboard.Treeview", rowheight=26, borderwidth=0,
                    background=BG2, fieldbackground=BG2, foreground=FG)
    style.configure("Dashboard.Treeview.Heading", background=BG3, foreground=FG_DIM,
                    relief="flat", font=("TkDefaultFont", 9, "bold"))
    style.map("Dashboard.Treeview", background=[("selected", ACCENT)],
              foreground=[("selected", "#ffffff")])
    runs_tree = ttk.Treeview(
        recent_table_frame, columns=("cases", "detected", "issues", "when"),
        show="tree headings", selectmode="browse", height=9, style="Dashboard.Treeview")
    runs_tree.heading("#0", text="RUN ID", anchor="center")
    runs_tree.heading("cases", text="CASES")
    runs_tree.heading("detected", text="DETECTED")
    runs_tree.heading("issues", text="ATTENTION")
    runs_tree.heading("when", text="LAST RUN")
    runs_tree.column("#0", width=145, minwidth=125, anchor="center", stretch=True)
    runs_tree.column("cases", width=55, minwidth=50, anchor="center", stretch=True)
    runs_tree.column("detected", width=70, minwidth=65, anchor="center", stretch=True)
    runs_tree.column("issues", width=78, minwidth=70, anchor="center", stretch=True)
    runs_tree.column("when", width=128, minwidth=110, anchor="center", stretch=True)
    runs_tree.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
    runs_scroll = ttk.Scrollbar(recent_table_frame, orient="vertical",
                                command=runs_tree.yview)
    runs_tree.configure(yscrollcommand=runs_scroll.set)
    runs_scroll.grid(row=0, column=1, sticky="ns", pady=(0, 5))
    runs_tree.tag_configure("attention", foreground=BAD)

    def render_dashboard():
        runs = scan_all_runs()
        counts = tally_verdicts(runs)
        detection_tests = sum(counts.get(verdict, 0)
                      for verdict in ("detected", "logged_no_rule", "silent"))
        detected = counts.get("detected", 0)

        card_cases_val.configure(text=str(env["n_cases"]))
        card_cases_cap.configure(text="cases defined")
        card_rules_val.configure(text=str(env["n_rules"]))
        card_rules_cap.configure(text="rules loaded")
        card_runs_val.configure(text=str(len(runs)))
        card_runs_cap.configure(text="runs recorded")
        if detection_tests:
            rate = 100 * detected / detection_tests
            card_rate_val.configure(text=f"{rate:.0f}%", fg=FG)
            card_rate_cap.configure(
                text=f"detection rate\n{detected} / {detection_tests} detection tests")
        else:
            card_rate_val.configure(text="—", fg=FG)
            card_rate_cap.configure(text="no detection tests yet")

        for child in dash_verdict_frame.winfo_children():
            child.destroy()
        if not counts:
            tk.Label(dash_verdict_frame, text="no runs recorded under store/ yet",
                     bg=BG, fg=FG_DIM, font=("TkFixedFont", 9)).pack(
                         anchor="w", pady=5)
        else:
            for verdict in ("detected", "logged_no_rule", "silent", "tamper_positive",
                             "inconclusive", "dry_run"):
                n = counts.get(verdict, 0)
                if n == 0:
                    continue
                item = tk.Frame(dash_verdict_frame, bg=BG, height=32)
                item.pack(fill="x", pady=1)
                item.pack_propagate(False)
                tk.Frame(item, bg=VERDICT_COLOUR[verdict], width=3).pack(
                    side="left", fill="y")
                tk.Label(item, text=verdict, bg=BG, fg=VERDICT_COLOUR[verdict],
                         font=("TkDefaultFont", 9, "bold"), anchor="w").pack(
                             side="left", padx=(8, 4))
                tk.Label(item, text=str(n), bg=BG, fg=FG,
                         font=("TkDefaultFont", 10, "bold"), anchor="e").pack(
                             side="right", padx=8)
                tk.Frame(item, bg=BG3, height=1).pack(side="bottom", fill="x")

        runs_tree.delete(*runs_tree.get_children())
        for r in runs[:20]:
            v = Counter(x["verdict"] for x in r["verdicts"].values())
            issues = sum(v.get(k, 0) for k in VERDICT_NEEDS_ATTENTION)
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["mtime"]))
            tag = "attention" if issues else ""
            runs_tree.insert(
                "", "end", text=r["run_id"],
                values=(len(r["verdicts"]), v.get("detected", 0),
                        issues if issues else "", when),
                tags=(tag,) if tag else ())

    # ---- Run log / Report / Evidence tabs ----------------------------------
    log_frame, log_txt = text_tab("Run log")

    # Report and Evidence each get a run selector so past runs stay reachable
    # — the original console only ever showed the latest one. The combobox
    # itself is built here, in header(), so it packs above the text widget;
    # it's wired up (values populated, selection bound) further down, once
    # report_txt/ev_txt and the functions that fill them exist.
    def _report_header(frame):
        nonlocal report_run_menu
        bar = ttk.Frame(frame)
        bar.pack(fill="x", padx=10, pady=(8, 4))
        ttk.Label(bar, text="report:", style="Dim.TLabel").pack(side="left")
        report_run_menu = ttk.Combobox(bar, textvariable=report_run_var, state="readonly",
                                        width=40)
        report_run_menu.pack(side="left", padx=(6, 0))

    def _evidence_header(frame):
        nonlocal ev_run_menu
        bar = ttk.Frame(frame)
        bar.pack(fill="x", padx=10, pady=(8, 4))
        ttk.Label(bar, text="run:", style="Dim.TLabel").pack(side="left")
        ev_run_menu = ttk.Combobox(bar, textvariable=ev_run_var, state="readonly", width=20)
        ev_run_menu.pack(side="left", padx=(6, 0))

    report_frame, report_txt = text_tab("Report", header=_report_header)
    _, ev_txt = text_tab("Evidence", header=_evidence_header)

    analysis_frame = ttk.Frame(nb)
    nb.add(analysis_frame, text="Analysis")
    analysis_toolbar = ttk.Frame(analysis_frame)
    analysis_toolbar.pack(fill="x", padx=10, pady=(10, 6))
    ttk.Label(analysis_toolbar, text="RUN", style="Dim.TLabel").pack(side="left")
    analysis_run_menu = ttk.Combobox(
        analysis_toolbar, textvariable=analysis_run_var, state="readonly", width=17)
    analysis_run_menu.pack(side="left", padx=(6, 10))
    ttk.Label(analysis_toolbar, text="CASE", style="Dim.TLabel").pack(side="left")
    analysis_case_menu = ttk.Combobox(
        analysis_toolbar, textvariable=analysis_case_var, state="readonly", width=20)
    analysis_case_menu.pack(side="left", padx=(6, 10))
    ttk.Label(analysis_toolbar, text="FILE", style="Dim.TLabel").pack(side="left")
    analysis_source_menu = ttk.Combobox(
        analysis_toolbar, textvariable=analysis_source_var, state="readonly", width=20)
    analysis_source_menu.pack(side="left", padx=(6, 8), fill="x", expand=True)
    ttk.Button(analysis_toolbar, text="Refresh", command=lambda: refresh_analysis()).pack(
        side="left")

    analysis_summary = tk.Text(analysis_frame, height=9, bg=BG2, fg=FG,
                               insertbackground=FG, relief="flat", wrap="word",
                               font=("TkFixedFont", 9), padx=10, pady=8)
    analysis_summary.pack(fill="x", padx=10, pady=(0, 8))
    analysis_summary.configure(state="disabled")
    analysis_viewer_frame = ttk.Frame(analysis_frame)
    analysis_viewer_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    analysis_viewer = tk.Text(analysis_viewer_frame, bg=BG2, fg=FG,
                              insertbackground=FG, relief="flat", wrap="none",
                              font=("TkFixedFont", 9), padx=10, pady=8,
                              selectbackground=ACCENT)
    analysis_scroll_y = ttk.Scrollbar(analysis_viewer_frame, orient="vertical",
                                     command=analysis_viewer.yview)
    analysis_scroll_x = ttk.Scrollbar(analysis_viewer_frame, orient="horizontal",
                                     command=analysis_viewer.xview)
    analysis_viewer.configure(yscrollcommand=analysis_scroll_y.set,
                              xscrollcommand=analysis_scroll_x.set)
    analysis_scroll_y.pack(side="right", fill="y")
    analysis_scroll_x.pack(side="bottom", fill="x")
    analysis_viewer.pack(side="left", fill="both", expand=True)

    # ---- Rules tab (new: browse rules/windows + rules/linux) --------------
    rules_frame = ttk.Frame(nb)
    nb.add(rules_frame, text="Rules")
    rules_split = ttk.Frame(rules_frame)
    rules_split.pack(fill="both", expand=True, padx=10, pady=10)
    rules_list = ttk.Treeview(rules_split, columns=("suite",), show="tree headings", height=10)
    rules_list.heading("#0", text="rule file")
    rules_list.heading("suite", text="os")
    rules_list.column("#0", width=220)
    rules_list.column("suite", width=70, anchor="center")
    rules_list.pack(side="left", fill="y", padx=(0, 10))
    rules_preview = tk.Text(rules_split, bg=BG2, fg=FG, relief="flat", wrap="none",
                             font=("TkFixedFont", 9), padx=10, pady=8)
    rules_preview.pack(side="left", fill="both", expand=True)
    rules_preview.configure(state="disabled")

    def render_rules_list():
        rules_list.delete(*rules_list.get_children())
        for path in env["rule_files"]:
            suite = os.path.basename(os.path.dirname(path))
            rules_list.insert("", "end", iid=path, text=os.path.basename(path),
                               values=(suite,))

    def show_rule(_event=None):
        sel = rules_list.selection()
        if not sel:
            return
        rules_preview.configure(state="normal")
        rules_preview.delete("1.0", "end")
        try:
            rules_preview.insert("end", open(sel[0]).read())
        except OSError as exc:
            rules_preview.insert("end", f"could not read: {exc}")
        rules_preview.configure(state="disabled")

    rules_list.bind("<<TreeviewSelect>>", show_rule)

    # ---- Setup tab ----------------------------------------------------------
    def render_setup():
        nonlocal env
        env = probe_environment()

        setup_txt.configure(state="normal")
        setup_txt.delete("1.0", "end")

        def line(label, value, tag=None, width=15):
            setup_txt.insert("end", f"  {label:<{width}} ", "dim")
            setup_txt.insert("end", f"{value}\n", tag)

        setup_txt.insert("end", "ENVIRONMENT\n", "cmd")
        line("repo root", env["root"])
        line("python", env["python"])
        line("PyYAML", "yes" if env["has_yaml"] else "NO — pip install -r requirements.txt",
             "ok" if env["has_yaml"] else "bad")

        tr = env["transports"]
        line("pywinrm", "yes" if tr.get("pywinrm") else "no (needed to reach win-victim)",
             "ok" if tr.get("pywinrm") else "warn")
        line("paramiko", "yes" if tr.get("paramiko") else "no (needed to reach lin-victim)",
             "ok" if tr.get("paramiko") else "warn")
        line("vmrun", env["tools"].get("vmrun") or "not on PATH (needed on the hypervisor host)",
             "ok" if env["tools"].get("vmrun") else "warn")
        line("ansible", env["tools"].get("ansible-playbook") or "not on PATH",
             "ok" if env["tools"].get("ansible-playbook") else "warn")
        line("LAB_PASS", "set" if env["lab_pass"] else "not set (scored runs need it)",
             "ok" if env["lab_pass"] else "bad")
        line("cases", f"{env['n_cases']} discovered")
        line("rules", f"{env['n_rules']} loaded from rules/ (templates excluded)")

        if env["isolation"]:
            line("isolation", f"verified {env['isolation']['age_days']}d ago "
                               f"({env['isolation']['dir']})",
                 "ok" if env["isolation"]["age_days"] < 7 else "warn")
        else:
            line("isolation", "NOT VERIFIED — Preflight (isolation) first", "bad")

        if env["missing"]:
            setup_txt.insert("end", "\nMISSING FILES\n", "bad")
            for m in env["missing"]:
                setup_txt.insert("end", f"  {m}\n", "bad")

        if env["problems"]:
            setup_txt.insert("end", "\nBLOCKING\n", "bad")
            for p in env["problems"]:
                setup_txt.insert("end", f"  * {p}\n", "bad")

        if env["warnings"]:
            setup_txt.insert("end", "\nWARNINGS (do not block; each one is a caveat on your "
                                     "results)\n", "warn")
            for w in env["warnings"]:
                setup_txt.insert("end", f"  * {w}\n", "warn")

        setup_txt.insert("end", "\nWHAT EACH BUTTON NEEDS\n", "cmd")
        setup_txt.insert("end",
            "  Case discovery, Replay, Self-test, Rules check    anywhere, no VMs\n"
            "  Manifest, Open report, Dashboard, Rules browser   anywhere\n"
            "  Preflight (static)                                the repo only\n"
            "  Preflight (isolation)                             hypervisor host + VMs running\n"
            "  Dry run                                           the repo only (no VM contact)\n"
            "  Run selected case / Run suite                     hypervisor host, VMs up, "
            "LAB_PASS set\n", "dim")

        setup_txt.insert("end", "\nFIRST RUN, IN ORDER\n", "cmd")
        setup_txt.insert("end",
            "  1. Preflight (static)\n"
            "  2. Self-test\n"
            "  3. Replay\n"
            "  4. Preflight (isolation)\n"
            "  5. Run suite: baseline\n"
            "  6. Run suite: windows, then linux\n", "dim")

        setup_txt.insert("end", "\nBEFORE YOU TRUST A VERDICT\n", "cmd")
        setup_txt.insert("end",
            "  * A case with no marker file scores inconclusive.\n"
            "  * Replay cannot tell silent from inconclusive.\n"
            "  * Read the vintage-bias line in every report.\n", "dim")

        setup_txt.configure(state="disabled")

    setup_frame2 = ttk.Frame(nb)
    nb.add(setup_frame2, text="Setup")
    setup_txt = tk.Text(setup_frame2, bg=BG2, fg=FG, relief="flat", wrap="word",
                         font=("TkFixedFont", 9), padx=10, pady=8)
    for tag, colour in (("ok", OK), ("warn", WARN), ("bad", BAD), ("cmd", ACCENT), ("dim", FG_DIM)):
        setup_txt.tag_configure(tag, foreground=colour)
    sb = ttk.Scrollbar(setup_frame2, orient="vertical", command=setup_txt.yview)
    setup_txt.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    setup_txt.pack(side="left", fill="both", expand=True)

    render_setup()
    render_rules_list()
    render_dashboard()

    # ---- bottom bar ---------------------------------------------------------
    bottom = ttk.Frame(root)
    bottom.pack(fill="x", padx=10, pady=10)

    status = tk.StringVar()
    status_lbl = ttk.Label(bottom, textvariable=status, style="Dim.TLabel")
    status_lbl.pack(side="right", padx=(10, 0))

    def set_status(msg, colour=FG_DIM):
        status.set(msg)
        status_lbl.configure(foreground=colour)

    # ---- runner ---------------------------------------------------------------
    def log(line_text, tag=None):
        log_txt.configure(state="normal")
        if tag == "cmd":
            log_txt.insert("end", line_text, "cmd")
        elif tag == "warn":
            log_txt.insert("end", line_text, "warn")
        else:
            low = line_text.lower()
            if "fail" in low or "error" in low or "traceback" in low or "silent" in low:
                log_txt.insert("end", line_text, "bad")
            elif "tamper_positive" in low:
                log_txt.insert("end", line_text, "purple")
            elif "warn" in low or "inconclusive" in low or "logged_no_rule" in low:
                log_txt.insert("end", line_text, "warn")
            elif re.search(r"\b(detected|ok|pass)\b", low):
                log_txt.insert("end", line_text, "ok")
            else:
                log_txt.insert("end", line_text)
        log_txt.see("end")
        log_txt.configure(state="disabled")

    def on_done(label, rc):
        for b in action_buttons:
            try:
                b.configure(state="normal")
            except tk.TclError:
                pass
        if blocked_reason:
            run_case_btn.configure(state="disabled")
            run_suite_btn.configure(state="disabled")
        if rc == 0:
            log(f"[gui] {label} finished (exit 0)\n", "ok")
            set_status(f"{label}: done", OK)
        else:
            log(f"[gui] {label} finished with exit {rc}\n", "bad")
            set_status(f"{label}: exit {rc}", BAD)
        select_latest = label.startswith("run ")
        refresh_reports(select_latest=select_latest)
        if select_latest:
            open_selected_report()
            load_evidence(select_latest=True)
            refresh_analysis(select_latest=True)
        refresh_selected_tab()
        render_dashboard()

    runner = Runner(on_line=log, on_done=on_done)
    runner.attach(root)

    action_buttons: list = []

    def run(argv, label):
        if runner.busy:
            messagebox.showinfo("Busy", f"'{runner.label}' is still running.\n\n"
                                         "The harness runs cases strictly serially — a second "
                                         "run would interleave evidence from two cases against "
                                         "the same VM.")
            return False
        set_status(f"{label}: running…", ACCENT)
        log_txt.configure(state="normal")
        if runner.start(argv, label):
            for b in action_buttons:
                b.configure(state="disabled")
            return True
        return False

    # elapsed-time ticker: only touches the status bar while a run is busy,
    # so it never overwrites a "done"/"exit N" status on_done just set.
    def tick_elapsed():
        if runner.busy:
            set_status(f"{runner.label}: running… {runner.elapsed()}s", ACCENT)
        root.after(1000, tick_elapsed)

    tick_elapsed()

    # ------------------------------------------------------------------ #
    # case list
    # ------------------------------------------------------------------ #
    cases: list[dict] = []
    last_verdicts: dict[str, str] = {}

    def load_cases():
        cases.clear()
        for path in env["case_files"]:
            info = {"path": path, "id": os.path.splitext(os.path.basename(path))[0],
                     "suite": os.path.basename(os.path.dirname(path)),
                     "title": "", "phase": "", "raw": ""}
            try:
                text = open(path).read()
                info["raw"] = text
                m = re.search(r"^title:\s*(.+)$", text, re.M)
                if m:
                    info["title"] = m.group(1).strip()
                m = re.search(r"^phase:\s*(.+)$", text, re.M)
                if m:
                    info["phase"] = m.group(1).strip()
            except OSError:
                pass
            cases.append(info)

    def render_cases(*_):
        case_tree.delete(*case_tree.get_children())
        want_suite = suite_var.get()
        needle = search_var.get().lower().strip()
        shown = 0
        for c in cases:
            if want_suite != "all" and c["suite"] != want_suite:
                continue
            if needle and needle not in c["id"].lower() and needle not in c["title"].lower():
                continue
            mark = ""
            text = c["raw"]
            for m in re.finditer(r"from:\s*([^\s,}]+)", text):
                ref = m.group(1).strip("\"'")
                if "/" in ref and not os.path.exists(os.path.join(ROOT, ref)):
                    mark = "  ⚠"
                    break
            last = last_verdicts.get(c["id"], "")
            tag = f"v_{last}" if last in VERDICT_COLOUR else ""
            case_tree.insert("", "end", iid=c["id"],
                              text=c["id"] + mark,
                              values=(c["suite"], c["phase"], last),
                              tags=(tag,) if tag else ())
            shown += 1
        set_status(f"{shown} of {len(cases)} case(s) shown", FG_DIM)

    def show_case(_event=None):
        sel = case_tree.selection()
        if not sel:
            case_info.configure(state="normal")
            case_info.delete("1.0", "end")
            case_info.insert("end", "Case Details:\nSelect a case to view its details.")
            case_info.configure(state="disabled")
            return
        c = next((x for x in cases if x["id"] == sel[0]), None)
        if not c:
            return
        case_info.configure(state="normal")
        case_info.delete("1.0", "end")
        body = f"{c['id']}\n{c['title']}\nsuite={c['suite']}  phase={c['phase']}\n"
        refs = re.findall(r"from:\s*([^\s,}]+)", c["raw"])
        missing = [r.strip("\"'") for r in refs
                   if "/" in r and not os.path.exists(os.path.join(ROOT, r.strip("\"'")))
                   and not re.match(r"^[A-Za-z]:", r)]
        if missing:
            body += "\nNOT BUILT:\n" + "\n".join("  " + m for m in missing)
        case_info.insert("end", body)
        case_info.configure(state="disabled")

    case_tree.bind("<<TreeviewSelect>>", show_case)
    suite_var.trace_add("write", render_cases)
    search_var.trace_add("write", render_cases)

    def reload_case_data():
        load_cases()
        nonlocal_runs = scan_all_runs()
        last_verdicts.clear()
        last_verdicts.update(last_verdict_by_case(nonlocal_runs))
        render_cases()

    reload_case_data()

    # ------------------------------------------------------------------ #
    # reports + evidence, with a run selector so history stays reachable
    # ------------------------------------------------------------------ #
    report_index: list[str] = []
    # report_run_var / report_run_menu were created back in _report_header();
    # reused here, not recreated, so the Combobox stays wired to this data.

    def refresh_reports(select_latest=False):
        report_index.clear()
        d = os.path.join(ROOT, "reports")
        if os.path.isdir(d):
            report_index.extend(sorted(
                (os.path.join(d, f) for f in os.listdir(d) if f.endswith(".md")),
                reverse=True))
        labels = [os.path.basename(p) for p in report_index]
        report_run_menu.configure(values=labels or ["(none yet)"])
        if labels and (select_latest or report_run_var.get() not in labels):
            report_run_var.set(labels[0])

    def open_selected_report(*_):
        report_txt.configure(state="normal")
        report_txt.delete("1.0", "end")
        if not report_index:
            report_txt.insert("end", "No reports yet.\n\nReports appear in reports/ after a run "
                                      "— or run Replay against tests/make_fixtures.py output to "
                                      "produce one without any VMs.\n")
            report_txt.configure(state="disabled")
            return
        chosen = report_run_var.get()
        path = next((p for p in report_index if os.path.basename(p) == chosen), report_index[0])
        report_txt.insert("end", open(path).read())
        report_txt.configure(state="disabled")
        set_status(f"report: {os.path.basename(path)}", FG_DIM)

    report_run_menu.bind("<<ComboboxSelected>>", open_selected_report)

    def open_run_report(event):
        row = runs_tree.identify_row(event.y)
        if not row:
            return
        runs_tree.selection_set(row)
        run_id = runs_tree.item(row, "text")
        report_name = f"report_{run_id}.md"
        refresh_reports()
        nb.select(report_frame)
        if any(os.path.basename(path) == report_name for path in report_index):
            report_run_var.set(report_name)
            open_selected_report()
        else:
            report_txt.configure(state="normal")
            report_txt.delete("1.0", "end")
            report_txt.insert("end", f"No report found for run {run_id}.\n")
            report_txt.configure(state="disabled")
            set_status(f"no report for {run_id}", FG_DIM)
        return "break"

    runs_tree.bind("<Double-1>", open_run_report)

    # ev_run_var / ev_run_menu were created back in _evidence_header().

    def load_evidence(*_, select_latest=False):
        ev_txt.configure(state="normal")
        ev_txt.delete("1.0", "end")
        runs = scan_all_runs()
        run_ids = [r["run_id"] for r in runs]
        ev_run_menu.configure(values=run_ids or ["(none yet)"])
        if not runs:
            ev_txt.insert("end", "No runs recorded yet under store/.\n")
            ev_txt.configure(state="disabled")
            return
        if select_latest or ev_run_var.get() not in run_ids:
            ev_run_var.set(run_ids[0])
        run = next(r for r in runs if r["run_id"] == ev_run_var.get())
        ev_txt.insert("end", f"RUN {run['run_id']}\n" + "=" * 60 + "\n\n")
        cases_dir = os.path.join(run["dir"], "cases")
        if not os.path.isdir(cases_dir):
            ev_txt.insert("end", "no cases/ directory\n")
            ev_txt.configure(state="disabled")
            return
        for cid in sorted(os.listdir(cases_dir)):
            cdir = os.path.join(cases_dir, cid)
            v = run["verdicts"].get(cid, {})
            verdict, reason = v.get("verdict", "?"), (v.get("reason") or "")[:160]
            tag = "ok" if verdict == "detected" else (
                "bad" if verdict in ("silent", "tamper_positive") else None)
            ev_txt.insert("end", f"{cid}\n", tag)
            ev_txt.insert("end", f"   verdict : {verdict.upper()}\n",
                          "purple" if verdict == "tamper_positive" else tag)
            if reason:
                ev_txt.insert("end", f"   reason  : {reason}\n")
            for rel in ("exec.jsonl", "normalized/events.jsonl", "findings.jsonl", "raw"):
                p = os.path.join(cdir, rel)
                if os.path.exists(p):
                    ev_txt.insert("end", f"   {rel:<26} {p}\n", "dim")
            ev_txt.insert("end", "\n")
        ev_txt.configure(state="disabled")

    analysis_files = {
        "exec.jsonl": ("exec.jsonl",),
        "normalized/events.jsonl": ("normalized", "events.jsonl"),
        "findings.jsonl": ("findings.jsonl",),
    }

    def set_analysis_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def load_analysis_source(*_):
        runs = scan_all_runs()
        run = next((item for item in runs if item["run_id"] == analysis_run_var.get()), None)
        case_id = analysis_case_var.get()
        source = analysis_source_var.get()
        if run is None or not case_id or source not in analysis_files:
            set_analysis_text(analysis_viewer, "Not available")
            return
        case_dir = os.path.join(run["dir"], "cases", case_id)
        path = os.path.join(case_dir, *analysis_files[source])
        if (os.path.islink(run["dir"]) or os.path.islink(case_dir)
                or os.path.islink(path) or not os.path.isfile(path)):
            set_analysis_text(analysis_viewer, "Not available")
            return
        try:
            with open(path, "rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            if b"\0" in raw[:8192]:
                text = "Binary content is not available in this text viewer."
            else:
                text = raw[:1024 * 1024].decode("utf-8", errors="replace")
                if len(raw) > 1024 * 1024:
                    text += "\n\n[Display limited to 1 MiB. Source file was not modified.]"
        except OSError:
            text = "Not available"
        set_analysis_text(analysis_viewer, text or "Not available")

    def load_analysis_case(*_):
        runs = scan_all_runs()
        run = next((item for item in runs if item["run_id"] == analysis_run_var.get()), None)
        case_id = analysis_case_var.get()
        if run is None or not case_id:
            set_analysis_text(analysis_summary, "Select a run and case to view its evidence.")
            analysis_source_menu.configure(values=list(analysis_files))
            analysis_source_var.set("exec.jsonl")
            set_analysis_text(analysis_viewer, "Not available")
            return

        case_dir = os.path.join(run["dir"], "cases", case_id)
        if (os.path.islink(run["dir"]) or os.path.islink(case_dir)
                or not os.path.isdir(case_dir)):
            set_analysis_text(analysis_summary,
                              f"Case ID: {case_id}\nRun: {run['run_id']}\n"
                              "Evidence files found: Not available")
            analysis_source_menu.configure(values=list(analysis_files))
            if analysis_source_var.get() not in analysis_files:
                analysis_source_var.set("exec.jsonl")
            set_analysis_text(analysis_viewer, "Not available")
            return

        score = {}
        score_path = os.path.join(case_dir, "score.json")
        if not os.path.islink(score_path):
            try:
                with open(score_path, encoding="utf-8") as stream:
                    loaded = json.load(stream)
                if isinstance(loaded, dict):
                    score = loaded
            except (OSError, ValueError):
                pass
        verdict_data = run.get("verdicts", {}).get(case_id, {})
        verdict = score.get("verdict", verdict_data.get("verdict")) or "Not available"
        reason = score.get("reason", verdict_data.get("reason")) or "Not available"
        available = []
        for name, parts in analysis_files.items():
            path = os.path.join(case_dir, *parts)
            if not os.path.islink(path) and os.path.isfile(path):
                available.append(name)
        lines = [
            f"Case ID: {case_id}",
            f"Verdict: {verdict}",
            f"Reason: {reason}",
            f"Evidence files found: {', '.join(available) if available else 'None'}",
            f"Number of evidence files: {len(available)}",
            f"exec.jsonl: {'Available' if 'exec.jsonl' in available else 'Not available'}",
            ("normalized/events.jsonl: "
             f"{'Available' if 'normalized/events.jsonl' in available else 'Not available'}"),
            f"findings.jsonl: {'Available' if 'findings.jsonl' in available else 'Not available'}",
        ]
        set_analysis_text(analysis_summary, "\n".join(lines))
        analysis_source_menu.configure(values=list(analysis_files))
        current_source = analysis_source_var.get()
        if current_source not in available:
            current_source = available[0] if available else "exec.jsonl"
            analysis_source_var.set(current_source)
        load_analysis_source()

    def refresh_analysis(*_, select_latest=False):
        previous_run = "" if select_latest else analysis_run_var.get()
        previous_case = analysis_case_var.get()
        runs = scan_all_runs()
        run_ids = [run["run_id"] for run in runs]
        analysis_run_menu.configure(values=run_ids or ["(none yet)"])
        if not runs:
            analysis_run_var.set("")
            analysis_case_menu.configure(values=[])
            analysis_case_var.set("")
            analysis_source_menu.configure(values=list(analysis_files))
            analysis_source_var.set("exec.jsonl")
            set_analysis_text(analysis_summary, "No runs recorded yet under store/.")
            set_analysis_text(analysis_viewer, "Not available")
            return
        selected_run = (run_ids[0] if select_latest or previous_run not in run_ids
                else previous_run)
        analysis_run_var.set(selected_run)
        run = next(item for item in runs if item["run_id"] == selected_run)
        cases_dir = os.path.join(run["dir"], "cases")
        case_ids = []
        if not os.path.islink(cases_dir) and os.path.isdir(cases_dir):
            try:
                case_ids = sorted(name for name in os.listdir(cases_dir)
                                  if not os.path.islink(os.path.join(cases_dir, name))
                                  and os.path.isdir(os.path.join(cases_dir, name)))
            except OSError:
                pass
        analysis_case_menu.configure(values=case_ids or ["(none available)"])
        if not case_ids:
            analysis_case_var.set("")
            analysis_source_menu.configure(values=list(analysis_files))
            analysis_source_var.set("exec.jsonl")
            set_analysis_text(analysis_summary, f"Run: {selected_run}\nNo cases available.")
            set_analysis_text(analysis_viewer, "Not available")
            return
        selected_case = previous_case if previous_case in case_ids else case_ids[0]
        analysis_case_var.set(selected_case)
        load_analysis_case()

    analysis_run_menu.bind("<<ComboboxSelected>>", refresh_analysis)
    analysis_case_menu.bind("<<ComboboxSelected>>", load_analysis_case)
    analysis_source_menu.bind("<<ComboboxSelected>>", load_analysis_source)
    refresh_analysis()

    ev_run_menu.bind("<<ComboboxSelected>>", load_evidence)

    def refresh_selected_tab(_event=None):
        try:
            tab_text = nb.tab(nb.select(), "text")
        except tk.TclError:
            return
        if tab_text == "Report":
            refresh_reports()
            open_selected_report()
        elif tab_text == "Evidence":
            load_evidence()
        elif tab_text == "Setup":
            render_setup()
        elif tab_text == "Dashboard":
            render_dashboard()
        elif tab_text == "Rules":
            render_rules_list()

    nb.bind("<<NotebookTabChanged>>", refresh_selected_tab)

    # ------------------------------------------------------------------ #
    # actions
    # ------------------------------------------------------------------ #
    def py() -> str:
        return sys.executable or "python3"

    def do_preflight_static():
        run(["bash", "tools/preflight.sh", "--quick"], "preflight (static)")

    def do_preflight_iso():
        run(["bash", "tools/preflight.sh", "--isolation-only"], "preflight (isolation)")

    def do_self_test():
        run(["make", "self-test"], "self-test")

    def do_manifest():
        run(["bash", "tools/manifest.sh", "--write", "--with-tests"], "manifest")

    def do_rules():
        run([py(), "tools/minisiem/engine.py", "--check-rules"], "rules check")

    def do_list():
        run([py(), "harness/run_all.py", "--list"], "case discovery")

    def do_dry_run():
        run([py(), "harness/run_all.py", "--dry-run", "--skip-preflight"], "dry run")

    def do_replay():
        d = filedialog.askdirectory(
            title="Directory of recorded evidence (tests/make_fixtures.py --out ...)",
            initialdir=os.path.join(ROOT, "tests"))
        if not d:
            return
        run([py(), "harness/run_all.py", "--offline", d], f"replay {os.path.basename(d)}")

    def do_run_case():
        sel = case_tree.selection()
        if not sel:
            messagebox.showinfo("No case", "Select a case on the left first.")
            return
        if not env["lab_pass"]:
            messagebox.showwarning(
                "LAB_PASS not set",
                "Scored runs need the victim credential.\n\n"
                "Set it in the terminal you launched this from:\n\n"
                "  export LAB_PASS='…'      (bash / VS Code terminal)\n"
                "  $env:LAB_PASS='…'        (PowerShell)\n\n"
                "Then restart this console so it inherits the variable. It is deliberately "
                "not a field in this GUI — a credential typed into a GUI ends up in shell "
                "history files and screenshots.")
            return
        if not messagebox.askyesno(
                "Run case",
                f"Run {sel[0]} against the victim VM?\n\n"
                f"This reverts the VM to the baseline snapshot, executes the payload, waits the "
                f"capture window, then reverts again. It takes minutes, not seconds."):
            return
        argv = [py(), "harness/run_all.py", "--case", sel[0]]
        if skip_preflight_var.get():
            argv.append("--skip-preflight")
        if run(argv, f"run {sel[0]}"):
            nb.select(log_frame)

    def do_run_suite():
        suite = suite_var.get()
        if suite == "all":
            messagebox.showinfo("Pick a suite", "Choose windows, linux or baseline in the "
                                                 "dropdown first — 'all' would run every case, "
                                                 "including ones that need the C2 running.")
            return
        if not env["lab_pass"]:
            messagebox.showwarning("LAB_PASS not set", "Scored runs need the victim credential.")
            return
        if not messagebox.askyesno("Run suite", f"Run every case in '{suite}'?\n\n"
                                                  f"Cases run strictly serially and each one "
                                                  f"reverts the VM twice. A full suite takes a "
                                                  f"while."):
            return
        argv = [py(), "harness/run_all.py", "--suite", suite]
        if skip_preflight_var.get():
            argv.append("--skip-preflight")
        run(argv, f"run {suite}")

    def do_add_payload():
        if runner.busy:
            messagebox.showinfo("Runner busy", "Wait for the current action to finish before adding a case.")
            return
        try:
            import yaml
        except ImportError:
            messagebox.showerror("PyYAML required", "Install the project requirements before adding cases.")
            return

        dialog = tk.Toplevel(root)
        dialog.title("Add Payload")
        dialog.transient(root)
        dialog.geometry("900x700")
        dialog.minsize(760, 600)

        content = ttk.Frame(dialog, padding=12)
        content.pack(fill="both", expand=True)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(9, weight=1)
        ttk.Label(
            content,
            text=("This copies files into the repository only. Nothing is transferred to a victim "
                "or executed. "
                  "Review the command and side-effect expectation below. Running the case "
                  "later still uses the existing confirmation."),
            style="Dim.TLabel", wraplength=850, justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        os_var = tk.StringVar(value="Windows")
        case_id_var = tk.StringVar()
        title_var = tk.StringVar()
        payload_path_var = tk.StringVar()
        storage_var = tk.StringVar(value="staging")
        telemetry_var = tk.StringVar()
        rules_var = tk.StringVar()
        summary_var = tk.StringVar(value="Choose a payload file to see its destination.")
        case_id_auto = {"value": True}

        def form_row(row, label, widget):
            ttk.Label(content, text=label, style="Dim.TLabel").grid(
                row=row, column=0, sticky="w", padx=(0, 10), pady=4)
            widget.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4)

        def storage_directory():
            return "variants/staging" if storage_var.get() == "staging" else "payloads"

        def relative_payload_path():
            filename = os.path.basename(payload_path_var.get().strip())
            return f"{storage_directory()}/{filename}" if filename else ""

        def remote_paths(case_id, filename):
            if os_var.get() == "Windows":
                return (f"C:\\lab\\in\\{filename}",
                        f"C:\\lab\\artifacts\\{case_id}.marker")
            return (f"/tmp/{filename}", f"/opt/edrlab/artifacts/{case_id}.marker")

        def generate_yaml_preview():
            case_id = case_id_var.get().strip()
            title = title_var.get().strip()
            source = payload_path_var.get().strip()
            filename = os.path.basename(source)
            if not safe_name(case_id):
                messagebox.showerror("Invalid case ID",
                                     "Use letters, numbers, dots, underscores, and hyphens only; '..' is not allowed.",
                                     parent=dialog)
                return False
            if not title:
                messagebox.showerror("Missing title", "Enter a case title.", parent=dialog)
                return False
            if (not source or os.path.islink(source) or not os.path.isfile(source)
                    or not safe_name(filename)):
                messagebox.showerror("Invalid payload", "Choose a regular, non-symlink file with a safe filename.", parent=dialog)
                return False

            suite = "windows" if os_var.get() == "Windows" else "linux"
            transport = "winrm" if suite == "windows" else "ssh"
            remote_path, marker_path = remote_paths(case_id, filename)
            data = {
                "id": case_id,
                "title": title,
                "phase": 5,
                "os": suite,
                "payload": os.path.splitext(filename)[0],
                "stages": [
                    {"name": "stage", "transport": transport,
                     "copy": {"from": relative_payload_path(), "to": remote_path}},
                    {"name": "execute", "transport": transport,
                     "command": default_command(remote_path, marker_path, case_id),
                     "expect_exit": 0, "sleep_after_s": 4},
                ],
                "expect_side_effect": {"type": "file", "path": marker_path},
                "assert": {"logged_if_any": [s.strip() for s in telemetry_var.get().split(",")
                                               if s.strip()],
                           "detected_rule": [s.strip() for s in rules_var.get().split(",")
                                             if s.strip()],
                           "max_findings": 8},
                "teardown": {"revert_snapshot": "baseline-clean",
                             "remove_paths": [remote_path, marker_path]},
                "notes": ("Review the command and marker behavior for this payload. "
                          "Saving does not execute or transfer it to a victim."),
            }
            yaml_text.configure(state="normal")
            yaml_text.delete("1.0", "end")
            yaml_text.insert("1.0", yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
            return True

        def suggested_case_id(os_name, source):
            prefix = "W" if os_name == "Windows" else "L"
            used = []
            for path in probe_cases():
                stem = os.path.splitext(os.path.basename(path))[0]
                match = re.match(rf"^{prefix}(\d+)-", stem)
                if match:
                    used.append(int(match.group(1)))
            number = max(used, default=0) + 1
            stem = os.path.splitext(os.path.basename(source))[0].lower()
            slug = re.sub(r"[^a-z0-9]+", "-", stem).strip("-") or "payload"
            return f"{prefix}{number:02d}-{slug[:48].rstrip('-')}"

        def default_command(remote_path, marker_path, case_id):
            extension = os.path.splitext(payload_path_var.get())[1].lower()
            if os_var.get() == "Windows":
                quoted = f'"{remote_path}"'
                if extension == ".py":
                    return (f'"C:\\Python312\\python.exe" {quoted} --case {case_id} '
                            f'--marker "{marker_path}"')
                if extension in (".cmd", ".bat"):
                    return f'call {quoted} --case {case_id} --marker "{marker_path}"'
                if extension == ".ps1":
                    return (f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File {quoted} '
                            f'-Case {case_id} -Marker "{marker_path}"')
                if extension == ".js":
                    return f'wscript.exe //B {quoted}'
                return f'{quoted} --case {case_id} --marker "{marker_path}"'
            quoted = shlex.quote(remote_path)
            if extension == ".py":
                return f"python3 {quoted} --case {case_id} --marker {shlex.quote(marker_path)}"
            if extension == ".sh":
                return f"sh {quoted} --case {case_id} --marker {shlex.quote(marker_path)}"
            return (f"chmod +x {quoted} && {quoted} --case {case_id} "
                    f"--marker {shlex.quote(marker_path)}")

        def update_summary(*_):
            filename = os.path.basename(payload_path_var.get().strip())
            case_id = case_id_var.get().strip()
            suite = "windows" if os_var.get() == "Windows" else "linux"
            if filename and case_id:
                summary_var.set(
                    f"Payload: {relative_payload_path()}    "
                    f"Case: harness/cases/{suite}/{case_id}.yml")
            else:
                summary_var.set("Choose a payload file and enter a case ID to see destinations.")

        for variable in (os_var, case_id_var, payload_path_var, storage_var):
            variable.trace_add("write", update_summary)

        def safe_name(value):
            return (bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value))
                    and value not in (".", "..") and ".." not in value)

        def generate_yaml_preview():
            case_id = case_id_var.get().strip()
            title = title_var.get().strip()
            source = payload_path_var.get().strip()
            filename = os.path.basename(source)
            if not safe_name(case_id):
                messagebox.showerror("Invalid case ID",
                                     "Use letters, numbers, dots, underscores, and hyphens only; '..' is not allowed.",
                                     parent=dialog)
                return False
            if not title:
                messagebox.showerror("Missing title", "Enter a case title.", parent=dialog)
                return False
            if (not source or os.path.islink(source) or not os.path.isfile(source)
                    or not safe_name(filename)):
                messagebox.showerror(
                    "Invalid payload",
                    "Choose a regular, non-symlink file with a filename containing only letters, numbers, dots, underscores, or hyphens.",
                    parent=dialog)
                return False

            suite = "windows" if os_var.get() == "Windows" else "linux"
            transport = "winrm" if suite == "windows" else "ssh"
            remote_path, marker_path = remote_paths(case_id, filename)
            data = {
                "id": case_id,
                "title": title,
                "phase": 5,
                "os": suite,
                "payload": os.path.splitext(filename)[0],
                "stages": [
                    {"name": "stage", "transport": transport,
                     "copy": {"from": relative_payload_path(), "to": remote_path}},
                    {"name": "execute", "transport": transport,
                     "command": default_command(remote_path, marker_path, case_id),
                     "expect_exit": 0, "sleep_after_s": 4},
                ],
                "expect_side_effect": {"type": "file", "path": marker_path},
                "assert": {"logged_if_any": [s.strip() for s in telemetry_var.get().split(",")
                                               if s.strip()],
                           "detected_rule": [s.strip() for s in rules_var.get().split(",")
                                             if s.strip()],
                           "max_findings": 8},
                "teardown": {"revert_snapshot": "baseline-clean",
                             "remove_paths": [remote_path, marker_path]},
                "notes": ("Review the command and marker behavior for this payload. "
                          "Saving does not execute or transfer it to a victim."),
            }
            yaml_text.configure(state="normal")
            yaml_text.delete("1.0", "end")
            yaml_text.insert("1.0", yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
            return True

        def browse_payload():
            source = filedialog.askopenfilename(parent=dialog, title="Choose payload file",
                                                initialdir=ROOT)
            if not source:
                return
            payload_path_var.set(source)
            filename = os.path.basename(source)
            if not title_var.get():
                title_var.set(os.path.splitext(filename)[0].replace("_", " "))
            if not case_id_var.get():
                case_id_var.set(suggested_case_id(os_var.get(), source))
            update_summary()
            generate_yaml_preview()

        os_menu = ttk.Combobox(content, textvariable=os_var, state="readonly",
                               values=("Windows", "Linux"), width=12)
        form_row(1, "Operating system", os_menu)
        form_row(2, "Case ID", ttk.Entry(content, textvariable=case_id_var))
        form_row(3, "Case title", ttk.Entry(content, textvariable=title_var))

        payload_row = ttk.Frame(content)
        payload_row.columnconfigure(0, weight=1)
        ttk.Entry(payload_row, textvariable=payload_path_var).grid(
            row=0, column=0, sticky="ew")
        ttk.Button(payload_row, text="Browse…", command=browse_payload).grid(
            row=0, column=1, padx=(6, 0))
        form_row(4, "Payload file", payload_row)

        storage_row = ttk.Frame(content)
        ttk.Radiobutton(storage_row, text="Case-specific staging", value="staging",
                        variable=storage_var, command=update_summary).pack(side="left")
        ttk.Radiobutton(storage_row, text="Reusable payload", value="payloads",
                        variable=storage_var, command=update_summary).pack(
                            side="left", padx=(12, 0))
        form_row(5, "Store as", storage_row)
        form_row(6, "Expected telemetry (comma-separated)",
                 ttk.Entry(content, textvariable=telemetry_var))
        form_row(7, "Detection rule IDs (optional)", ttk.Entry(content, textvariable=rules_var))
        ttk.Label(content, textvariable=summary_var, style="Dim.TLabel").grid(
            row=8, column=0, columnspan=3, sticky="w", pady=(4, 6))

        yaml_frame = ttk.Frame(content)
        yaml_frame.grid(row=9, column=0, columnspan=3, sticky="nsew")
        yaml_frame.columnconfigure(0, weight=1)
        yaml_frame.rowconfigure(1, weight=1)
        yaml_toolbar = ttk.Frame(yaml_frame)
        yaml_toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        ttk.Label(yaml_toolbar, text="CASE YAML (review/edit before saving)",
                  style="Head.TLabel").pack(side="left")
        ttk.Button(yaml_toolbar, text="Generate YAML", command=generate_yaml_preview).pack(
            side="right")
        yaml_text = tk.Text(yaml_frame, height=14, bg=BG2, fg=FG,
                            insertbackground=FG, relief="flat", wrap="none",
                            font=("TkFixedFont", 9), padx=8, pady=7,
                            selectbackground=ACCENT)
        yaml_scroll = ttk.Scrollbar(yaml_frame, orient="vertical", command=yaml_text.yview)
        yaml_text.configure(yscrollcommand=yaml_scroll.set)
        yaml_text.grid(row=1, column=0, sticky="nsew")
        yaml_scroll.grid(row=1, column=1, sticky="ns")
        yaml_text.insert("1.0", "Choose the OS and payload, then generate a case YAML.\n")

        def safe_repo_path(relative):
            root_path = os.path.realpath(ROOT)
            candidate = os.path.realpath(os.path.join(root_path, relative))
            try:
                return candidate if os.path.commonpath((root_path, candidate)) == root_path else None
            except ValueError:
                return None

        def validate_case_yaml(data, case_id, suite, planned_payload):
            if not isinstance(data, dict):
                raise ValueError("Case YAML must contain a mapping.")
            if data.get("id") != case_id:
                raise ValueError("YAML id must exactly match the case ID / filename stem.")
            if data.get("os") != suite:
                raise ValueError(f"YAML os must be {suite!r}.")
            for key in ("title", "phase", "payload", "stages", "expect_side_effect", "assert"):
                if key not in data:
                    raise ValueError(f"Missing case field: {key}")
            if not isinstance(data["title"], str) or not data["title"].strip():
                raise ValueError("title must be a non-empty string.")
            if not isinstance(data["phase"], int) or isinstance(data["phase"], bool):
                raise ValueError("phase must be an integer.")
            if not isinstance(data["payload"], str) or not data["payload"].strip():
                raise ValueError("payload must be a non-empty string.")
            if not isinstance(data["stages"], list) or not data["stages"]:
                raise ValueError("stages must be a non-empty list.")
            transport = "winrm" if suite == "windows" else "ssh"
            copy_sources = []
            has_command = False
            for index, stage in enumerate(data["stages"], 1):
                if not isinstance(stage, dict) or stage.get("transport") != transport:
                    raise ValueError(f"Every stage must use {transport!r} transport.")
                has_command = has_command or bool(stage.get("command"))
                copy_spec = stage.get("copy")
                if copy_spec:
                    if not isinstance(copy_spec, dict) or not copy_spec.get("from") or not copy_spec.get("to"):
                        raise ValueError(f"Stage {index} copy requires from and to.")
                    local_rel = str(copy_spec["from"])
                    if (os.path.isabs(local_rel) or "\\" in local_rel
                            or local_rel.startswith("../") or "/../" in f"/{local_rel}/"):
                        raise ValueError(f"Unsafe copy.from path: {local_rel}")
                    local_path = safe_repo_path(local_rel)
                    if local_path is None:
                        raise ValueError(f"copy.from escapes the repository: {local_rel}")
                    if os.path.islink(local_path):
                        raise ValueError(f"copy.from cannot be a symlink: {local_rel}")
                    remote_path = str(copy_spec["to"]).replace("\\", "/")
                    remote_parts = remote_path.split("/")
                    if ".." in remote_parts:
                        raise ValueError(f"Unsafe victim copy.to path: {copy_spec['to']}")
                    if suite == "windows":
                        if not remote_path.lower().startswith("c:/lab/in/"):
                            raise ValueError("Windows copy.to paths must stay under C:\\lab\\in\\.")
                    elif not remote_path.startswith("/tmp/"):
                        raise ValueError("Linux copy.to paths must stay under /tmp/.")
                    copy_sources.append((local_rel, local_path))
            if not has_command:
                raise ValueError("At least one stage needs a command to execute the payload.")
            if planned_payload not in [source for source, _path in copy_sources]:
                raise ValueError("A stage must copy the selected payload into the victim.")
            if not isinstance(data["expect_side_effect"], dict) or data["expect_side_effect"].get("type") not in ("file", "connection", "none"):
                raise ValueError("expect_side_effect.type must be file, connection, or none.")
            if (data["expect_side_effect"].get("type") == "file"
                    and not data["expect_side_effect"].get("path")):
                raise ValueError("A file side effect requires expect_side_effect.path.")
            assertion = data["assert"]
            if not isinstance(assertion, dict):
                raise ValueError("assert must be a mapping.")
            for key in ("logged_if_any", "detected_rule"):
                if (key not in assertion or not isinstance(assertion[key], list)
                        or any(not isinstance(value, str) for value in assertion[key])):
                    raise ValueError(f"assert.{key} must be a list of strings.")
            return copy_sources, assertion.get("detected_rule", [])

        def known_rule_ids():
            ids = set()
            for path in env["rule_files"]:
                try:
                    with open(path, encoding="utf-8") as stream:
                        for rule in yaml.safe_load_all(stream):
                            if isinstance(rule, dict) and rule.get("id"):
                                ids.add(str(rule["id"]))
                except (OSError, yaml.YAMLError):
                    continue
            return ids

        def save_payload_case():
            source = payload_path_var.get().strip()
            case_id = case_id_var.get().strip()
            title = title_var.get().strip()
            suite = "windows" if os_var.get() == "Windows" else "linux"
            filename = os.path.basename(source)
            if not safe_name(case_id):
                messagebox.showerror("Invalid case ID", "Use letters, numbers, dots, underscores, and hyphens only; '..' is not allowed.", parent=dialog)
                return
            if not title:
                messagebox.showerror("Missing title", "Enter a case title.", parent=dialog)
                return
            if (not source or os.path.islink(source) or not os.path.isfile(source)
                    or not safe_name(filename)):
                messagebox.showerror("Invalid payload", "Choose a regular, non-symlink file with a safe filename.", parent=dialog)
                return

            payload_rel = relative_payload_path()
            case_rel = f"harness/cases/{suite}/{case_id}.yml"
            payload_dest = safe_repo_path(payload_rel)
            case_dest = safe_repo_path(case_rel)
            if payload_dest is None or case_dest is None:
                messagebox.showerror("Unsafe destination", "A destination resolves outside the repository.", parent=dialog)
                return
            if os.path.lexists(payload_dest) or os.path.lexists(case_dest):
                messagebox.showerror("File exists", "The payload or case destination already exists; nothing was overwritten.", parent=dialog)
                return

            try:
                for path in probe_cases():
                    with open(path, encoding="utf-8") as stream:
                        existing = yaml.safe_load(stream)
                    if isinstance(existing, dict) and existing.get("id") == case_id:
                        raise ValueError(f"Case ID {case_id!r} is already used.")
                yaml_content = yaml_text.get("1.0", "end-1c")
                case_data = yaml.safe_load(yaml_content)
                copy_sources, rule_ids = validate_case_yaml(case_data, case_id, suite, payload_rel)
            except (OSError, yaml.YAMLError, ValueError) as exc:
                messagebox.showerror("Invalid case YAML", str(exc), parent=dialog)
                return

            missing_rules = sorted(set(rule_ids) - known_rule_ids())
            if missing_rules and not messagebox.askyesno(
                    "Rule IDs not found",
                    "These rule IDs must be created separately:\n\n" + "\n".join(missing_rules)
                    + "\n\nSave the case anyway?", parent=dialog):
                return

            root_path = os.path.realpath(ROOT)
            if any(os.path.commonpath((root_path, os.path.realpath(os.path.dirname(path)))) != root_path
                   or not os.path.isdir(os.path.dirname(path)) for path in (payload_dest, case_dest)):
                messagebox.showerror("Destination unavailable", "Target folders must exist inside the repository.", parent=dialog)
                return
            if not messagebox.askyesno(
                    "Confirm Add Payload",
                    f"Create these repository files?\n\n{payload_rel}\n{case_rel}\n\n"
                    "The payload is copied locally into the repository only. It will not be "
                    "transferred to a victim or executed.", parent=dialog):
                return

            created_payload = False
            created_case = False
            try:
                if os.path.islink(source) or not os.path.isfile(source):
                    raise ValueError("Selected payload is no longer a regular file.")
                with open(source, "rb") as input_file:
                    payload_fd = os.open(payload_dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                    created_payload = True
                    with os.fdopen(payload_fd, "wb") as output_file:
                        shutil.copyfileobj(input_file, output_file)
                for local_rel, local_path in copy_sources:
                    if os.path.islink(local_path) or not os.path.isfile(local_path):
                        raise ValueError(f"copy.from does not exist as a regular file: {local_rel}")
                case_fd = os.open(case_dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                created_case = True
                with os.fdopen(case_fd, "w", encoding="utf-8", newline="\n") as output_file:
                    output_file.write(yaml_content.rstrip() + "\n")
            except (OSError, ValueError) as exc:
                if created_case:
                    try:
                        os.unlink(case_dest)
                    except OSError:
                        pass
                if created_payload:
                    try:
                        os.unlink(payload_dest)
                    except OSError:
                        pass
                messagebox.showerror("Add Payload failed", str(exc), parent=dialog)
                return

            env["case_files"] = probe_cases()
            env["n_cases"] = len(env["case_files"])
            search_var.set("")
            suite_var.set(suite)
            reload_case_data()
            if case_tree.exists(case_id):
                case_tree.selection_set(case_id)
                case_tree.focus(case_id)
                case_tree.see(case_id)
                case_tree.event_generate("<<TreeviewSelect>>")
            render_dashboard()
            set_status(f"Added {case_id}", OK)
            dialog.destroy()
            messagebox.showinfo("Payload added", f"Created:\n{payload_rel}\n{case_rel}", parent=root)

        def refresh_case_id_for_os(_event=None):
            if payload_path_var.get() and case_id_auto["value"]:
                case_id_var.set(suggested_case_id(os_var.get(), payload_path_var.get()))
            update_summary()

        def mark_case_id_manual(_event=None):
            case_id_auto["value"] = False

        os_menu = ttk.Combobox(content, textvariable=os_var, state="readonly",
                               values=("Windows", "Linux"), width=12)
        form_row(1, "Operating system", os_menu)
        os_menu.bind("<<ComboboxSelected>>", refresh_case_id_for_os)
        id_entry = ttk.Entry(content, textvariable=case_id_var)
        form_row(2, "Case ID", id_entry)
        id_entry.bind("<KeyRelease>", mark_case_id_manual)
        form_row(3, "Case title", ttk.Entry(content, textvariable=title_var))

        payload_row = ttk.Frame(content)
        payload_row.columnconfigure(0, weight=1)
        ttk.Entry(payload_row, textvariable=payload_path_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(payload_row, text="Browse…", command=browse_payload).grid(
            row=0, column=1, padx=(6, 0))
        form_row(4, "Payload file", payload_row)

        storage_row = ttk.Frame(content)
        ttk.Radiobutton(storage_row, text="Case-specific staging", value="staging",
                        variable=storage_var, command=update_summary).pack(side="left")
        ttk.Radiobutton(storage_row, text="Reusable payload", value="payloads",
                        variable=storage_var, command=update_summary).pack(side="left", padx=(12, 0))
        form_row(5, "Store as", storage_row)
        form_row(6, "Expected telemetry (comma-separated)", ttk.Entry(content, textvariable=telemetry_var))
        form_row(7, "Detection rule IDs (optional)", ttk.Entry(content, textvariable=rules_var))
        ttk.Label(content, textvariable=summary_var, style="Dim.TLabel").grid(
            row=8, column=0, columnspan=3, sticky="w", pady=(4, 6))

        yaml_frame = ttk.Frame(content)
        yaml_frame.grid(row=9, column=0, columnspan=3, sticky="nsew")
        yaml_frame.columnconfigure(0, weight=1)
        yaml_frame.rowconfigure(1, weight=1)
        yaml_toolbar = ttk.Frame(yaml_frame)
        yaml_toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        ttk.Label(yaml_toolbar, text="CASE YAML (review/edit before saving)",
                  style="Head.TLabel").pack(side="left")
        ttk.Button(yaml_toolbar, text="Generate YAML", command=generate_yaml_preview).pack(side="right")
        yaml_text = tk.Text(yaml_frame, height=14, bg=BG2, fg=FG, insertbackground=FG,
                            relief="flat", wrap="none", font=("TkFixedFont", 9),
                            padx=8, pady=7, selectbackground=ACCENT)
        yaml_scroll = ttk.Scrollbar(yaml_frame, orient="vertical", command=yaml_text.yview)
        yaml_text.configure(yscrollcommand=yaml_scroll.set)
        yaml_text.grid(row=1, column=0, sticky="nsew")
        yaml_scroll.grid(row=1, column=1, sticky="ns")
        yaml_text.insert("1.0", "Choose the OS and payload, then generate a case YAML.\n")

        ttk.Button(content, text="Cancel", command=dialog.destroy).grid(
            row=10, column=1, sticky="e", pady=(8, 0))
        ttk.Button(content, text="Add Payload", command=save_payload_case).grid(
            row=10, column=2, sticky="e", padx=(8, 0), pady=(8, 0))
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.grab_set()
        dialog.focus_set()

    def do_open_root():
        if sys.platform == "darwin":
            subprocess.Popen(["open", ROOT])
        elif os.name == "nt":
            os.startfile(ROOT)  # noqa: S606
        else:
            subprocess.Popen(["xdg-open", ROOT])

    # ------------------------------------------------------------------ #
    # buttons
    # ------------------------------------------------------------------ #
    btns = ttk.Frame(right)
    btns.pack(fill="x")
    nb.configure(height=350)
    for column in range(2):
        btns.columnconfigure(column, weight=1)

    def shade(color, factor):
        channels = [int(color[index:index + 2], 16) for index in (1, 3, 5)]
        return "#" + "".join(f"{min(255, max(0, round(value * factor))):02x}"
                              for value in channels)

    class ModernButton(tk.Frame):
        """Compact custom button with mouse, keyboard, and ttk-like state support."""

        def __init__(self, parent, text, command, variant="secondary"):
            self._command = command
            self._variant = variant
            self._state = "normal"
            self._hovered = False
            self._pressed = False
            self._focused = False
            super().__init__(parent, bg=BG2, bd=0, relief="flat",
                             highlightthickness=1, highlightbackground=BG3,
                             highlightcolor=ACCENT, takefocus=1, cursor="hand2")
            self._label = tk.Label(
                self, text=text, bg=BG2, fg=FG, bd=0, relief="flat",
                padx=13, pady=7, font=("TkDefaultFont", 9, "bold"),
                anchor="center", cursor="hand2")
            self._label.pack(fill="both", expand=True)
            self._label.bind("<Enter>", self._on_enter)
            self._label.bind("<Leave>", self._on_leave)
            self._label.bind("<ButtonPress-1>", self._on_press)
            self._label.bind("<ButtonRelease-1>", self._on_release)
            self.bind("<FocusIn>", self._on_focus_in)
            self.bind("<FocusOut>", self._on_focus_out)
            self.bind("<KeyPress-space>", self._on_key_press)
            self.bind("<KeyRelease-space>", self._on_key_release)
            self.bind("<KeyPress-Return>", self._on_key_press)
            self.bind("<KeyRelease-Return>", self._on_key_release)
            self._render()

        def configure(self, cnf=None, **kwargs):
            if cnf == "state":
                return self._state
            if isinstance(cnf, dict):
                options = dict(cnf)
                options.update(kwargs)
                kwargs = options
                cnf = None
            state = kwargs.pop("state", None)
            result = super().configure(cnf, **kwargs)
            if state is not None:
                self._state = state
                self._pressed = False
                self._render()
            return result

        config = configure

        def cget(self, key):
            if key == "state":
                return self._state
            return super().cget(key)

        def invoke(self):
            if self._state != "disabled" and self._command:
                return self._command()
            return None

        def _render(self):
            if not hasattr(self, "_label"):
                return
            if self._state == "disabled":
                background, foreground, border = BG2, FG_DIM, BG3
            elif self._variant == "primary":
                background, foreground, border = ACCENT, BG, ACCENT
            elif self._variant == "primary-secondary":
                background, foreground, border = BG3, FG, ACCENT
            elif self._variant == "danger":
                background, foreground, border = BG2, BAD, BAD
            else:
                background, foreground, border = BG2, FG, BG3

            if self._state != "disabled":
                if self._pressed:
                    background = shade(background, 0.78)
                elif self._hovered:
                    if self._variant == "danger":
                        background, foreground = BAD, BG
                    else:
                        background = shade(background, 1.14)
                if self._focused:
                    border = ACCENT

            cursor = "hand2" if self._state == "normal" else "arrow"
            self.configure(bg=background, highlightbackground=border,
                           highlightcolor=ACCENT, cursor=cursor)
            self._label.configure(bg=background, fg=foreground, cursor=cursor)

        def _on_enter(self, _event):
            self._hovered = True
            self._render()

        def _on_leave(self, _event):
            self._hovered = False
            self._pressed = False
            self._render()

        def _on_press(self, _event):
            if self._state == "normal":
                self.focus_set()
                self._pressed = True
                self._render()
            return "break"

        def _on_release(self, event):
            was_pressed = self._pressed
            inside = (0 <= event.x < self._label.winfo_width()
                      and 0 <= event.y < self._label.winfo_height())
            self._pressed = False
            self._render()
            if was_pressed and inside:
                self.invoke()
            return "break"

        def _on_focus_in(self, _event):
            self._focused = True
            self._render()

        def _on_focus_out(self, _event):
            self._focused = False
            self._render()

        def _on_key_press(self, _event):
            if self._state == "normal":
                self._pressed = True
                self._render()
            return "break"

        def _on_key_release(self, _event):
            was_pressed = self._pressed
            self._pressed = False
            self._render()
            if was_pressed:
                self.invoke()
            return "break"

    def button_group(title, row, column):
        frame = tk.Frame(btns, bg=BG2, bd=0, highlightthickness=1,
                         highlightbackground=BG3)
        frame.grid(row=row, column=column, sticky="nsew",
                   padx=(0, 6) if column == 0 else (6, 0), pady=(0, 6))
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        heading = tk.Label(frame, text=title.upper(), bg=BG2, fg=FG_DIM,
                           font=("TkDefaultFont", 9, "bold"), anchor="w")
        heading.grid(row=0, column=0, columnspan=2, sticky="ew",
                     padx=11, pady=(8, 5))
        tk.Frame(frame, bg=BG3, height=1).grid(
            row=1, column=0, columnspan=2, sticky="ew", padx=10)
        return frame

    def add_action(parent, label, command, row, column):
        button = ModernButton(parent, label, command)
        button.grid(row=row, column=column, sticky="ew",
                    padx=(8, 4) if column == 0 else (4, 8), pady=(6, 0))
        action_buttons.append(button)
        return button

    def select_page(title):
        for tab in nb.tabs():
            if nb.tab(tab, "text") == title:
                nb.select(tab)
                return

    def route_action(command, page):
        def invoke():
            if page == "Cases":
                case_tree.focus_set()
            elif page:
                select_page(page)
            return command()
        return invoke

    def stop_and_show_log():
        select_page("Run log")
        return runner.stop()

    run_group = tk.Frame(btns, bg=BG2, bd=0, highlightthickness=1,
                         highlightbackground=BG3)
    run_group.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))
    run_header = tk.Label(run_group, text="RUN", bg=BG2, fg=ACCENT,
                          font=("TkDefaultFont", 9, "bold"), anchor="w")
    run_header.pack(fill="x", padx=12, pady=(8, 4))
    run_controls = tk.Frame(run_group, bg=BG2)
    run_controls.pack(fill="x", padx=10, pady=(0, 9))
    run_controls.columnconfigure(0, weight=2)
    skip_preflight_var = tk.BooleanVar(value=False)
    run_controls.columnconfigure(1, weight=1)
    run_case_btn = ModernButton(run_controls, "▶  Run selected case", do_run_case, "primary")
    run_case_btn.grid(row=0, column=0, sticky="ew", padx=(0, 7))
    run_suite_btn = ModernButton(run_controls, "▶  Run suite",
                                 route_action(do_run_suite, "Run log"),
                                 "primary-secondary")
    run_suite_btn.grid(row=0, column=1, sticky="ew", padx=(0, 7))
    stop_btn = ModernButton(run_controls, "■  Stop", stop_and_show_log, "danger")
    stop_btn.grid(row=0, column=2, sticky="ew", padx=(0, 12))
    skip_preflight_cb = ttk.Checkbutton(
        run_controls, text="Skip preflight", variable=skip_preflight_var)
    skip_preflight_cb.grid(row=0, column=3, sticky="e", padx=(4, 2))
    action_buttons.extend((run_case_btn, run_suite_btn))

    checks_group = button_group("Lab & workspace", 1, 0)
    for index, (label, fn) in enumerate((
            ("Preflight (static)", do_preflight_static),
            ("Preflight (isolation)", do_preflight_iso),
            ("Self-test", do_self_test),
            ("Rules check", do_rules),
            ("Manifest", do_manifest),
            ("Open repo folder", do_open_root))):
        page = None if label == "Open repo folder" else "Run log"
        add_action(checks_group, label,
               route_action(fn, page) if page else fn,
               2 + index // 2, index % 2)

    evidence_group = button_group("Evidence & cases", 1, 1)
    for index, (label, fn) in enumerate((
            ("Replay evidence…", do_replay),
            ("Dry run", do_dry_run),
            ("List cases", do_list),
            ("Add Payload…", do_add_payload),
            ("Refresh dashboard", render_dashboard),
            ("Reload cases", reload_case_data))):
        page = {"Refresh dashboard": "Dashboard", "Reload cases": "Cases"}.get(label)
        add_action(evidence_group, label, route_action(fn, page),
                   2 + index // 2, index % 2)

    reasons = []
    if env["missing"]:
        reasons.append("repo files missing")
    if not env["lab_pass"]:
        reasons.append("LAB_PASS not set")
    if not env["isolation"]:
        reasons.append("isolation not verified")
    blocked_reason = ", ".join(reasons)
    if blocked_reason:
        run_case_btn.configure(state="disabled")
        run_suite_btn.configure(state="disabled")
        ttk.Label(run_group, text=f"Scored runs disabled: {blocked_reason}",
                  style="Dim.TLabel", wraplength=700).pack(anchor="w", padx=12,
                                                           pady=(0, 8))

    set_status(f"{env['n_cases']} cases · {env['n_rules']} rules · "
               f"{'cred set' if env['lab_pass'] else 'no credential'}", FG_DIM)

    log_txt.insert("end",
                    "EDR Lab console\n"
                    "===============\n\n"
                    "Every button runs the same entry point the Makefile does. The GUI decides\n"
                    "nothing: verdicts come from harness/score.py, the report from "
                    "harness/report.py.\n\n"
                    "Open the Setup tab for what this machine can and cannot do, or Dashboard for\n"
                    "how every run so far has gone, then:\n"
                    "  1. Preflight (static)   2. Self-test   3. Replay evidence…\n\n"
                    "A case with no marker file scores inconclusive — that is a broken test, not a\n"
                    "sensor gap. Check the Evidence tab before you blame a rule.\n")
    log_txt.configure(state="disabled")

    root.lab_widgets = {
        "notebook": nb, "case_tree": case_tree, "log": log_txt,
        "report": report_txt, "evidence": ev_txt, "setup": setup_txt,
        "dashboard": dash_frame, "rules": rules_frame,
        "case_info": case_info, "status": status, "runner": runner,
        "run_case_btn": run_case_btn, "run_suite_btn": run_suite_btn,
        "reload_cases": reload_case_data, "analysis_runs": analysis_run_menu,
        "analysis_cases": analysis_case_menu, "analysis_sources": analysis_source_menu,
        "analysis_summary": analysis_summary, "analysis_viewer": analysis_viewer,
        "refresh_analysis": refresh_analysis,
    }
    return root


# =========================================================================== #
def main() -> int:
    if "--check" in sys.argv:
        env = probe_environment()
        print("EDR Lab — environment check")
        print(f"  repo root   {env['root']}")
        print(f"  python      {env['python']}")
        print(f"  cases       {env['n_cases']}")
        print(f"  rules       {env['n_rules']}")
        print(f"  PyYAML      {'yes' if env['has_yaml'] else 'NO'}")
        print(f"  LAB_PASS    {'set' if env['lab_pass'] else 'not set'}")
        print(f"  isolation   {env['isolation'] or 'not verified'}")
        for p in env["problems"]:
            print(f"  BLOCKING    {p}")
        for w in env["warnings"]:
            print(f"  warning     {w}")
        try:
            import tkinter  # noqa: F401
            print("  tkinter     available")
        except ImportError as exc:
            print(f"  tkinter     MISSING ({exc})")
            print("              Linux: sudo apt install python3-tk")
            print("              macOS/Windows: use a python.org build, which bundles it")
            return 2
        if env["missing"]:
            return 1
        print("\nOK — run: python3 lab_gui.py")
        return 0

    if not os.path.exists(os.path.join(ROOT, "harness", "run_all.py")):
        print(f"lab_gui.py must sit at the repo root; harness/run_all.py not found under {ROOT}",
              file=sys.stderr)
        return 2
    try:
        root = build_app()
    except ImportError:
        print("tkinter is not available.\n"
              "  Linux:   sudo apt install python3-tk\n"
              "  Windows: reinstall Python from python.org with 'tcl/tk and IDLE' selected\n"
              "  macOS:   use a python.org build (the Xcode-bundled python has no tkinter)",
              file=sys.stderr)
        return 2
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
