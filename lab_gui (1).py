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

    ttk.Label(left, text="CASES", style="Head.TLabel").pack(anchor="w")
    filt = ttk.Frame(left)
    filt.pack(fill="x", pady=(6, 6))
    suite_var = tk.StringVar(value="all")
    ttk.Combobox(filt, textvariable=suite_var, state="readonly", width=10,
                 values=["all", "windows", "linux", "baseline"]).pack(side="left")
    search_var = tk.StringVar()
    ttk.Entry(filt, textvariable=search_var, width=16).pack(side="left", padx=(6, 0), fill="x",
                                                             expand=True)

    case_tree = ttk.Treeview(left, columns=("suite", "phase", "last"), show="tree headings",
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

    case_info = tk.Text(left, height=7, bg=BG2, fg=FG_DIM, insertbackground=FG,
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
        card = tk.Frame(parent, bg=BG2)
        card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 8, 0))
        parent.grid_columnconfigure(col, weight=1)
        value_lbl = tk.Label(card, text="—", bg=BG2, fg=FG,
                              font=("TkDefaultFont", 20, "bold"))
        value_lbl.pack(anchor="w", padx=12, pady=(10, 0))
        caption_lbl = tk.Label(card, text="", bg=BG2, fg=FG_DIM, font=("TkDefaultFont", 9))
        caption_lbl.pack(anchor="w", padx=12, pady=(0, 10))
        return value_lbl, caption_lbl

    card_cases_val, card_cases_cap = stat_card(dash_cards, 0)
    card_rules_val, card_rules_cap = stat_card(dash_cards, 1)
    card_runs_val, card_runs_cap = stat_card(dash_cards, 2)
    card_rate_val, card_rate_cap = stat_card(dash_cards, 3)

    ttk.Label(dash_frame, text="VERDICTS ACROSS ALL RUNS", style="Head.TLabel").pack(
        anchor="w", padx=10, pady=(8, 4))
    dash_verdict_frame = ttk.Frame(dash_frame)
    dash_verdict_frame.pack(fill="x", padx=10, pady=(0, 10))

    ttk.Label(dash_frame, text="RECENT RUNS  (⚠ = silent or tamper_positive present)",
              style="Head.TLabel").pack(anchor="w", padx=10, pady=(4, 4))
    runs_tree = ttk.Treeview(
        dash_frame, columns=("cases", "detected", "issues", "when"),
        show="tree headings", selectmode="browse", height=12)
    runs_tree.heading("#0", text="run")
    runs_tree.heading("cases", text="cases")
    runs_tree.heading("detected", text="detected")
    runs_tree.heading("issues", text="issues")
    runs_tree.heading("when", text="when")
    runs_tree.column("#0", width=140)
    runs_tree.column("cases", width=70, anchor="center")
    runs_tree.column("detected", width=80, anchor="center")
    runs_tree.column("issues", width=80, anchor="center")
    runs_tree.column("when", width=160, anchor="center")
    runs_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    runs_tree.tag_configure("attention", foreground=BAD)

    def render_dashboard():
        runs = scan_all_runs()
        counts = tally_verdicts(runs)
        total_scored = sum(counts.values())
        detected = counts.get("detected", 0)

        card_cases_val.configure(text=str(env["n_cases"]))
        card_cases_cap.configure(text="cases defined")
        card_rules_val.configure(text=str(env["n_rules"]))
        card_rules_cap.configure(text="rules loaded")
        card_runs_val.configure(text=str(len(runs)))
        card_runs_cap.configure(text="runs recorded")
        if total_scored:
            rate = 100 * detected / total_scored
            card_rate_val.configure(text=f"{rate:.0f}%", fg=OK if rate >= 50 else BAD)
            card_rate_cap.configure(text=f"detected ({total_scored} scored cases)")
        else:
            card_rate_val.configure(text="—", fg=FG)
            card_rate_cap.configure(text="no scored cases yet")

        for child in dash_verdict_frame.winfo_children():
            child.destroy()
        if not counts:
            tk.Label(dash_verdict_frame, text="no runs recorded under store/ yet",
                     bg=BG, fg=FG_DIM, font=("TkFixedFont", 9)).pack(anchor="w")
        else:
            for verdict in ("detected", "logged_no_rule", "silent", "tamper_positive",
                             "inconclusive", "dry_run"):
                n = counts.get(verdict, 0)
                if n == 0:
                    continue
                row = tk.Frame(dash_verdict_frame, bg=BG)
                row.pack(fill="x", pady=1)
                tk.Label(row, text=verdict, bg=BG, fg=VERDICT_COLOUR[verdict],
                         font=("TkFixedFont", 10, "bold"), width=18, anchor="w").pack(side="left")
                tk.Label(row, text=str(n), bg=BG, fg=FG, font=("TkFixedFont", 10)).pack(
                    side="left")

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
            ("Refresh dashboard", render_dashboard),
            ("Reload cases", reload_case_data))):
        page = {"Refresh dashboard": "Dashboard", "Reload cases": "Cases"}.get(
            label, "Run log")
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
        "reload_cases": reload_case_data,
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
