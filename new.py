#!/usr/bin/env python3
"""
lab_gui.py — a Tkinter console for the EDR lab. Standard library only.

    python3 lab_gui.py            # launch
    python3 lab_gui.py --check    # verify the environment without opening a window

WHY A GUI AND NOT JUST THE MAKEFILE
    The Makefile is the right interface for a scripted run. It is a poor one for
    the question you will actually ask forty times a day — "what happened in
    W05, and why is it TAMPER_POSITIVE?" — because answering it means reading a
    report, then opening the case directory, then grepping the findings. This
    window puts the case list, the command output, the report and the evidence
    paths in one place.

WHAT IT IS NOT
    It is not a second implementation of anything. Every button shells out to
    the same entry points the Makefile calls — harness/run_all.py,
    tools/preflight.sh, tools/isolation_check.py. If a button and the
    command line disagree, the GUI is wrong, not the harness. Nothing here
    writes evidence, scores anything, or decides a verdict.

WHY IT STARTS IN A DEGRADED, HONEST STATE
    Most of these buttons need the hypervisor host. If you open this on a
    laptop that cannot reach the VMs, it does not pretend otherwise: the victim
    buttons disable themselves, the status bar says why, and the offline
    buttons (replay, self-test, case discovery) stay live because they work
    anywhere. A GUI that offers a Run button it cannot honour is worse than no
    GUI, because you learn to distrust all of them.
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

VERDICT_COLOUR = {
    "detected": OK,
    "logged_no_rule": WARN,
    "silent": BAD,
    "tamper_positive": "#c586c0",
    "inconclusive": FG_DIM,
    "dry_run": FG_DIM,
}


# =========================================================================== #
# environment probing
# =========================================================================== #
def which_all(*names: str) -> dict[str, str | None]:
    return {n: shutil.which(n) for n in names}


def probe_environment() -> dict:
    """Work out what this machine can actually do. Runs no case, touches no VM."""
    env: dict = {
        "root": ROOT,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "tools": which_all("vmrun", "ansible-playbook", "git"),
        "lab_pass": bool(os.environ.get("LAB_PASS")),
        "problems": [],
        "warnings": [],
    }

    env["has_yaml"] = False
    try:
        import yaml  # noqa: F401
        env["has_yaml"] = True
    except ImportError:
        env["problems"].append("PyYAML missing — most of the harness cannot run. "
                               "pip install -r requirements.txt")

    # The harness is the thing being driven; if it is absent, nothing works.
    required = [
        "harness/run_all.py", "harness/score.py", "harness/report.py",
        "tools/preflight.sh", "tools/isolation_check.py", "tools/minisiem/engine.py",
        "Makefile",
    ]
    env["missing"] = [r for r in required if not os.path.exists(os.path.join(ROOT, r))]
    if env["missing"]:
        env["problems"].append(f"{len(env['missing'])} required file(s) missing — "
                               f"is this the repo root? see the Setup tab")

    # Optional transports: absence only downgrades, never blocks the offline work.
    for mod, label in (("winrm", "pywinrm"), ("paramiko", "paramiko")):
        try:
            __import__(mod)
            env.setdefault("transports", {})[label] = True
        except ImportError:
            env.setdefault("transports", {})[label] = False

    if not any((env.get("transports") or {}).values()):
        env["warnings"].append("neither pywinrm nor paramiko installed — offline modes only")

    # Cases and rules: cheap to count, and a zero is a loud signal.
    cases_dir = os.path.join(ROOT, "harness", "cases")
    env["case_files"] = []
    if os.path.isdir(cases_dir):
        for suite in ("windows", "linux", "baseline"):
            d = os.path.join(cases_dir, suite)
            if os.path.isdir(d):
                env["case_files"] += [os.path.join(d, f) for f in sorted(os.listdir(d))
                                      if f.endswith(".yml") and not f.startswith("_")]
    env["n_cases"] = len(env["case_files"])

    rules_dir = os.path.join(ROOT, "rules")
    n_rules = 0
    if os.path.isdir(rules_dir):
        for sub in ("windows", "linux"):
            d = os.path.join(rules_dir, sub)
            if not os.path.isdir(d):
                continue
            for f in os.listdir(d):
                if f.endswith((".yml", ".yaml")) and not f.startswith("_"):
                    try:
                        text = open(os.path.join(d, f)).read()
                        n_rules += len(re.findall(r"^id:\s*\S+", text, re.M))
                    except OSError:
                        pass
    env["n_rules"] = n_rules

    # Isolation evidence: run_all.py refuses a scored run without it, so the GUI
    # must surface the same fact rather than letting the user discover it at
    # the point of clicking Run.
    iso_root = os.path.join(ROOT, "store", "_isolation")
    env["isolation"] = None
    if os.path.isdir(iso_root):
        entries = sorted(os.listdir(iso_root))
        if entries:
            newest = entries[-1]
            env["isolation"] = {
                "dir": newest,
                "age_days": int((time.time() - os.path.getmtime(
                    os.path.join(iso_root, newest))) / 86400),
            }
    if env["isolation"] is None:
        env["warnings"].append("no isolation evidence yet — run Preflight (isolation) "
                               "before any scored run")

    return env


# =========================================================================== #
# subprocess runner that never blocks the UI
# =========================================================================== #
class Runner:
    """Runs commands on a worker thread and streams output to a queue.

    A GUI that freezes on a 60-second capture window looks broken, and the
    natural reaction is to click Run again — which, for this harness, would
    start a SECOND case against the same VMs and produce evidence from two
    interleaved runs. So everything long-running goes through here, and the
    Run button is disabled while anything is in flight.
    """

    def __init__(self, on_line, on_done):
        self.on_line = on_line
        self.on_done = on_done
        self.proc: subprocess.Popen | None = None
        self.busy = False
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
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        if env_extra:
            env.update(env_extra)

        self._thread = threading.Thread(
            target=self._run, args=(argv, label, cwd or ROOT, env), daemon=True)
        self._thread.start()
        return True

    def _run(self, argv, label, cwd, env):
        # NOTE: this runs on a worker thread. It must not touch a widget, not
        # even to echo the command — Tk raises "main thread is not in main
        # loop". Everything goes on the queue; the main thread renders it.
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

    def _pump(self):
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "line":
                    self.on_line(payload)
                else:
                    label, rc = payload
                    self.busy = False
                    self.on_done(label, rc)
        except queue.Empty:
            pass
        except Exception:  # noqa: BLE001
            pass
        # Only reschedule once there is a widget to schedule against. Calling
        # this before attach() raised AttributeError inside a bare except, which
        # silently killed the pump for the life of the process: the GUI ran
        # commands and displayed nothing.
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
    root.geometry("1300x830")
    root.minsize(1000, 620)
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
    style.configure("Treeview", background=BG2, fieldbackground=BG2,
                    foreground=FG, rowheight=24, borderwidth=0)
    style.configure("Treeview.Heading", background=BG3, foreground=FG, relief="flat")
    style.map("Treeview", background=[("selected", ACCENT)],
              foreground=[("selected", "#ffffff")])

    # ---- layout: left = cases, right = tabs -------------------------------
    outer = ttk.Frame(root)
    outer.pack(fill="both", expand=True, padx=10, pady=(10, 0))

    left = ttk.Frame(outer, width=340)
    left.pack(side="left", fill="y", padx=(0, 10))
    left.pack_propagate(False)

    ttk.Label(left, text="CASES", style="Head.TLabel").pack(anchor="w")
    filt = ttk.Frame(left)
    filt.pack(fill="x", pady=(6, 6))
    suite_var = tk.StringVar(value="all")
    ttk.Combobox(filt, textvariable=suite_var, state="readonly", width=10,
                 values=["all", "windows", "linux", "baseline"]).pack(side="left")
    search_var = tk.StringVar()
    ttk.Entry(filt, textvariable=search_var, width=18).pack(side="left", padx=(6, 0), fill="x",
                                                            expand=True)

    case_tree = ttk.Treeview(left, columns=("suite", "phase"), show="tree headings",
                             selectmode="browse")
    case_tree.heading("#0", text="case")
    case_tree.heading("suite", text="suite")
    case_tree.column("#0", width=232, stretch=True)
    case_tree.column("suite", width=78, anchor="center")
    case_tree.column("phase", width=46, anchor="center")
    case_tree.pack(fill="both", expand=True)

    case_info = tk.Text(left, height=7, bg=BG2, fg=FG_DIM, insertbackground=FG,
                        relief="flat", wrap="word", font=("TkFixedFont", 9), padx=8, pady=6)
    case_info.pack(fill="x", pady=(6, 0))
    case_info.configure(state="disabled")

    right = ttk.Frame(outer)
    right.pack(side="left", fill="both", expand=True)

    nb = ttk.Notebook(right)
    nb.pack(fill="both", expand=True)

    def text_tab(title):
        frame = ttk.Frame(nb)
        nb.add(frame, text=title)
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
                            ("cmd", ACCENT), ("dim", FG_DIM)):
            txt.tag_configure(tag, foreground=colour)
        return frame, txt

    _, log_txt = text_tab("CONSOLE")
    _, report_txt = text_tab("REPORT")
    _, ev_txt = text_tab("EVIDENCE")

    # ---- setup tab --------------------------------------------------------
    def render_setup():
        nonlocal env

        # Re-check the environment every time Setup is opened.
        env = probe_environment()

        setup_txt.configure(state="normal")
        setup_txt.delete("1.0", "end")

        L = []
        L.append("ENVIRONMENT\n")
        L.append(f"  repo root      {env['root']}\n")
        L.append(f"  python         {env['python']}\n")
        L.append(
            f"  PyYAML         "
            f"{'yes' if env['has_yaml'] else 'NO — pip install -r requirements.txt'}\n"
        )

        tr = env.get("transports") or {}
        L.append(
            f"  pywinrm        "
            f"{'yes' if tr.get('pywinrm') else 'no (needed to reach win-victim)'}\n"
        )
        L.append(
            f"  paramiko       "
            f"{'yes' if tr.get('paramiko') else 'no (needed to reach lin-victim)'}\n"
        )
        L.append(
            f"  vmrun          "
            f"{env['tools'].get('vmrun') or 'not on PATH (needed on the hypervisor host)'}\n"
        )
        L.append(
            f"  ansible        "
            f"{env['tools'].get('ansible-playbook') or 'not on PATH'}\n"
        )
        L.append(
            f"  LAB_PASS       "
            f"{'set' if env['lab_pass'] else 'not set (scored runs need it)'}\n"
        )
        L.append(f"  cases          {env['n_cases']} discovered\n")
        L.append(
            f"  rules          {env['n_rules']} loaded from rules/ "
            f"(templates excluded)\n"
        )

        if env.get("isolation"):
            L.append(
                f"  isolation      verified "
                f"{env['isolation']['age_days']}d ago "
                f"({env['isolation']['dir']})\n"
            )
        else:
            L.append(
                "  isolation      NOT VERIFIED — "
                "Preflight (isolation) first\n"
            )

        if env.get("missing"):
            L.append("\nMISSING FILES\n")
            for m in env["missing"]:
                L.append(f"  {m}\n")

        if env["problems"]:
            L.append("\nBLOCKING\n")
            for p in env["problems"]:
                L.append(f"  * {p}\n")

        if env["warnings"]:
            L.append(
                "\nWARNINGS (do not block; each one is a caveat on your results)\n"
            )
            for w in env["warnings"]:
                L.append(f"  * {w}\n")

        L.append("""
WHAT EACH BUTTON NEEDS
  Case discovery, Replay, Self-test, Rules check    anywhere, no VMs
  Manifest, Open report                             anywhere
  Preflight (static)                                the repo only
  Preflight (isolation)                             hypervisor host + VMs running
  Dry run                                           the repo only (no VM contact)
  Run selected case / Run suite                     hypervisor host, VMs up, LAB_PASS set

FIRST RUN, IN ORDER
  1. Preflight (static)
  2. Self-test
  3. Replay
  4. Preflight (isolation)
  5. Run suite: baseline
  6. Run suite: windows, then linux

BEFORE YOU TRUST A VERDICT
  * A case with no marker file scores inconclusive.
  * Replay cannot tell silent from inconclusive.
  * Read the vintage-bias line in every report.
""")

        setup_txt.insert("1.0", "".join(L))
        setup_txt.configure(state="disabled")
        setup_txt.pack(side="left", fill="both", expand=True)
        def refresh_selected_tab(event=None):
            selected = nb.select()

            # Compare the actual widget/frame, not the displayed tab name.
            if selected == str(setup_frame2):
                render_setup()

            elif selected == str(report_txt.master):
                open_latest_report()

            elif selected == str(ev_txt.master):
                load_evidence()

        nb.bind("<<NotebookTabChanged>>", refresh_selected_tab)




    setup_frame2 = ttk.Frame(nb)
    nb.add(setup_frame2, text="Setup")
    setup_txt = tk.Text(setup_frame2, bg=BG2, fg=FG, relief="flat", wrap="word",
                        font=("TkFixedFont", 9), padx=10, pady=8)
    sb = ttk.Scrollbar(setup_frame2, orient="vertical", command=setup_txt.yview)
    setup_txt.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    setup_txt.pack(side="left", fill="both", expand=True)

    render_setup()

    # ---- bottom bar -------------------------------------------------------
    bottom = ttk.Frame(root)
    bottom.pack(fill="x", padx=10, pady=10)

    status = tk.StringVar()
    status_lbl = ttk.Label(bottom, textvariable=status, style="Dim.TLabel")
    status_lbl.pack(side="right", padx=(10, 0))

    def set_status(msg, colour=FG_DIM):
        status.set(msg)
        status_lbl.configure(foreground=colour)

    # ---- runner -----------------------------------------------------------
    def log(line, tag=None):
        log_txt.configure(state="normal")
        if tag == "cmd":
            log_txt.insert("end", line, "cmd")
        elif tag == "warn":
            log_txt.insert("end", line, "warn")
        else:
            # Colour the verdict lines, since they are the reason you are here.
            low = line.lower()
            if "fail" in low or "error" in low or "traceback" in low or "silent" in low:
                log_txt.insert("end", line, "bad")
            elif "warn" in low or "inconclusive" in low or "logged_no_rule" in low:
                log_txt.insert("end", line, "warn")
            elif re.search(r"\b(detected|ok|pass)\b", low):
                log_txt.insert("end", line, "ok")
            else:
                log_txt.insert("end", line)
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
        refresh_reports()
        refresh_selected_tab()

        try:
            current_tab = nb.tab(nb.select(), "text")
            if current_tab == "REPORT":
                open_latest_report()
            elif current_tab == "EVIDNCE":
                load_evidence()
            elif current_tab == "Setup":
                render_setup()
        except tk.TclError:
            pass


    runner = Runner(on_line=log, on_done=on_done)
    runner.attach(root)

    action_buttons: list = []

    def run(argv, label):
        """Start an action, or explain why not. True if it started."""
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

    # ------------------------------------------------------------------ #
    # case list
    # ------------------------------------------------------------------ #
    cases: list[dict] = []

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
            # Flag the cases whose payloads are not built yet, so "why did this
            # come back inconclusive" has an answer before you run it.
            mark = ""
            text = c["raw"]
            for m in re.finditer(r"from:\s*([^\s,}]+)", text):
                ref = m.group(1).strip("\"'")
                if "/" in ref and not os.path.exists(os.path.join(ROOT, ref)):
                    mark = "  ⚠"
                    break
            case_tree.insert("", "end", iid=c["id"],
                             text=c["id"] + mark,
                             values=(c["suite"], c["phase"]))
            shown += 1
        set_status(f"{shown} of {len(cases)} case(s) shown", FG_DIM)

    def show_case(_event=None):
        sel = case_tree.selection()
        if not sel:
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
    load_cases()
    render_cases()


    def on_tab_changeed(_expct = None):
        try:
            tab_id = nb.select()
            tab_text = nb.tab(tab_id, "text")
        except tk.TclError:
            return

        if tab_text == "REPORT":
            open_latest_report()
        elif tab_text == "EVIDENCE":
            load_evidence()
        elif tab_text == "Setup":
            render_setup()
    nb.bind("<<NotebookTabChanged>>", on_tab_changeed)
        
    # ------------------------------------------------------------------ #
    # reports + evidence
    # ------------------------------------------------------------------ #
    report_index: list[str] = []

    def refresh_reports():
        report_index.clear()
        d = os.path.join(ROOT, "reports")
        if os.path.isdir(d):
            report_index.extend(sorted(
                (os.path.join(d, f) for f in os.listdir(d) if f.endswith(".md")),
                reverse=True))

    def open_latest_report():
        refresh_reports()
        if not report_index:
            report_txt.configure(state="normal")
            report_txt.delete("1.0", "end")
            report_txt.insert("end", "No reports yet.\n\nReports appear in reports/ after a run "
                                     "— or run Replay against tests/make_fixtures.py output to "
                                     "produce one without any VMs.\n")
            report_txt.configure(state="disabled")
            return
        path = report_index[0]
        report_txt.configure(state="normal")
        report_txt.delete("1.0", "end")
        report_txt.insert("end", open(path).read())
        report_txt.configure(state="disabled")
        set_status(f"report: {os.path.basename(path)}", FG_DIM)

    def load_evidence():
        ev_txt.configure(state="normal")
        ev_txt.delete("1.0", "end")
        store = os.path.join(ROOT, "store")
        runs = sorted((r for r in os.listdir(store)), reverse=True) if os.path.isdir(store) else []
        runs = [r for r in runs if r.startswith("R")]
        if not runs:
            ev_txt.insert("end", "No runs recorded yet under store/.\n")
            ev_txt.configure(state="disabled")
            return
        run = runs[0]
        ev_txt.insert("end", f"RUN {run}\n" + "=" * 60 + "\n\n")
        cases_dir = os.path.join(store, run, "cases")
        if not os.path.isdir(cases_dir):
            ev_txt.insert("end", "no cases/ directory\n")
            ev_txt.configure(state="disabled")
            return
        for cid in sorted(os.listdir(cases_dir)):
            cdir = os.path.join(cases_dir, cid)
            score = os.path.join(cdir, "score.json")
            verdict, reason = "?", ""
            if os.path.isfile(score):
                try:
                    s = json.load(open(score))
                    verdict = s.get("verdict", "?")
                    reason = (s.get("reason") or "")[:160]
                except (OSError, ValueError):
                    pass
            ev_txt.insert("end", f"{cid}\n", "ok" if verdict == "detected" else None)
            ev_txt.insert("end", f"   verdict : {verdict.upper()}\n")
            if reason:
                ev_txt.insert("end", f"   reason  : {reason}\n")
            for rel in ("exec.jsonl", "normalized/events.jsonl", "findings.jsonl", "raw"):
                p = os.path.join(cdir, rel)
                if os.path.exists(p):
                    ev_txt.insert("end", f"   {rel:<26} {p}\n", "dim")
            ev_txt.insert("end", "\n")
        ev_txt.configure(state="disabled")
        

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
        run(argv, f"run {sel[0]}")

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
                                                f"Cases run strictly serially and each one reverts "
                                                f"the VM twice. A full suite takes a while."):
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
    btns.pack(fill="x", pady=(8, 0))

    def row():
        f = ttk.Frame(btns)
        f.pack(fill="x", pady=(0, 6))
        return f

    r1 = row()
    for label, fn in (("Preflight (static)", do_preflight_static),
                      ("Preflight (isolation)", do_preflight_iso),
                      ("Self-test", do_self_test),
                      ("Rules check", do_rules),
                      ("Manifest", do_manifest),
                      ("Open repo folder", do_open_root)):
        ttk.Button(r1, text=label, command=fn).pack(side="left", padx=(0, 6))

    r2 = row()
    for label, fn in (("Replay evidence…", do_replay),
                      ("Dry run", do_dry_run),
                      ("List cases", do_list),
                      ("Open latest report", open_latest_report),
                      ("Evidence viewer", load_evidence)):
        ttk.Button(r2, text=label, command=fn).pack(side="left", padx=(0, 6))

    r3 = row()
    skip_preflight_var = tk.BooleanVar(value=False)
    skip_preflight_cb = ttk.Checkbutton(
        r3,
        text="Skip preflight",
        variable=skip_preflight_var,
    )
    skip_preflight_cb.pack(side="left", padx=(0, 12))

    run_case_btn = ttk.Button(r3, text="▶  Run selected case", command=do_run_case)
    run_case_btn.pack(side="left", padx=(0, 6))
    run_suite_btn = ttk.Button(r3, text="▶  Run suite", command=do_run_suite)
    run_suite_btn.pack(side="left", padx=(0, 6))
    stop_btn = ttk.Button(r3, text="■  Stop", command=runner.stop)
    stop_btn.pack(side="left", padx=(0, 6))

    # Everything that shells out is disabled while one command is in flight.
    # Two interleaved harness commands against the same victims is the single
    # thing this GUI must make impossible.
    for frame in (r1, r2, r3):
        action_buttons.extend(w for w in frame.winfo_children()
                              if isinstance(w, ttk.Button) and w is not stop_btn)

    # Be explicit about why the Run buttons are disabled, rather than letting the
    # user guess. The GUI cannot create the isolation evidence or reach the VMs,
    # so it says which of the two is missing.
    reasons = []
    if env.get("missing"):
        reasons.append("repo files missing")
    if not env["lab_pass"]:
        reasons.append("LAB_PASS not set")
    if not env["isolation"]:
        reasons.append("isolation not verified")
    blocked_reason = ", ".join(reasons)
    if blocked_reason:
        run_case_btn.configure(state="disabled")
        run_suite_btn.configure(state="disabled")
        ttk.Label(r3, text=f"  (scored runs disabled: {blocked_reason})",
                  style="Dim.TLabel").pack(side="left")

    set_status(f"{env['n_cases']} cases · {env['n_rules']} rules · "
               f"{'cred set' if env['lab_pass'] else 'no credential'}", FG_DIM)

    log_txt.insert("end",
                   "EDR Lab console\n"
                   "===============\n\n"
                   "Every button runs the same entry point the Makefile does. The GUI decides\n"
                   "nothing: verdicts come from harness/score.py, the report from harness/report.py.\n\n"
                   "Open the Setup tab for what this machine can and cannot do, then:\n"
                   "  1. Preflight (static)   2. Self-test   3. Replay evidence…\n\n"
                   "A case with no marker file scores inconclusive — that is a broken test, not a\n"
                   "sensor gap. Check the Evidence tab before you blame a rule.\n")
    log_txt.configure(state="disabled")

    # Handles for anything that needs to drive the window programmatically —
    # the headless smoke test uses these, and so can a future tab. Reading them
    # is safe; nothing outside should need to write.
    root.lab_widgets = {
        "notebook": nb, "case_tree": case_tree, "log": log_txt,
        "report": report_txt, "evidence": ev_txt, "setup": setup_txt,
        "case_info": case_info, "status": status, "runner": runner,
        "run_case_btn": run_case_btn, "run_suite_btn": run_suite_btn,
        "reload_cases": lambda: (load_cases(), render_cases()),
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
        if env.get("missing"):
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
