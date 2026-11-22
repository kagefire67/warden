"""
Warden App (Stage 8)
====================
The window a normal person sees. Start it with:

    .venv\\Scripts\\pythonw.exe warden_app.py      (no console window)
    .venv\\Scripts\\python.exe  warden_app.py      (with a console, for debugging)

Tabs:
  Home        - "You're protected" checks + today's numbers
  History     - what Warden stopped, as plain-language stories
  Attack Lab  - run the fake attacks and see the score

While it runs, it answers Warden's approval questions with an Allow / Deny popup
(see warden_approval.py). If the app is closed, "ask" actions stay blocked.

Built with Tkinter (comes with Python, nothing to install). The checks below are
plain functions so they can be tested without opening a window.
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import urllib.request
from datetime import datetime, timezone
from glob import glob
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Any

import warden_protect
from warden_approval import ApprovalServer, app_is_running
from warden_policy import Policy
from warden_protect import ProtectError, Target

WARDEN_DIR = Path(__file__).resolve().parent
CONFIG = WARDEN_DIR / "warden_config.json"
LOG = WARDEN_DIR / "logs" / "actions.jsonl"


# ---------------------------------------------------------------------------
# Checks (no window needed - these are unit-tested)
# ---------------------------------------------------------------------------

def find_claude_configs() -> list[Path]:
    """Claude Desktop's config file can live in a few places on Windows (normal vs Store install)."""
    appdata, local = os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", "")
    patterns = [
        os.path.join(appdata, "Claude", "claude_desktop_config.json"),
        os.path.join(local, "Claude-Data", "*", "claude_desktop_config.json"),
        os.path.join(local, "Packages", "*Claude*", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"),
    ]
    found: list[Path] = []
    for pattern in patterns:
        found += [Path(p) for p in glob(pattern) if Path(p) not in found]
    return found


def protection_status(config_path: Path) -> tuple[str, list[str]]:
    """("protected" | "not_protected" | "unreadable", [servers that SKIP Warden]) for a Claude Desktop config."""
    return warden_protect.status(Target("Claude Desktop", "claude_desktop", config_path))


def app_check(target: Target) -> tuple[bool | None, str]:
    """One line for the Home tab about one AI app. None = nothing to protect yet (grey, not red)."""
    state, bypass = warden_protect.status(target)
    if state == "unreadable":
        return False, f"{target.name}: its config could not be read, so Warden left it alone"
    if state == "protected" and bypass:
        return False, f"{target.name} goes through Warden, but these tools skip it: {', '.join(bypass)}"
    if state == "protected":
        return True, f"{target.name} goes through Warden"
    if bypass:
        return False, f"{target.name} is NOT protected ({len(bypass)} tools skip Warden)"
    return None, f"{target.name}: no AI tools set up yet"


def load_config() -> dict[str, Any]:
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def check_rules(config: dict[str, Any]) -> tuple[bool, str]:
    rules = Path(config.get("rules_file", "rules.json"))
    rules = rules if rules.is_absolute() else WARDEN_DIR / rules
    try:
        return True, f"{len(Policy.load(rules).rules)} rules loaded"
    except Exception as exc:
        return False, f"rules.json has a problem ({type(exc).__name__}) - Warden blocks everything until it is fixed"


def check_ai(config: dict[str, Any]) -> tuple[bool | None, str]:
    """None = switched off. Otherwise: is Ollama running and is the model downloaded?"""
    settings = config.get("intent_check") or {}
    if not settings.get("enabled"):
        return None, "AI check is switched off (rules + scanner only)"
    url, model = settings.get("url", "http://127.0.0.1:11434"), settings.get("model", "qwen3:8b")
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/tags", timeout=2) as resp:
            names = [m.get("name") for m in json.loads(resp.read()).get("models", [])]
    except Exception:
        return False, "AI check offline: Ollama is not running, so risky actions will ask you"
    if model not in names:
        return False, f"AI model {model} is not downloaded (run: ollama pull {model})"
    return True, f"AI check ready ({model})"


def read_events(log_path: Path = LOG, limit: int = 300) -> list[dict[str, Any]]:
    """The newest `limit` log entries, newest first."""
    try:
        lines = log_path.read_text(encoding="utf-8").splitlines()[-limit:]
    except OSError:
        return []
    events = []
    for line in reversed(lines):
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def today_summary(events: list[dict[str, Any]], today: str | None = None) -> dict[str, int]:
    today = today or datetime.now(timezone.utc).date().isoformat()
    todays = [e for e in events if str(e.get("time", "")).startswith(today)]
    return {
        "actions": len(todays),
        "attacks": sum(1 for e in todays if e.get("tainted_session") and e.get("status") == "ok" and e.get("story")),
        "blocked": sum(1 for e in todays if e.get("status") == "blocked"),
        "you_allowed": sum(1 for e in todays if e.get("approval") == "allow"),
    }


def event_icon(e: dict[str, Any]) -> str:
    if e.get("event") == "tool_flagged":
        return "TOOL HIDDEN"
    if e.get("approval") == "allow":
        return "YOU ALLOWED"
    if e.get("tainted_session") and e.get("status") == "ok" and e.get("story"):
        return "ATTACK FOUND"
    if e.get("decision") == "ask":
        return "NEEDED OK"
    if e.get("status") == "blocked":
        return "BLOCKED"
    return "allowed"


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------

GREEN, RED, AMBER, GREY = "#1a7f37", "#cf222e", "#9a6700", "#57606a"
FONT = ("Segoe UI", 10)


class ApprovalPopup(tk.Toplevel):
    """Allow / Deny window. Closing it or waiting too long = Deny."""

    def __init__(self, app: "WardenApp", request: dict[str, Any], done: threading.Event, box: dict[str, str]):
        super().__init__(app.root)
        self.done, self.box = done, box
        self.remaining = max(5, int(float(request.get("timeout", 60))) - 2)
        self.title("Warden - your approval is needed")
        self.attributes("-topmost", True)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", lambda: self.answer("deny"))

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Warden stopped an action and needs your OK", font=("Segoe UI", 9), foreground=GREY).pack(anchor="w")
        ttk.Label(frame, text=request.get("title", "An AI action needs your approval"),
                  font=("Segoe UI", 13, "bold"), wraplength=520).pack(anchor="w", pady=(4, 8))
        ttk.Label(frame, text=request.get("story", ""), font=FONT, wraplength=520, justify="left").pack(anchor="w")
        details = f"Tool: {request.get('server')}/{request.get('tool')}\nDetails: {request.get('arguments', '')}"
        ttk.Label(frame, text=details, font=("Consolas", 9), foreground=GREY, wraplength=520,
                  justify="left").pack(anchor="w", pady=(10, 0))
        self.countdown = ttk.Label(frame, font=("Segoe UI", 9), foreground=AMBER)
        self.countdown.pack(anchor="w", pady=(10, 0))

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        deny = tk.Button(buttons, text="Deny", width=14, bg=RED, fg="white", font=("Segoe UI", 10, "bold"),
                         command=lambda: self.answer("deny"))
        deny.pack(side="right")
        tk.Button(buttons, text="Allow once", width=14, bg=GREEN, fg="white", font=("Segoe UI", 10, "bold"),
                  command=lambda: self.answer("allow")).pack(side="right", padx=(0, 8))
        deny.focus_set()          # pressing Enter by accident = Deny, never Allow
        self.bell()
        self.lift()
        self.tick()

    def tick(self) -> None:
        if self.done.is_set():
            self.destroy()
            return
        self.countdown.config(text=f"No answer = Deny in {self.remaining}s")
        self.remaining -= 1
        if self.remaining < 0:
            self.answer("timeout")   # nobody clicked: blocked, and the story says so (not "you chose Deny")
        else:
            self.after(1000, self.tick)

    def answer(self, decision: str) -> None:
        if not self.done.is_set():
            self.box["decision"] = decision
            self.done.set()
        self.destroy()


class WardenApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.inbox: queue.Queue = queue.Queue()     # messages from background threads to the window
        root.title("Warden")
        root.geometry("920x640")
        root.minsize(760, 520)
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=26, font=FONT)

        header = ttk.Frame(root, padding=(18, 14))
        header.pack(fill="x")
        self.status = tk.Label(header, text="Checking...", font=("Segoe UI", 20, "bold"), anchor="w")
        self.status.pack(fill="x")
        self.substatus = ttk.Label(header, text="", font=FONT, foreground=GREY)
        self.substatus.pack(fill="x")

        tabs = ttk.Notebook(root)
        tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.home = ttk.Frame(tabs, padding=16)
        self.history = ttk.Frame(tabs, padding=12)
        self.lab = ttk.Frame(tabs, padding=12)
        tabs.add(self.home, text="  Home  ")
        tabs.add(self.history, text="  History  ")
        tabs.add(self.lab, text="  Attack Lab  ")
        self.build_home()
        self.build_history()
        self.build_lab()

        self.server = ApprovalServer(self.decide)
        self.server.start()
        root.protocol("WM_DELETE_WINDOW", self.quit)

        self.refresh_status()
        self.refresh_history()
        self.root.after(200, self.process_inbox)

    # --- Home ---------------------------------------------------------------

    def build_home(self) -> None:
        ttk.Label(self.home, text="Protection checks", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.checks = ttk.Frame(self.home)
        self.checks.pack(fill="x", pady=(6, 16))
        ttk.Label(self.home, text="AI apps on this PC", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.apps = ttk.Frame(self.home)
        self.apps.pack(fill="x", pady=(6, 16))
        ttk.Label(self.home, text="Today", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.today = ttk.Label(self.home, text="", font=("Segoe UI", 11))
        self.today.pack(anchor="w", pady=(6, 16))
        buttons = ttk.Frame(self.home)
        buttons.pack(anchor="w")
        ttk.Button(buttons, text="Check again", command=self.refresh_status).pack(side="left")
        ttk.Button(buttons, text="Open Warden folder", command=lambda: os.startfile(WARDEN_DIR)).pack(side="left", padx=8)

    def refresh_status(self) -> None:
        """Run the checks in the background (the AI check can take a moment)."""
        def work() -> None:
            config = load_config()
            checks: list[tuple[bool | None, str]] = [(True, "Approval popups are on (this window is open)")]
            targets = warden_protect.detect_targets()
            if not targets:
                checks.append((False, "No supported AI app found on this PC"))
            apps = [(t, app_check(t), warden_protect.status(t)[0]) for t in targets]
            checks += [check for _, check, _ in apps]
            checks.append(check_rules(config))
            checks.append(check_ai(config))
            self.inbox.put(("status", checks))
            self.inbox.put(("apps", apps))
        threading.Thread(target=work, daemon=True).start()
        self.root.after(15000, self.refresh_status)

    def show_status(self, checks: list[tuple[bool | None, str]]) -> None:
        for child in self.checks.winfo_children():
            child.destroy()
        for ok, text in checks:
            mark, color = {True: ("✔", GREEN), False: ("✖", RED), None: ("–", GREY)}[ok]
            row = ttk.Frame(self.checks)
            row.pack(anchor="w", pady=2)
            tk.Label(row, text=mark, fg=color, font=("Segoe UI Symbol", 12, "bold"), width=2).pack(side="left")
            ttk.Label(row, text=text, font=("Segoe UI", 11)).pack(side="left")
        problems = [t for ok, t in checks if ok is False]
        if not any(ok for ok, t in checks if "goes through Warden" in t):
            self.status.config(text="✖  Not protected", fg=RED)
            self.substatus.config(text="No AI app goes through Warden yet. Click Protect below.")
        elif not problems:
            self.status.config(text="✔  You're protected", fg=GREEN)
            self.substatus.config(text="Warden is checking every action your AI takes.")
        elif any("NOT protected" in p or "rules" in p for p in problems):
            self.status.config(text="✖  Not protected", fg=RED)
            self.substatus.config(text=problems[0])
        else:
            self.status.config(text="⚠  Protected, with warnings", fg=AMBER)
            self.substatus.config(text=problems[0])

    def show_apps(self, apps: list[tuple[Target, tuple[bool | None, str], str]]) -> None:
        for child in self.apps.winfo_children():
            child.destroy()
        for target, (_, text), state in apps:
            row = ttk.Frame(self.apps)
            row.pack(fill="x", pady=2)
            label = "Unprotect" if state == "protected" else "Protect"
            button = ttk.Button(row, text=label, width=12,
                                command=lambda t=target, s=state: self.toggle_protection(t, s))
            button.pack(side="left")
            if state == "unreadable":
                button.state(["disabled"])
            ttk.Label(row, text=f"  {target.name}", font=("Segoe UI", 11, "bold")).pack(side="left")
            ttk.Label(row, text=f"   {target.config}", font=("Segoe UI", 8), foreground=GREY).pack(side="left")

    def toggle_protection(self, target: Target, state: str) -> None:
        """One-click Protect / Unprotect, always with a confirmation and a backup."""
        if state == "protected":
            if not messagebox.askyesno(f"Unprotect {target.name}?",
                                       f"{target.name} will talk to its tools directly again, WITHOUT Warden checking them.\n\n"
                                       "A backup of its config is made first. Continue?"):
                return
            action, verb = warden_protect.unprotect, "unprotected"
        else:
            if not messagebox.askyesno(f"Protect {target.name}?",
                                       f"Warden will:\n"
                                       f"  1. back up {target.name}'s config file,\n"
                                       f"  2. move its tools behind Warden (kept in your private Warden folder),\n"
                                       f"  3. make {target.name} talk only to Warden.\n\n"
                                       "You can undo this any time with Unprotect. Continue?"):
                return
            action, verb = warden_protect.protect, "protected"
        try:
            result = action(target)
        except (ProtectError, OSError) as exc:
            messagebox.showerror("Nothing was changed", str(exc))
            return
        lines = [f"{target.name} is now {verb}."]
        if result.moved:
            lines.append(("Tools moved behind Warden: " if verb == "protected" else "Tools given back: ")
                         + ", ".join(result.moved))
        if result.left:
            lines.append("Online tools Warden cannot protect yet (they still skip it): " + ", ".join(result.left))
        if result.backup:
            lines.append(f"Backup: {result.backup}")
        lines.append(f"\nFully restart {target.name} (also from the system tray) to finish.")
        messagebox.showinfo("Done", "\n".join(lines))
        self.refresh_status()

    # --- History ------------------------------------------------------------

    def build_history(self) -> None:
        top = ttk.Frame(self.history)
        top.pack(fill="x")
        self.show_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Show every action (not only when Warden stepped in)", variable=self.show_all,
                        command=self.refresh_history_now).pack(side="left")
        self.tree = ttk.Treeview(self.history, columns=("when", "what", "title"), show="headings", height=12)
        for col, text, width in (("when", "When", 130), ("what", "What", 120), ("title", "Story", 560)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=8)
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_story)
        self.detail = scrolledtext.ScrolledText(self.history, height=7, wrap="word", font=FONT)
        self.detail.pack(fill="x")
        self.events: dict[str, dict[str, Any]] = {}
        self.last_seen = None

    def refresh_history_now(self) -> None:
        self.last_seen = None
        self.refresh_history(reschedule=False)

    def refresh_history(self, reschedule: bool = True) -> None:
        events = read_events()
        newest = events[0].get("id") if events else None
        if newest != self.last_seen:
            self.last_seen = newest
            self.tree.delete(*self.tree.get_children())
            self.events.clear()
            for e in events:
                if not self.show_all.get() and not e.get("story"):
                    continue
                when = str(e.get("time", "")).replace("T", " ")[:16]
                title = e.get("story_title") or f"{e.get('server')}/{e.get('tool')}"
                iid = self.tree.insert("", "end", values=(when, event_icon(e), title))
                self.events[iid] = e
            summary = today_summary(events)
            self.today.config(text=f"{summary['actions']} actions checked   •   {summary['attacks']} attacks found   •   "
                                   f"{summary['blocked']} stopped   •   {summary['you_allowed']} allowed by you")
        if reschedule:
            self.root.after(3000, self.refresh_history)

    def show_selected_story(self, _event: Any = None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        e = self.events.get(selected[0], {})
        text = e.get("story") or f"{e.get('server')}/{e.get('tool')} {json.dumps(e.get('arguments', {}), ensure_ascii=False)}"
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)

    # --- Attack Lab -----------------------------------------------------------

    def build_lab(self) -> None:
        ttk.Label(self.lab, text="Run safe, fake attacks through Warden and see how many it stops.",
                  font=("Segoe UI", 11)).pack(anchor="w")
        row = ttk.Frame(self.lab)
        row.pack(anchor="w", pady=8)
        self.use_ai = tk.BooleanVar(value=False)
        self.lab_button = ttk.Button(row, text="Run Attack Lab", command=self.run_lab)
        self.lab_button.pack(side="left")
        ttk.Checkbutton(row, text="Include the AI check (slower, needs Ollama)", variable=self.use_ai).pack(side="left", padx=10)
        self.score = ttk.Label(self.lab, text="", font=("Segoe UI", 12, "bold"))
        self.score.pack(anchor="w", pady=(4, 8))
        self.lab_output = scrolledtext.ScrolledText(self.lab, wrap="none", font=("Consolas", 9))
        self.lab_output.pack(fill="both", expand=True)

    def run_lab(self) -> None:
        self.lab_button.config(state="disabled")
        self.lab_output.delete("1.0", "end")
        self.score.config(text="Running... (about a minute)")
        args = [sys.executable, str(WARDEN_DIR / "attack_lab" / "run_lab.py")] + (["--ai"] if self.use_ai.get() else [])

        def work() -> None:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                    encoding="utf-8", cwd=WARDEN_DIR, creationflags=flags)
            score = []
            for line in proc.stdout:
                self.inbox.put(("lab_line", line))
                if line.startswith(("Attacks stopped", "Safe actions", "Attacks missed")):
                    score.append(line.strip())
            proc.wait()
            self.inbox.put(("lab_done", "\n".join(score) or "The lab did not finish - see the output below."))
        threading.Thread(target=work, daemon=True).start()

    # --- Approvals (called from the approval server's thread) ----------------------

    def decide(self, request: dict[str, Any]) -> str:
        done, box = threading.Event(), {}
        self.inbox.put(("approval", request, done, box))
        if not done.wait(float(request.get("timeout", 60))):
            done.set()                     # closes the popup if it is still open
            return "timeout"
        return box.get("decision", "deny")

    # --- Plumbing ----------------------------------------------------------------

    def process_inbox(self) -> None:
        """Tkinter may only be touched from the main thread, so background work sends messages here."""
        try:
            while True:
                kind, *data = self.inbox.get_nowait()
                if kind == "status":
                    self.show_status(data[0])
                elif kind == "apps":
                    self.show_apps(data[0])
                elif kind == "approval":
                    ApprovalPopup(self, *data)
                elif kind == "lab_line":
                    self.lab_output.insert("end", data[0])
                    self.lab_output.see("end")
                elif kind == "lab_done":
                    self.score.config(text=data[0])
                    self.lab_button.config(state="normal")
        except queue.Empty:
            pass
        self.root.after(200, self.process_inbox)

    def quit(self) -> None:
        if messagebox.askyesno("Close Warden App?",
                               "While the Warden App is closed, actions that need your approval are blocked.\n\nClose it?"):
            self.server.stop()
            self.root.destroy()


def main() -> None:
    if asyncio.run(app_is_running()):
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Warden", "The Warden App is already running.")
        return
    root = tk.Tk()
    WardenApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
