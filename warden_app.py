"""
Warden App (Stage 8, new look)
==============================
The window a normal person sees. Double-click "Warden App.cmd", or run:

    .venv\\Scripts\\pythonw.exe warden_app.py      (no console window)
    .venv\\Scripts\\python.exe  warden_app.py      (with a console, for debugging)

The screens are HTML/CSS/JS in the ui/ folder, shown in a real app window by
pywebview (it uses the Edge engine built into Windows). Python and the screens
talk through `Api` below: the page calls window.pywebview.api.<method>().

Pages:
  Home        - "You're protected", today's numbers, AI apps with Protect buttons, checks
  History     - what Warden stopped, as plain-language stories
  Attack Lab  - run the fake attacks and see the score

While it runs, it answers Warden's approval questions with an Allow / Deny popup
(see warden_approval.py). If the app is closed, "ask" actions stay blocked.

SECURITY: stories may contain an attacker's text. The ui/*.js files only insert
text with textContent (never as HTML) and a strict Content-Security-Policy only
lets Warden's own scripts run. tests/test_app_ui.py checks both.

The checks below are plain functions so they can be tested without a window.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import threading
import urllib.request
from datetime import datetime, timezone
from glob import glob
from pathlib import Path
from typing import Any

import warden_protect
from warden_approval import ApprovalServer, app_is_running
from warden_policy import Policy
from warden_protect import ProtectError, Target

WARDEN_DIR = Path(__file__).resolve().parent
UI_DIR = WARDEN_DIR / "ui"
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
    """One line about one AI app. None = nothing to protect yet (grey, not red)."""
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


def status_summary(checks: list[tuple[bool | None, str]]) -> tuple[str, str, str]:
    """(overall "ok" | "warn" | "bad", headline, subline) for the big card at the top."""
    problems = [t for ok, t in checks if ok is False]
    if not any(ok for ok, t in checks if "goes through Warden" in t):
        return "bad", "Not protected", "No AI app goes through Warden yet. Click Protect below."
    if any("NOT protected" in p or "rules" in p for p in problems):
        return "bad", "Not fully protected", problems[0]
    if problems:
        return "warn", "Protected, with warnings", problems[0]
    return "ok", "You're protected", "Warden is checking every action your AI takes."


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


def event_for_ui(e: dict[str, Any]) -> dict[str, str]:
    """A log entry turned into plain strings for the History page (shown as text, never HTML)."""
    when = str(e.get("time", "")).replace("T", " ")[:16]
    args = json.dumps(e.get("arguments", {}), ensure_ascii=False)
    return {
        "id": str(e.get("id", "")),
        "when": when,
        "badge": event_icon(e),
        "title": str(e.get("story_title") or f"{e.get('server')}/{e.get('tool')}"),
        "story": str(e.get("story") or ""),
        "details": f"{e.get('server')}/{e.get('tool')} {args[:400]}",
    }


LAB_SCORE = re.compile(r"Attacks stopped:\s+(\d+/\d+)\s+\((\d+) blocked.*?\)|Attacks missed:\s+(\d+/\d+)|Safe actions allowed:\s+(\d+/\d+)")


def parse_lab_score(lines: list[str]) -> dict[str, str] | None:
    score: dict[str, str] = {}
    for line in lines:
        m = LAB_SCORE.search(line)
        if not m:
            continue
        if m.group(1):
            score["stopped"], score["blocked"] = m.group(1), m.group(2)
        elif m.group(3):
            score["missed"] = m.group(3)
        elif m.group(4):
            score["safe"] = m.group(4)
    return score if len(score) == 4 else None


# ---------------------------------------------------------------------------
# The bridge between the screens (JavaScript) and Python
# ---------------------------------------------------------------------------
# pywebview exposes the PUBLIC methods of these objects to the page.
# Everything internal starts with "_" so the page cannot reach it.

class Api:
    def __init__(self) -> None:
        self._lab_lock = threading.Lock()
        self._lab_lines: list[str] = []
        self._lab_sent = 0
        self._lab_running = False

    def get_status(self) -> dict[str, Any]:
        config = load_config()
        checks: list[tuple[bool | None, str]] = [(True, "Approval popups are on (this window is open)")]
        apps = []
        targets = warden_protect.detect_targets()
        if not targets:
            checks.append((False, "No supported AI app found on this PC"))
        for t in targets:
            check = app_check(t)
            state, bypass = warden_protect.status(t)
            checks.append(check)
            apps.append({"id": str(t.config), "name": t.name, "path": str(t.config), "state": state,
                         "has_tools": bool(bypass) or state == "protected",
                         "note": check[1] if bypass else ""})
        checks.append(check_rules(config))
        checks.append(check_ai(config))
        overall, headline, subline = status_summary(checks)
        return {"overall": overall, "headline": headline, "subline": subline,
                "checks": [{"ok": ok, "text": text} for ok, text in checks],
                "apps": apps, "today": today_summary(read_events())}

    def get_history(self, show_all: bool = False) -> list[dict[str, str]]:
        events = read_events()
        return [event_for_ui(e) for e in events if show_all or e.get("story")][:200]

    def toggle_protection(self, app_id: str) -> dict[str, Any]:
        target = next((t for t in warden_protect.detect_targets() if str(t.config) == app_id), None)
        if target is None:
            return {"ok": False, "lines": ["That app could not be found any more."]}
        protecting = warden_protect.status(target)[0] != "protected"
        try:
            result = (warden_protect.protect if protecting else warden_protect.unprotect)(target)
        except (ProtectError, OSError) as exc:
            return {"ok": False, "lines": [str(exc)]}
        lines = [f"{target.name} is now {'protected' if protecting else 'unprotected'}."]
        if result.moved:
            lines.append(("Tools moved behind Warden: " if protecting else "Tools given back: ") + ", ".join(result.moved))
        if result.left:
            lines.append("Online tools Warden cannot protect yet (they still skip it): " + ", ".join(result.left))
        if result.backup:
            lines.append(f"Backup of the old config: {result.backup}")
        lines.append(f"Fully restart {target.name} (also from the system tray) to finish.")
        return {"ok": True, "lines": lines}

    def run_lab(self, use_ai: bool = False) -> bool:
        with self._lab_lock:
            if self._lab_running:
                return False
            self._lab_running, self._lab_lines, self._lab_sent = True, [], 0
        threading.Thread(target=self._run_lab, args=(bool(use_ai),), daemon=True).start()
        return True

    def lab_poll(self) -> dict[str, Any]:
        with self._lab_lock:
            new = self._lab_lines[self._lab_sent:]
            self._lab_sent = len(self._lab_lines)
            running = self._lab_running
            score = None if running else parse_lab_score(self._lab_lines)
        return {"running": running, "lines": new, "score": score}

    def _run_lab(self, use_ai: bool) -> None:
        args = [sys.executable.replace("pythonw.exe", "python.exe"), str(WARDEN_DIR / "attack_lab" / "run_lab.py")]
        if use_ai:
            args.append("--ai")
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                    encoding="utf-8", cwd=WARDEN_DIR, creationflags=flags)
            for line in proc.stdout:
                with self._lab_lock:
                    self._lab_lines.append(line)
            proc.wait()
        except OSError as exc:
            with self._lab_lock:
                self._lab_lines.append(f"Could not start the Attack Lab: {exc}\n")
        finally:
            with self._lab_lock:
                self._lab_running = False


class ApprovalApi:
    """The bridge for ONE approval popup."""

    def __init__(self, request: dict[str, Any], done: threading.Event, box: dict[str, str]) -> None:
        self._request, self._done, self._box = request, done, box

    def get_request(self) -> dict[str, Any]:
        keys = ("title", "story", "server", "tool", "arguments", "timeout")
        return {k: self._request.get(k) for k in keys}

    def answer(self, decision: str) -> None:
        if decision in ("allow", "deny", "timeout") and not self._done.is_set():
            self._box["decision"] = decision
            self._done.set()


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def main() -> None:
    import webview   # imported here so the checks above can be tested without it

    if asyncio.run(app_is_running()):
        webview.create_window("Warden", html="<p style='font-family:Segoe UI;padding:20px'>"
                                              "The Warden App is already running.</p>", width=360, height=140)
        webview.start()
        return

    def decide(request: dict[str, Any]) -> str:
        """Called by the approval server (in its own thread) for every "ask" action."""
        done, box = threading.Event(), {}
        popup = webview.create_window(
            "Warden - your approval is needed", str(UI_DIR / "approval.html"),
            js_api=ApprovalApi(request, done, box), width=560, height=470,
            resizable=False, on_top=True, focus=True)
        popup.events.closed += lambda: done.set()          # closing the window = not allowed
        answered = done.wait(float(request.get("timeout", 60)))
        try:
            popup.destroy()
        except Exception:
            pass
        if not answered:
            return "timeout"
        return box.get("decision", "deny")

    server = ApprovalServer(decide)
    server.start()
    window = webview.create_window(
        "Warden", str(UI_DIR / "index.html"), js_api=Api(),
        width=1060, height=760, min_size=(820, 560), confirm_close=True)

    def shutdown() -> None:
        server.stop()
        for w in list(webview.windows):               # close any open popups too
            if w is not window:
                try:
                    w.destroy()
                except Exception:
                    pass

    window.events.closed += shutdown
    webview.start(localization={
        "global.quitConfirmation": "While the Warden App is closed, actions that need your approval are blocked. Close it?",
    })


if __name__ == "__main__":
    main()
