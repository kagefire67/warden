"""
Warden approval channel (Stage 8)
=================================
Lets Warden (started by the AI app) ask the user "Allow or Deny?" through the
Warden App window.

    Warden gateway  --"may I?"-->  Warden App (approval server)  -->  popup
                    <--"allow"---

How it works:
  - The Warden App starts an ApprovalServer on 127.0.0.1 (this PC only) and
    writes its port and a fresh random SECRET TOKEN to app.json in the user's
    AppData folder. A new token is made every time the app starts.
  - The gateway reads app.json and sends one JSON line per question. Requests
    without the right token are refused.
  - The AI cannot approve anything: approving only happens by a click in the
    app window. There is no "approve" command on this channel.

FAIL SAFE: if the app is not running, does not answer in time, or anything goes
wrong, ask_user() returns None and the gateway keeps the action BLOCKED.

Notices (one-way): the gateway also uses this channel to TELL the user when it
found an attack or stopped an action (tell_user). The app shows a small notice
window; nothing is asked and nothing comes back, so a notice can never allow anything.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import socketserver
import threading
import time
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("warden")

MAX_LINE = 64 * 1024     # one request is small; refuse anything huge


def default_app_file() -> Path:
    """Where the running app publishes its port + token. Tests point this elsewhere."""
    override = os.environ.get("WARDEN_APP_FILE")
    if override:
        return Path(override)
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    return base / "Warden" / "app.json"


# ---------------------------------------------------------------------------
# Server side (runs inside the Warden App)
# ---------------------------------------------------------------------------

class ApprovalServer:
    """Answers approval questions by calling `decide(request) -> "allow" | "deny"`.

    `decide` runs in a background thread and may block (e.g. while a popup is open).
    `notify(notice)` (optional) shows a notice; it is started in its own thread so the
    gateway never waits for it.
    """

    def __init__(self, decide: Callable[[dict[str, Any]], str], app_file: Path | None = None,
                 notify: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.decide = decide
        self.notify = notify
        self.app_file = app_file or default_app_file()
        self.token = secrets.token_hex(16)
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                try:
                    line = self.rfile.readline(MAX_LINE)
                    request = json.loads(line)
                    # Constant-time comparison, so the token cannot be guessed by timing.
                    if not hmac.compare_digest(str(request.get("token", "")), outer.token):
                        reply = {"error": "bad token"}
                    elif request.get("type") == "ping":
                        reply = {"ok": True}
                    elif request.get("type") == "approval":
                        request = {k: v for k, v in request.items() if k != "token"}
                        decision = outer.decide(request)
                        reply = {"decision": decision if decision in ("allow", "deny", "timeout") else "deny"}
                    elif request.get("type") == "notice":
                        notice = {k: v for k, v in request.items() if k not in ("token", "type")}
                        if outer.notify:
                            threading.Thread(target=outer.notify, args=(notice,), daemon=True).start()
                        reply = {"ok": bool(outer.notify)}
                    else:
                        reply = {"error": "unknown request"}
                except Exception as exc:  # never crash the server thread
                    reply = {"error": type(exc).__name__}
                try:
                    self.wfile.write((json.dumps(reply) + "\n").encode("utf-8"))
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = False

        self.server = Server(("127.0.0.1", 0), Handler)   # port 0 = any free port
        self.port = self.server.server_address[1]

    def start(self) -> None:
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.app_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.app_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"port": self.port, "token": self.token, "pid": os.getpid()}), encoding="utf-8")
        os.replace(tmp, self.app_file)    # atomic: Warden never reads a half-written file

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        try:   # only remove the file if it is still ours
            if json.loads(self.app_file.read_text(encoding="utf-8")).get("token") == self.token:
                self.app_file.unlink()
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------------------
# Client side (used by the Warden gateway)
# ---------------------------------------------------------------------------

def _read_app_file(app_file: Path) -> dict[str, Any] | None:
    try:
        info = json.loads(app_file.read_text(encoding="utf-8"))
        return info if isinstance(info.get("port"), int) and info.get("token") else None
    except (OSError, ValueError):
        return None


async def _send(message: dict[str, Any], timeout: float, app_file: Path | None) -> dict[str, Any] | None:
    info = _read_app_file(app_file or default_app_file())
    if info is None:
        return None
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", info["port"]), 3)
        writer.write((json.dumps({**message, "token": info["token"]}, ensure_ascii=False) + "\n").encode("utf-8"))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout)
        return json.loads(line)
    except Exception as exc:
        log.info("Warden App not reachable (%s)", type(exc).__name__)
        return None
    finally:
        if writer is not None:
            writer.close()


async def ask_user(request: dict[str, Any], timeout: float = 60, app_file: Path | None = None) -> str | None:
    """Ask the user through the Warden App.

    Returns "allow", "deny", "timeout" (nobody clicked in time) or None (app not running / error).
    Only "allow" lets the action run.
    """
    reply = await _send({**request, "type": "approval", "timeout": timeout}, timeout + 5, app_file)
    decision = (reply or {}).get("decision")
    return decision if decision in ("allow", "deny", "timeout") else None


async def tell_user(notice: dict[str, Any], app_file: Path | None = None) -> bool:
    """Show the user a notice in the Warden App (attack found / action stopped).

    One-way: returns True if the app took it, False if the app is not running.
    """
    reply = await _send({**notice, "type": "notice"}, 3, app_file)
    return bool((reply or {}).get("ok"))


async def app_is_running(app_file: Path | None = None) -> bool:
    return bool((await _send({"type": "ping"}, 3, app_file) or {}).get("ok"))


# ---------------------------------------------------------------------------
# Opening the app when it is closed
# ---------------------------------------------------------------------------
# If Warden needs the user (a notice or an approval) and the app is closed, the
# gateway opens it MINIMIZED. This is not a Windows Startup entry: nothing runs
# until Warden actually needs the user. The app itself makes sure only one copy runs.

APP_SCRIPT = Path(__file__).resolve().parent / "warden_app.py"
RELAUNCH_PAUSE = 60          # seconds: never try to open the app more than once a minute
_last_launch = 0.0


def launch_app() -> bool:
    """Start the Warden App in the background. Never shares the gateway's stdout (the MCP channel)."""
    import subprocess
    import sys
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    python = pythonw if pythonw.exists() else Path(sys.executable)
    flags = 0
    if os.name == "nt":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    try:
        subprocess.Popen([str(python), str(APP_SCRIPT), "--background"], cwd=str(APP_SCRIPT.parent),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=flags, close_fds=True)
        return True
    except OSError as exc:
        log.info("Could not open the Warden App (%s)", type(exc).__name__)
        return False


async def reach_app(app_file: Path | None = None, wait_seconds: float = 20,
                    launch: Callable[[], bool] = launch_app) -> bool:
    """True if the app is running - opening it first if needed (at most once a minute)."""
    global _last_launch
    if await app_is_running(app_file):
        return True
    now = time.monotonic()
    if now - _last_launch < RELAUNCH_PAUSE:
        return False                               # we just tried; do not open window after window
    _last_launch = now
    log.info("The Warden App is closed - opening it")
    if not launch():
        return False
    deadline = now + wait_seconds
    while time.monotonic() < deadline:
        await asyncio.sleep(0.5)
        if await app_is_running(app_file):
            return True
    return False
