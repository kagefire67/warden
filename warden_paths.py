"""
Where Warden's files live - from source and when installed.

Two ways Warden runs:
  - FROM SOURCE (this project folder, with Python): everything lives next to the code,
    as before. Commands are "python warden_gateway.py" etc.
  - INSTALLED (WardenSetup.exe, built with PyInstaller): the program files are read-only
    resources; everything Warden WRITES (settings, log, lab reports) goes to
    %LOCALAPPDATA%\\Warden. Commands are the two .exe files:
        Warden.exe          the Warden App (window)
        warden-gateway.exe  the gateway the AI app starts (plus helper modes, see warden_main.py)
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

INSTALLED = bool(getattr(sys, "frozen", False))

# Read-only resources (ui/, rules.json, attack_lab/ scenarios).
CODE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
# The folder that holds the .exe files (installed) or the project (from source).
PROGRAM_DIR = Path(sys.executable).resolve().parent if INSTALLED else CODE_DIR
# Everything Warden writes.
USER_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share") / "Warden"
DATA_DIR = USER_DIR if INSTALLED else CODE_DIR

CONFIG = DATA_DIR / "warden_config.json"
LOG = DATA_DIR / "logs" / "actions.jsonl"
RULES = CODE_DIR / "rules.json"
UI_DIR = CODE_DIR / "ui"
LAB_DIR = CODE_DIR / "attack_lab"
LAB_REPORT_DIR = (USER_DIR / "attack_lab") if INSTALLED else LAB_DIR

GATEWAY_EXE = PROGRAM_DIR / "warden-gateway.exe"
APP_EXE = PROGRAM_DIR / "Warden.exe"


def ensure_config() -> Path:
    """Installed Warden: create the user's settings file from the bundled default the first time."""
    if INSTALLED and not CONFIG.exists():
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(CODE_DIR / "warden_config.default.json", CONFIG)
    return CONFIG


def _python(windowless: bool = False) -> str:
    """The Python to use when running from source (pythonw = no console window)."""
    exe = Path(sys.executable)
    if windowless:
        w = exe.with_name("pythonw.exe")
        return str(w if w.exists() else exe)
    return str(exe.with_name("python.exe")) if exe.name.lower() == "pythonw.exe" else str(exe)


def gateway_command() -> list[str]:
    """How an AI app should start Warden's gateway."""
    if INSTALLED:
        return [str(GATEWAY_EXE)]
    venv = CODE_DIR / ".venv" / "Scripts" / "python.exe"
    return [str(venv if venv.exists() else _python()), str(CODE_DIR / "warden_gateway.py")]


def app_command(background: bool = False) -> list[str]:
    """How to open the Warden App."""
    base = [str(APP_EXE)] if INSTALLED else [_python(windowless=True), str(CODE_DIR / "warden_app.py")]
    return base + (["--background"] if background else [])


def lab_command(use_ai: bool = False) -> list[str]:
    """How to run the Attack Lab (prints its progress)."""
    base = [str(GATEWAY_EXE), "lab"] if INSTALLED else [_python(), str(LAB_DIR / "run_lab.py")]
    return base + (["--ai"] if use_ai else [])


def lab_server_command() -> list[str]:
    """How the lab starts its fake tool server."""
    return [str(GATEWAY_EXE), "lab-server"] if INSTALLED else [_python(), str(LAB_DIR / "lab_server.py")]
