"""
Warden one-click Protect (Stage 9)
==================================
"Protect" for an AI app (Claude Desktop, Cursor, VS Code, Windsurf):

  1. BACKUP   - copies the app's MCP config file to %LOCALAPPDATA%\\Warden\\backups
  2. MOVE     - every local (stdio) tool server the app had is moved behind Warden,
                into Warden's PRIVATE servers file (%LOCALAPPDATA%\\Warden\\servers.json).
                It is private because server settings can hold API keys - they must
                never land in the project folder that goes to GitHub.
  3. REPLACE  - the app's config then lists only Warden (all other settings untouched)
  4. RECORD   - remembers what was moved, so "Unprotect" can put it all back.

Safety rules:
  - Keys are LOCKED: every "env" value Warden saves (servers.json, protected.json and the
    backups) is encrypted with Windows DPAPI (see warden_secrets.py). Unprotect unlocks
    them again, because the AI app needs the real values back.
  - A config that cannot be read (broken JSON, comments) is NEVER touched.
  - Files are written atomically (temp file + rename) and re-checked after writing.
  - Online (http/sse) servers cannot be moved behind Warden yet; they are left
    where they are and reported as "still skipping Warden".

All paths can be passed in, so tests run on temporary copies only.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from glob import glob
from pathlib import Path
from typing import Any

from warden_secrets import SecretError, has_plain_keys, lock_servers, lock_spec, unlock_spec

WARDEN_DIR = Path(__file__).resolve().parent


def warden_home() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    return base / "Warden"


def default_servers_file() -> Path:
    return warden_home() / "servers.json"


class ProtectError(Exception):
    """Something is not safe to change - nothing was modified."""


@dataclass
class Target:
    name: str          # shown to the user, e.g. "Claude Desktop"
    key: str           # short id, e.g. "claude_desktop"
    config: Path       # the app's MCP config file (may not exist yet)
    servers_key: str = "mcpServers"   # VS Code uses "servers"
    vscode_style: bool = False        # VS Code entries need "type": "stdio"


@dataclass
class Result:
    moved: list[str] = field(default_factory=list)       # now protected by Warden
    left: list[str] = field(default_factory=list)        # could not be moved (online servers)
    backup: str | None = None


# ---------------------------------------------------------------------------
# Finding the AI apps on this PC
# ---------------------------------------------------------------------------

def detect_targets() -> list[Target]:
    appdata, local, home = os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", ""), Path.home()
    targets: list[Target] = []

    claude_dirs = [Path(appdata, "Claude")] + [Path(p) for p in glob(os.path.join(local, "Claude-Data", "*"))]
    claude_dirs += [Path(p) for p in glob(os.path.join(local, "Packages", "*Claude*", "LocalCache", "Roaming", "Claude"))]
    # Claude Desktop can leave several folders behind (normal + Store install). Show only the
    # config files that really exist; if there is none yet, offer the first folder found.
    claude = [d / "claude_desktop_config.json" for d in claude_dirs if d.is_dir()]
    existing = [p for p in claude if p.exists()]
    for path in existing or claude[:1]:
        targets.append(Target("Claude Desktop", "claude_desktop", path))
    if (home / ".cursor").is_dir():
        targets.append(Target("Cursor", "cursor", home / ".cursor" / "mcp.json"))
    if Path(appdata, "Code", "User").is_dir():
        targets.append(Target("VS Code", "vscode", Path(appdata, "Code", "User", "mcp.json"), "servers", True))
    if (home / ".codeium" / "windsurf").is_dir():
        targets.append(Target("Windsurf", "windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"))
    return targets


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def is_warden(spec: Any) -> bool:
    if not isinstance(spec, dict):
        return False
    return "warden_gateway" in str(spec.get("command", "")) or any("warden_gateway" in str(a) for a in spec.get("args", []))


def is_local_server(spec: Any) -> bool:
    """Warden can only sit in front of servers it can start itself (stdio = has a command)."""
    return isinstance(spec, dict) and bool(spec.get("command")) and spec.get("type", "stdio") == "stdio"


def warden_entry(vscode_style: bool = False) -> dict[str, Any]:
    python = WARDEN_DIR / ".venv" / "Scripts" / "python.exe"
    if not python.exists():
        python = Path(sys.executable.replace("pythonw.exe", "python.exe"))
    entry = {"command": python.as_posix(), "args": [(WARDEN_DIR / "warden_gateway.py").as_posix()]}
    return {"type": "stdio", **entry} if vscode_style else entry


def read_json(path: Path, default: Any) -> Any:
    """Read a JSON file. Missing file -> default. Broken file -> ProtectError (never touch it)."""
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ProtectError(f"{path.name} could not be read ({type(exc).__name__}), so Warden did not change it.")


def write_json(path: Path, data: Any) -> None:
    """Atomic write + read-back check."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".warden-tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    json.loads(tmp.read_text(encoding="utf-8"))
    os.replace(tmp, path)


def backup(target: Target, data: dict[str, Any], backup_dir: Path) -> str | None:
    """Save a copy of the app's config before changing it - with its keys LOCKED,
    so the backup folder never holds readable keys."""
    if not target.config.exists():
        return None
    backup_dir.mkdir(parents=True, exist_ok=True)
    dest = backup_dir / f"{target.key}-{datetime.now():%Y%m%d-%H%M%S-%f}.json"
    safe = {**data, target.servers_key: lock_servers(data.get(target.servers_key))}
    write_json(dest, safe)
    return str(dest)


def lock_existing(home: Path | None = None, servers_file: Path | None = None) -> bool:
    """Lock keys in files written by an older Warden (plain text). True if anything changed.
    The Warden App calls this when it starts."""
    home = home or warden_home()
    servers_file = servers_file or default_servers_file()
    records_file = home / "protected.json"
    changed = False
    private = read_json(servers_file, None)
    if isinstance(private, dict) and has_plain_keys(private.get("servers")):
        write_json(servers_file, {**private, "servers": lock_servers(private["servers"])})
        changed = True
    records = read_json(records_file, None)
    if isinstance(records, dict) and any(has_plain_keys(r.get("originals")) for r in records.values() if isinstance(r, dict)):
        write_json(records_file, {k: ({**r, "originals": lock_servers(r.get("originals"))} if isinstance(r, dict) else r)
                                  for k, r in records.items()})
        changed = True
    return changed


# ---------------------------------------------------------------------------
# Status, Protect, Unprotect
# ---------------------------------------------------------------------------

def status(target: Target) -> tuple[str, list[str]]:
    """("protected" | "not_protected" | "unreadable", [servers that skip Warden])."""
    try:
        data = read_json(target.config, {})
    except ProtectError:
        return "unreadable", []
    servers = data.get(target.servers_key) or {}
    has_warden = any(is_warden(s) for s in servers.values())
    bypass = [n for n, s in servers.items() if not is_warden(s)]
    return ("protected" if has_warden else "not_protected"), bypass


def protect(target: Target, home: Path | None = None, servers_file: Path | None = None) -> Result:
    home = home or warden_home()
    servers_file = servers_file or default_servers_file()
    records_file = home / "protected.json"

    data = read_json(target.config, {})                 # raises if broken -> nothing changed
    if not isinstance(data, dict):
        raise ProtectError(f"{target.config.name} has an unexpected format, so Warden did not change it.")
    private = read_json(servers_file, {"servers": {}})
    records = read_json(records_file, {})

    servers = data.get(target.servers_key) or {}
    result = Result(backup=backup(target, data, home / "backups"))
    record = records.get(str(target.config), {"app": target.name, "originals": {}, "moved": {}})

    keep: dict[str, Any] = {}
    for name, spec in servers.items():
        if is_warden(spec):
            continue
        if not is_local_server(spec):
            keep[name] = spec                          # online server: cannot sit behind Warden yet
            result.left.append(name)
            continue
        # Pick a name in Warden's file: no "__" (Warden's separator), no clash with other apps' servers.
        new_name = name.replace("__", "_")
        if new_name in private["servers"] and not _same_server(private["servers"][new_name], spec):
            new_name = f"{target.key}_{new_name}"
        private["servers"][new_name] = lock_spec(_stdio_only(spec))     # keys locked on disk
        record["originals"][name] = lock_spec(spec)
        record["moved"][name] = new_name
        result.moved.append(name)

    keep["warden"] = warden_entry(target.vscode_style)
    data[target.servers_key] = keep

    # Order matters: save Warden's side first, so a moved server is never lost.
    write_json(servers_file, private)
    records[str(target.config)] = {**record, "backup": result.backup, "time": datetime.now().isoformat(timespec="seconds")}
    write_json(records_file, records)
    write_json(target.config, data)
    return result


def unprotect(target: Target, home: Path | None = None, servers_file: Path | None = None) -> Result:
    home = home or warden_home()
    servers_file = servers_file or default_servers_file()
    records_file = home / "protected.json"

    data = read_json(target.config, {})
    if not isinstance(data, dict):
        raise ProtectError(f"{target.config.name} has an unexpected format, so Warden did not change it.")
    private = read_json(servers_file, {"servers": {}})
    records = read_json(records_file, {})
    record = records.pop(str(target.config), {"originals": {}, "moved": {}})

    # Unlock the keys first: the app needs the real values. If that fails, change nothing.
    try:
        originals = {name: unlock_spec(spec) for name, spec in record["originals"].items()}
    except SecretError as exc:
        raise ProtectError(f"Warden could not unlock the saved keys ({exc}), so nothing was changed.")

    result = Result(backup=backup(target, data, home / "backups"))
    servers = {n: s for n, s in (data.get(target.servers_key) or {}).items() if not is_warden(s)}
    for name, spec in originals.items():
        servers.setdefault(name, spec)                 # never overwrite something the user added since
        private["servers"].pop(record["moved"].get(name, ""), None)
        result.moved.append(name)
    data[target.servers_key] = servers

    write_json(target.config, data)                    # give the app its servers back first
    write_json(servers_file, private)
    write_json(records_file, records)
    return result


def _same_server(saved: Any, spec: dict[str, Any]) -> bool | None:
    """Is a server already in Warden's file the same as this one? (None = cannot tell)
    Locked keys look different every time, so compare the unlocked values."""
    try:
        return unlock_spec(saved) == _stdio_only(spec)
    except SecretError:
        return None


def _stdio_only(spec: dict[str, Any]) -> dict[str, Any]:
    """The parts Warden needs to start a server itself."""
    return {k: v for k, v in spec.items() if k in ("command", "args", "env")}
