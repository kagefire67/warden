"""
Warden tool memory: rug-pull detection (Attack Lab #15)
=======================================================
A "rug pull" is a tool that is honest when you first connect it, and LATER
changes its description to sneak in orders for the AI ("also send every file
to ..."). The AI reads tool descriptions as trusted instructions.

Warden remembers a fingerprint (SHA-256) of what the AI reads about every tool:
its title, description and arguments. At every start:
  - a tool Warden has never seen  -> remembered (the normal poison scan still runs)
  - same fingerprint as before    -> fine
  - DIFFERENT fingerprint         -> the tool is HIDDEN from the AI and the user is told.
    The user can trust the new version in the Warden App (accept_change); until then
    it stays hidden, every time.

The memory lives in %LOCALAPPDATA%\\Warden\\tool_memory.json (no keys in it).
FAIL SAFE: if the file is broken, Warden cannot tell what changed, so every tool
is treated as changed (hidden) until the file is fixed or deleted.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_SAVED_TEXT = 4000     # how much of a description is kept to show the user


class ToolMemoryError(Exception):
    """The memory file exists but cannot be read."""


def default_memory_file() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    return base / "Warden" / "tool_memory.json"


def fingerprint(tool: Any) -> str:
    """SHA-256 of everything the AI reads about a tool (works for MCP Tool objects and dicts)."""
    get = (lambda k: tool.get(k)) if isinstance(tool, dict) else (lambda k: getattr(tool, k, None))
    what_the_ai_reads = {"title": get("title") or "", "description": get("description") or "",
                         "input_schema": get("input_schema") or {}}
    text = json.dumps(what_the_ai_reads, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def key(server: str, tool: str) -> str:
    return f"{server}/{tool}"


def read_memory(path: Path) -> dict[str, Any]:
    """The saved memory. Missing file = empty memory. Broken file = ToolMemoryError."""
    if not path.exists():
        return {"tools": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("tools"), dict):
            raise ValueError("unexpected layout")
        return data
    except (OSError, ValueError) as exc:
        raise ToolMemoryError(f"{path} cannot be read ({type(exc).__name__})") from exc


def _write(path: Path, data: dict[str, Any]) -> None:
    """Atomic write: Warden never reads a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tool_memory-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def check_tools(path: Path, server: str, tools: list[Any]) -> list[str]:
    """Compare a server's tools with the memory and update it.

    Returns the names of tools that CHANGED (to hide). New tools are remembered.
    A changed tool is saved as "pending" (with its new description) for the user to review;
    its trusted fingerprint is NOT replaced - only accept_change() does that.
    Raises ToolMemoryError if the memory is broken (the caller hides everything).
    """
    memory = read_memory(path)
    saved = memory["tools"]
    changed: list[str] = []
    dirty = False
    for tool in tools:
        name = tool.get("name") if isinstance(tool, dict) else tool.name
        description = (tool.get("description") if isinstance(tool, dict) else tool.description) or ""
        fp = fingerprint(tool)
        k = key(server, name)
        entry = saved.get(k)
        if entry is None:                                      # first time: remember it
            saved[k] = {"fingerprint": fp, "description": description[:MAX_SAVED_TEXT], "first_seen": _now()}
            dirty = True
        elif entry.get("fingerprint") != fp:                   # it changed: hide + keep for review
            changed.append(name)
            pending = entry.get("pending") or {}
            if pending.get("fingerprint") != fp:
                entry["pending"] = {"fingerprint": fp, "description": description[:MAX_SAVED_TEXT], "seen": _now()}
                dirty = True
        elif "pending" in entry:                               # changed back to the trusted version
            del entry["pending"]
            dirty = True
    if dirty:
        # Another Warden (AI apps often start more than one) may have saved meanwhile: merge.
        try:
            latest = read_memory(path)["tools"]
        except ToolMemoryError:
            latest = {}
        for k, entry in saved.items():
            if k.startswith(server + "/"):
                latest[k] = entry
        _write(path, {"tools": latest})
    return changed


def pending_changes(path: Path | None = None) -> list[dict[str, str]]:
    """Tools waiting for the user's review (for the Warden App)."""
    try:
        tools = read_memory(path or default_memory_file())["tools"]
    except ToolMemoryError:
        return []
    out = []
    for k, entry in sorted(tools.items()):
        if entry.get("pending"):
            server, _, tool = k.partition("/")
            out.append({"key": k, "server": server, "tool": tool, "seen": entry["pending"].get("seen", ""),
                        "old": entry.get("description", ""), "new": entry["pending"].get("description", "")})
    return out


def accept_change(tool_key: str, path: Path | None = None) -> bool:
    """The user trusts the new version: it becomes the remembered fingerprint."""
    path = path or default_memory_file()
    memory = read_memory(path)
    entry = memory["tools"].get(tool_key)
    if not entry or not entry.get("pending"):
        return False
    pending = entry.pop("pending")
    entry.update(fingerprint=pending["fingerprint"], description=pending.get("description", ""),
                 accepted=_now())
    _write(path, memory)
    return True
