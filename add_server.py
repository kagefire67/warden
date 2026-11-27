"""
Add a tool server behind Warden, with its key LOCKED.

    python add_server.py NAME --command PROGRAM [--arg ARG ...] [--secret ENV_NAME ...]

Example (GitHub's official MCP tool, issues only):
    python add_server.py github --command "C:/.../github-mcp-server.exe" ^
        --arg stdio --arg=--toolsets=issues --secret GITHUB_PERSONAL_ACCESS_TOKEN

For every --secret you are asked to paste the key. It is NOT shown while you paste,
never printed, never logged, and saved only LOCKED (Windows DPAPI) in Warden's
private servers file (%LOCALAPPDATA%\\Warden\\servers.json). Restart your AI app afterwards.

    python add_server.py NAME --remove      takes the server out again
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from warden_protect import ProtectError, default_servers_file, read_json, write_json
from warden_secrets import SecretError, can_lock, lock_spec

NAME_SEPARATOR = "__"   # Warden shows tools as <server>__<tool>, so names must not contain it


def add_server(name: str, command: str, args: list[str], secrets: dict[str, str],
               servers_file: Path | None = None) -> None:
    """Save one server (keys locked) in Warden's private file. Raises ValueError/SecretError/ProtectError."""
    if not name or NAME_SEPARATOR in name or not name.replace("-", "").replace("_", "").isalnum():
        raise ValueError("Use a simple name like 'github' (letters, digits, - or _)")
    if secrets and not can_lock():
        raise SecretError("Keys can only be locked on Windows, so nothing was saved")
    servers_file = servers_file or default_servers_file()
    private = read_json(servers_file, {"servers": {}})
    spec: dict = {"command": command, "args": args}
    if secrets:
        spec["env"] = dict(secrets)
    private.setdefault("servers", {})[name] = lock_spec(spec)
    write_json(servers_file, private)


def remove_server(name: str, servers_file: Path | None = None) -> bool:
    servers_file = servers_file or default_servers_file()
    private = read_json(servers_file, {"servers": {}})
    if name not in private.get("servers", {}):
        return False
    del private["servers"][name]
    write_json(servers_file, private)
    return True


def main() -> int:
    p = argparse.ArgumentParser(description="Add a tool server behind Warden (keys are locked).")
    p.add_argument("name")
    p.add_argument("--command")
    p.add_argument("--arg", action="append", default=[], help="one argument for the program (repeat)")
    p.add_argument("--secret", action="append", default=[], help="name of an env key to ask for (repeat)")
    p.add_argument("--remove", action="store_true")
    a = p.parse_args()

    try:
        if a.remove:
            print(f"Removed '{a.name}'." if remove_server(a.name) else f"'{a.name}' was not set up.")
            return 0
        if not a.command:
            p.error("--command is required")
        secrets = {}
        for env_name in a.secret:
            value = getpass.getpass(f"Paste {env_name} (it stays hidden), then press Enter: ").strip()
            if not value:
                print("Nothing pasted - stopped, nothing saved.")
                return 1
            secrets[env_name] = value
        add_server(a.name, a.command, a.arg, secrets)
    except (ValueError, SecretError, ProtectError) as exc:
        print(f"Not saved: {exc}")
        return 1
    print(f"Saved '{a.name}' behind Warden" + (" with its key locked." if secrets else "."))
    print("Fully restart your AI app (also from the system tray) to load it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
