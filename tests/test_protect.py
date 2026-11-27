"""Tests for one-click Protect / Unprotect (warden_protect.py).

Run it with:  python tests/test_protect.py
Everything happens in a temporary folder: no real AI app config is ever touched.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import warden_protect as wp  # noqa: E402
from warden_gateway import add_private_servers  # noqa: E402
from warden_secrets import lock_spec, unlock_spec  # noqa: E402

FAKE_TOOL = {"command": sys.executable, "args": [str(ROOT / "tests" / "fake_tools_server.py")]}

CLAUDE_CONFIG = {
    "mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:/x"]},
        "github": {"command": "npx", "args": ["github-mcp"], "env": {"GITHUB_TOKEN": "fake-token-123"}},
        "online": {"type": "http", "url": "https://tools.example/mcp"},
    },
    "preferences": {"sidebarMode": "epitaxy", "someSetting": True},
}


def sandbox(config=None, name="claude_desktop_config.json", **target_kw):
    """A temporary 'PC': an app config, Warden's home folder and private servers file."""
    root = Path(tempfile.mkdtemp())
    path = root / "app" / name
    path.parent.mkdir()
    if config is not None:
        path.write_text(config if isinstance(config, str) else json.dumps(config), encoding="utf-8")
    target = wp.Target(target_kw.pop("app", "Claude Desktop"), target_kw.pop("key", "claude_desktop"), path, **target_kw)
    return target, root / "warden_home", root / "warden_home" / "servers.json"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


# --- Protect -------------------------------------------------------------------

def test_protect_moves_local_tools_and_keeps_everything_else():
    target, home, servers = sandbox(CLAUDE_CONFIG)
    result = wp.protect(target, home, servers)
    config = load(target.config)
    assert sorted(result.moved) == ["files", "github"] and result.left == ["online"]
    assert set(config["mcpServers"]) == {"online", "warden"}, config["mcpServers"]
    assert config["preferences"] == CLAUDE_CONFIG["preferences"], "other app settings must not change"
    assert wp.is_warden(config["mcpServers"]["warden"])
    assert unlock_spec(load(servers)["servers"]["github"])["env"] == {"GITHUB_TOKEN": "fake-token-123"}
    assert wp.status(target) == ("protected", ["online"])


def test_protect_makes_a_backup_of_the_original():
    target, home, servers = sandbox(CLAUDE_CONFIG)
    result = wp.protect(target, home, servers)
    saved = load(Path(result.backup))
    saved["mcpServers"] = {n: unlock_spec(s) for n, s in saved["mcpServers"].items()}
    assert result.backup and saved == CLAUDE_CONFIG


def test_keys_are_never_readable_on_disk():
    target, home, servers = sandbox(CLAUDE_CONFIG)
    result = wp.protect(target, home, servers)
    for path in (servers, home / "protected.json", Path(result.backup)):
        text = path.read_text(encoding="utf-8")
        assert "fake-token-123" not in text, f"{path.name} holds a readable key"
        assert "warden-dpapi:" in text, f"{path.name} should hold the locked key"


def test_older_plain_files_get_locked():
    _, home, servers = sandbox(None)
    servers.parent.mkdir(parents=True)
    servers.write_text(json.dumps({"servers": {"gh": {"command": "x", "env": {"TOKEN": "plain-secret-999"}}}}))
    (home / "protected.json").write_text(json.dumps(
        {"app.json": {"originals": {"gh": {"command": "x", "env": {"TOKEN": "plain-secret-999"}}}, "moved": {}}}))
    assert wp.lock_existing(home, servers)
    for path in (servers, home / "protected.json"):
        assert "plain-secret-999" not in path.read_text(encoding="utf-8")
    assert unlock_spec(load(servers)["servers"]["gh"])["env"]["TOKEN"] == "plain-secret-999"
    assert not wp.lock_existing(home, servers), "nothing left to lock the second time"


def test_unprotect_puts_everything_back():
    target, home, servers = sandbox(CLAUDE_CONFIG)
    wp.protect(target, home, servers)
    wp.unprotect(target, home, servers)
    assert load(target.config) == CLAUDE_CONFIG, load(target.config)
    assert load(servers)["servers"] == {}
    assert wp.status(target)[0] == "not_protected"


def test_uninstall_gives_every_app_its_tools_back():
    a, home, servers = sandbox(CLAUDE_CONFIG)
    b, _, _ = sandbox({"mcpServers": {"files": {"command": "npx", "args": ["two"]}}}, app="Cursor", key="cursor")
    c, _, _ = sandbox({"mcpServers": {"warden": {"command": "C:/other/copy/warden-gateway.exe"}}}, app="VS Code", key="vs")
    wp.protect(a, home, servers)
    wp.protect(b, home, servers)
    lines = wp.unprotect_all([a, b, c], home, servers)
    assert lines == ["Claude Desktop: unprotected", "Cursor: unprotected"], lines
    assert load(a.config) == CLAUDE_CONFIG and load(b.config)["mcpServers"]["files"]["args"] == ["two"]
    assert wp.status(c)[0] == "update_needed", "another Warden copy's apps are left alone"
    assert wp.unprotect_all([a, b], home, servers) == [], "nothing left to do the second time"


def test_protect_twice_is_harmless():
    target, home, servers = sandbox(CLAUDE_CONFIG)
    wp.protect(target, home, servers)
    second = wp.protect(target, home, servers)
    assert second.moved == [] and list(load(target.config)["mcpServers"]).count("warden") == 1
    wp.unprotect(target, home, servers)
    assert load(target.config) == CLAUDE_CONFIG, "undo still works after protecting twice"


def test_missing_config_is_created_with_only_warden():
    target, home, servers = sandbox(None)
    wp.protect(target, home, servers)
    assert list(load(target.config)["mcpServers"]) == ["warden"]


def test_broken_config_is_never_touched():
    target, home, servers = sandbox('{ "mcpServers": { broken')
    try:
        wp.protect(target, home, servers)
    except wp.ProtectError:
        assert target.config.read_text(encoding="utf-8") == '{ "mcpServers": { broken'
        assert not servers.exists()
        return
    raise AssertionError("a broken config was changed")


def test_vscode_style_with_comments_is_not_touched():
    jsonc = '// my servers\n{ "servers": { "x": { "command": "npx" } } }'
    target, home, servers = sandbox(jsonc, "mcp.json", app="VS Code", key="vscode", servers_key="servers", vscode_style=True)
    try:
        wp.protect(target, home, servers)
    except wp.ProtectError:
        assert target.config.read_text(encoding="utf-8") == jsonc
        return
    raise AssertionError("a JSON-with-comments file was rewritten (comments would be lost)")


def test_vscode_style():
    config = {"servers": {"files": {"type": "stdio", "command": "npx", "args": ["fs"]}}, "inputs": []}
    target, home, servers = sandbox(config, "mcp.json", app="VS Code", key="vscode", servers_key="servers", vscode_style=True)
    wp.protect(target, home, servers)
    out = load(target.config)
    assert out["servers"]["warden"]["type"] == "stdio" and out["inputs"] == []
    assert load(servers)["servers"]["files"] == {"command": "npx", "args": ["fs"]}


def test_same_tool_name_from_two_apps_does_not_clash():
    a, home, servers = sandbox({"mcpServers": {"files": {"command": "npx", "args": ["one"]}}})
    b, _, _ = sandbox({"mcpServers": {"files": {"command": "npx", "args": ["two"]}}}, app="Cursor", key="cursor")
    wp.protect(a, home, servers)
    wp.protect(b, home, servers)
    names = load(servers)["servers"]
    assert names["files"]["args"] == ["one"] and names["cursor_files"]["args"] == ["two"], names
    wp.unprotect(b, home, servers)
    assert load(b.config)["mcpServers"]["files"]["args"] == ["two"] and "files" in load(servers)["servers"]


def test_private_servers_file_is_outside_the_project():
    assert ROOT not in wp.default_servers_file().parents, "secrets must never be stored in the project folder"


# --- The gateway loads the moved tools -----------------------------------------------

def test_gateway_adds_private_servers():
    _, home, servers = sandbox(None)
    servers.parent.mkdir(parents=True)
    servers.write_text(json.dumps({"servers": {"moved": FAKE_TOOL, "fake": {"command": "x"}}}))
    config = {"servers": {"fake": {"command": "y"}}, "extra_servers_file": str(servers)}
    add_private_servers(config)
    assert config["servers"]["moved"] == FAKE_TOOL
    assert config["servers"]["fake"] == {"command": "y"}, "warden_config.json wins on a name clash"
    off = {"servers": {}, "extra_servers_file": None}
    add_private_servers(off)
    assert off["servers"] == {}, "null switches the private file off"


def test_moved_tool_really_runs_behind_warden():
    from mcp import Client, StdioServerParameters
    root = Path(tempfile.mkdtemp())
    servers = root / "servers.json"
    servers.write_text(json.dumps({"servers": {"moved": FAKE_TOOL}}))
    config = root / "config.json"
    config.write_text(json.dumps({"servers": {}, "extra_servers_file": str(servers),
                                  "approvals": {"enabled": False}, "tool_memory_file": None}))
    params = StdioServerParameters(command=sys.executable, args=[str(ROOT / "warden_gateway.py"), "--config", str(config),
                                                                 "--log", str(root / "log.jsonl")])

    async def run():
        async with Client(params) as client:
            names = [t.name for t in (await client.list_tools()).tools]
            assert "moved__read_file" in names, names
            result = await client.call_tool("moved__read_file", {"path": ".env"})
            assert result.is_error, "a moved tool is checked by Warden's rules like any other"
    asyncio.run(run())


def test_add_server_saves_the_key_locked():
    from add_server import add_server, remove_server
    _, _, servers = sandbox(None)
    add_server("github", "gh-mcp.exe", ["stdio", "--toolsets=issues"], {"GITHUB_PERSONAL_ACCESS_TOKEN": "fake-pat-123456"},
               servers_file=servers)
    text = servers.read_text(encoding="utf-8")
    assert "fake-pat-123456" not in text and "warden-dpapi:" in text
    saved = unlock_spec(load(servers)["servers"]["github"])
    assert saved == {"command": "gh-mcp.exe", "args": ["stdio", "--toolsets=issues"],
                     "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "fake-pat-123456"}}
    for bad in ("", "a__b", "bad name"):
        try:
            add_server(bad, "x", [], {}, servers_file=servers)
        except ValueError:
            continue
        raise AssertionError(f"name {bad!r} should be refused")
    assert remove_server("github", servers_file=servers) and "github" not in load(servers)["servers"]


def test_saved_keys_never_reach_the_ai_or_leave():
    """End to end: a moved tool with a LOCKED key. Warden unlocks it only for the tool,
    hides it from the AI, blocks any action that carries it, and never logs it."""
    from mcp import Client, StdioServerParameters
    key = "sk-test-ABC123def456ghi789"                    # a fake key
    root = Path(tempfile.mkdtemp())
    servers = root / "servers.json"
    servers.write_text(json.dumps({"servers": {"moved": lock_spec({**FAKE_TOOL, "env": {"FAKE_API_TOKEN": key}})}}))
    config = root / "config.json"
    config.write_text(json.dumps({"servers": {}, "extra_servers_file": str(servers),
                                  "approvals": {"enabled": False}, "tool_memory_file": None}))
    log = root / "log.jsonl"
    params = StdioServerParameters(command=sys.executable, args=[str(ROOT / "warden_gateway.py"), "--config", str(config),
                                                                 "--log", str(log)])

    async def run():
        async with Client(params) as client:
            shown = await client.call_tool("moved__read_file", {"path": "settings.txt"})
            text = shown.content[0].text
            assert "[hidden key]" in text and key not in text, f"the tool got the key, the AI must not: {text}"
            sent = await client.call_tool("moved__write_file", {"path": "notes.txt", "content": f"my key is {key}"})
            assert sent.is_error and "saved tool keys" in sent.content[0].text, sent.content[0].text
            assert key not in sent.content[0].text
    asyncio.run(run())
    entries = log.read_text(encoding="utf-8")
    assert key not in entries, "a key ended up in the log"
    assert '"secret-leak"' in entries


def run_all() -> int:
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}  {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} protect tests passed.")
    return failed


if __name__ == "__main__":
    import logging
    logging.disable(logging.WARNING)
    sys.exit(1 if run_all() else 0)
