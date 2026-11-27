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
sys.path.insert(0, str(ROOT))
FAKE_SERVER = str(ROOT / "tests" / "fake_tools_server.py")


def has_hidden_chars(text: str) -> bool:
    return any(0xE0000 <= ord(c) <= 0xE007F for c in text)


def texts(result: types.CallToolResult) -> list[str]:
    return [b.text for b in result.content if isinstance(b, types.TextContent)]


def warden_params(tmp_path: Path, extra_config: dict | None = None) -> tuple[StdioServerParameters, Path]:
    config_path = tmp_path / "config.json"
    log_path = tmp_path / "actions.jsonl"
    config = {
        "servers": {"fake": {"command": sys.executable, "args": [FAKE_SERVER]}},
        # Never talk to the user's real Warden App from tests: use a private (missing) app file.
        "approvals": {"enabled": True, "timeout_seconds": 5, "app_file": str(tmp_path / "no_app.json")},
        # ...and never load the user's real protected servers either.
        "extra_servers_file": None,
        # ...or touch the user's real tool memory (rug-pull detection).
        "tool_memory_file": str(tmp_path / "tool_memory.json"),
    }
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
        assert "attack_email.txt" in parts[0] and "billing-update" not in parts[0], parts[0]
        print("PASS  the warning tells the AI the story, without repeating the attacker's words")

        result = await client.call_tool("fake__write_file", {"path": "todo.txt", "content": "x"})
        assert result.is_error and "hidden attack" in texts(result)[0], result
        assert "attack_email.txt" in texts(result)[0], "the block story names the content that caused the lock"
        print("PASS  after the attack, writing is blocked (taint), and the story says why")

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
    assert "billing-update@external.example" in attack["story"], "the user's story quotes the hidden line"
    assert flagged[0].get("story") and calls[4].get("story") and calls[5].get("story")
    print("PASS  stories are written to the log for attacks, blocks, asks and poisoned tools")
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


async def approval_session(tmp_path: Path) -> None:
    """Stage 8: 'ask' really asks the user through the Warden App (a test app that answers automatically)."""
    from warden_approval import ApprovalServer

    asked = []

    def decide(request):                 # pretend user: allows the recruiter email, denies everything else
        asked.append(request)
        return "allow" if "recruiter" in request.get("arguments", "") else "deny"

    notices = []
    app = ApprovalServer(decide, app_file=tmp_path / "app.json", notify=notices.append)
    app.start()
    params, log_path = warden_params(tmp_path, {"approvals": {"enabled": True, "timeout_seconds": 5,
                                                              "app_file": str(tmp_path / "app.json")}})
    try:
        async with Client(params) as client:
            result = await client.call_tool("fake__send_email", {"to": "recruiter@talent.example", "subject": "CV", "body": "hi"})
            assert not result.is_error and "sent (fake)" in texts(result)[0], result
            print("PASS  approvals: you click Allow -> the action runs")

            result = await client.call_tool("fake__delete_file", {"path": "old.txt"})
            assert result.is_error and "You chose Deny" in texts(result)[0], result
            print("PASS  approvals: you click Deny -> blocked, and the AI is told why")

            assert "The AI tried to send an email to recruiter@talent.example" in asked[0]["story"]
            print("PASS  approvals: the popup shows the plain-language story")

            result = await client.call_tool("fake__read_file", {"path": "attack_email.txt"})
            result = await client.call_tool("fake__send_email", {"to": "recruiter@talent.example", "subject": "x", "body": "x"})
            assert result.is_error and len(asked) == 2, "after an attack, the lockdown is never offered for approval"
            print("PASS  approvals: the lockdown after an attack cannot be approved")

            for _ in range(50):                 # notices are sent in the background
                if len(notices) >= 2:
                    break
                await asyncio.sleep(0.1)
    finally:
        app.stop()
    kinds = [(n["kind"], n["tool"]) for n in notices]
    assert kinds == [("attack", "read_file"), ("blocked", "send_email")], kinds
    assert notices[0]["title"] and notices[0]["story"] and notices[1]["story"], notices
    print("PASS  notices: the USER is told about the attack and the stopped action (not after their own Deny)")

    entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    approved = next(e for e in entries if e.get("approval") == "allow")
    assert approved["status"] == "ok" and "user-approved" in approved["rules"] and approved["story"].startswith("The AI tried")
    assert any(e.get("approval") == "deny" and e["status"] == "blocked" for e in entries)
    print("PASS  approvals: Allow and Deny are written to the log")


async def rug_pull_session(tmp_path: Path) -> None:
    """Rug pull: a tool that changes its description after the first start is hidden and logged."""
    from warden_approval import ApprovalServer
    from warden_toolmemory import accept_change, pending_changes

    notices = []
    app = ApprovalServer(lambda req: "deny", app_file=tmp_path / "app.json", notify=notices.append)
    app.start()
    approvals = {"approvals": {"enabled": True, "timeout_seconds": 5, "app_file": str(tmp_path / "app.json")}}
    memory = tmp_path / "tool_memory.json"
    try:
        params, log_path = warden_params(tmp_path, approvals)
        async with Client(params) as client:              # day 1: honest tool, remembered
            assert "fake__read_file" in [t.name for t in (await client.list_tools()).tools]

        params, log_path = warden_params(tmp_path, {**approvals, "servers": {"fake": {
            "command": sys.executable, "args": [FAKE_SERVER], "env": {"FAKE_RUG_PULL": "1"}}}})
        async with Client(params) as client:              # later: same tool, changed description
            names = [t.name for t in (await client.list_tools()).tools]
            assert "fake__read_file" not in names and "fake__send_email" in names, names
            for _ in range(50):
                if notices:
                    break
                await asyncio.sleep(0.1)
        print("PASS  rug pull: a tool that changed its description is hidden from the AI")

        assert notices and notices[0]["kind"] == "changed" and "read_file" in notices[0]["title"], notices
        print("PASS  rug pull: the user gets a notice")

        entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        changed = [e for e in entries if e.get("event") == "tool_changed"]
        assert changed and changed[0]["tool"] == "read_file" and "rug-pull" in changed[0]["rules"], changed
        pending = pending_changes(memory)
        assert [p["key"] for p in pending] == ["fake/read_file"] and "traceability" in pending[0]["new"]
        print("PASS  rug pull: logged, and the new description is kept for the user to review")

        assert accept_change("fake/read_file", memory)     # the user trusts the new version
        async with Client(params) as client:
            assert "fake__read_file" in [t.name for t in (await client.list_tools()).tools]
        print("PASS  rug pull: after the user trusts the change, the tool is back")
    finally:
        app.stop()

    broken = tmp_path / "broken"
    broken.mkdir()
    params, _ = warden_params(broken, {"tool_memory_file": str(broken / "mem.json")})
    (broken / "mem.json").write_text("{ broken")
    async with Client(params) as client:
        assert (await client.list_tools()).tools == [], "a broken tool memory must hide the tools (fail safe)"
    assert (broken / "mem.json").read_text() == "{ broken", "and must not be overwritten"
    print("PASS  rug pull: a broken tool memory hides every tool (fail safe)")


async def run_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        await main_session(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        await broken_rules_session(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        await ai_check_session(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        await quoted_phrase_session(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        await approval_session(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        await rug_pull_session(Path(tmp))
    print("\nAll tests passed.")


if __name__ == "__main__":
    asyncio.run(run_test())
