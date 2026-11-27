"""Tests for the approval channel (warden_approval.py) and the Warden App's checks (warden_app.py).

Run it with:  python tests/test_approval.py
No window is opened: the app's checks are plain functions.
"""

import asyncio
import json
import socket
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from warden_approval import ApprovalServer, app_is_running, ask_user, tell_user  # noqa: E402
from warden_app import event_icon, protection_status, read_events, today_summary  # noqa: E402

TMP = Path(tempfile.mkdtemp())


def server(decide, name="app.json"):
    s = ApprovalServer(decide, app_file=TMP / name)
    s.start()
    return s


# --- The approval channel ------------------------------------------------------

def test_user_allows():
    s = server(lambda req: "allow", "a.json")
    try:
        assert asyncio.run(ask_user({"title": "x"}, timeout=5, app_file=s.app_file)) == "allow"
    finally:
        s.stop()


def test_user_denies():
    s = server(lambda req: "deny", "b.json")
    try:
        assert asyncio.run(ask_user({"title": "x"}, timeout=5, app_file=s.app_file)) == "deny"
    finally:
        s.stop()


def test_request_details_reach_the_app_but_not_the_token():
    seen = {}
    s = server(lambda req: seen.update(req) or "deny", "c.json")
    try:
        asyncio.run(ask_user({"title": "Send email?", "story": "The AI tried..."}, timeout=5, app_file=s.app_file))
    finally:
        s.stop()
    assert seen["title"] == "Send email?" and "token" not in seen


def test_notice_reaches_the_app_without_the_token():
    seen, arrived = [], __import__("threading").Event()
    s = ApprovalServer(lambda req: "allow", app_file=TMP / "n.json",
                       notify=lambda n: (seen.append(n), arrived.set()))
    s.start()
    try:
        assert asyncio.run(tell_user({"kind": "attack", "title": "Hidden attack found"}, app_file=s.app_file))
        assert arrived.wait(5)
    finally:
        s.stop()
    assert seen[0] == {"kind": "attack", "title": "Hidden attack found"}, seen


def test_notice_can_never_approve_anything():
    asked = []
    s = ApprovalServer(lambda req: asked.append(req) or "allow", app_file=TMP / "n2.json", notify=lambda n: None)
    s.start()
    try:
        assert asyncio.run(tell_user({"kind": "blocked", "decision": "allow"}, app_file=s.app_file))
    finally:
        s.stop()
    assert asked == [], "a notice must never reach the approval code"


def test_notice_without_app_is_harmless():
    assert asyncio.run(tell_user({"kind": "attack"}, app_file=TMP / "missing.json")) is False
    s = server(lambda req: "allow", "n3.json")      # an app without a notice window
    try:
        assert asyncio.run(tell_user({"kind": "attack"}, app_file=s.app_file)) is False
    finally:
        s.stop()


def test_closed_app_is_opened_once():
    import warden_approval
    app_file = TMP / "opened.json"
    started = []

    def fake_launch():                    # instead of opening the real app: start a test app
        started.append(1)
        s = ApprovalServer(lambda req: "deny", app_file=app_file)
        s.start()
        started.append(s)
        return True

    warden_approval._last_launch = 0.0
    try:
        assert asyncio.run(warden_approval.reach_app(app_file, wait_seconds=5, launch=fake_launch))
        assert asyncio.run(warden_approval.reach_app(app_file, wait_seconds=5, launch=fake_launch))
        assert started.count(1) == 1, "an app that is already running is not opened again"
    finally:
        started[1].stop()
    # It just tried: a closed app is not re-opened again and again (at most once a minute).
    assert not asyncio.run(warden_approval.reach_app(app_file, wait_seconds=1, launch=fake_launch))
    assert started.count(1) == 1
    warden_approval._last_launch = 0.0


def test_app_that_cannot_open_means_blocked():
    import warden_approval
    warden_approval._last_launch = 0.0
    assert not asyncio.run(warden_approval.reach_app(TMP / "never.json", wait_seconds=1, launch=lambda: False))
    warden_approval._last_launch = 0.0


def test_only_one_app_copy():
    from warden_app import first_copy
    name = f"Local\\WardenTest-{time.time_ns()}"
    assert first_copy(name), "the first copy may run"
    assert not first_copy(name), "a second copy must not start"


def test_wrong_token_is_refused():
    s = server(lambda req: "allow", "d.json")
    try:
        with socket.create_connection(("127.0.0.1", s.port), timeout=5) as sock:
            sock.sendall(b'{"type": "approval", "token": "guess"}\n')
            reply = json.loads(sock.makefile().readline())
    finally:
        s.stop()
    assert "decision" not in reply and reply.get("error") == "bad token", reply


def test_garbage_does_not_crash_the_app():
    s = server(lambda req: "allow", "e.json")
    try:
        with socket.create_connection(("127.0.0.1", s.port), timeout=5) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\n\r\n")       # e.g. a web-fetch tool poking the port
            reply = sock.makefile().readline()
        assert "decision" not in reply
        assert asyncio.run(app_is_running(s.app_file))     # still alive afterwards
    finally:
        s.stop()


def test_no_app_means_none():                            # fail safe: gateway keeps it blocked
    assert asyncio.run(ask_user({"title": "x"}, timeout=2, app_file=TMP / "missing.json")) is None


def test_stale_app_file_means_none():                    # app crashed and left its file behind
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    stale = TMP / "stale.json"
    stale.write_text(json.dumps({"port": port, "token": "abc", "pid": 1}))
    assert asyncio.run(ask_user({"title": "x"}, timeout=2, app_file=stale)) is None


def test_timeout_answer_is_passed_on():
    s = server(lambda req: "timeout", "f.json")
    try:
        assert asyncio.run(ask_user({"title": "x"}, timeout=5, app_file=s.app_file)) == "timeout"
    finally:
        s.stop()


def test_app_file_is_removed_on_stop_and_token_changes():
    s1 = server(lambda req: "deny", "g.json")
    token1 = s1.token
    s1.stop()
    assert not s1.app_file.exists()
    s2 = server(lambda req: "deny", "g.json")
    try:
        assert s2.token != token1
    finally:
        s2.stop()


# --- The app's checks ------------------------------------------------------------

def write_json(name, data):
    path = TMP / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_claude_config_protected():
    from warden_protect import warden_entry
    path = write_json("p.json", {"mcpServers": {"warden": warden_entry()}})
    assert protection_status(path) == ("protected", [])


def test_claude_config_with_tool_that_skips_warden():
    from warden_protect import warden_entry
    path = write_json("q.json", {"mcpServers": {
        "warden": warden_entry(),
        "github": {"command": "npx", "args": ["github-mcp"]}}})
    assert protection_status(path) == ("protected", ["github"])


def test_claude_config_protected_by_another_warden_copy():
    # e.g. still pointing at the project folder after Warden was installed
    path = write_json("u.json", {"mcpServers": {"warden": {"command": "python", "args": ["C:/old/warden_gateway.py"]}}})
    assert protection_status(path) == ("update_needed", [])
    path = write_json("v.json", {"mcpServers": {"warden": {"command": "C:/Programs/Warden/warden-gateway.exe"}}})
    assert protection_status(path)[0] == "update_needed", "the installed .exe is recognised as Warden too"


def test_claude_config_not_protected_or_broken():
    assert protection_status(write_json("r.json", {"preferences": {}}))[0] == "not_protected"
    broken = TMP / "s.json"
    broken.write_text("{ not json")
    assert protection_status(broken)[0] == "unreadable"


def test_history_and_today_summary():
    log = TMP / "actions.jsonl"
    entries = [
        {"id": "1", "time": "2026-11-22T10:00:00+00:00", "status": "ok", "decision": "allow"},
        {"id": "2", "time": "2026-11-22T10:01:00+00:00", "status": "ok", "tainted_session": True, "story": "attack"},
        {"id": "3", "time": "2026-11-22T10:02:00+00:00", "status": "blocked", "decision": "block", "story": "b"},
        {"id": "4", "time": "2026-11-22T10:03:00+00:00", "status": "ok", "decision": "allow", "approval": "allow"},
        {"id": "5", "time": "2026-11-21T09:00:00+00:00", "status": "blocked"},
    ]
    log.write_text("\n".join(json.dumps(e) for e in entries) + "\nnot json\n", encoding="utf-8")
    events = read_events(log)
    assert [e["id"] for e in events] == ["5", "4", "3", "2", "1"]          # newest first, bad line skipped
    assert today_summary(events, "2026-11-22") == {"actions": 4, "attacks": 1, "blocked": 1, "you_allowed": 1}
    assert [event_icon(e) for e in events[1:4]] == ["YOU ALLOWED", "BLOCKED", "ATTACK FOUND"]


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
    print(f"\n{len(tests) - failed}/{len(tests)} approval/app tests passed.")
    return failed


if __name__ == "__main__":
    import logging
    logging.disable(logging.WARNING)
    sys.exit(1 if run_all() else 0)
