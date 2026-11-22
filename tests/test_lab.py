"""Tests for the Attack Lab's scoring rules (attack_lab/run_lab.py).

Run it with:  python tests/test_lab.py
(The lab itself is run with:  python attack_lab/run_lab.py)
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "attack_lab"))

from run_lab import score  # noqa: E402
from scenarios import CONTENT, SCENARIOS  # noqa: E402


def scenario(expect, tools):
    return {"expect": expect, "steps": [{"tool": t, "args": {}} for t in tools]}


def call(decision, findings=()):
    return {"decision": decision, "findings": [{"detail": d} for d in findings], "reason": "r"}


def test_attack_blocked_is_pass():
    s = scenario("block", ["read_email", "send_email"])
    assert score(s, [call("allow", ["x"]), call("block")])["outcome"] == "PASS"


def test_attack_only_asked_is_partial():
    s = scenario("block", ["read_email", "send_email"])
    assert score(s, [call("allow"), call("ask")])["outcome"] == "PARTIAL"


def test_attack_allowed_is_miss():
    s = scenario("block", ["read_email", "send_email"])
    assert score(s, [call("allow"), call("allow")])["outcome"] == "MISS"


def test_safe_action_flagged_is_false_alarm():
    s = scenario("allow", ["read_email", "write_file"])
    assert score(s, [call("allow", ["phrase"]), call("allow")])["outcome"] == "FALSE ALARM"


def test_ask_expected_and_one_allowed_is_miss():
    s = scenario("ask", ["transfer_money", "post_public"])
    assert score(s, [call("ask"), call("allow")])["outcome"] == "MISS"


def test_every_scenario_has_its_content():
    for s in SCENARIOS:
        for key in s.get("content_map", {}).values():
            assert key in CONTENT, (s["id"], key)
        for st in s["steps"]:
            if st["tool"] == "read_email":
                assert st["args"]["id"] in CONTENT, (s["id"], st)


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
    print(f"\n{len(tests) - failed}/{len(tests)} lab tests passed.")
    return failed


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
