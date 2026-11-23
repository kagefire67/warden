"""Tests for warden_secrets.py: locking tool keys on disk and stopping them from leaking.

Run it with:  python tests/test_secrets.py
Only fake keys are used.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import warden_secrets as ws  # noqa: E402

KEY = "github_pat_FAKE0123456789abcdef"


# --- Locking (Windows DPAPI) -----------------------------------------------------

def test_lock_and_unlock():
    locked = ws.lock(KEY)
    assert locked.startswith(ws.PREFIX) and KEY not in locked
    assert ws.unlock(locked) == KEY
    assert ws.lock(locked) == locked, "locking twice does nothing"


def test_plain_values_pass_through_unlock():
    assert ws.unlock("plain-old-value") == "plain-old-value"     # files from an older Warden


def test_damaged_value_is_an_error_not_a_crash():
    for bad in (ws.PREFIX + "not base64 !!", ws.PREFIX + "AAAA"):
        try:
            ws.unlock(bad)
        except ws.SecretError as exc:
            assert KEY not in str(exc)
            continue
        raise AssertionError(f"{bad!r} should not unlock")


def test_server_settings_round_trip():
    spec = {"command": "gh-mcp", "args": ["stdio"], "env": {"GITHUB_TOKEN": KEY, "DEBUG": "1"}}
    locked = ws.lock_spec(spec)
    assert KEY not in json.dumps(locked) and locked["command"] == "gh-mcp"
    assert ws.unlock_spec(locked) == spec
    assert spec["env"]["GITHUB_TOKEN"] == KEY, "the original settings are not changed"
    assert ws.has_plain_keys({"gh": spec}) and not ws.has_plain_keys({"gh": locked})
    assert ws.lock_spec({"command": "x"}) == {"command": "x"}, "no env = nothing to lock"


# --- Which values are keys ----------------------------------------------------------

def test_what_counts_as_a_key():
    assert ws.looks_like_secret("GITHUB_TOKEN", KEY)
    assert ws.looks_like_secret("API_KEY", "abcd1234")
    assert ws.looks_like_secret("SOMETHING", "x9Y8z7W6v5U4t3S2r1Q0p")      # shaped like a key
    assert not ws.looks_like_secret("DEBUG", "1"), "short flags would cause false alarms"
    assert not ws.looks_like_secret("ROOT_DIR", "C:/Users/demo/project2024"), "paths are not keys"
    assert not ws.looks_like_secret("MODE", "production")


def test_secret_values_from_servers():
    servers = {"gh": {"command": "x", "env": {"GITHUB_TOKEN": KEY, "DEBUG": "1"}}, "fs": {"command": "y"}}
    assert ws.secret_values(servers) == [KEY]


# --- Finding and hiding keys --------------------------------------------------------------

def test_contains_and_redact_nested_values():
    args = {"to": "a@b.example", "body": f"here: {KEY}", "extra": [{"note": KEY}]}
    assert ws.contains_secret(args, [KEY])
    clean = ws.redact(args, [KEY])
    assert KEY not in json.dumps(clean) and clean["body"] == "here: [hidden key]"
    assert args["body"] == f"here: {KEY}", "the original is not changed"
    assert not ws.contains_secret({"body": "nothing secret"}, [KEY])
    assert not ws.contains_secret(args, []), "no saved keys = nothing to find"


def test_longer_key_is_hidden_completely():
    short, long = "abcd1234", "abcd1234-and-more-5678"
    assert ws.redact(f"x {long} y", ws.secret_values(
        {"s": {"env": {"API_KEY": short, "OTHER_TOKEN": long}}})) == "x [hidden key] y"


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
    print(f"\n{len(tests) - failed}/{len(tests)} secrets tests passed.")
    return failed


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
