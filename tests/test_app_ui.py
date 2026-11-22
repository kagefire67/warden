"""Tests for the Warden App's new web-style UI (ui/ folder) and its Python bridge.

Run it with:  python tests/test_app_ui.py

The most important tests here are SECURITY guards: stories can contain an attacker's
text, so the UI must never insert text as HTML (cross-site scripting), and a strict
Content-Security-Policy must stop any script that is not one of Warden's own files.
"""

import re
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"
sys.path.insert(0, str(ROOT))

from warden_app import ApprovalApi, event_for_ui, parse_lab_score, status_summary  # noqa: E402

JS_FILES = sorted(UI.glob("*.js"))
HTML_FILES = sorted(UI.glob("*.html"))


# --- Security guards ---------------------------------------------------------------

def test_ui_never_inserts_html():
    dangerous = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function|setTimeout\(\s*['\"]")
    for path in JS_FILES:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("//")[0]           # comments may mention the rule
            assert not dangerous.search(code), f"{path.name}:{n} inserts HTML or runs strings as code: {line.strip()}"


def test_every_page_has_a_strict_content_security_policy():
    for path in HTML_FILES:
        html = path.read_text(encoding="utf-8")
        csp = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', html)
        assert csp, f"{path.name} has no Content-Security-Policy"
        policy = csp.group(1)
        assert "script-src 'self'" in policy and "unsafe-inline" not in policy and "unsafe-eval" not in policy, policy
        assert "object-src 'none'" in policy


def test_no_inline_scripts_handlers_or_styles():
    for path in HTML_FILES:
        html = path.read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), f"{path.name} has an inline <script>"
        assert not re.search(r"\son[a-z]+\s*=", html), f"{path.name} has an inline event handler (onclick=...)"
        assert not re.search(r"\sstyle\s*=", html), f"{path.name} has an inline style (blocked by the CSP)"


def test_no_remote_resources():
    for path in HTML_FILES + JS_FILES + [UI / "style.css"]:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"(src|href)\s*=\s*['\"]https?://", text), f"{path.name} loads something from the internet"
        assert "@import" not in text and "url(http" not in text


# --- The Python bridge ----------------------------------------------------------------

def test_history_items_are_plain_strings():
    e = {"id": "x1", "time": "2026-11-22T10:00:00+00:00", "server": "fs", "tool": "read_file",
         "arguments": {"path": "<img src=x onerror=alert(1)>"}, "story": "<script>alert(1)</script>",
         "story_title": "Hidden attack", "tainted_session": True, "status": "ok"}
    item = event_for_ui(e)
    assert all(isinstance(v, str) for v in item.values())
    assert item["badge"] == "ATTACK FOUND" and item["when"] == "2026-11-22 10:00"
    assert item["story"] == "<script>alert(1)</script>", "text is passed on unchanged; the UI shows it as text"


def test_status_summary():
    assert status_summary([(True, "Claude Desktop goes through Warden")])[0] == "ok"
    assert status_summary([(True, "Claude Desktop goes through Warden"), (False, "AI check offline")])[0] == "warn"
    assert status_summary([(None, "VS Code: no AI tools set up yet")])[0] == "bad"
    assert status_summary([(True, "Claude Desktop goes through Warden"),
                           (False, "Cursor is NOT protected (2 tools skip Warden)")])[0] == "bad"


def test_lab_score_is_read_from_the_output():
    lines = ["PASS #1 ...\n", "Attacks stopped:   24/25  (23 blocked outright, 1 stopped by asking the user)\n",
             "Attacks missed:    1/25\n", "Safe actions allowed: 8/9  (1 false alarms)\n"]
    assert parse_lab_score(lines) == {"stopped": "24/25", "blocked": "23", "missed": "1/25", "safe": "8/9"}
    assert parse_lab_score(["crashed\n"]) is None


def test_approval_popup_accepts_only_real_answers_once():
    done, box = threading.Event(), {}
    api = ApprovalApi({"title": "t", "story": "s", "server": "fs", "tool": "w", "arguments": "{}",
                       "timeout": 60, "id": "secret-internal"}, done, box)
    assert "id" not in api.get_request(), "the page only gets what it needs to show"
    api.answer("approve-everything")
    assert not done.is_set(), "unknown answers are ignored"
    api.answer("deny")
    api.answer("allow")                      # a second click cannot change the answer
    assert done.is_set() and box["decision"] == "deny"


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
    print(f"\n{len(tests) - failed}/{len(tests)} app UI tests passed.")
    return failed


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
