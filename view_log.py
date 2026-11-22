"""Show what the AI has been doing, from Warden's action log.

  python view_log.py                     every logged action (technical view)
  python view_log.py --follow            keep watching and show new actions live
  python view_log.py --stories           only what Warden stopped, as plain-language stories
  python view_log.py --stories --follow  live stories
"""

import argparse
import json
import sys
import time
from pathlib import Path

LOG = Path(__file__).resolve().parent / "logs" / "actions.jsonl"
LABELS = {"ok": "[ALLOW]", "blocked": "[BLOCK]", "error": "[ERROR]"}


def show(line: str) -> None:
    """Technical view: one line per action, plus reasons and findings."""
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return
    label = LABELS.get(e.get("status") or e.get("decision"), "[?????]")
    if e.get("decision") == "ask":
        label = "[ASK]  "          # stopped until the user approves
    if e.get("event") == "tool_flagged":
        label = "[TOOL!]"          # a poisoned tool was hidden from the AI
    args = json.dumps(e.get("arguments", {}), ensure_ascii=False)
    if len(args) > 80:
        args = args[:80] + "..."
    print(f"{e.get('time', '')}  {label}  {e.get('server')}/{e.get('tool')}  {args}")
    if e.get("status") != "ok" and e.get("reason"):
        print(f"{'':27}reason: {e['reason']}")
    ai = e.get("ai_check")
    if ai:
        risk = "?" if ai.get("risk") is None else f"{ai['risk']}/10"
        print(f"{'':27}AI check: risk {risk} -> {ai['decision']} ({ai.get('ms', 0)} ms): {ai['reason']}")
    for finding in e.get("findings", []):
        tag = "noted: " if finding.get("severity") == "info" else "found: "
        print(f"{'':27}{tag} {finding['detail']}")
        if finding.get("snippet"):
            print(f"{'':27}        \"{finding['snippet'][:100]}\"")
    if e.get("story"):
        print(f"{'':27}story:  {e['story']}")


ICONS = {"ask": "✋", "block": "⛔"}


def show_story(line: str) -> None:
    """Plain-language view: only the moments where Warden stepped in."""
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return
    if not e.get("story"):
        return
    icon = "⚠️" if e.get("tainted_session") and e.get("status") == "ok" else ICONS.get(e.get("decision"), "•")
    when = e.get("time", "").replace("T", " ")[:16]
    print(f"{icon}  {e.get('story_title', '')}   ({when} UTC)")
    print(f"    {e['story']}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--follow", action="store_true", help="watch for new actions")
    parser.add_argument("--stories", action="store_true", help="only plain-language stories")
    parser.add_argument("--log", type=Path, default=LOG)
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    render = show_story if args.stories else show

    if not args.log.exists():
        print(f"No actions logged yet ({args.log}).")
        if not args.follow:
            return
        while not args.log.exists():
            time.sleep(1)

    with args.log.open(encoding="utf-8") as f:
        for line in f:
            render(line)
        while args.follow:
            line = f.readline()
            if line:
                render(line)
            else:
                time.sleep(0.5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
