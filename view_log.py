"""Show what the AI has been doing, from Warden's action log.

  python view_log.py            show every logged action
  python view_log.py --follow   keep watching and show new actions live
"""

import argparse
import json
import sys
import time
from pathlib import Path

LOG = Path(__file__).resolve().parent / "logs" / "actions.jsonl"
LABELS = {"ok": "[ALLOW]", "blocked": "[BLOCK]", "error": "[ERROR]"}


def show(line: str) -> None:
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return
    label = LABELS.get(e.get("status") or e.get("decision"), "[?????]")
    args = json.dumps(e.get("arguments", {}), ensure_ascii=False)
    if len(args) > 80:
        args = args[:80] + "..."
    print(f"{e.get('time', '')}  {label}  {e.get('server')}/{e.get('tool')}  {args}")
    if e.get("status") != "ok" and e.get("reason"):
        print(f"{'':27}reason: {e['reason']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--follow", action="store_true", help="watch for new actions")
    parser.add_argument("--log", type=Path, default=LOG)
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    if not args.log.exists():
        print(f"No actions logged yet ({args.log}).")
        if not args.follow:
            return
        while not args.log.exists():
            time.sleep(1)

    with args.log.open(encoding="utf-8") as f:
        for line in f:
            show(line)
        while args.follow:
            line = f.readline()
            if line:
                show(line)
            else:
                time.sleep(0.5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
