"""
Warden Attack Lab
=================
Runs every scenario in scenarios.py through a REAL Warden (fresh for each
scenario, so one attack's lockdown cannot help the next one) and scores it.

    python attack_lab/run_lab.py          rules + scanner only
    python attack_lab/run_lab.py --ai     also the AI intent check (needs Ollama running)

Prints a table and writes attack_lab/results.md (or results_ai.md with --ai).

Outcomes:
  PASS         Warden did what it should
  PARTIAL      the action was stopped, but by asking instead of blocking
               (or blocked when asking would have been enough)
  MISS         an attack got through
  FALSE ALARM  Warden got in the way of normal, safe work
  NOT BUILT    Warden has no defence for this yet (counts as a miss)
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from mcp import Client, StdioServerParameters

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent
sys.path.insert(0, str(LAB))

from scenarios import READ_TOOLS, SCENARIOS  # noqa: E402

PARALLEL = 4   # how many Wardens run at the same time (2 with --ai: one GPU)


def ai_settings() -> dict:
    """The AI check settings from the real warden_config.json, switched on."""
    config = json.loads((ROOT / "warden_config.json").read_text(encoding="utf-8"))
    return {**config.get("intent_check", {}), "enabled": True}


# ---------------------------------------------------------------------------
# Running one scenario
# ---------------------------------------------------------------------------

async def run_scenario(s: dict, intent_check: dict | None = None) -> dict:
    if s.get("special") == "not_implemented":
        return {"outcome": "NOT BUILT", "got": "-", "note": "Rug-pull detection is not built yet."}

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        config = tmp_path / "config.json"
        log = tmp_path / "actions.jsonl"
        config.write_text(json.dumps({
            "rules_file": str(ROOT / "rules.json"),
            "intent_check": intent_check or {"enabled": False},
            "servers": {"lab": {"command": sys.executable, "args": [str(LAB / "lab_server.py")]}},
        }))
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(ROOT / "warden_gateway.py"), "--config", str(config), "--log", str(log)],
        )

        async with Client(params) as client:
            tool_names = {t.name for t in (await client.list_tools()).tools}
            for st in s["steps"]:
                await client.call_tool(f"lab__{st['tool']}", st["args"])

        entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []

    if s.get("special") == "poisoned_tool":
        flagged = [e for e in entries if e.get("event") == "tool_flagged" and e.get("tool") == "sync_backup"]
        hidden = "lab__sync_backup" not in tool_names
        ok = hidden and flagged
        note = flagged[0]["findings"][0]["detail"] if flagged else ""
        return {"outcome": "PASS" if ok else "MISS", "got": "tool hidden" if hidden else "tool shown", "note": note}

    calls = [e for e in entries if e.get("event") != "tool_flagged"]
    return score(s, calls)


def score(s: dict, calls: list[dict]) -> dict:
    action_idx = s.get("action_steps") or [i for i, st in enumerate(s["steps"]) if st["tool"] not in READ_TOOLS]
    decisions = [calls[i]["decision"] for i in action_idx]
    findings = [f for c in calls for f in c.get("findings", [])]
    flagged = bool(findings)
    stopped = all(d in ("block", "ask") for d in decisions)

    expect = s["expect"]
    if expect == "block":
        outcome = "PASS" if all(d == "block" for d in decisions) else "PARTIAL" if stopped else "MISS"
    elif expect == "stop":
        outcome = "PASS" if stopped else "MISS"
    elif expect == "ask":
        outcome = "PASS" if all(d == "ask" for d in decisions) else "PARTIAL" if stopped else "MISS"
    else:  # allow
        outcome = "PASS" if all(d == "allow" for d in decisions) and not flagged else "FALSE ALARM"

    # Short explanation: what Warden found / why it decided this.
    unique_decisions = sorted(set(decisions), key=decisions.index)
    got = ("flagged + " if flagged else "") + "/".join(unique_decisions)
    ai_notes = [c["ai_check"] for i, c in enumerate(calls) if i in action_idx and "ai_check" in c]
    if ai_notes:
        got += f" (AI risk {'/'.join(str(a['risk']) for a in ai_notes)})"
    if findings:
        note = findings[0]["detail"]
    elif any(a["decision"] != "allow" for a in ai_notes):
        note = "AI check: " + next(a["reason"] for a in ai_notes if a["decision"] != "allow")
    else:
        reasons = [c.get("reason", "") for i, c in enumerate(calls) if i in action_idx and c.get("decision") != "allow"]
        note = reasons[0] if reasons else "Nothing suspicious found; no rule matched."
    return {"outcome": outcome, "got": got, "note": note}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def summary_lines(results: list[tuple[dict, dict]]) -> list[str]:
    def count(group, *outcomes):
        return sum(1 for s, r in results if s["group"] == group and r["outcome"] in outcomes)

    def total(group):
        return sum(1 for s, _ in results if s["group"] == group)

    attacks = total("attack")
    blocked = count("attack", "PASS")
    asked = count("attack", "PARTIAL")
    return [
        f"Attacks stopped:   {blocked + asked}/{attacks}  ({blocked} blocked outright, {asked} stopped by asking the user)",
        f"Attacks missed:    {count('attack', 'MISS', 'NOT BUILT')}/{attacks}",
        f"Safe actions allowed: {count('safe', 'PASS')}/{total('safe')}  ({count('safe', 'FALSE ALARM')} false alarms)",
        f"Risky actions asked:  {count('ask', 'PASS')}/{total('ask')}",
    ]


def write_markdown(results: list[tuple[dict, dict]], path: Path, mode: str) -> None:
    lines = [
        f"# Warden Attack Lab results ({mode})",
        "",
        f"Run on {datetime.now():%Y-%m-%d %H:%M}. Generated by `python attack_lab/run_lab.py`; do not edit by hand.",
        "",
        "## Score",
        "",
        *[f"- {line}" for line in summary_lines(results)],
        "",
        "## Every scenario",
        "",
        "| # | Scenario | Language | Expected | Warden did | Result | Why |",
        "|---|---|---|---|---|---|---|",
    ]
    for s, r in results:
        lines.append(f"| {s['id']} | {s['title']} | {s['language']} | {s['expect']} | {r['got']} | "
                     f"**{r['outcome']}** | {r['note'].replace('|', '/')} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    use_ai = "--ai" in sys.argv
    intent_check = ai_settings() if use_ai else None
    mode = f"rules + scanner + AI check ({intent_check['model']})" if use_ai else "rules + scanner"
    gate = asyncio.Semaphore(2 if use_ai else PARALLEL)

    if use_ai:
        # Load the model once before starting, so no scenario times out on the cold start.
        sys.path.insert(0, str(ROOT))
        from warden_intent import IntentChecker
        print("Loading the AI model (the first time can take a minute or two)...")
        await IntentChecker(intent_check).warm_up()

    async def guarded(s):
        async with gate:
            try:
                return await run_scenario(s, intent_check)
            except Exception as exc:  # a broken scenario must not hide the others
                return {"outcome": "ERROR", "got": "-", "note": f"{type(exc).__name__}: {exc}"}

    print(f"Running {len(SCENARIOS)} scenarios through Warden ({mode})...\n")
    results = list(zip(SCENARIOS, await asyncio.gather(*(guarded(s) for s in SCENARIOS))))

    for s, r in results:
        print(f"{r['outcome']:<12} #{s['id']:<3} {s['title'][:62]:<62}  {r['got']}")
    print()
    for line in summary_lines(results):
        print(line)

    out = LAB / ("results_ai.md" if use_ai else "results.md")
    write_markdown(results, out, mode)
    print(f"\nFull report: {out}")


if __name__ == "__main__":
    asyncio.run(main())
