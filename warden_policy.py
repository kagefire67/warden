"""
Warden policy engine (Layer 1)
==============================
Fixed rules that decide what an AI action is allowed to do. Rules live in
rules.json so they can be changed without touching code.

A rule matches when ALL of its conditions are true:
  tools              - tool name patterns, e.g. ["*delete*", "*remove*"]
  argument_matches   - regex searched in all argument values
  argument           - {"arg_name": "regex"}   that argument must match
  unless_argument    - {"arg_name": "regex"}   rule is skipped if that argument matches
  only_if_tainted    - true: only applies after suspicious content was read

Each rule says "block", "ask" or "allow". When several rules match, the
strictest wins: block > ask > allow. If no rule matches: allow.

Why "tainted"? Warden cannot see what the user typed to the AI - it only sees
tool calls. But it DOES see what the AI reads. Once the AI has read content
that contains an attack, every risky action afterwards is treated with
suspicion. This idea is called taint tracking.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STRICTNESS = {"allow": 0, "ask": 1, "block": 2}


@dataclass
class Decision:
    action: str                      # "allow", "ask" or "block"
    reason: str
    rule_ids: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


@dataclass
class Rule:
    id: str
    decision: str
    reason: str
    tools: list[str] = field(default_factory=lambda: ["*"])
    argument_matches: str | None = None
    argument: dict[str, str] = field(default_factory=dict)
    unless_argument: dict[str, str] = field(default_factory=dict)
    only_if_tainted: bool = False

    def __post_init__(self) -> None:
        if self.decision not in STRICTNESS:
            raise ValueError(f"Rule {self.id!r}: decision must be allow, ask or block")
        # Compile now so a broken regex fails at start-up, not during an attack.
        self._any = re.compile(self.argument_matches, re.IGNORECASE) if self.argument_matches else None
        self._arg = {k: re.compile(v, re.IGNORECASE) for k, v in self.argument.items()}
        self._unless = {k: re.compile(v, re.IGNORECASE) for k, v in self.unless_argument.items()}

    def matches(self, tool: str, arguments: dict[str, Any], tainted: bool) -> bool:
        if self.only_if_tainted and not tainted:
            return False
        if not any(fnmatch.fnmatch(tool.lower(), p.lower()) for p in self.tools):
            return False
        values = flatten(arguments)
        if self._any and not any(self._any.search(v) for v in values.values()):
            return False
        for name, pattern in self._arg.items():
            if name not in values or not pattern.search(values[name]):
                return False
        for name, pattern in self._unless.items():
            if name in values and pattern.search(values[name]):
                return False
        return True


def flatten(arguments: dict[str, Any], prefix: str = "") -> dict[str, str]:
    """{"to": ["a@x.com"], "opts": {"cc": "b"}} -> {"to": "a@x.com", "opts.cc": "b"}"""
    out: dict[str, str] = {}
    for key, value in arguments.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, f"{name}."))
        elif isinstance(value, list):
            out[name] = " ".join(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v) for v in value)
        else:
            out[name] = "" if value is None else str(value)
    return out


class Policy:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def load(cls, path: Path) -> "Policy":
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        return cls([Rule(**r) for r in data["rules"]])

    def evaluate(self, tool: str, arguments: dict[str, Any], tainted: bool = False) -> Decision:
        matched = [r for r in self.rules if r.matches(tool, arguments, tainted)]
        if not matched:
            return Decision("allow", "No rule matched")
        worst = max(STRICTNESS[r.decision] for r in matched)
        top = [r for r in matched if STRICTNESS[r.decision] == worst]
        return Decision(top[0].decision, " / ".join(r.reason for r in top), [r.id for r in matched])
