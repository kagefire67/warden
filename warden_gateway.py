"""
Warden - AI agent security gateway
==================================
Stage 1: the engine.

What this file does:
  1. Starts the real tool servers listed in warden_config.json
     (for example the official filesystem server).
  2. Collects all of their tools and offers them to the AI app
     (Claude Desktop, Cursor, VS Code...) as if Warden owned them.
  3. Every time the AI calls a tool, Warden:
       - runs check_action()  -> allow or block   (rules come in Stage 3)
       - forwards allowed calls to the real server
       - writes the action to logs/actions.jsonl

    AI app  --->  WARDEN  --->  real tool servers
                    |
                    +--> logs/actions.jsonl

IMPORTANT: an MCP server that runs over "stdio" talks to the AI app through
stdout. Never use print() in this file - it would corrupt the conversation.
Diagnostics go to stderr through the `log` object instead.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
import uuid
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

WARDEN_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = WARDEN_DIR / "warden_config.json"
DEFAULT_LOG = WARDEN_DIR / "logs" / "actions.jsonl"

# Tool names shown to the AI look like "filesystem__read_file".
NAME_SEPARATOR = "__"

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="[warden] %(levelname)s %(message)s")
log = logging.getLogger("warden")


# ---------------------------------------------------------------------------
# 1. Decisions  (Stage 3 and later add real rules here)
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    allowed: bool
    reason: str


def check_action(server: str, tool: str, arguments: dict[str, Any]) -> Decision:
    """Decide whether one AI action may run.

    Stage 1 is monitor-only: everything is allowed and logged.
    This single function is where the rule engine (Stage 3), the AI intent
    check (Stage 5) and the multilingual scanner (Stage 6) will plug in.
    """
    return Decision(allowed=True, reason="Monitor-only mode (Stage 1)")


# ---------------------------------------------------------------------------
# 2. Action log
# ---------------------------------------------------------------------------

class ActionLog:
    """Appends one JSON line per action, so the log is easy to read and stream."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, entry: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def preview(result: types.CallToolResult, limit: int = 300) -> str:
    """Short text summary of a tool result for the log."""
    parts = [block.text for block in result.content if isinstance(block, types.TextContent)]
    text = " ".join(parts).strip()
    return text if len(text) <= limit else text[:limit] + "..."


def text_result(message: str, is_error: bool = False) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=is_error)


# ---------------------------------------------------------------------------
# 3. Connections to the real tool servers
# ---------------------------------------------------------------------------

@dataclass
class Route:
    """Where a tool shown to the AI really lives."""
    server: str          # e.g. "filesystem"
    tool: str            # the tool's real name, e.g. "read_file"
    client: Client       # live connection to that server


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"Config file not found: {path}")
    with path.open(encoding="utf-8") as f:
        config = json.load(f)
    if not config.get("servers"):
        raise SystemExit(f"No servers listed in {path}")
    return config


async def list_all_tools(client: Client) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return tools


async def connect_servers(
    config: dict[str, Any], stack: AsyncExitStack
) -> tuple[list[types.Tool], dict[str, Route]]:
    """Start every configured server and build the combined tool list."""
    exposed: list[types.Tool] = []
    routes: dict[str, Route] = {}

    for server_name, spec in config["servers"].items():
        if NAME_SEPARATOR in server_name:
            log.error("Server name %r must not contain %r - skipped", server_name, NAME_SEPARATOR)
            continue
        params = StdioServerParameters(
            command=spec["command"],
            args=spec.get("args", []),
            env=spec.get("env"),
        )
        try:
            client = await stack.enter_async_context(Client(params))
            tools = await list_all_tools(client)
        except Exception as exc:  # one broken server must not take Warden down
            log.error("Could not start server %r: %s", server_name, exc)
            continue

        for tool in tools:
            public_name = f"{server_name}{NAME_SEPARATOR}{tool.name}"
            if len(public_name) > 64:
                log.warning("Tool name %r is longer than 64 characters; some AI apps may reject it", public_name)
            description = f"[{server_name}] {tool.description or ''}".strip()
            exposed.append(tool.model_copy(update={"name": public_name, "description": description}))
            routes[public_name] = Route(server=server_name, tool=tool.name, client=client)

        log.info("Protecting server %r (%d tools)", server_name, len(tools))

    return exposed, routes


# ---------------------------------------------------------------------------
# 4. The Warden server the AI app talks to
# ---------------------------------------------------------------------------

def build_server(exposed: list[types.Tool], routes: dict[str, Route], action_log: ActionLog) -> Server:

    async def on_list_tools(ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        return types.ListToolsResult(tools=exposed)

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        arguments = dict(params.arguments or {})
        entry: dict[str, Any] = {
            "id": uuid.uuid4().hex[:12],
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": params.name,
            "arguments": arguments,
        }

        route = routes.get(params.name)
        if route is None:
            entry.update(server=None, decision="error", reason="Unknown tool")
            action_log.write(entry)
            return text_result(f"Warden: unknown tool '{params.name}'", is_error=True)

        entry.update(server=route.server, tool=route.tool)

        decision = check_action(route.server, route.tool, arguments)
        entry.update(decision="allow" if decision.allowed else "block", reason=decision.reason)

        if not decision.allowed:
            entry["status"] = "blocked"
            action_log.write(entry)
            return text_result(f"Warden blocked this action: {decision.reason}", is_error=True)

        started = time.perf_counter()
        try:
            result = await route.client.call_tool(route.tool, arguments)
        except Exception as exc:
            entry.update(status="error", error=str(exc), duration_ms=round((time.perf_counter() - started) * 1000))
            action_log.write(entry)
            return text_result(f"Warden: the '{route.server}' server failed: {exc}", is_error=True)

        entry.update(
            status="error" if result.is_error else "ok",
            duration_ms=round((time.perf_counter() - started) * 1000),
            result_preview=preview(result),
        )
        action_log.write(entry)
        return result

    return Server(
        "warden",
        version="0.1.0",
        instructions="Warden checks and logs every tool call before it reaches the real tool.",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


# ---------------------------------------------------------------------------
# 5. Start-up
# ---------------------------------------------------------------------------

async def main() -> None:
    parser = argparse.ArgumentParser(description="Warden AI agent security gateway")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="path to warden_config.json")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="path to the action log")
    args = parser.parse_args()

    config = load_config(args.config)
    action_log = ActionLog(args.log)

    async with AsyncExitStack() as stack:
        exposed, routes = await connect_servers(config, stack)
        if not routes:
            log.error("No tool servers could be started - check warden_config.json")
        server = build_server(exposed, routes, action_log)
        log.info("Warden is running: %d tools protected, logging to %s", len(routes), args.log)

        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
