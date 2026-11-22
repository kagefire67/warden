"""End-to-end test: AI app -> Warden -> fake tool server.

Run it with:  python tests/test_gateway.py

It starts Warden exactly the way Claude Desktop would, connects to it as an
MCP client, calls two tools, and checks that both calls were forwarded and logged.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent


async def run_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        config_path = tmp_path / "config.json"
        log_path = tmp_path / "actions.jsonl"
        config_path.write_text(json.dumps({
            "servers": {
                "fake": {"command": sys.executable, "args": [str(ROOT / "tests" / "fake_tools_server.py")]}
            }
        }))

        warden = StdioServerParameters(
            command=sys.executable,
            args=[str(ROOT / "warden_gateway.py"), "--config", str(config_path), "--log", str(log_path)],
        )

        async with Client(warden) as client:
            tools = (await client.list_tools()).tools
            names = sorted(t.name for t in tools)
            assert names == ["fake__read_file", "fake__send_email"], names
            print("PASS  Warden lists the protected tools:", names)

            result = await client.call_tool("fake__read_file", {"path": "invoices.pdf"})
            assert not result.is_error, result
            assert "invoices.pdf" in result.content[0].text
            print("PASS  read_file was forwarded through Warden")

            result = await client.call_tool(
                "fake__send_email", {"to": "boss@company.com", "subject": "Hi", "body": "Summary"}
            )
            assert not result.is_error, result
            print("PASS  send_email was forwarded through Warden")

            result = await client.call_tool("fake__does_not_exist", {})
            assert result.is_error
            print("PASS  unknown tools are refused")

        entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        assert len(entries) == 3, entries
        assert entries[0]["tool"] == "read_file" and entries[0]["server"] == "fake"
        assert entries[0]["decision"] == "allow" and entries[0]["status"] == "ok"
        assert entries[1]["arguments"]["to"] == "boss@company.com"
        assert entries[2]["decision"] == "error"
        print("PASS  all 3 actions were written to the log")
        print("\nAll tests passed.")


if __name__ == "__main__":
    asyncio.run(run_test())
