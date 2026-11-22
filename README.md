# Warden

A security guard for AI agents. Warden sits between AI apps (Claude Desktop, Cursor, VS Code...) and the tools they use, checks every action, and logs everything.

```
AI app  --->  WARDEN  --->  real tools (files, email, ...)
                 |
                 +--> logs/actions.jsonl
```

**Current stage: 1 (engine, monitor-only).** Every action is passed through and logged. Blocking rules arrive in Stage 3 inside `check_action()` in `warden_gateway.py`.

## Files

| File | What it is |
|---|---|
| `warden_gateway.py` | The Warden engine |
| `warden_config.json` | Which real tool servers Warden protects |
| `view_log.py` | Shows what the AI has done (`--follow` for live view) |
| `tests/test_gateway.py` | End-to-end test with a fake tool server |

## Setup (Windows)

You need **Python 3.11+**, **Node.js** (for the filesystem tool) and **Claude Desktop**.

1. Put this folder at `C:\warden`.
2. Open a terminal in `C:\warden` and run:
   ```
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Run the test. It should end with `All tests passed.`
   ```
   python tests\test_gateway.py
   ```
4. Create a test folder for the AI to work in, e.g. `C:\Users\<you>\WardenTest`, and put a few text files in it.
5. Edit `warden_config.json` and replace `C:/Users/YOUR_NAME/WardenTest` with that folder (use forward slashes).
6. In Claude Desktop: **Settings → Developer → Edit Config**, and set `claude_desktop_config.json` to:
   ```json
   {
     "mcpServers": {
       "warden": {
         "command": "C:/warden/.venv/Scripts/python.exe",
         "args": ["C:/warden/warden_gateway.py"]
       }
     }
   }
   ```
   If you already have other servers in that file, keep only Warden there and move them into `warden_config.json` instead, so they are protected too.
7. Fully quit Claude Desktop (also from the system tray) and reopen it.
8. In a terminal, start the live log:
   ```
   python view_log.py --follow
   ```
9. Ask Claude: *"List the files in my WardenTest folder and read one of them."* Each action appears in the log.

## Troubleshooting

- **Warden doesn't appear in Claude:** check Claude Desktop's MCP logs (Settings → Developer). Warden's messages start with `[warden]`.
- **`npx` not found:** install Node.js, then restart Claude Desktop. If it still fails, use `npx.cmd` as the command.
- **Never add `print()` to `warden_gateway.py`.** Warden talks to Claude through stdout; printing breaks the connection. Use `log.info(...)`.
