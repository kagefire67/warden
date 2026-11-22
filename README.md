# Warden

A security guard for AI agents. Warden sits between AI apps (Claude Desktop, Cursor, VS Code...) and the tools they use, checks every action, and logs everything.

```
AI app  --->  WARDEN  --->  real tools (files, email, ...)
                 |
                 +--> logs/actions.jsonl
```

**Current stage: 3 done (rules + scanner).** Every action is checked against `rules.json` (allow / ask / block), tool results are scanned for hidden prompt-injection attacks, and after an attack risky actions are blocked for the rest of the session. Run all tests with `python tests\run_tests.py`.

**AI check (Stage 5):** for risky actions Warden asks a local AI (Ollama + `qwen3:8b`) whether the action looks like an attack. Setup: install Ollama from ollama.com, then run `ollama pull qwen3:8b` (about 5 GB). Switch it off with `"enabled": false` under `intent_check` in `warden_config.json`. If Ollama is not running, risky actions need approval (fail safe).

**Attack Lab (Stage 4):** `python attack_lab\run_lab.py` replays 22 fake attack and safe scenarios through Warden and writes a score report to `attack_lab\results.md`. Add `--ai` to include the AI check (report in `attack_lab\results_ai.md`).

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
