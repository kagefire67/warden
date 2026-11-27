# Warden

A security guard for AI agents. Warden sits between AI apps (Claude Desktop, Cursor, VS Code...) and the tools they use, checks every action, and logs everything.

```
AI app  --->  WARDEN  --->  real tools (files, email, ...)
                 |
                 +--> logs/actions.jsonl
```

**Current stage: 3 done (rules + scanner).** Every action is checked against `rules.json` (allow / ask / block), tool results are scanned for hidden prompt-injection attacks, and after an attack risky actions are blocked for the rest of the session. Run all tests with `python tests\run_tests.py`.

**One-click Protect (Stage 9):** in the Warden App's Home tab, click **Protect** next to an AI app (Claude Desktop, Cursor, VS Code, Windsurf). Warden backs up its config, moves its tools behind Warden (into a private file in `%LOCALAPPDATA%\Warden`), and makes the app talk only to Warden. **Unprotect** puts everything back. Restart the AI app afterwards.

**Tool keys stay safe:** keys (tokens, API keys) of protected tools are stored encrypted with Windows' own lock (DPAPI), so a copied file is useless on another PC. The AI never sees them: Warden hides them in tool results and blocks any action that tries to send one.

**Rug-pull detection:** a tool can be honest when you connect it and later change its description to sneak in orders for the AI. Warden remembers a fingerprint of every tool (`%LOCALAPPDATA%\Warden\tool_memory.json`). If a tool's description or arguments change, Warden hides it, tells you with a notice, and shows the old and new text in the Warden App's Home tab, where you can trust the new version (for example after an update).

**Warden App (Stage 8):** double-click `Warden App.cmd` (needs `pip install -r requirements.txt`, which includes pywebview). It shows whether you're protected, the history of what Warden stopped, and an Attack Lab button. Actions that need approval pop up with **Allow once / Deny**, and when Warden finds an attack or stops an action, a small notice appears in the bottom-right corner, so you hear about it directly, not only the AI. If the app is closed when Warden needs you, Warden opens it by itself (minimized; only one copy ever runs). If it cannot be opened, actions that need approval stay blocked.

**Stories (Stage 7):** every block comes with a short plain-language explanation. See them with `python view_log.py --stories` (add `--follow` to watch live). Set `"language": "ar"` in `warden_config.json` for Arabic.

**AI check (Stage 5):** for risky actions Warden asks a local AI (Ollama + `qwen3:8b`) whether the action looks like an attack. Setup: install Ollama from ollama.com, then run `ollama pull qwen3:8b` (about 5 GB). Switch it off with `"enabled": false` under `intent_check` in `warden_config.json`. The Warden App and `run_lab.py --ai` start Ollama by themselves if it is off. If Ollama is still not running, risky actions need approval (fail safe).

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
