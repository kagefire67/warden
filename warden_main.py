"""
Entry point of the INSTALLED Warden (both .exe files are built from this file).

    Warden.exe                          the Warden App (window)
    warden-gateway.exe                  the gateway an AI app starts (talks MCP over stdin/stdout)
    warden-gateway.exe lab [--ai]       run the Attack Lab
    warden-gateway.exe lab-server       the Attack Lab's fake tool server (started by the lab)
    warden-gateway.exe add-server ...   same as "python add_server.py ..."
    warden-gateway.exe view-log ...     same as "python view_log.py ..."
    warden-gateway.exe unprotect-all    give every AI app its tools back (run by the uninstaller)

From source you never need this file: run the .py files directly.
In gateway mode nothing may be printed: stdout is the channel to the AI app.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path


def run_mode(mode: str, rest: list[str]) -> int:
    sys.argv = [f"warden {mode}", *rest]          # each tool reads its own options from sys.argv
    if mode == "lab":
        import run_lab
        asyncio.run(run_lab.main())
    elif mode == "lab-server":
        import lab_server
        lab_server.mcp.run()
    elif mode == "add-server":
        import add_server
        return add_server.main()
    elif mode == "view-log":
        import view_log
        try:
            view_log.main()
        except KeyboardInterrupt:
            pass
    elif mode == "unprotect-all":
        import warden_protect
        for line in warden_protect.unprotect_all() or ["No AI app was protected."]:
            print(line)
    else:
        print(f"Unknown mode {mode!r}. See the top of warden_main.py.")
        return 2
    return 0


def main() -> int:
    if Path(sys.executable).stem.lower() == "warden":       # Warden.exe: the app window
        import warden_app
        warden_app.main()
        return 0
    args = sys.argv[1:]
    if args and not args[0].startswith("-"):                 # a helper mode
        return run_mode(args[0], args[1:])
    import warden_gateway                                    # default: the gateway
    asyncio.run(warden_gateway.main(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
