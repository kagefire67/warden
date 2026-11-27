# PyInstaller recipe for the installed Warden.  Build with:  packaging\build.ps1
#
# Makes ONE folder (dist\Warden) holding two programs that share a bundled Python:
#   Warden.exe          the Warden App (window, no console)
#   warden-gateway.exe  the gateway AI apps start (console program: it talks over stdin/stdout)
# Both run warden_main.py, which picks the job from the program's name and arguments.

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent

a = Analysis(
    [str(ROOT / "warden_main.py")],
    pathex=[str(ROOT), str(ROOT / "attack_lab")],
    # Modules that warden_main imports only inside functions, plus the MCP libraries.
    hiddenimports=["warden_gateway", "warden_app", "add_server", "view_log",
                   "run_lab", "lab_server", "scenarios"]
                  # (mcp.cli is the SDK's optional command-line tool; Warden does not use it)
                  + collect_submodules("mcp", filter=lambda name: not name.startswith("mcp.cli"),
                                       on_error="ignore")
                  + collect_submodules("mcp_types", on_error="ignore"),
    datas=[
        (str(ROOT / "ui"), "ui"),                                   # the app's screens
        (str(ROOT / "rules.json"), "."),                            # the built-in rules
        (str(ROOT / "warden_config.default.json"), "."),            # first-run settings
    ],
    excludes=["tkinter", "pytest"],
)
pyz = PYZ(a.pure)

icon = str(ROOT / "packaging" / "warden.ico")

gateway = EXE(pyz, a.scripts, [], exclude_binaries=True, name="warden-gateway",
              console=True, icon=icon, version=None)
app = EXE(pyz, a.scripts, [], exclude_binaries=True, name="Warden",
          console=False, icon=icon, version=None)

coll = COLLECT(gateway, app, a.binaries, a.datas, name="Warden")
