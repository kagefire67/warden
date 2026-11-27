# Builds WardenSetup.exe from this project.
#
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#
# Needs (build machine only, users need nothing):
#   - the project's .venv with requirements.txt + PyInstaller  (pip install pyinstaller)
#   - Inno Setup 6                                              (jrsoftware.org)
# Steps: run the tests -> bundle Warden + Python into build\dist\Warden (PyInstaller)
#        -> pack that folder into build\installer\WardenSetup-<version>.exe (Inno Setup).

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$python = Join-Path $root ".venv\Scripts\python.exe"

Write-Host "1/3 Running the tests..."
& $python tests\run_tests.py
if ($LASTEXITCODE -ne 0) { throw "Tests failed - not building an installer." }

Write-Host "2/3 Bundling Warden with PyInstaller..."
if (-not (Test-Path packaging\warden.ico)) { & $python packaging\make_icon.py }
& $python -m PyInstaller --noconfirm --clean --distpath build\dist --workpath build\work packaging\warden.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

Write-Host "3/3 Making the installer with Inno Setup..."
$iscc = @("$env:LOCALAPPDATA\Programs\Inno\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
          "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
          "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found. Install it from jrsoftware.org." }
& $iscc /Q packaging\warden.iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed." }

$setup = Get-ChildItem build\installer\WardenSetup-*.exe | Sort-Object LastWriteTime | Select-Object -Last 1
Write-Host ("Done: {0} ({1:N1} MB)" -f $setup.FullName, ($setup.Length / 1MB))
