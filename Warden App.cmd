@echo off
rem Double-click to open the Warden App (no console window stays open).
start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0warden_app.py"
