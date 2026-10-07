@echo off
cd /d "%~dp0"
if exist config.bat call config.bat
cd backend
.venv\Scripts\python.exe main.py
