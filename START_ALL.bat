@echo off
cd /d "%~dp0"
if exist config.bat call config.bat
where python >nul 2>nul
if errorlevel 1 (echo Install Python 3.12 and enable Add Python to PATH. & pause & exit /b 1)
where npm >nul 2>nul
if errorlevel 1 (echo Install Node.js LTS and restart this terminal. & pause & exit /b 1)
if not exist backend\.venv\Scripts\python.exe python -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
if errorlevel 1 (echo Backend dependency installation failed. & pause & exit /b 1)
pushd frontend
call npm install --no-audit --no-fund
if errorlevel 1 (popd & echo Frontend dependency installation failed. & pause & exit /b 1)
popd
start "CodeGuard Backend" cmd /k call "%~dp0START_BACKEND.bat"
start "CodeGuard Frontend" cmd /k call "%~dp0START_FRONTEND.bat"
echo Open http://localhost:5173 after Vite reports ready.
pause
