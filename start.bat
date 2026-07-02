@echo off
title WhatsApp Backup Merger
cd /d "%~dp0"

if not exist venv (
    echo [*] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Python not found. Install Python 3.10+ from python.org
        pause & exit /b 1
    )
    echo [*] Installing dependencies...
    venv\Scripts\pip install -q -r requirements.txt
    if errorlevel 1 (
        echo ERROR: pip install failed. Check your internet connection.
        pause & exit /b 1
    )
    echo [*] Setup complete.
)

echo.
echo  WhatsApp Backup Merger
echo  Opening http://127.0.0.1:5000 ...
echo  Press Ctrl+C to stop.
echo.
venv\Scripts\python app.py
pause
