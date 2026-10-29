@echo off
cd /d "%~dp0"
python main.py
if errorlevel 1 (
  echo.
  echo Failed to start. Install dependencies: pip install -r requirements.txt
  pause
)
