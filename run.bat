@echo off
title ForensIQ Server
cd /d "%~dp0"
echo Starting ForensIQ on http://localhost:5000
echo Press Ctrl+C to stop.
echo.
python app.py
pause
