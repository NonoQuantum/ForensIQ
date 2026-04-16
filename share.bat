@echo off
title ForensIQ - Public Share
cd /d "%~dp0"

echo Starting ForensIQ server...
start "ForensIQ Server" python app.py

timeout /t 2 /nobreak > nul

echo Opening public tunnel...
echo Your public URL will appear below. Share it with anyone.
echo Press Ctrl+C to stop sharing.
echo.
ngrok.exe http 5000 --pooling-enabled=true
