@echo off
chcp 65001 >nul
title Pro 12 months - step 1
cd /d "%~dp0..\.."
set PYTHONIOENCODING=utf-8
.venv\Scripts\python.exe scripts\ultra0-17.py --account "current@device" --no-add --force --plan pro12
echo.
pause
