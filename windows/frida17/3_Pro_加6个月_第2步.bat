@echo off
chcp 65001 >nul
title Pro +6 months - step 2
cd /d "%~dp0..\.."
set PYTHONIOENCODING=utf-8
.venv\Scripts\python.exe scripts\ultra0-17.py --account "current@device" --no-add --force --stack --plan pro6
echo.
pause
