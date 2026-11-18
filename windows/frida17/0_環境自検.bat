@echo off
chcp 65001 >nul
title Env check (frida17)
cd /d "%~dp0..\.."
set PYTHONIOENCODING=utf-8
.venv\Scripts\python.exe scripts\ultra0-17.py --check
echo.
pause
