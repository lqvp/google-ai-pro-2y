@echo off
chcp 65001 >nul
title Env check
cd /d "%~dp0..\.."
set PYTHONIOENCODING=utf-8
python scripts\ultra0.py --check
echo.
pause
