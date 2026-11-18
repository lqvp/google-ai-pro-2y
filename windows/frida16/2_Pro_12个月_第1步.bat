@echo off
chcp 65001 >nul
title Pro 12 months - step 1
cd /d "%~dp0..\.."
set PYTHONIOENCODING=utf-8
python scripts\ultra0.py --account "current@device" --no-add --force --plan pro12
echo.
pause
