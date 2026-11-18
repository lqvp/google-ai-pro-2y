@echo off
chcp 65001 >nul
title List offers (no purchase)
cd /d "%~dp0..\.."
set PYTHONIOENCODING=utf-8
python scripts\ultra0.py --account "current@device" --no-add --force --list --plan pro12
echo.
pause
