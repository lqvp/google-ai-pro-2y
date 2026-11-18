@echo off
chcp 65001 >nul
title Pro +6 months (extra)
cd /d "%~dp0..\.."
set PYTHONIOENCODING=utf-8
python scripts\ultra0.py --account "current@device" --no-add --force --stack --plan pro6c
echo.
pause
