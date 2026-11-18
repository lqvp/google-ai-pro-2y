@echo off
chcp 65001 >nul
title Pro +6 months - step 3
cd /d "%~dp0..\.."
set PYTHONIOENCODING=utf-8
python scripts\ultra0.py --account "current@device" --no-add --force --stack --plan pro6b
echo.
pause
