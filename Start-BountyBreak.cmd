@echo off
setlocal
cd /d "%~dp0"
title BountyBreak
python workbench.py --open
if errorlevel 1 pause
