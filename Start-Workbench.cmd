@echo off
setlocal
cd /d "%~dp0"
title Bounty Workbench
python workbench.py --open
if errorlevel 1 pause
