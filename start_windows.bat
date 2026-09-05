@echo off
chcp 65001 >nul
cd /d "%~dp0"
python server.py --root "%~dp0data_root"
pause
