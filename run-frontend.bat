@echo off
title Minecraft SS Forensics - Web Dashboard
echo ========================================================
echo  Starting Minecraft SS Forensics Web Dashboard
echo  Access at: http://localhost:3000
echo ========================================================
cd /d "%~dp0frontend"
npm run dev
pause
