@echo off
title Minecraft SS Forensics - Scanner App
set "DOTNET_ROOT=%USERPROFILE%\.dotnet"
set "PATH=%USERPROFILE%\.dotnet;%PATH%"
echo ========================================================
echo  Launching Minecraft SS Forensics Windows Scanner GUI
echo ========================================================
cd /d "%~dp0backend\src\MinecraftSsForensics.Scanner.App"
dotnet run
pause
