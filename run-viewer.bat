@echo off
title Minecraft SS Forensics - Staff Report Viewer
set "DOTNET_ROOT=%USERPROFILE%\.dotnet"
set "PATH=%USERPROFILE%\.dotnet;%PATH%"
echo ========================================================
echo  Launching Minecraft SS Forensics Staff Report Viewer
echo ========================================================
cd /d "%~dp0backend\src\MinecraftSsForensics.Viewer.App"
dotnet run
pause
