@echo off
title Minecraft SS Forensics - Backend API
set "DOTNET_ROOT=%USERPROFILE%\.dotnet"
set "PATH=%USERPROFILE%\.dotnet;%PATH%"
echo ========================================================
echo  Starting Minecraft SS Forensics Backend API
echo  Listening on: http://localhost:5000
echo ========================================================
cd /d "%~dp0backend\src\MinecraftSsForensics.Api"
dotnet run
pause
