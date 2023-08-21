@echo off
cd %~dp0

xcopy nvoclock.sys C:\
sc create nvoclock binpath=C:\nvoclock.sys type=kernel
sc start nvoclock

echo Press any key to unload driver
pause

sc stop nvoclock
sc delete nvoclock
del /f C:\nvoclock.sys

pause
