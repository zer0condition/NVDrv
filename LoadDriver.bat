@echo off
cd %~dp0

xcopy nvaudio.sys C:\
sc create nvaudio binpath=C:\nvaudio.sys type=kernel
sc start nvaudio

echo Press any key to unload driver
pause

sc stop nvaudio
sc delete nvaudio
del /f C:\nvaudio.sys

pause