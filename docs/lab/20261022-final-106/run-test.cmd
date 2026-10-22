@echo off
set BLOOK_KDU_DRIVER_DIR=C:\byovd\drivers
C:\byovd\kdu.exe exploits test %1
exit /b %ERRORLEVEL%
