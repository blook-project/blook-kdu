@echo off
set BLOOK_KDU_DRIVER_DIR=C:\byovd\drivers
set BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1
C:\byovd\kdu.exe exploits test %1
exit /b %ERRORLEVEL%
