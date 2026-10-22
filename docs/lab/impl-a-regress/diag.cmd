@echo off
set BLOOK_KDU_DRIVER_DIR=C:\byovd\drivers
echo ===== OLD-KDU-ASROCK =====
C:\byovd\kdu-old.exe exploits test asrock
echo OLD-EXIT=%ERRORLEVEL%
echo ===== NEW-KDU-ASROCK-TRACE =====
C:\byovd\kdu.exe --log-level trace --exploit asrock exploits test asrock
echo NEW-EXIT=%ERRORLEVEL%
