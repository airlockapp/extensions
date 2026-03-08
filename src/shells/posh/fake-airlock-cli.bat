@echo off
REM Fake airlock-cli for testing the PowerShell profile.
REM Set AIRLOCK_CLI to this batch file's path and FAKE_AIRLOCK_EXIT to 0, 1, 2, or 5 etc.
if "%FAKE_AIRLOCK_EXIT%"=="" set FAKE_AIRLOCK_EXIT=0
exit /b %FAKE_AIRLOCK_EXIT%
