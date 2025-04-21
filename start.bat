@echo off
setlocal
:: this script launches the PowerShell script in the current directory regardless of it's name
:: if there's only one PowerShell script, it launches the PowerShell script as admin
:: if there's more than one PowerShell script in the current directory, it prints an error

set "psScriptPath="
set "scriptDir=%~dp0"
set "checkFile=%scriptDir%ps_check_%RANDOM%.tmp"
set "powershellCommand="
set "errorOccurred=0"

if exist "%checkFile%" del "%checkFile%"


set "powershellCommand=$scriptDir = '%scriptDir%'; $checkFile = '%checkFile%'; $files = Get-ChildItem -Path $scriptDir -Filter '*.ps1' -File; if ($files.Count -eq 1) { $files.FullName | Out-File -FilePath $checkFile -Encoding ascii; exit 0 } elseif ($files.Count -eq 0) { exit 2 } else { exit $files.Count }"
powershell -NoProfile -Command "& {%powershellCommand%}"

if not exist "%checkFile%" goto CheckFailed

set /p psScriptPath=<"%checkFile%"

:: Cleanup the check file immediately after reading
if exist "%checkFile%" del "%checkFile%"

if not defined psScriptPath goto ReadFailed

if not exist "%psScriptPath%" goto PathInvalid

:: Checks passed, proceed to launch
goto LaunchScript




:CheckFailed
echo ERROR: Check file "%checkFile%" not found. Assuming 0 or multiple .ps1 files were present.
set errorOccurred=1
goto EndScript

:ReadFailed
echo ERROR: Check file existed, but could not read script path from it.
set errorOccurred=1
goto EndScript

:PathInvalid
echo ERROR: Script path read from check file does not exist: "%psScriptPath%"
set errorOccurred=1
goto EndScript

:LaunchScript
:: Launch the found PowerShell script using Start-Process for elevation
powershell -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%psScriptPath%""' -Verb RunAs"
goto EndScript

:EndScript
endlocal
exit /b %errorOccurred%
