@echo off
setlocal
cd /d "%~dp0"
if not defined PORT set "PORT=8000"

set "PYTHON=%~dp0.venv\Scripts\python.exe"
if exist "%PYTHON%" goto check_flask

where py >nul 2>nul
if not errorlevel 1 goto create_venv_with_py
where python >nul 2>nul
if not errorlevel 1 goto create_venv_with_python
goto missing_python

:create_venv_with_py
py -3 -m venv ".venv"
if errorlevel 1 goto venv_failed
goto check_flask

:create_venv_with_python
python -m venv ".venv"
if errorlevel 1 goto venv_failed

:check_flask
"%PYTHON%" -c "import flask" >nul 2>nul
if not errorlevel 1 goto register_startup

"%PYTHON%" -m ensurepip --upgrade
if errorlevel 1 goto pip_bootstrap_failed
"%PYTHON%" -m pip install -r requirements.txt
if errorlevel 1 goto install_failed
"%PYTHON%" -c "import flask" >nul 2>nul
if errorlevel 1 goto install_failed

:register_startup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Register Luxe Strand Startup.ps1"
if errorlevel 1 goto startup_failed

:: Reuse an existing Luxe Strand server instead of starting a second copy.
powershell.exe -NoProfile -Command "$response = try { Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:%PORT%/health' -TimeoutSec 2 } catch { $null }; if ($null -ne $response -and $response.StatusCode -eq 200 -and $response.Content.Contains('ok')) { exit 0 }; exit 1"
if not errorlevel 1 goto open_site

start "Luxe Strand Flask server - close this window to stop" /D "%~dp0" "%PYTHON%" "%~dp0server.py"

powershell.exe -NoProfile -Command "$deadline = (Get-Date).AddSeconds(30); do { try { $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:%PORT%/health' -TimeoutSec 2; if ($response.StatusCode -eq 200 -and $response.Content.Contains('ok')) { exit 0 } } catch {}; Start-Sleep -Seconds 1 } while ((Get-Date) -lt $deadline); exit 1"
if errorlevel 1 goto server_failed

:open_site
start "" "http://127.0.0.1:%PORT%"
endlocal
exit /b 0

:missing_python
echo Python 3 was not found. Install Python 3, then run this launcher again.
pause
exit /b 1

:venv_failed
echo Could not create the project's Python environment.
echo Make sure Python 3 is installed and try again.
pause
exit /b 1

:pip_bootstrap_failed
echo Could not enable pip in the project's Python environment.
echo Reinstall Python 3 with the pip and venv options enabled, then try again.
pause
exit /b 1

:install_failed
echo Could not install Flask from requirements.txt.
pause
exit /b 1

:startup_failed
echo Could not add Luxe Strand to your Windows Startup folder.
pause
exit /b 1

:server_failed
echo Flask did not respond at http://127.0.0.1:%PORT% within 30 seconds.
echo Check the Luxe Strand server window for the error message.
pause
exit /b 1
