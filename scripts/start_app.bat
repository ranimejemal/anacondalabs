@echo off
REM AegisLab launcher (Windows) — one-click setup + run.
REM ------------------------------------------------------
REM On first run: creates a local Python virtual environment (.venv) at the
REM project root, installs backend\requirements.txt into it, and installs the
REM Electron frontend's node_modules. On every run after that those steps are
REM skipped automatically, and it just launches.
REM
REM No conda, no manual "activate" step required — only a system Python
REM 3.11+ and Node.js need to already be installed.

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR%.."
set "VENV_DIR=%ROOT_DIR%\.venv"

echo === AegisLab setup ^& launch ===

REM --- 1. Find a usable system Python launcher ---
REM Prefer specific versions known to have prebuilt wheels for every pinned
REM dependency. A bare "py -3" can silently resolve to whatever's newest
REM (e.g. a brand-new release like 3.14) which may not have prebuilt wheels
REM yet for a pinned package (pydantic-core in particular) — pip then falls
REM back to compiling it from source, which means downloading an entire
REM Rust toolchain and can take 10+ minutes instead of seconds. Trying
REM known-good versions first avoids that trap for most people.
set "PY_CMD="
where py >nul 2>nul
if %errorlevel%==0 (
    for %%V in (3.12 3.11 3.13) do (
        if not defined PY_CMD (
            py -%%V -c "1" >nul 2>nul
            if !errorlevel!==0 set "PY_CMD=py -%%V"
        )
    )
    if not defined PY_CMD (
        py -3 -c "1" >nul 2>nul
        if !errorlevel!==0 (
            set "PY_CMD=py -3"
            echo NOTE: Using whatever "py -3" resolves to on this system ^(not a
            echo pinned 3.11/3.12/3.13^). If dependency installation is very slow
            echo or tries to compile something from source, install Python 3.12
            echo from https://www.python.org/downloads/release/python-3120/ instead.
        )
    )
)
if not defined PY_CMD (
    where python >nul 2>nul
    if %errorlevel%==0 set "PY_CMD=python"
)

if not defined PY_CMD (
    echo.
    echo ERROR: No Python interpreter found on PATH.
    echo Install Python 3.11 or newer from https://www.python.org/downloads/
    echo   ^(during install, check "Add python.exe to PATH"^) and re-run this script.
    exit /b 1
)
echo Using system Python launcher: %PY_CMD%

REM --- 2. Create the project-local venv if it doesn't exist yet ---
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo Creating virtual environment at %VENV_DIR% ^(first run only^)...
    %PY_CMD% -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo ERROR: Failed to create the virtual environment.
        exit /b 1
    )
)

set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
if not exist "%VENV_PYTHON%" (
    echo ERROR: venv creation appears to have failed - %VENV_PYTHON% not found.
    exit /b 1
)

REM --- 3. Install/update backend dependencies (fast no-op if already satisfied) ---
echo Checking backend dependencies...
"%VENV_PYTHON%" -m pip install --quiet --upgrade pip
"%VENV_PYTHON%" -m pip install --quiet -r "%ROOT_DIR%\requirements.txt"
if errorlevel 1 (
    echo ERROR: Failed to install backend dependencies. See the output above.
    exit /b 1
)

set "AEGISLAB_PYTHON=%VENV_PYTHON%"
echo Backend will run on: %AEGISLAB_PYTHON%

REM --- 4. Check Node.js / npm are present ---
where node >nul 2>nul
if errorlevel 1 (
    echo.
    echo ERROR: Node.js is required to run the AegisLab desktop app but wasn't found on PATH.
    echo Install it from https://nodejs.org/ ^(LTS version^) and re-run this script.
    exit /b 1
)
where npm >nul 2>nul
if errorlevel 1 (
    echo.
    echo ERROR: npm was not found on PATH ^(usually installed alongside Node.js^).
    exit /b 1
)

REM --- 5. Install frontend dependencies if missing ---
cd /d "%ROOT_DIR%\frontend"
if not exist "node_modules" (
    echo Installing Electron dependencies ^(first run only^)...
    call npm install
    if errorlevel 1 (
        echo ERROR: npm install failed. See the output above.
        exit /b 1
    )
)

REM --- 6. Optional: warn if AI/Supabase env vars aren't configured ---
if not exist "%ROOT_DIR%\backend\.env" (
    echo.
    echo NOTE: backend\.env not found - AI suggestions and account sign-in will show a
    echo 'not configured' message until you copy backend\.env.example to backend\.env
    echo and fill in your Supabase/Anthropic keys. Scanning itself works fine without it.
)

echo.
echo Launching AegisLab...
call npm start