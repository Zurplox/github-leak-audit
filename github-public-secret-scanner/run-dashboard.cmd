@echo off
setlocal EnableExtensions DisableDelayedExpansion

for %%I in ("%~dp0..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1

python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if errorlevel 1 (
  echo Python 3.11 or newer is required.
  popd
  exit /b 1
)

if not exist "config.toml" (
  copy /Y "config.example.toml" "config.toml" >nul
  if errorlevel 1 (
    echo Could not create config.toml from config.example.toml.
    popd
    exit /b 1
  )
)

if not defined SCANNER_FINGERPRINT_KEY (
  echo SCANNER_FINGERPRINT_KEY must be set in the environment.
  popd
  exit /b 1
)

python -m scanner.dashboard --config config.toml --open
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%
