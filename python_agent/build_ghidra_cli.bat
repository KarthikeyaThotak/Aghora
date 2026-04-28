@echo off
setlocal enabledelayedexpansion

echo ============================================
echo  Ghidra-CLI Build Script for Windows
echo ============================================
echo.

:: Check for Rust/Cargo
where cargo >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] cargo not found. Please install Rust from https://rustup.rs/
    echo         After installing, restart your terminal and run this script again.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('cargo --version') do echo [OK] Found %%v

:: Check for Java 17+
where java >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] java not found. Ghidra requires Java 17 or newer.
    echo           Download from https://adoptium.net/
) else (
    for /f "tokens=*" %%v in ('java -version 2^>^&1') do (
        echo [OK] Found %%v
        goto :java_ok
    )
)
:java_ok

:: Check for GHIDRA_INSTALL_DIR
if "%GHIDRA_INSTALL_DIR%"=="" (
    echo.
    echo [WARNING] GHIDRA_INSTALL_DIR environment variable is not set.
    echo           Set it to your Ghidra installation directory, e.g.:
    echo           set GHIDRA_INSTALL_DIR=C:\ghidra_10.4_PUBLIC
    echo.
    echo           You can also add it to your .env file:
    echo           GHIDRA_INSTALL_DIR=C:\ghidra_10.4_PUBLIC
    echo.
    echo           Download Ghidra from https://ghidra-sre.org/
) else (
    echo [OK] GHIDRA_INSTALL_DIR = %GHIDRA_INSTALL_DIR%
)

:: Build ghidra-cli
echo.
echo [*] Building ghidra-cli (this may take a few minutes)...
echo.

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%ghidra_cli"

if not exist "Cargo.toml" (
    echo [ERROR] ghidra_cli/Cargo.toml not found.
    echo         Make sure the ghidra_cli directory exists with source files.
    pause
    exit /b 1
)

cargo install --path .
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed. Check the output above for errors.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  Build successful!
echo ============================================
echo.
echo  ghidra.exe installed to: %USERPROFILE%\.cargo\bin\ghidra.exe
echo.
echo  Next steps:
echo  1. Make sure GHIDRA_INSTALL_DIR is set in your .env file
echo  2. Restart the Python server (server.py)
echo  3. Upload a PE file to trigger Ghidra analysis
echo.

:: Verify the binary is accessible
where ghidra >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] 'ghidra' is on your PATH and ready to use.
) else (
    echo [WARNING] 'ghidra' is not on your PATH.
    echo           Add %USERPROFILE%\.cargo\bin to your PATH, or the tool will
    echo           use the full path automatically.
)

pause
