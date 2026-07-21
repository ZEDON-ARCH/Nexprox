@echo off
title Nexprox Node.js Edition — Installer
color 0A
setlocal enabledelayedexpansion

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║    NEXPROX NODE.JS EDITION — SETUP ^& LAUNCHER  ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: ── Check Node.js ──
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Node.js is NOT installed or not in your PATH.
    echo.
    echo  Please install Node.js ^>= 18.0:
    echo    https://nodejs.org/
    echo.
    echo  After installing, re-run this script.
    pause
    exit /b 1
)

echo  [OK] Node.js found:
node --version
echo.

:: ── Check npm ──
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] npm not found. Install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

:: ── Verify files ──
if not exist "server.js" (
    echo  [ERROR] server.js not found. Run this from the Nexprox-Node directory.
    pause
    exit /b 1
)

:: ── Install dependencies ──
if not exist "node_modules" (
    echo  [SETUP] Installing npm dependencies...
    npm install
    echo.
)

:: ── Create data files ──
if not exist "users.json" echo {} > users.json

echo  [OK] Dependencies ready.
echo.
echo  ═════════════════════════════════════════════════
echo   Starting Nexprox Dashboard on http://localhost:3000
echo   Press Ctrl+C to stop the server.
echo  ═════════════════════════════════════════════════
echo.

:: Start the Node.js server
node server.js

pause
