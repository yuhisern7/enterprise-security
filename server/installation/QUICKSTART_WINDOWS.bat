@echo off
REM Quick start script for Windows (uses bridge networking with port mapping)

echo Starting Enterprise Security on Windows...
echo Using bridge networking mode (Windows compatible)
echo.

REM Change to server directory
cd /d "%~dp0\.."

REM Copy .env.windows to .env if .env doesn't exist
if not exist .env (
    echo Creating .env from .env.windows template...
    copy /Y .env.windows .env
)

REM Create JSON directory structure for enterprise features
if not exist json mkdir json
if not exist json\compliance_reports mkdir json\compliance_reports
if not exist json\performance_metrics mkdir json\performance_metrics

REM Initialize JSON files if they don't exist
if not exist json\threat_log.json echo [] > json\threat_log.json
if not exist json\blocked_ips.json echo [] > json\blocked_ips.json
if not exist json\visualization_data.json echo {} > json\visualization_data.json

echo Enterprise directories and files initialized...

docker compose -f docker-compose.windows.yml down 2>nul
docker compose -f docker-compose.windows.yml up -d --build

echo.
echo Container starting...
echo Dashboard: https://localhost:60000 (HTTPS - Accept SSL warning)
echo P2P Port: wss://localhost:60001
echo.
echo Waiting for container to be healthy...
timeout /t 30 /nobreak >nul

docker compose -f docker-compose.windows.yml ps

echo.
echo Note: Windows bridge mode has limited network scanning
echo Will detect Docker network devices only
echo For P2P mesh with Linux, ensure both containers are running
