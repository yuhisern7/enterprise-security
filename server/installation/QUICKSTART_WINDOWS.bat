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

docker compose down 2>nul
docker compose up -d --build

echo.
echo Container starting...
echo Dashboard: http://localhost:60000
echo P2P Port: https://localhost:60001
echo.
echo Waiting for container to be healthy...
timeout /t 30 /nobreak >nul

docker compose ps

echo.
echo Note: Windows bridge mode has limited network scanning
echo Will detect Docker network devices only
echo For P2P mesh with Linux, ensure both containers are running
