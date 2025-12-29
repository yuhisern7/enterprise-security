@echo off
REM Quick setup script for relay server deployment on Windows

echo ==================================
echo 🌍 Security Mesh Relay Server
echo ==================================
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker not found! Please install Docker Desktop for Windows
    echo Download from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Check if Docker Compose is available
docker compose version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker Compose not found! Please update Docker Desktop
    pause
    exit /b 1
)

echo.
echo 🚀 Starting relay server...
docker compose down >nul 2>&1
docker compose up -d --build

echo.
echo ✅ Relay server started!
echo.
echo ==================================
echo 📋 Next Steps:
echo ==================================
echo.
echo 1. Get your public IP:
echo    Visit https://whatismyip.com
echo.
echo 2. Configure firewall (if applicable):
echo    Allow TCP port 60001 inbound
echo.
echo 3. On each security container, edit server\.env:
echo    RELAY_ENABLED=true
echo    RELAY_URL=wss://YOUR-PUBLIC-IP:60001
echo    P2P_SYNC_ENABLED=false
echo.
echo 4. Restart containers:
echo    docker compose down
echo    docker compose up -d
echo.
echo 5. Verify connection:
echo    docker logs security-relay-server
echo.
echo ==================================
echo 🌐 Relay Server: ws://localhost:60001
echo ==================================
echo.
pause
