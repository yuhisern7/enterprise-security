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
echo 🚀 Creating required directories...
if not exist ai_training_materials\ml_models mkdir ai_training_materials\ml_models
if not exist ai_training_materials\exploitdb mkdir ai_training_materials\exploitdb
if not exist json mkdir json
if not exist ml_models mkdir ml_models

echo.
echo 📚 Training materials setup (for Premium mode):
echo    To enable Premium mode, upload training data to ai_training_materials\
echo    • Run: cd ..\AI ^& setup_exploitdb.sh
echo    • Copy ExploitDB to ai_training_materials\exploitdb\
echo.

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
echo 1. Verify relay services are running:
echo    docker logs -f security-relay-server
echo    (Should see: WebSocket Relay + Model Distribution API)
echo.
echo 2. Test Model Distribution API:
echo    curl http://localhost:60002/models/list
echo    curl http://localhost:60002/stats
echo.
echo 3. Get your public IP:
echo    Visit https://whatismyip.com
echo.
echo 4. Configure firewall (if applicable):
echo    Allow TCP ports 60001 and 60002 inbound
echo.
echo 5. On each subscriber container, edit server\.env:
echo    RELAY_ENABLED=true
echo    RELAY_URL=ws://YOUR-PUBLIC-IP:60001
echo    MODEL_SYNC_URL=http://YOUR-PUBLIC-IP:60002
echo    RELAY_CRYPTO_ENABLED=true
echo.
echo 6. Rebuild subscriber containers:
echo    cd ..\server
echo    docker compose down
echo    docker compose build
echo    docker compose up -d
echo.
echo 7. Test connection:
echo    curl http://localhost:60000/api/relay/status
echo    (Should show: "connected": true)
echo.
echo 8. Verify relay logs:
echo    docker logs security-relay-server
echo.
echo ==================================
echo 🌐 WebSocket Relay: ws://localhost:60001
echo 📦 Model Distribution API: http://localhost:60002
echo 🔒 Crypto: RSA-2048 + HMAC-SHA256
echo 📚 Training Materials: ai_training_materials\ (825 MB)
echo 🤖 ML Models: Served via API (280 KB total)
echo ==================================
echo.
pause
