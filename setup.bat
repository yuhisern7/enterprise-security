@echo off
REM Enterprise Security System - Auto Setup Script (Windows)
REM One-command installation

echo ==============================================
echo 🛡️  Enterprise Security System Setup
echo ==============================================
echo.

REM Check if Docker is installed
where docker >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Docker not found
    echo.
    echo Please install Docker Desktop for Windows from:
    echo https://www.docker.com/products/docker-desktop/
    echo.
    pause
    exit /b 1
)
echo ✅ Docker found

REM Check if Docker is running
docker info >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Docker is not running
    echo.
    echo Please start Docker Desktop and try again
    pause
    exit /b 1
)
echo ✅ Docker is running
echo.

echo Step 1/6: Setting up ExploitDB database...
echo --------------------------------------------
cd AI
if not exist "exploitdb" (
    echo Downloading ExploitDB ^(46,948 exploits^)...
    echo This may take 5-10 minutes...
    
    REM Download using Git (if available) or curl
    where git >nul 2>nul
    if %ERRORLEVEL% EQU 0 (
        git clone https://github.com/offensive-security/exploitdb.git
        echo ✅ ExploitDB downloaded
    ) else (
        echo ⚠️  Git not found. Please install Git or manually download ExploitDB
        echo From: https://github.com/offensive-security/exploitdb
        echo To: AI/exploitdb/
        pause
    )
) else (
    echo ✅ ExploitDB already exists
)
cd ..
echo.

echo Step 2/6: Configuring environment...
echo --------------------------------------------

REM Create .env file if it doesn't exist
if not exist ".env" (
    echo Creating .env file...
    (
        echo # VirusTotal API Key ^(REQUIRED - Get free key from https://www.virustotal.com^)
        echo VIRUSTOTAL_API_KEY=
        echo.
        echo # AbuseIPDB API Key ^(Optional - Get from https://www.abuseipdb.com^)
        echo ABUSEIPDB_API_KEY=
        echo.
        echo # Timezone
        echo TZ=UTC
        echo.
        echo # Flask Environment
        echo FLASK_ENV=production
        echo.
        echo # AI Learning
        echo AI_LEARNING_ENABLED=true
    ) > .env
    
    echo ⚠️  Created .env file
    echo.
    echo IMPORTANT: Edit .env and add your VirusTotal API key!
    echo Opening .env in Notepad...
    notepad .env
) else (
    echo ✅ .env file exists
)
echo.

echo Step 3/6: Building Docker image...
echo --------------------------------------------
cd server
docker compose build
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Build failed
    pause
    exit /b 1
)
echo.

echo Step 4/6: Starting services...
echo --------------------------------------------
docker compose up -d
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Failed to start services
    pause
    exit /b 1
)
echo.

echo Step 5/6: Waiting for services to start...
echo --------------------------------------------
echo Waiting for server to be ready...
timeout /t 10 /nobreak >nul

REM Try to check if server is responding
curl -s http://localhost:5000 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo ✅ Server is ready!
) else (
    echo ⚠️  Server is starting... This may take a minute
)
echo.

echo ==============================================
echo 🎉 Setup Complete!
echo ==============================================
echo.
echo 📊 Dashboard: http://localhost:5000
echo.
echo 🐳 Container Status:
docker compose ps
echo.
echo 📝 View Logs:
echo    docker compose logs -f
echo.
echo 🛑 Stop System:
echo    cd server
echo    docker compose down
echo.
echo ⚙️  Next Steps:
echo    1. Open http://localhost:5000 in your browser
echo    2. Add your VirusTotal API key in .env if you haven't
echo    3. Restart if you added API key: docker compose restart
echo.
echo ==============================================
echo.

REM Open browser automatically
start http://localhost:5000

pause
