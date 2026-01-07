# Battle-Hardened AI - Installation Guide

Complete installation instructions for Windows, Linux, and macOS.

---

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Linux Installation](#linux-installation)
- [Windows Installation](#windows-installation)
- [macOS Installation](#macos-installation)
- [Post-Installation](#post-installation)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### ✅ Required on All Platforms

| Requirement | Minimum Version | Check Command |
|-------------|----------------|---------------|
| **Docker Engine** | 20.10.0+ | `docker --version` |
| **Docker Compose** | v2.0.0+ | `docker compose version` |
| **Disk Space** | 2 GB free | 5 GB recommended |
| **RAM** | 2 GB | 4 GB recommended |
| **Internet** | Required for initial build | |

### ✅ Required Ports

- **60000** - HTTPS Dashboard (required)
- **60001** - WebSocket Relay Client (optional, for global mesh)

### ❌ NOT Required (Included in Docker Container)

- ❌ Python 3
- ❌ pip
- ❌ System packages (tcpdump, openssl, gcc)
- ❌ Python libraries (scikit-learn, tensorflow, flask)
- ❌ SSL certificates (auto-generated)
- ❌ Root access for Python

---

## Linux Installation

### Supported Distributions

- Ubuntu 20.04+, 22.04, 24.04
- Debian 11+, 12
- RHEL 8+, 9
- CentOS Stream 8+
- Fedora 36+
- Arch Linux (latest)

### Quick Install (Automated Script)

```bash
# Download and run installer
curl -fsSL https://raw.githubusercontent.com/yuhisern7/battle-hardened-ai/main/install.sh | bash
```

### Manual Installation

#### Step 1: Install Docker

**Ubuntu/Debian:**
```bash
# Update package index
sudo apt-get update

# Install prerequisites
sudo apt-get install -y ca-certificates curl gnupg

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add user to docker group (avoid sudo)
sudo usermod -aG docker $USER

# Logout and login again for group changes to take effect
```

**RHEL/CentOS/Fedora:**
```bash
# Install Docker
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
```

#### Step 2: Install Battle-Hardened AI

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
cd battle-hardened-ai/server

# Create configuration file
cat > .env << 'EOF'
# Battle-Hardened AI Configuration
TZ=Asia/Kuala_Lumpur
NETWORK_INTERFACE=eth0

# Optional: Enable relay connection for global threat sharing
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
# MODEL_SYNC_URL=https://YOUR_VPS_IP:60002
RELAY_CRYPTO_ENABLED=true
EOF

# Build and start container
docker compose up -d --build

# Wait for startup
sleep 10

# Check status
docker ps | grep battle-hardened-ai
```

#### Step 3: Verify Installation

```bash
# Check logs
docker logs battle-hardened-ai --tail=50

# Should see:
# ✅ ML models initialized successfully
# [ENTERPRISE] System ready for commercial deployment

# Test dashboard
curl -k https://localhost:60000
```

#### Step 4: Access Dashboard

Open browser: **https://localhost:60000**

Accept self-signed SSL certificate warning (one-time).

---

### Linux Installation Script

Save as `install-linux.sh`:

```bash
#!/bin/bash
# Battle-Hardened AI - Linux Installer
# Supports: Ubuntu, Debian, RHEL, CentOS, Fedora

set -e

echo "🔒 Battle-Hardened AI Security System - Linux Installer"
echo "========================================================="
echo ""

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "❌ Cannot detect Linux distribution"
    exit 1
fi

echo "📊 Detected: $PRETTY_NAME"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "⚠️  Please do not run as root. Run as regular user with sudo access."
    exit 1
fi

# Check sudo access
if ! sudo -v &> /dev/null; then
    echo "❌ This script requires sudo access"
    exit 1
fi
echo "✅ Sudo access confirmed"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker not found. Installing Docker..."
    
    case $OS in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y ca-certificates curl gnupg
            sudo install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$OS/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            sudo chmod a+r /etc/apt/keyrings/docker.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        rhel|centos|fedora)
            sudo dnf -y install dnf-plugins-core
            sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
            sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            sudo systemctl start docker
            sudo systemctl enable docker
            ;;
        *)
            echo "❌ Unsupported distribution: $OS"
            echo "   Please install Docker manually: https://docs.docker.com/engine/install/"
            exit 1
            ;;
    esac
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    echo "✅ Docker installed. You may need to logout and login for group changes."
fi
echo "✅ Docker: $(docker --version)"

# Check Docker Compose
if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose v2 not found. Please upgrade Docker."
    exit 1
fi
echo "✅ Docker Compose: $(docker compose version)"

# Check if can run docker (group membership)
if ! docker ps &> /dev/null; then
    echo "⚠️  Cannot run docker commands. Adding user to docker group..."
    sudo usermod -aG docker $USER
    echo "✅ User added to docker group. Please logout and run this script again."
    exit 0
fi
echo "✅ Docker permissions OK"

# Check disk space
available_space=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
if [ "$available_space" -lt 2 ]; then
    echo "⚠️  Warning: Low disk space (${available_space}GB available, 2GB+ recommended)"
fi
echo "✅ Disk space: ${available_space}GB available"

# Check port 60000
if ss -tuln 2>/dev/null | grep -q ':60000 ' || netstat -tuln 2>/dev/null | grep -q ':60000 '; then
    echo "❌ Port 60000 already in use. Please free this port first."
    exit 1
fi
echo "✅ Port 60000 available"

echo ""
echo "🎯 All prerequisites met! Starting installation..."
echo ""

# Clone or update repository
if [ ! -d "battle-hardened-ai" ]; then
    echo "📥 Cloning repository..."
    git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
    cd battle-hardened-ai/server
else
    echo "📂 Using existing repository"
    cd battle-hardened-ai/server
    git pull
fi

# Create .env if doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️  Creating default configuration..."
    cat > .env << 'EOF'
# Battle-Hardened AI Configuration
TZ=Asia/Kuala_Lumpur
NETWORK_INTERFACE=eth0

# Optional: Enable relay connection for global threat sharing
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
# MODEL_SYNC_URL=https://YOUR_VPS_IP:60002
RELAY_CRYPTO_ENABLED=true
EOF
fi

# Start container
echo "🚀 Building and starting Battle-Hardened AI..."
docker compose up -d --build

# Wait for container
echo "⏳ Waiting for container to start..."
for i in {1..30}; do
    if docker ps | grep -q "battle-hardened-ai"; then
        break
    fi
    sleep 1
done

# Check if running
if docker ps | grep -q "battle-hardened-ai"; then
    echo ""
    echo "========================================================="
    echo "✅ Installation complete!"
    echo "========================================================="
    echo ""
    echo "🌐 Access your dashboard at:"
    echo "   https://localhost:60000"
    echo ""
    echo "⚠️  Accept the self-signed SSL certificate in your browser"
    echo ""
    echo "📊 Useful commands:"
    echo "   View logs:    docker logs -f battle-hardened-ai"
    echo "   Stop system:  docker compose down"
    echo "   Restart:      docker compose restart"
    echo "   Update:       git pull && docker compose up -d --build"
    echo ""
    echo "📖 Documentation:"
    echo "   README.md for features and configuration"
    echo "   testconnection.md for relay server setup"
    echo ""
else
    echo "❌ Container failed to start. Check logs:"
    echo "   docker logs battle-hardened-ai"
    exit 1
fi
```

Make executable:
```bash
chmod +x install-linux.sh
./install-linux.sh
```

---

## Windows Installation

### Supported Versions

- Windows 10 (64-bit, build 19041+)
- Windows 11 (all versions)
- Windows Server 2019+
- Windows Server 2022

### Prerequisites

1. **WSL2** (Windows Subsystem for Linux 2)
2. **Docker Desktop for Windows**

### Step 1: Enable WSL2

Open PowerShell as Administrator:

```powershell
# Enable WSL
wsl --install

# Restart computer
Restart-Computer
```

After restart, WSL will complete installation. Set up Ubuntu username/password when prompted.

### Step 2: Install Docker Desktop

1. Download from: https://www.docker.com/products/docker-desktop/
2. Run installer: `Docker Desktop Installer.exe`
3. During installation:
   - ✅ Check "Use WSL 2 instead of Hyper-V"
   - ✅ Check "Add shortcut to desktop"
4. Restart computer
5. Start Docker Desktop
6. Wait for "Docker is running" notification

### Step 3: Install Battle-Hardened AI

Open PowerShell (regular user, not Administrator):

```powershell
# Clone repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
cd battle-hardened-ai\server

# Create configuration file
@"
# Battle-Hardened AI Configuration
TZ=Asia/Kuala_Lumpur
NETWORK_INTERFACE=eth0

# Optional: Enable relay connection for global threat sharing
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
# MODEL_SYNC_URL=https://YOUR_VPS_IP:60002
RELAY_CRYPTO_ENABLED=true
"@ | Out-File -Encoding UTF8 .env

# Build and start container
docker compose -f docker-compose.windows.yml up -d --build

# Wait for startup
Start-Sleep -Seconds 10

# Check status
docker ps
```

### Step 4: Verify Installation

```powershell
# Check logs
docker logs battle-hardened-ai --tail=50

# Test dashboard
curl.exe -k https://localhost:60000
```

### Step 5: Access Dashboard

Open browser: **https://localhost:60000**

Accept certificate warning (click "Advanced" → "Proceed to localhost").

---

### Windows Installation Script

Save as `install-windows.ps1`:

```powershell
# Battle-Hardened AI - Windows Installer
# Requires: Windows 10/11 with WSL2 and Docker Desktop

Write-Host "🔒 Battle-Hardened AI Security System - Windows Installer" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check Windows version
$winVersion = [System.Environment]::OSVersion.Version
if ($winVersion.Major -lt 10) {
    Write-Host "❌ Windows 10 or higher required" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Windows $($winVersion.Major).$($winVersion.Minor) detected" -ForegroundColor Green

# Check if Docker is installed
try {
    $dockerVersion = docker --version
    Write-Host "✅ Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker not found. Please install Docker Desktop:" -ForegroundColor Red
    Write-Host "   https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "After installing Docker Desktop:" -ForegroundColor Yellow
    Write-Host "1. Restart your computer" -ForegroundColor Yellow
    Write-Host "2. Start Docker Desktop" -ForegroundColor Yellow
    Write-Host "3. Run this script again" -ForegroundColor Yellow
    exit 1
}

# Check Docker Compose
try {
    docker compose version | Out-Null
    Write-Host "✅ Docker Compose found" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker Compose not available. Please update Docker Desktop." -ForegroundColor Red
    exit 1
}

# Check if Docker is running
try {
    docker ps | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Check disk space (need at least 2GB)
$drive = (Get-Location).Drive
$freeSpace = [math]::Round((Get-PSDrive $drive.Name).Free / 1GB, 2)
if ($freeSpace -lt 2) {
    Write-Host "⚠️  Warning: Low disk space (${freeSpace}GB available, 2GB+ recommended)" -ForegroundColor Yellow
}
Write-Host "✅ Disk space: ${freeSpace}GB available" -ForegroundColor Green

# Check port 60000
$portInUse = Get-NetTCPConnection -LocalPort 60000 -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "❌ Port 60000 already in use. Please free this port first." -ForegroundColor Red
    exit 1
}
Write-Host "✅ Port 60000 available" -ForegroundColor Green

Write-Host ""
Write-Host "🎯 All prerequisites met! Starting installation..." -ForegroundColor Cyan
Write-Host ""

# Clone or update repository
if (-not (Test-Path "battle-hardened-ai")) {
    Write-Host "📥 Cloning repository..." -ForegroundColor Cyan
    git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
    Set-Location battle-hardened-ai\server
} else {
    Write-Host "📂 Using existing repository" -ForegroundColor Cyan
    Set-Location battle-hardened-ai\server
    git pull
}

# Create .env if doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host "⚙️  Creating default configuration..." -ForegroundColor Cyan
    @"
# Battle-Hardened AI Configuration
TZ=Asia/Kuala_Lumpur
NETWORK_INTERFACE=eth0

# Optional: Enable relay connection for global threat sharing
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
# MODEL_SYNC_URL=https://YOUR_VPS_IP:60002
RELAY_CRYPTO_ENABLED=true
"@ | Out-File -Encoding UTF8 .env
}

# Start container
Write-Host "🚀 Building and starting Battle-Hardened AI..." -ForegroundColor Cyan
docker compose -f docker-compose.windows.yml up -d --build

# Wait for container
Write-Host "⏳ Waiting for container to start..." -ForegroundColor Cyan
Start-Sleep -Seconds 15

# Check if running
$running = docker ps | Select-String "battle-hardened-ai"
if ($running) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "🌐 Access your dashboard at:" -ForegroundColor Cyan
    Write-Host "   https://localhost:60000" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "⚠️  Accept the self-signed SSL certificate in your browser" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "📊 Useful commands:" -ForegroundColor Cyan
    Write-Host "   View logs:    docker logs -f battle-hardened-ai" -ForegroundColor White
    Write-Host "   Stop system:  docker compose -f docker-compose.windows.yml down" -ForegroundColor White
    Write-Host "   Restart:      docker compose -f docker-compose.windows.yml restart" -ForegroundColor White
    Write-Host "   Update:       git pull; docker compose -f docker-compose.windows.yml up -d --build" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "❌ Container failed to start. Check logs:" -ForegroundColor Red
    Write-Host "   docker logs battle-hardened-ai" -ForegroundColor Yellow
    exit 1
}
```

Run in PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File install-windows.ps1
```

---

## macOS Installation

### Supported Versions

- macOS 11 (Big Sur) or higher
- macOS 12 (Monterey)
- macOS 13 (Ventura)
- macOS 14 (Sonoma)

**⚠️ Note:** macOS is supported but **not recommended for production** due to performance limitations. Best for development/testing only.

### Step 1: Install Docker Desktop

1. Download from: https://www.docker.com/products/docker-desktop/
2. Open `Docker.dmg`
3. Drag Docker icon to Applications folder
4. Open Docker from Applications
5. Grant permissions when prompted
6. Wait for "Docker is running" notification

### Step 2: Install Battle-Hardened AI

Open Terminal:

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
cd battle-hardened-ai/server

# Create configuration file
cat > .env << 'EOF'
# Battle-Hardened AI Configuration
TZ=America/New_York
NETWORK_INTERFACE=en0

# Optional: Enable relay connection for global threat sharing
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
# MODEL_SYNC_URL=https://YOUR_VPS_IP:60002
RELAY_CRYPTO_ENABLED=true
EOF

# Build and start container
docker compose up -d --build

# Wait for startup
sleep 10

# Check status
docker ps | grep battle-hardened-ai
```

### Step 3: Verify Installation

```bash
# Check logs
docker logs battle-hardened-ai --tail=50

# Test dashboard
curl -k https://localhost:60000
```

### Step 4: Access Dashboard

Open browser: **https://localhost:60000**

Accept certificate warning (click "Show Details" → "visit this website").

---

### macOS Installation Script

Save as `install-macos.sh`:

```bash
#!/bin/bash
# Battle-Hardened AI - macOS Installer

set -e

echo "🔒 Battle-Hardened AI Security System - macOS Installer"
echo "========================================================"
echo ""

# Check macOS version
if [[ ! "$OSTYPE" == "darwin"* ]]; then
    echo "❌ This script is for macOS only"
    exit 1
fi

macos_version=$(sw_vers -productVersion)
echo "✅ macOS $macos_version detected"

# Warn about production use
echo "⚠️  macOS is supported for development/testing only."
echo "   For production, use Linux on dedicated hardware or VPS."
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker Desktop:"
    echo "   https://www.docker.com/products/docker-desktop/"
    echo ""
    echo "After installing:"
    echo "1. Open Docker from Applications"
    echo "2. Wait for 'Docker is running' notification"
    echo "3. Run this script again"
    exit 1
fi
echo "✅ Docker found: $(docker --version)"

# Check Docker Compose
if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not found. Please update Docker Desktop."
    exit 1
fi
echo "✅ Docker Compose found"

# Check if Docker is running
if ! docker ps &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi
echo "✅ Docker is running"

# Check disk space
available_space=$(df -g . | tail -1 | awk '{print $4}')
if [ "$available_space" -lt 2 ]; then
    echo "⚠️  Warning: Low disk space (${available_space}GB available, 2GB+ recommended)"
fi
echo "✅ Disk space: ${available_space}GB available"

# Check port 60000
if lsof -Pi :60000 -sTCP:LISTEN -t &> /dev/null; then
    echo "❌ Port 60000 already in use. Please free this port first."
    exit 1
fi
echo "✅ Port 60000 available"

echo ""
echo "🎯 All prerequisites met! Starting installation..."
echo ""

# Clone or update repository
if [ ! -d "battle-hardened-ai" ]; then
    echo "📥 Cloning repository..."
    git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
    cd battle-hardened-ai/server
else
    echo "📂 Using existing repository"
    cd battle-hardened-ai/server
    git pull
fi

# Create .env if doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️  Creating default configuration..."
    cat > .env << 'EOF'
# Battle-Hardened AI Configuration
TZ=America/New_York
NETWORK_INTERFACE=en0

# Optional: Enable relay connection for global threat sharing
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
# MODEL_SYNC_URL=https://YOUR_VPS_IP:60002
RELAY_CRYPTO_ENABLED=true
EOF
fi

# Start container
echo "🚀 Building and starting Battle-Hardened AI..."
docker compose up -d --build

# Wait for container
echo "⏳ Waiting for container to start..."
sleep 15

# Check if running
if docker ps | grep -q "battle-hardened-ai"; then
    echo ""
    echo "========================================================"
    echo "✅ Installation complete!"
    echo "========================================================"
    echo ""
    echo "🌐 Access your dashboard at:"
    echo "   https://localhost:60000"
    echo ""
    echo "⚠️  Accept the self-signed SSL certificate in your browser"
    echo ""
    echo "📊 Useful commands:"
    echo "   View logs:    docker logs -f battle-hardened-ai"
    echo "   Stop system:  docker compose down"
    echo "   Restart:      docker compose restart"
    echo "   Update:       git pull && docker compose up -d --build"
    echo ""
else
    echo "❌ Container failed to start. Check logs:"
    echo "   docker logs battle-hardened-ai"
    exit 1
fi
```

Make executable:
```bash
chmod +x install-macos.sh
./install-macos.sh
```

---

## Post-Installation

### 1. Access Dashboard

Open browser: **https://localhost:60000**

**Accept SSL Certificate:**
- Chrome/Edge: Click "Advanced" → "Proceed to localhost (unsafe)"
- Firefox: Click "Advanced" → "Accept the Risk and Continue"
- Safari: Click "Show Details" → "visit this website"

### 2. Verify System Status

You should see:
- ✅ "0 threats detected" (clean start)
- ✅ ML Status: "3 models trained"
- ✅ Section 4: Auto-training active
- ✅ System Status: All green

### 3. Test Threat Detection

Trigger a test attack to verify the system works:

```bash
# Linux/macOS
curl -k "https://localhost:60000/?id=1' OR '1'='1"

# Windows PowerShell
curl.exe -k "https://localhost:60000/?id=1' OR '1'='1"
```

Reload dashboard - you should see **1 SQL Injection attack detected**.

### 4. Configure Timezone (Optional)

Edit `.env` file:
```bash
TZ=America/New_York     # US East Coast
TZ=Europe/London        # UK
TZ=Asia/Tokyo           # Japan
TZ=Australia/Sydney     # Australia
```

Restart container:
```bash
docker compose restart
```

### 5. Enable Relay Connection (Optional)

For global threat sharing with VPS relay server:

Edit `.env`:
```bash
RELAY_ENABLED=true
RELAY_URL=wss://YOUR_VPS_IP:60001
MODEL_SYNC_URL=https://YOUR_VPS_IP:60002
RELAY_CRYPTO_ENABLED=true
```

Restart:
```bash
docker compose restart
```

Check connection:
```bash
docker logs battle-hardened-ai | grep RELAY
# Should see: [RELAY] Connected to relay server
```

---

## Installation Checklist

### Pre-Installation ✅

- [ ] Docker Engine 20.10.0+ installed
- [ ] Docker Compose v2.0.0+ available
- [ ] Port 60000 available
- [ ] 2+ GB disk space free
- [ ] Internet connection active
- [ ] User has docker permissions (Linux) or Docker Desktop running (Windows/Mac)

### During Installation ✅

- [ ] Repository cloned successfully
- [ ] `.env` file created
- [ ] Container build completed (5-10 minutes)
- [ ] Container shows "healthy" status
- [ ] No error messages in logs

### Post-Installation ✅

- [ ] Dashboard accessible at https://localhost:60000
- [ ] SSL certificate accepted
- [ ] Dashboard shows "0 threats detected"
- [ ] ML Status shows "3 models trained"
- [ ] Test SQL injection detected successfully
- [ ] Logs show no critical errors

---

## Troubleshooting

### Issue: Docker not found

**Linux:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Logout and login
```

**Windows:**
- Download Docker Desktop: https://www.docker.com/products/docker-desktop/
- Enable WSL2: `wsl --install` (PowerShell as Admin)
- Restart computer

**macOS:**
- Download Docker Desktop: https://www.docker.com/products/docker-desktop/
- Drag to Applications folder

### Issue: Port 60000 already in use

**Linux/macOS:**
```bash
# Find process using port
sudo lsof -i :60000

# Kill process
sudo kill -9 <PID>
```

**Windows:**
```powershell
# Find process
Get-NetTCPConnection -LocalPort 60000

# Kill process
Stop-Process -Id <PID> -Force
```

### Issue: Container fails to start

Check logs:
```bash
docker logs battle-hardened-ai

# Common issues:
# - Port conflict → Free port 60000
# - Permission denied → Add user to docker group
# - Out of disk space → Free up 2+ GB
```

### Issue: Permission denied (Linux)

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Logout and login
# OR force refresh
newgrp docker
```

### Issue: SSL certificate warning

**This is normal for self-signed certificates.**

Each browser handles it differently:
- Chrome: "Advanced" → "Proceed to localhost"
- Firefox: "Advanced" → "Accept Risk"
- Safari: "Show Details" → "visit this website"

### Issue: Dashboard shows 404 or blank page

```bash
# Restart container
docker compose restart

# Wait 10 seconds
sleep 10

# Check logs for errors
docker logs battle-hardened-ai --tail=100
```

### Issue: Windows Docker Desktop not starting

1. Check WSL2 is installed: `wsl --list`
2. Update WSL: `wsl --update`
3. Check Hyper-V disabled in BIOS (conflicts with WSL2)
4. Restart Docker Desktop as Administrator
5. Check Windows version (needs build 19041+)

### Issue: macOS performance slow

macOS uses virtualization which is slower than native Linux.

**Solutions:**
- Increase Docker Desktop resources (Settings → Resources)
- Allocate 4 GB RAM minimum
- Allocate 2 CPU cores minimum
- For production, use Linux server instead

### Issue: Can't connect to relay server

```bash
# Test relay connectivity
curl -k https://YOUR_VPS_IP:60002/stats

# Check RELAY_URL format
RELAY_URL=wss://YOUR_VPS_IP:60001  # NOT ws://

# Check firewall
# VPS must allow ports 60001, 60002
```

### Issue: ML models not training

```bash
# Check logs
docker logs battle-hardened-ai | grep "ML"

# Should see:
# [AI] ✅ ML models initialized successfully

# Force retrain
docker exec battle-hardened-ai python3 -c "from AI import pcs_ai; pcs_ai.retrain_ml_models_now()"
```

---

## Updating Battle-Hardened AI

### Update Process

```bash
# Navigate to installation directory
cd battle-hardened-ai/server

# Pull latest code
git pull

# Rebuild and restart
docker compose down
docker compose up -d --build

# Verify
docker logs battle-hardened-ai --tail=50
```

### Backup Before Update (Recommended)

```bash
# Backup threat logs and ML models
docker cp battle-hardened-ai:/app/ml_models ./backup_ml_models
docker cp battle-hardened-ai:/app/json ./backup_json

# After update, restore if needed
docker cp ./backup_ml_models/. battle-hardened-ai:/app/ml_models/
```

---

## Uninstallation

### Complete Removal

```bash
# Stop and remove container
cd battle-hardened-ai/server
docker compose down

# Remove images
docker rmi battle-hardened-ai:latest

# Remove repository
cd ../..
rm -rf battle-hardened-ai

# Clean Docker system (optional)
docker system prune -a
```

---

## Support & Resources

- **GitHub Repository:** https://github.com/YOUR_USERNAME/battle-hardened-ai
- **Documentation:** README.md
- **Relay Setup:** testconnection.md
- **AI Training:** relay/aitrainingcommands.md
- **Model Distribution:** relay/MODEL_DISTRIBUTION_PROOF.md

---

**Last Updated:** January 7, 2026  
**Version:** 2.0  
**Compatibility:** Docker 20.10+, Docker Compose v2.0+
