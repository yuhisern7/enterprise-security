# Battle-Hardened AI - Installation Guide

Complete installation instructions for Windows, Linux, and macOS.

---

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Install Docker](#step-1-install-docker)
  - [Linux Docker Installation](#linux-docker-installation)
  - [Windows Docker Installation](#windows-docker-installation)
  - [macOS Docker Installation](#macos-docker-installation)
- [Step 2: Install Battle-Hardened AI](#step-2-install-battle-hardened-ai)
  - [Linux](#linux)
  - [Windows](#windows)
  - [macOS](#macos)
- [Post-Installation](#post-installation)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### ✅ System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Operating System** | Windows 10 (build 19041+), Linux (Ubuntu 20.04+), macOS 11+ | Windows 11, Ubuntu 22.04+, macOS 13+ |
| **Disk Space** | 2 GB free | 5 GB free |
| **RAM** | 2 GB | 4 GB |
| **Internet** | Required for installation | |
| **Ports** | 60000 (Dashboard), 60001 (Relay - optional) | |

### ❌ NOT Required (Everything Runs Inside Docker)

- ❌ Python installation
- ❌ pip or package managers
- ❌ System libraries (tcpdump, openssl, gcc)
- ❌ Python packages (scikit-learn, tensorflow, flask)
- ❌ SSL certificate setup
- ❌ Admin/root access (except for Docker installation)

**You ONLY need Docker installed. Everything else is included in the container.**

---

## Step 1: Install Docker

**⚠️ IMPORTANT:** You must install Docker BEFORE proceeding. Choose your operating system below:

---

### Linux Docker Installation

#### Supported Linux Distributions

✅ **Ubuntu** 20.04, 22.04, 24.04  
✅ **Debian** 11, 12  
✅ **RHEL/CentOS** 8+, 9  
✅ **Fedora** 36+  
✅ **Kali Linux** (all versions)

---

#### Ubuntu / Debian / Kali Linux

**Copy and paste these commands into your terminal:**

```bash
# Update system
sudo apt-get update

# Install prerequisites
sudo apt-get install -y ca-certificates curl gnupg

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository (works for Ubuntu, Debian, Kali)
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add your user to docker group (avoid needing sudo)
sudo usermod -aG docker $USER

# Apply group changes (IMPORTANT - choose one option)
# Option 1: Logout and login again (recommended)
# Option 2: Run this command (temporary for current session)
newgrp docker
```

**Verify Docker Installation:**

```bash
docker --version
# Should show: Docker version 20.10.0 or higher

docker compose version
# Should show: Docker Compose version v2.0.0 or higher

docker ps
# Should show empty list (no containers running yet)
```

**If you see "permission denied" error:**
```bash
sudo usermod -aG docker $USER
newgrp docker
# OR logout and login again
```

---

#### RHEL / CentOS / Fedora

**Copy and paste these commands:**

```bash
# Install prerequisites
sudo dnf -y install dnf-plugins-core

# Add Docker repository
sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo

# Install Docker
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

**Verify:**
```bash
docker --version
docker compose version
docker ps
```

---

### Windows Docker Installation

#### Requirements

- **Windows 10** (64-bit, build 19041 or higher) OR **Windows 11**
- **Admin access** (only for installation)
- **Internet connection**

#### Step-by-Step Guide

**1. Enable WSL2 (Windows Subsystem for Linux 2)**

Open **PowerShell as Administrator** and run:

```powershell
wsl --install
```

**Restart your computer** when prompted.

After restart, WSL will finish installing. You'll be asked to create a Ubuntu username and password (choose any - you won't need it for Battle-Hardened AI).

**2. Download Docker Desktop**

- Go to: https://www.docker.com/products/docker-desktop/
- Click **"Download for Windows"**
- Run the downloaded file: `Docker Desktop Installer.exe`

**3. Install Docker Desktop**

During installation:
- ✅ **Check:** "Use WSL 2 instead of Hyper-V"
- ✅ **Check:** "Add shortcut to desktop"
- Click **"Ok"** and wait for installation to complete

**4. Restart Computer** (required)

**5. Start Docker Desktop**

- Double-click **Docker Desktop** icon on desktop
- Wait for notification: **"Docker Desktop is running"**
- You may see a tutorial - you can skip it

**6. Verify Docker Installation**

Open **PowerShell** (regular user, NOT administrator) and run:

```powershell
docker --version
# Should show: Docker version 20.10.0 or higher

docker compose version  
# Should show: Docker Compose version v2.0.0 or higher

docker ps
# Should show: CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES
# (empty list - this is correct)
```

**✅ Docker is now installed!** Keep Docker Desktop running in the background.

---

### macOS Docker Installation

#### Requirements

- **macOS 11 (Big Sur)** or higher
- **Admin access**
- **Internet connection**

**⚠️ Note:** macOS is supported but NOT recommended for production use. Best for testing/development only.

#### Installation Steps

**1. Download Docker Desktop**

- Go to: https://www.docker.com/products/docker-desktop/
- Click **"Download for Mac"**
- Choose your Mac type:
  - **Apple Silicon (M1/M2/M3)** - newer Macs
  - **Intel Chip** - older Macs

**2. Install Docker Desktop**

- Open the downloaded `Docker.dmg` file
- Drag the **Docker** icon to **Applications** folder
- Open **Docker** from Applications folder
- Grant permissions when asked
- Wait for **"Docker Desktop is running"** notification

**3. Verify Installation**

Open **Terminal** and run:

```bash
docker --version
# Should show: Docker version 20.10.0 or higher

docker compose version
# Should show: Docker Compose version v2.0.0 or higher

docker ps
# Should show empty container list
```

**✅ Docker is now installed!**

---

## Step 2: Install Battle-Hardened AI

**⚠️ Make sure Docker is installed and running first!**

Choose your operating system:

---

### Linux

### Linux

**1. Clone Repository**

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git

# Navigate to server directory
cd battle-hardened-ai/server
```

**2. Create Configuration File**

```bash
cat > .env << 'EOF'
# Battle-Hardened AI Configuration
TZ=Asia/Kuala_Lumpur
NETWORK_INTERFACE=eth0

# Optional: Global Threat Sharing (requires VPS relay server)
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
RELAY_CRYPTO_ENABLED=true
EOF
```

**3. Build and Start**

```bash
# Build and start the container (takes 3-5 minutes first time)
docker compose up -d --build

# Wait for container to start
sleep 10

# Check status
docker ps
```

You should see:
```
CONTAINER ID   IMAGE                  STATUS                    PORTS
abc123def456   battle-hardened-ai    Up 10 seconds (healthy)   0.0.0.0:60000-60001->60000-60001/tcp
```

**4. Verify It's Working**

```bash
# Check logs
docker logs battle-hardened-ai --tail 20

# You should see:
# ✅ ML models initialized successfully
# [ENTERPRISE] System ready for commercial deployment
```

**5. Access Dashboard**

Open browser: **https://localhost:60000**

Accept the SSL certificate warning (click "Advanced" → "Proceed to localhost").

**✅ Installation Complete!** The dashboard should show "0 threats detected" and green status indicators.

---

### Windows

**1. Clone Repository**

Open **PowerShell** (regular user, NOT administrator):

```powershell
# Clone the repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git

# Navigate to server directory
cd battle-hardened-ai\server
```

**2. Create Configuration File**

```powershell
# Create .env file
@"
# Battle-Hardened AI Configuration
TZ=Asia/Kuala_Lumpur
NETWORK_INTERFACE=eth0

# Optional: Global Threat Sharing (requires VPS relay server)
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
RELAY_CRYPTO_ENABLED=true
"@ | Out-File -Encoding UTF8 .env
```

**3. Build and Start**

```powershell
# Build and start (takes 3-5 minutes first time)
docker compose -f docker-compose.windows.yml up -d --build

# Wait for container to start
Start-Sleep -Seconds 10

# Check status
docker ps
```

You should see:
```
CONTAINER ID   IMAGE                  STATUS                    PORTS
abc123def456   battle-hardened-ai    Up 10 seconds (healthy)   0.0.0.0:60000-60001->60000-60001/tcp
```

**4. Verify It's Working**

```powershell
# Check logs
docker logs battle-hardened-ai --tail 30

# You should see:
# [AI] 💡 Generating synthetic training data for immediate deployment...
# [AI] ✅ Anomaly Detector trained on synthetic data
# [AI] ✅ Threat Classifier trained: 10 classes
# [AI] ✅ IP Reputation trained on synthetic data
# [RELAY] WebSocket relay client loaded - unlimited global peers
# [ENTERPRISE] System ready for commercial deployment
```

**5. Access Dashboard**

Open browser: **https://localhost:60000**

Accept certificate warning (click "Advanced" → "Proceed to localhost (unsafe)").

**✅ Installation Complete!**

---

### macOS

**1. Clone Repository**

Open **Terminal**:

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git

# Navigate to server directory
cd battle-hardened-ai/server
```

**2. Create Configuration File**

```bash
cat > .env << 'EOF'
# Battle-Hardened AI Configuration
TZ=America/New_York
NETWORK_INTERFACE=en0

# Optional: Global Threat Sharing
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
RELAY_CRYPTO_ENABLED=true
EOF
```

**3. Build and Start**

```bash
# Build and start
docker compose up -d --build

# Wait
sleep 10

# Check status
docker ps
```

**4. Verify**

```bash
docker logs battle-hardened-ai --tail 20
```

**5. Access Dashboard**

Browser: **https://localhost:60000**

**✅ Done!**

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
- ✅ ML Status: "3 models trained" (auto-trained with synthetic data)
- ✅ Section 4: Anomaly Detector, Threat Classifier, IP Reputation all showing "✅ TRAINED"
- ✅ Section 29: Relay status (if enabled)
- ✅ System Status: All green indicators

### 3. Verify ML Models Trained

Open Dashboard Section 4 - should show:
- 🔍 Anomaly Detector: Status **✅ TRAINED** (IsolationForest, 100 trees)
- 🎯 Threat Classifier: Status **✅ TRAINED** (RandomForest, 200 trees, 10 classes)
- 📡 IP Reputation: Status **✅ TRAINED** (GradientBoosting, 150 rounds)

**Note:** Models auto-train with synthetic data on first startup, then improve accuracy as real threats are detected. No manual training required.

### 4. Test Threat Detection

Trigger a test attack to verify the system works:

```bash
# Linux/macOS
curl -k "https://localhost:60000/?id=1' OR '1'='1"

# Windows PowerShell
curl.exe -k "https://localhost:60000/?id=1' OR '1'='1"
```

Reload dashboard - you should see **1 SQL Injection attack detected**.

### 5. Configure Timezone (Optional)

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

### 6. Enable Relay Connection (Optional)

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

**See detailed troubleshooting guides:**
- **Client firewall issues:** `testconnection.md` (iptables, Windows Firewall, connectivity tests)
- **VPS relay issues:** `relay/firewall.md` (ufw, DigitalOcean Cloud Firewall, port verification)

```bash
# Quick connectivity test
curl -k https://YOUR_VPS_IP:60002/stats

# Check RELAY_URL format (must use wss:// not ws://)
RELAY_URL=wss://YOUR_VPS_IP:60001

# Check relay status from inside container
docker exec battle-hardened-ai python3 -c "from AI.relay_client import get_relay_status; import json; print(json.dumps(get_relay_status(), indent=2))"

# Linux: Allow outbound to relay server
sudo iptables -A OUTPUT -p tcp -d YOUR_VPS_IP --dport 60001 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -d YOUR_VPS_IP --dport 60002 -j ACCEPT

# Windows: Allow outbound through Windows Firewall
New-NetFirewallRule -DisplayName "Battle-Hardened AI Relay" -Direction Outbound -RemoteAddress YOUR_VPS_IP -RemotePort 60001,60002 -Protocol TCP -Action Allow
```

### Issue: ML models showing "NOT TRAINED"

**This should NOT happen anymore** - models auto-train with synthetic data on startup.

If you see "NOT TRAINED" on dashboard:

```bash
# Check logs for training errors
docker logs battle-hardened-ai | grep -E "ML|TRAINED|synthetic"

# Should see:
# [AI] 💡 Generating synthetic training data...
# [AI] ✅ Anomaly Detector trained on synthetic data
# [AI] ✅ Threat Classifier trained: 10 classes
# [AI] ✅ IP Reputation trained on synthetic data

# If NOT shown, rebuild container (fix applied in latest version)
cd battle-hardened-ai/server
git pull
docker compose down
docker compose up -d --build

# Wait 60 seconds for training
sleep 60

# Verify training completed
docker exec battle-hardened-ai python3 -c "from AI import pcs_ai; print('Models trained:', pcs_ai._ml_last_trained)"
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

- **GitHub Repository:** https://github.com/yuhisern7/battle-hardened-ai
- **Main Documentation:** README.md
- **Client Relay Troubleshooting:** testconnection.md (firewall, connectivity, diagnostics)
- **VPS Relay Troubleshooting:** relay/firewall.md (server-side firewall, Cloud Firewall)
- **AI Training Commands:** relay/aitrainingcommands.md
- **Model Distribution:** relay/MODEL_DISTRIBUTION_PROOF.md
- **Dashboard Features:** dashboard.md
- **AI Capabilities:** ai-abilities.md

---

**Last Updated:** January 8, 2026  
**Version:** 2.1  
**Compatibility:** Docker 20.10+, Docker Compose v2.0+
