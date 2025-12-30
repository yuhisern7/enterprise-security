# Relay Server - Platform-Specific Setup

## ✨ Features (December 2025)

**Security:**
- ✅ **Cryptographic Signing**: RSA-2048 + HMAC-SHA256 message authentication
- ✅ **Replay Protection**: Timestamp validation (5-minute window) + nonce tracking
- ✅ **Peer Broadcasting**: Real-time peer_joined/peer_left notifications
- ✅ **Node Fingerprinting**: Automatic OS/type detection for federated learning
- ✅ **Compatibility Scoring**: 0.0-1.0 peer compatibility for data quality

**Machine Learning:**
- ✅ **Time-Weighted Training**: 10x weight for recent threats (<7 days)
- ✅ **90-Day Sliding Window**: Automatic expiration of stale threat data
- ✅ **Federated Normalization**: Z-score per node type (prevents feature skew)
- ✅ **Distribution Drift Detection**: Alerts when features >3σ from baseline

**Network:**
- ✅ **WebSocket Protocol**: Lightweight, persistent connections
- ✅ **Host Networking**: Direct port access (no Docker NAT overhead)
- ✅ **Health Checks**: Automatic container restart on failure
- ✅ **Graceful Shutdown**: Broadcasts peer_left before disconnecting

---

## 🖥️ Choose Your Platform:

### Linux (Ubuntu/Debian/CentOS)
```bash
./setup.sh
```

### macOS (Docker Desktop)
```bash
./setup-macos.sh
```

### Windows (Docker Desktop)
```cmd
setup.bat
```

---

## 📋 Platform-Specific Instructions

### 🐧 Linux (VPS/Cloud Server)

**Requirements:**
- Ubuntu 20.04+ or Debian 11+
- Docker & Docker Compose installed
- Root/sudo access
- Public IP address

**Quick Start:**
```bash
# SSH into your Linux VPS
ssh root@YOUR-VPS-IP

# Clone repository
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security/relay

# Run automated setup
chmod +x setup.sh
./setup.sh

# Verify running
docker logs -f security-relay-server
```

**Firewall Configuration:**
```bash
# UFW (Ubuntu/Debian)
ufw allow 60001/tcp
ufw enable

# Firewalld (CentOS/RHEL)
firewall-cmd --permanent --add-port=60001/tcp
firewall-cmd --reload
```

---

### 🍎 macOS (Local Testing or Relay Server)

**Requirements:**
- macOS 11 (Big Sur) or later
- Docker installed (via Homebrew or Docker Desktop)
- Docker running

**Install Docker:**
```bash
# Option 1: Homebrew (recommended)
brew install --cask docker

# Option 2: Download Docker Desktop
# https://www.docker.com/products/docker-desktop
```

**Quick Start:**
```bash
# Navigate to relay directory
cd enterprise-security/relay

# Make script executable and run
chmod +x setup-macos.sh
./setup-macos.sh

# Verify running
docker logs -f security-relay-server
```

**Notes:**
- macOS firewall automatically allows Docker
- No manual firewall configuration needed
- Public IP detection works automatically
- Use localhost for local testing

**Local Testing (Same Mac):**
```bash
# Set relay URL to localhost
RELAY_URL=ws://localhost:60001
```

**Public Relay (macOS as Server):**
```bash
# Get your Mac's public IP
curl https://ifconfig.me

# On other containers, use:
RELAY_URL=wss://YOUR-MAC-PUBLIC-IP:60001
```

---

### 🪟 Windows (Local Testing or Relay Server)

**Requirements:**
- Windows 10/11 (Pro, Enterprise, or Education)
- Docker installed (Docker Desktop or Podman)
- WSL 2 enabled
- Docker running

**Install Docker:**
```powershell
# Option 1: Winget (Windows Package Manager)
winget install Docker.DockerDesktop

# Option 2: Download Docker Desktop
# https://www.docker.com/products/docker-desktop
```

**Quick Start:**
```cmd
REM Navigate to relay directory
cd enterprise-security\relay

REM Run Windows setup script
setup.bat

REM Verify running
docker logs security-relay-server
```

**Firewall Configuration (if needed):**
```cmd
REM Open Windows Defender Firewall with Advanced Security
REM Create Inbound Rule:
netsh advfirewall firewall add rule name="Relay Server" dir=in action=allow protocol=TCP localport=60001
```

**Notes:**
- Docker Desktop handles most networking automatically
- Windows Firewall may prompt for permission
- Public IP detection via web service
- Use localhost for local testing

**Local Testing (Same PC):**
```cmd
REM Set relay URL to localhost
RELAY_URL=ws://localhost:60001
```

**Public Relay (Windows as Server):**
```cmd
REM Get your Windows PC's public IP
REM Visit: https://whatismyip.com

REM On other containers, use:
RELAY_URL=wss://YOUR-WINDOWS-PUBLIC-IP:60001
```

---

## 🔧 Platform Comparison

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| **Production Use** | ✅ Recommended | ⚠️ Testing Only | ⚠️ Testing Only |
| **VPS Deployment** | ✅ Yes | ❌ No | ❌ No |
| **Local Testing** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Setup Script** | setup.sh | setup-macos.sh | setup.bat |
| **Firewall Config** | Manual | Automatic | Automatic |
| **Public IP** | Static | Dynamic | Dynamic |
| **Cost (Cloud)** | $5/month | N/A | N/A |
| **24/7 Uptime** | ✅ Yes | ❌ Desktop Only | ❌ Desktop Only |

---

## 🎯 Recommended Deployment Strategy

### Production (Unlimited Containers Worldwide)
```
Relay Server: Linux VPS ($5/month)
Client Containers: Any platform (Linux/macOS/Windows)
```

### Development/Testing (2-5 containers locally)
```
Relay Server: macOS or Windows (local machine)
Client Containers: Same machine or local network
```

### Hybrid (Best of Both)
```
Production Relay: Linux VPS
Development Relay: macOS/Windows (local)
Clients: Connect to appropriate relay based on environment
```

---

## 📝 Configuration Examples

### Linux VPS as Production Relay
```bash
# On VPS (Linux)
cd relay
./setup.sh
# Relay: wss://YOUR-VPS-IP:60001

# On all client containers (any platform)
RELAY_ENABLED=true
RELAY_URL=wss://YOUR-VPS-IP:60001
P2P_SYNC_ENABLED=false
```

### macOS for Local Development
```bash
# On macOS
cd relay
./setup-macos.sh
# Relay: ws://localhost:60001

# On local containers
RELAY_ENABLED=true
RELAY_URL=ws://host.docker.internal:60001  # macOS Docker special hostname
P2P_SYNC_ENABLED=false
```

### Windows for Local Testing
```cmd
REM On Windows
cd relay
setup.bat
REM Relay: ws://localhost:60001

REM On local containers
RELAY_ENABLED=true
RELAY_URL=ws://host.docker.internal:60001  REM Windows Docker special hostname
P2P_SYNC_ENABLED=false
```

---

## 🐛 Troubleshooting by Platform

### Linux Issues

**Port 60001 already in use:**
```bash
# Find what's using port 60001
sudo lsof -i :60001
# Kill the process or change relay port
```

**Firewall blocking:**
```bash
# Check firewall status
sudo ufw status
# Allow port
sudo ufw allow 60001/tcp
```

### macOS Issues

**Docker Desktop not running:**
```bash
# Start Docker Desktop
open -a Docker
# Wait for startup, then retry
```

**Permission denied:**
```bash
# Docker Desktop needs full disk access
# System Preferences → Security & Privacy → Full Disk Access → Docker
```

**Port conflict:**
```bash
# Check what's using port
lsof -i :60001
# Change port in docker-compose.yml
```

### Windows Issues

**WSL 2 not enabled:**
```cmd
REM Enable WSL 2
wsl --install
REM Restart computer
```

**Docker Desktop not starting:**
```cmd
REM Reset Docker Desktop
"C:\Program Files\Docker\Docker\Docker Desktop.exe" --reset-to-defaults
```

**Firewall blocking:**
```cmd
REM Add firewall exception
netsh advfirewall firewall add rule name="Docker Relay" dir=in action=allow protocol=TCP localport=60001
```

---

## 🔐 SSL/TLS Setup (Production)

All platforms can use Let's Encrypt for free SSL certificates:

### Linux (Automated)
```bash
# Install certbot
apt install certbot

# Get certificate
certbot certonly --standalone -d relay.yourdomain.com

# Certificates saved to:
# /etc/letsencrypt/live/relay.yourdomain.com/
```

### macOS (Manual)
```bash
# Use mkcert for local development
brew install mkcert
mkcert -install
mkcert relay.local localhost 127.0.0.1

# Or use certbot for public relay
brew install certbot
certbot certonly --manual
```

### Windows (Manual)
```cmd
REM Download certbot-win
REM Or use IIS to generate certificate
REM Or use certbot-win from Certbot website
```

---

## 📊 Performance by Platform

| Platform | Max Containers | Latency | Reliability |
|----------|---------------|---------|-------------|
| Linux VPS | 1000+ | 50-100ms | ⭐⭐⭐⭐⭐ |
| macOS | 10-50 | 10-50ms | ⭐⭐⭐⭐ |
| Windows | 10-50 | 10-50ms | ⭐⭐⭐⭐ |

---

## ✅ Quick Verification

After setup on any platform:

```bash
# Check relay running
docker ps | grep relay

# View logs
docker logs security-relay-server

# Test WebSocket connection
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:60001

# Expected: HTTP 101 Switching Protocols
```

---

## 🆘 Support

- **Linux:** See main README.md for full deployment guide
- **macOS:** Docker Desktop docs: https://docs.docker.com/desktop/mac/
- **Windows:** Docker Desktop docs: https://docs.docker.com/desktop/windows/

---

**Choose your platform above and follow the instructions! 🚀**
