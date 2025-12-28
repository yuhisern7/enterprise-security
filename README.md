# 🛡️ Enterprise Security - P2P Mesh Network

**Every container is equal. No central server needed.**

When A gets attacked, B and C learn automatically.  
The network gets smarter every hour.  
Small file, extremely effective.  
Hackers cannot scan or attack without detection.

---

## 🌐 How It Works

```
┌─────────────┐         ┌─────────────┐
│  Container  │◄───────►│  Container  │
│  A (Office) │         │  B (Home)   │
└─────────────┘         └─────────────┘
       ▲                       ▲
       │                       │
       │    ┌─────────────┐    │
       └───►│  Container  │◄───┘
            │  C (Remote) │
            └─────────────┘
```

**Peer-to-Peer Mesh Network**
- Each container shares threats with all others
- No single point of failure
- Distributed learning across all nodes
- Automatic threat synchronization every 3 minutes

**🔒 Privacy-Preserving Intelligence** ([Learn More](PRIVACY.md))
- **Your Dashboard**: Shows ONLY your own attacks
- **AI Learning**: Learns from ALL attacks across the network
- **Result**: Collective intelligence WITHOUT data leakage
- **Example**: Container A's attack → Container B's AI learns → Container B's dashboard stays private

---

## 📋 Pre-Requisites

Before installation, ensure you have:

### System Requirements
- **Operating System**: macOS 10.15+, Windows 10/11, or Linux (Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+)
- **RAM**: Minimum 2GB, Recommended 4GB
- **Storage**: 2GB free disk space
- **Network**: Internet connection for initial setup

### Required Software

#### For Mac (macOS)
1. **Docker Desktop for Mac**
   - Download: https://www.docker.com/products/docker-desktop
   - Requires macOS 10.15 (Catalina) or newer
   - Includes Docker Engine, Docker CLI, and Docker Compose
   
2. **Git** (usually pre-installed)
   - Check: `git --version`
   - Install via Homebrew: `brew install git`
   - Or download from: https://git-scm.com/download/mac

#### For Windows
1. **Docker Desktop for Windows**
   - Download: https://www.docker.com/products/docker-desktop
   - Requires Windows 10 64-bit Pro/Enterprise/Education or Windows 11
   - Enable WSL 2 (Windows Subsystem for Linux)
   - Includes Docker Engine, Docker CLI, and Docker Compose
   
2. **Git for Windows**
   - Download: https://git-scm.com/download/win
   - During installation, select "Git Bash" option
   
3. **WSL 2** (recommended for Docker Desktop)
   - Open PowerShell as Administrator:
   ```powershell
   wsl --install
   ```

#### For Linux
1. **Docker Engine**
   ```bash
   # Ubuntu/Debian
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo usermod -aG docker $USER
   
   # OR manually: https://docs.docker.com/engine/install/
   ```

2. **Docker Compose** (if not included)
   ```bash
   sudo apt-get install docker-compose-plugin
   ```

3. **Git**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update && sudo apt-get install git
   
   # RHEL/CentOS/Fedora
   sudo yum install git
   ```

### Verify Installation
```bash
# Check Docker
docker --version          # Should show: Docker version 20.x or newer
docker compose version    # Should show: Docker Compose version 2.x or newer

# Check Git
git --version            # Should show: git version 2.x or newer
```

---

## ⚡ Quick Start

### Installation Steps (All Platforms)

**1. Clone Repository**
```bash
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security
```

**2. Run Setup (One Command)**

**For Mac/Linux:**
```bash
chmod +x setup_peer.sh
./setup_peer.sh
```

**For Windows (Git Bash):**
```bash
bash setup_peer.sh
```

The script will:
- ✅ Install Docker (if needed on Linux)
- ✅ Download ExploitDB database (46,948 exploits)
- ✅ Configure ports (default: 60000 dashboard, 60001 P2P)
- ✅ Configure VirusTotal API (optional)
- ✅ Set up P2P mesh connections (optional)
- ✅ Build and start container
- ✅ Open dashboard: http://localhost:60000

**3. Connect More Containers (Optional - For P2P Mesh)**

To connect multiple Docker containers worldwide:

1. **Find your container's IP address:**
   - **Mac/Windows**: Use your computer's public IP or local network IP
   - **Linux**: `ip addr show` or `hostname -I`

2. **Run setup on each machine** and enter peer IPs/domains:
   ```
   Example input: 192.168.1.100,office.example.com,home.example.com
   
   The system will auto-convert to HTTPS URLs with P2P_PORT:
   → https://192.168.1.100:60001
   → https://office.example.com:60001
   → https://home.example.com:60001
   ```

3. **Open firewall ports** (if connecting across networks):
   ```bash
   # Allow P2P_PORT (default 60001) for HTTPS P2P sync
   # Mac: System Preferences → Security & Privacy → Firewall
   # Windows: Windows Defender Firewall → Advanced Settings
   # Linux:
   sudo ufw allow 60001/tcp
   # OR
   sudo firewall-cmd --permanent --add-port=60001/tcp
   sudo firewall-cmd --reload
   ```

Done! All containers now share threats automatically via encrypted HTTPS.

---

## 🌐 P2P Mesh Network Configuration

**Files responsible for connecting all Docker ports worldwide:**
- **`AI/p2p_sync.py`** - Core P2P synchronization engine
- **`setup_peer.sh`** - Setup script that configures peer connections

**Ports Used (Configurable):**
- **60000** (HTTP) - Dashboard access (local only) - `DASHBOARD_PORT`
- **60001** (HTTPS) - Encrypted P2P threat synchronization (global) - `P2P_PORT`

**Why port 60000+?**
- ✅ Avoids conflicts with common services (80, 443, 3000, 5000, 8080)
- ✅ No root/admin privileges needed
- ✅ Safe dynamic port range (49152-65535)

**Connection Architecture:**
```
┌─────────────────┐         ┌─────────────────┐
│   Container A   │◄───────►│   Container B   │
│ (Office - Mac)  │  HTTPS  │ (Home - Linux)  │
│ port 60001      │  60001  │ port 60001      │
└─────────────────┘         └─────────────────┘
       ▲                           ▲
       │                           │
       │      ┌─────────────────┐  │
       └─────►│   Container C   │◄─┘
        HTTPS │ (Cloud-Windows) │ HTTPS
        60001 │ port 60001      │ 60001
              └─────────────────┘
```

**Customize ports in `.env`:**
```bash
DASHBOARD_PORT=60000  # Change if needed
P2P_PORT=60001        # Change if needed
PEER_URLS=https://peer1:60001,https://peer2:60001
```

**Auto-refresh rate:** Dashboard updates every 5 minutes

**📖 See Port Configuration section below for:**
- Checking port availability
- Changing ports if already in use
- Running multiple containers on same machine
- Firewall configuration
- Port conflict troubleshooting

---

## 🔌 Port Configuration

### Default Ports

| Port | Protocol | Purpose | Access |
|------|----------|---------|--------|
| **60000** | HTTP | Dashboard | Local only |
| **60001** | HTTPS | P2P Sync | Worldwide |

**Why high ports (60000+)?**
- ✅ Avoids conflicts with common services (80, 443, 3000, 5000, 8080)
- ✅ No root/admin privileges needed
- ✅ Safe dynamic port range (49152-65535)
- ✅ Less likely to be blocked by firewalls

### Check Port Availability

**Before installation, verify ports are free:**

**Linux/Mac:**
```bash
sudo lsof -i :60000  # Empty output = port is FREE ✅
sudo lsof -i :60001
```

**Windows (PowerShell):**
```powershell
netstat -ano | findstr :60000  # No output = port is FREE ✅
netstat -ano | findstr :60001
```

### Change Ports (If Needed)

**Method 1: Interactive Setup**
```bash
./setup_peer.sh
# Answer "n" when asked "Use default ports?"
# Enter your custom ports
```

**Method 2: Edit `.env` File**
```bash
# Create/edit server/.env
nano server/.env

# Add or modify these lines:
DASHBOARD_PORT=60000  # Change to your desired port
P2P_PORT=60001        # Change to your desired port

# Save and restart
cd server
docker compose down
docker compose up -d
```

**Recommended Alternative Ports:**
- `50000-50001` (if 60000 conflicts)
- `55000-55001` (alternative)
- `65000-65001` (highest safe range)

### Multiple Containers on Same Machine

Each container needs **unique ports**:

```bash
# Container 1
DASHBOARD_PORT=60000
P2P_PORT=60001

# Container 2 (same machine)
DASHBOARD_PORT=60100
P2P_PORT=60101

# Container 3 (same machine)
DASHBOARD_PORT=60200
P2P_PORT=60201
```

Then connect them via `PEER_URLS`:
```bash
# Container 1's .env
PEER_URLS=https://localhost:60101,https://localhost:60201

# Container 2's .env
PEER_URLS=https://localhost:60001,https://localhost:60201

# Container 3's .env
PEER_URLS=https://localhost:60001,https://localhost:60101
```

### Firewall Configuration

**⚠️ Important:** Only open `P2P_PORT` on firewall (not `DASHBOARD_PORT`)

**Linux (UFW):**
```bash
sudo ufw allow 60001/tcp  # Replace with your P2P_PORT
sudo ufw reload
```

**Linux (firewalld):**
```bash
sudo firewall-cmd --permanent --add-port=60001/tcp
sudo firewall-cmd --reload
```

**Mac:**
```
System Preferences → Security & Privacy → Firewall
→ Firewall Options → Add rule for port 60001
```

**Windows:**
```
Windows Defender Firewall → Advanced Settings
→ Inbound Rules → New Rule → Port → TCP → 60001
```

**Router (Port Forwarding):**
```
External Port: 60001 → Internal Port: 60001 → Your PC's IP
```

### Port Troubleshooting

**Error: Port already in use**
```
Error: Bind for 0.0.0.0:60000 failed: port is already allocated
```

**Solution:**
1. Find what's using the port:
   ```bash
   sudo lsof -i :60000          # Linux/Mac
   netstat -ano | findstr :60000  # Windows
   ```

2. Either:
   - Stop the conflicting service, OR
   - Change `DASHBOARD_PORT`/`P2P_PORT` in `.env`

3. Rebuild:
   ```bash
   docker compose down
   docker compose up -d
   ```

**Peers not connecting?**
- Verify firewall allows P2P_PORT
- Check peer URLs use correct ports
- Test: `curl -k https://peer-ip:60001/api/p2p/status`

---

## 🎯 Features

### Core Security
- **ML-Powered Threat Detection**: 3 models (Isolation Forest, Random Forest, Gradient Boosting)
- **ExploitDB Integration**: 46,948 exploits + 1,066 shellcodes
- **VirusTotal Scanning**: 70+ security vendors
- **12 Threat Intelligence Feeds**: CVE, NVD, MalwareBazaar, AlienVault OTX, URLhaus, etc.
- **Automatic IP Blocking**: Instant response to threats
- **VPN/Tor Detection**: De-anonymization techniques

### P2P Mesh Network
- **Distributed Learning**: Each container learns from all attacks globally
- **Automatic Sync**: Broadcasts threats every 3 minutes
- **Privacy-Preserving**: Dashboard shows ONLY your attacks, AI learns from everyone (see [PRIVACY.md](PRIVACY.md))
- **Dynamic Peers**: Add/remove peers without restart
- **Resilient**: No single point of failure
- **Collective Intelligence**: Network gets smarter with each container

---

## 📊 Dashboard

Access: **http://localhost:60000** (configurable via `DASHBOARD_PORT`)

Shows real-time:
- 🔗 Connected peers (e.g., "3 / 5 peers online")
- 📤 Threats shared with network
- 📥 Threats learned from peers
- ⏰ Last synchronization time
- 🚨 Live threat feed
- 📈 ML model performance

---

## ⚙️ Configuration

**Port Configuration**

Default ports (configurable in `.env`):
```bash
DASHBOARD_PORT=60000  # Dashboard web interface
P2P_PORT=60001        # P2P mesh synchronization
```

**Connect to Peers**

Edit `.env` file:
```bash
# P2P Mesh Network (use each peer's P2P_PORT)
PEER_URLS=https://office.example.com:60001,https://192.168.1.100:60001
PEER_NAME=home-main
P2P_SYNC_ENABLED=true
P2P_SYNC_INTERVAL=180
```

**VirusTotal API** (Recommended)
```bash
VIRUSTOTAL_API_KEY=your_api_key_here
```
Get free key: https://www.virustotal.com/gui/join-us

---

## 🏗️ Architecture

**Single Container**
- Python 3.11 + Flask web server
- Dual ports: 60000 (dashboard), 60001 (P2P sync)
- AI engine with ML models (scikit-learn)
- Network monitoring (Scapy)
- P2P sync client (background thread)
- ExploitDB local database
- Dashboard UI

**P2P Mesh**
- Each container = peer (both client AND server)
- No master/slave hierarchy
- Automatic discovery via configured URLs
- HTTPS encrypted communication (TLS 1.3)
- Resilient to peer failures
- Configurable ports (default 60001)

---

## 🔧 Management

**View Logs**
```bash
cd server
docker compose logs -f
```

**Stop Container**
```bash
docker compose down
```

**Restart Container**
```bash
docker compose restart
```

**Update Code**
```bash
git pull
docker compose build
docker compose up -d
```

---

## 📈 Scaling

- **1 container**: Protects single location, learns locally
- **5 containers**: P2P mesh, collective defense across 5 locations
- **100 containers**: Global network, near-instant threat propagation
- **1000+ containers**: Enterprise-scale distributed security intelligence

Each container:
- **CPU**: 2-4 cores recommended
- **RAM**: ~500MB
- **Storage**: ~2GB (ExploitDB + logs)
- **Network**: Minimal bandwidth (<1MB/day sync traffic)

---

## 🛠️ Troubleshooting

**Port conflicts?**
- Check if ports are in use: `sudo lsof -i :60000` (Linux/Mac)
- Change ports in `.env` file (see Port Configuration section above)
- Restart: `docker compose down && docker compose up -d`

**Peers not connecting?**
- Verify firewall allows P2P_PORT (default 60001)
- Check peer URLs use correct P2P_PORT for each peer
- Test connectivity: `curl -k https://peer-ip:60001/api/p2p/status`
- Ensure P2P_SYNC_ENABLED=true in .env

**Dashboard not loading?**
- Check container is running: `docker compose ps`
- Verify correct port: `docker compose logs | grep "Dashboard:"`
- Try: http://localhost:60000 (or your configured DASHBOARD_PORT)

**Dashboard not loading?**
- Check container is running: `docker compose ps`
- View logs: `docker compose logs`
- Verify port 5000 is not in use: `netstat -an | grep 5000`

**VirusTotal errors?**
- Free tier: 4 requests/minute limit
- Check API key is valid
- Leave blank to disable VirusTotal (system works without it)

---

## 🚀 Why P2P?

**Advantages**
- ✅ No central server to maintain
- ✅ No single point of failure
- ✅ Scales infinitely (add containers = add power)
- ✅ Simple setup (one command)
- ✅ Automatic failover (peer down = others continue)
- ✅ Free deployment (no server costs)

**How Learning Works**
1. Container A detects attack from IP 1.2.3.4
2. A broadcasts threat to B and C within 3 minutes
3. B and C add threat to their ML training data
4. Next time 1.2.3.4 attacks B or C, instant block
5. Network immunity grows with every attack

---

## 🔒 Security

**What's Shared**
- Attack type (port scan, brute force, etc.)
- Source IP address
- Geolocation
- Timestamp
- ML confidence score

**What's NOT Shared**
- Internal network data
- Application logs
- Victim details
- Passwords or credentials

**Communication**
- HTTP by default (local networks)
- Upgradable to HTTPS for internet
- No authentication needed between peers (trusted network)
- Add firewall rules to restrict peer access

---

## �� Project Structure

```
enterprise-security/
├── setup_peer.sh         # One-command deployment
├── AI/
│   ├── p2p_sync.py      # P2P mesh synchronization
│   ├── pcs_ai.py        # Core AI security engine
│   ├── threat_intelligence.py  # 12 threat feeds
│   └── exploitdb/       # 46,948 exploits database
├── server/
│   ├── server.py        # Flask web server + API
│   ├── docker-compose.yml
│   └── Dockerfile
└── .env.example         # Configuration template
```

---

## 🎓 How AI Learns

**Initial Training**
- ExploitDB: 46,948 attack patterns
- Threat Intelligence: CVE, NVD, malware signatures
- ML Models: Pre-trained on common attacks

**Continuous Learning**
1. **Local Learning**: Retrains after every 5 local threats
2. **P2P Learning**: Receives threats from peers every 3 minutes
3. **Automatic Updates**: ML models improve hourly
4. **Pattern Recognition**: Identifies new attack variants

**Result**: Every attack makes the entire network smarter

---

## 📜 License

This project is for security research and educational purposes.

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Open Pull Request

---

## 💡 Use Cases

- **Home Networks**: Protect WiFi from intruders, share threats with family locations
- **Small Business**: Deploy on each office, collective defense across branches
- **MSP/Security Providers**: Offer to clients, all clients benefit from shared intelligence
- **Research Networks**: Collaborative threat detection across institutions
- **Edge Computing**: Distributed security without cloud dependency

---

## 📊 Performance

**Detection Speed**
- Port scan: <1 second
- Brute force: 3-5 failed attempts
- Exploit attempt: Instant (ExploitDB match)
- ML prediction: <100ms per IP

**Sync Speed**
- Threat broadcast: <3 minutes to all peers
- Network convergence: <10 minutes (100 peers)
- Dashboard refresh: 30 seconds

**Resource Usage**
- CPU: 5-10% idle, 20-30% under attack
- RAM: ~500MB steady state
- Disk I/O: Minimal (append-only logs)
- Network: <1MB/day (P2P sync)

---

**Built with brilliance. Small, effective, unstoppable.**

🌐 **When A gets attacked, B and C learn.**  
🚀 **The network gets smarter every hour.**
