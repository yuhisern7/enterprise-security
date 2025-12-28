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

**🔒 Privacy-Preserving Intelligence**
- **Your Dashboard**: Shows ONLY your own attacks (local threats)
- **AI Learning**: Learns from ALL attacks across network (local + peer)
- **Privacy Guarantee**: Other containers' attacks never shown on your dashboard
- **Result**: Collective intelligence WITHOUT data leakage

**How It Works:**
```
YOUR Attack → _threat_log → Dashboard ✅ + Disk ✅ + AI ✅
PEER Attack → _peer_threats → Dashboard ❌ + Disk ❌ + AI ✅
```

**Verify Privacy:**
```bash
# Check ML training shows local + peer split
docker logs enterprise-security-ai | grep Privacy
# Output: "Dashboard shows only 90 local, but AI learns from all 91"

# Check system status
curl -s http://localhost:60000/api/system-status | grep ml_models
# Output: "3 models trained (90 samples: 90 local + 0 peer)"
```

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

**Files responsible for P2P connections:**
- **`AI/p2p_sync.py`** - Core P2P synchronization engine
- **`setup_peer.sh`** - Interactive setup script

**Default Ports:**
- **60000** (HTTP) - Dashboard (local only)
- **60001** (HTTPS) - P2P sync (worldwide)

📖 **See Port Configuration section below** for changing ports, firewall setup, and troubleshooting.

---

## 🔌 Port Configuration

**Default Ports** (configurable in `.env`):

| Port | Protocol | Purpose | Firewall |
|------|----------|---------|----------|
| **60000** | HTTP | Dashboard | ❌ Block external |
| **60001** | HTTPS | P2P Sync | ✅ Open worldwide |

**Why 60000+?** Avoids conflicts, no root needed, safe dynamic range (49152-65535)

### Quick Setup

**Check if ports are available:**
```bash
sudo lsof -i :60000  # Linux/Mac (empty = free ✅)
netstat -ano | findstr :60000  # Windows (no output = free ✅)
```

**Change ports if needed:**
```bash
# Interactive
./setup_peer.sh  # Answer "n" to use custom ports

# OR edit server/.env directly
DASHBOARD_PORT=60000  # Change to any free port
P2P_PORT=60001        # Change to any free port
```

**Multiple containers on same machine:**
```bash
# Container 1: Ports 60000-60001
# Container 2: Ports 60100-60101 + PEER_URLS=https://localhost:60001
# Container 3: Ports 60200-60201 + PEER_URLS=https://localhost:60001,https://localhost:60101
```

**Firewall setup (P2P_PORT only):**
```bash
# Linux
sudo ufw allow 60001/tcp && sudo ufw reload

# Mac: System Preferences → Firewall → Allow port 60001
# Windows: Defender Firewall → Inbound Rules → New Rule → Port 60001
# Router: Forward external 60001 → internal 60001 → your PC IP
```

**Troubleshooting port conflicts:**
```bash
# Find process using port
sudo lsof -i :60000  # Kill it OR change DASHBOARD_PORT in .env
docker compose down && docker compose up -d  # Restart with new ports
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
- **Privacy-Preserving**: Dashboard shows ONLY your attacks, AI learns from everyone
  - **Storage**: `_threat_log` (yours: dashboard+disk+AI) | `_peer_threats` (theirs: AI only)
  - **Verify**: `docker logs enterprise-security-ai | grep Privacy`
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

**How P2P Learning Works**
1. Container A detects attack from IP 1.2.3.4
2. A broadcasts threat to B and C (within 3 minutes)
3. B and C's **AI learns** (threat added to `_peer_threats` - private, not shown on dashboard)
4. Next attack from similar pattern → B and C block instantly with high confidence
5. **Privacy**: B's dashboard shows ONLY B's attacks, but AI learned from A's attack ✅

**Security & Privacy**
- **Shared**: Attack type, source IP, timestamp, ML confidence
- **Never Shared**: Internal network data, logs, credentials, victim details
- **Dashboard Privacy**: Each container shows ONLY its own attacks
- **AI Intelligence**: ML trains on local + peer threats (collective learning)
- **Communication**: HTTPS/TLS 1.3 (P2P port 60001)

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
- Dashboard refresh: 5 minutes (configurable)
- Network convergence: <10 minutes (100 peers)

---

## � Privacy-Preserving P2P Learning (Deep Dive)

### How Privacy Works

**The Problem We Solved:**
- ❌ **Before**: Container B's dashboard would show Container A's attacks (privacy violation)
- ✅ **After**: Container B's AI learns from A's attacks, but dashboard shows ONLY B's own attacks

### Architecture

```
CONTAINER A                          CONTAINER B
┌────────────────┐                  ┌────────────────┐
│ Dashboard      │                  │ Dashboard      │
│ Shows: 10 local│                  │ Shows: 25 local│
│ Hides: 25 peer │                  │ Hides: 10 peer │
└────────┬───────┘                  └────────┬───────┘
         │                                   │
         │  P2P Sync (HTTPS)                 │
         │◄──────────────────────────────────┤
         │                                   │
┌────────▼───────┐                  ┌────────▼───────┐
│ AI Training    │                  │ AI Training    │
│ Uses: 35 total │                  │ Uses: 35 total │
│ (10+25)        │                  │ (25+10)        │
└────────────────┘                  └────────────────┘
```

### Technical Implementation

**Separated Threat Storage:**
```python
_threat_log: List[Dict] = []     # YOUR attacks (dashboard + disk + AI)
_peer_threats: List[Dict] = []   # THEIR attacks (AI only, memory-only)
```

**Threat Logging:**
```python
def _log_threat(..., is_local: bool = True):
    event['source'] = 'local' if is_local else 'peer'
    
    if is_local:
        _threat_log.append(event)  # Dashboard ✅ + Disk ✅ + AI ✅
        _save_threat_log()
    else:
        _peer_threats.append(event)  # Dashboard ❌ + Disk ❌ + AI ✅
```

**ML Training (Collective Intelligence):**
```python
def train_ml_models():
    all_threats = _threat_log + _peer_threats  # Combine for training
    print(f"[AI] Training with {len(all_threats)} threats")
    print(f"     (local: {len(_threat_log)}, peer: {len(_peer_threats)})")
    print(f"[AI] 🔒 Privacy: Dashboard shows only {len(_threat_log)} local")
    model.fit(all_threats)  # Train on ALL data
```

### Privacy Guarantees

| Feature | Local Threats | Peer Threats |
|---------|--------------|--------------|
| **Dashboard** | ✅ Visible | ❌ Hidden |
| **Disk Storage** | ✅ Saved | ❌ Memory only |
| **ML Training** | ✅ Used | ✅ Used |
| **API Endpoints** | ✅ Returned | ❌ Not returned |
| **Persistence** | ✅ Survives restart | ❌ Deleted on restart |
| **Max Storage** | 1000 events | 500 events |

### Example Scenario

**Setup:**
- Container A: Home WiFi (192.168.1.100)
- Container B: Office Network (10.0.0.50)

**Attack Flow:**
1. Container A detects SQL injection from 203.0.113.25
   - A's dashboard: ✅ Shows attack
   - B's dashboard: ❌ No visibility (privacy)

2. P2P Sync (background)
   - A shares threat with B via HTTPS
   - B receives threat → calls `add_global_threat_to_learning(threat)`
   - Threat added to B's `_peer_threats` (not `_threat_log`)

3. Container B's AI
   ```
   [AI] Training with 1 threat (local: 0, peer: 1)
   [AI] 🔒 Privacy: Dashboard shows only 0 local, but AI learns from all 1
   ```
   - AI now recognizes SQL injection pattern ✅
   - Dashboard still shows 0 threats ✅ (privacy preserved)

4. Similar attack on Container B
   - Attacker 203.0.113.30 tries SQL injection on B
   - B's AI: ✅ Recognizes pattern (learned from A's attack)
   - B: ✅ Blocks instantly with 98% confidence
   - B's dashboard: ✅ Shows this attack (source: local)

**Result:** Network learns collectively, dashboards stay private!

### Verification Commands

**Check ML Training Logs:**
```bash
docker logs enterprise-security-ai | grep Privacy
# Output: "[AI] 🔒 Privacy: Dashboard shows only 90 local, but AI learns from all 91"
```

**Check System Status:**
```bash
curl -s http://localhost:60000/api/system-status | grep ml_models
# Output: "3 models trained (90 samples: 90 local + 0 peer)"
```

**Test Privacy Isolation:**
```bash
docker exec enterprise-security-ai python -c "
from AI import pcs_ai
print(f'Before: Local={len(pcs_ai._threat_log)}, Peer={len(pcs_ai._peer_threats)}')
pcs_ai.add_global_threat_to_learning({'ip': '1.2.3.4', 'type': 'TEST'})
print(f'After: Local={len(pcs_ai._threat_log)}, Peer={len(pcs_ai._peer_threats)}')
"
# Expected: Local unchanged, Peer +1 ✅
```

### What's Shared vs Not Shared

**✅ Shared via P2P:**
- Threat type (SQL_INJECTION, PORT_SCAN, etc.)
- Attacking IP address
- Timestamp
- Severity level
- Detection patterns

**❌ Never Shared:**
- Dashboard visibility (peer threats hidden)
- Disk persistence (peer threats not saved)
- API exposure (no endpoints return peer threats)
- Internal network data
- Application logs
- Victim details

### Benefits

**🔒 Privacy:**
- No data leakage between containers
- Compliance-friendly (sensitive data stays private)
- Organizations trust to join P2P mesh

**🧠 Intelligence:**
- AI learns from ALL attacks globally
- Better detection through collective learning
- Network gets smarter with each container

**📊 Transparency:**
- ML status shows: "90 samples: 90 local + 0 peer"
- Clear source tracking ('local' vs 'peer')
- Audit trail preserved

---

## 🔌 Port Configuration (Advanced)

### Port Overview

| Port | Default | Protocol | Purpose | Firewall |
|------|---------|----------|---------|----------|
| DASHBOARD_PORT | 60000 | HTTP | Web interface | ❌ Block external |
| P2P_PORT | 60001 | HTTPS | P2P mesh sync | ✅ Open worldwide |

**Why 60000+?**
- ✅ Avoids conflicts with common services (80, 443, 3000, 5000, 8080)
- ✅ No root/admin privileges needed
- ✅ Safe IANA dynamic/private port range (49152-65535)
- ✅ Less likely blocked by corporate firewalls

### Check Port Availability

**Before installation:**

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

### Custom Port Configuration

**Method 1: Interactive Setup**
```bash
./setup_peer.sh
# Answer "n" when asked "Use default ports?"
# Enter your custom ports (e.g., 55000, 55001)
```

**Method 2: Edit `.env` File**
```bash
# Create from example if needed
cp .env.example .env

# Edit server/.env
nano server/.env

# Add/modify:
DASHBOARD_PORT=60000  # Change to your port
P2P_PORT=60001        # Change to your port

# Save and restart
cd server
docker compose down
docker compose up -d
```

**Recommended Alternative Ports:**
- `50000-50001` (if 60000 conflicts)
- `55000-55001` (alternative)
- `60100-60101` (for 2nd container on same machine)
- `65000-65001` (highest safe range)

### Multiple Containers on Same Machine

**Scenario:** Running 3 containers on one machine

**Container 1:**
```bash
DASHBOARD_PORT=60000
P2P_PORT=60001
PEER_URLS=https://localhost:60101,https://localhost:60201
```

**Container 2:**
```bash
DASHBOARD_PORT=60100
P2P_PORT=60101
PEER_URLS=https://localhost:60001,https://localhost:60201
```

**Container 3:**
```bash
DASHBOARD_PORT=60200
P2P_PORT=60201
PEER_URLS=https://localhost:60001,https://localhost:60101
```

### Firewall Configuration

**⚠️ Important:** Only open `P2P_PORT` (not `DASHBOARD_PORT`)

**Linux (UFW):**
```bash
sudo ufw allow 60001/tcp  # Replace with your P2P_PORT
sudo ufw reload
sudo ufw status  # Verify rule added
```

**Linux (firewalld - RHEL/CentOS):**
```bash
sudo firewall-cmd --permanent --add-port=60001/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports  # Verify
```

**Mac:**
```
System Preferences → Security & Privacy → Firewall
→ Firewall Options → Add rule for port 60001 (or your P2P_PORT)
→ Allow incoming connections
```

**Windows:**
```
Windows Defender Firewall → Advanced Settings → Inbound Rules
→ New Rule → Port → TCP → Specific Port: 60001
→ Allow the connection → Domain, Private, Public
→ Name: "Enterprise Security P2P"
```

**Router (Port Forwarding):**
```
1. Log into router admin panel
2. Find "Port Forwarding" or "Virtual Server"
3. Add rule:
   - External Port: 60001
   - Internal Port: 60001
   - Internal IP: 192.168.1.100 (your PC's local IP)
   - Protocol: TCP
4. Save and test: curl -k https://your-public-ip:60001/api/p2p/status
```

### Troubleshooting

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

2. Kill the process OR change port:
   - Kill: `sudo kill -9 <PID>` (Linux/Mac) or Task Manager (Windows)
   - Change: Edit `DASHBOARD_PORT` in `.env`

3. Restart container:
   ```bash
   docker compose down
   docker compose up -d
   ```

**Peers not connecting?**

**Check firewall:**
```bash
# Test from peer machine
curl -k https://your-ip:60001/api/p2p/status
# Should return JSON, not timeout
```

**Verify peer URLs:**
```bash
cat server/.env | grep PEER_URLS
# Ensure each peer uses correct P2P_PORT
# Example: https://peer1:60001,https://peer2:60101
```

**Check container logs:**
```bash
docker compose logs | grep -i "p2p\|peer\|sync"
# Look for connection errors
```

**Corporate network blocking high ports?**

Use lower ports (requires root/admin):
```bash
DASHBOARD_PORT=8080  # Standard alternative HTTP
P2P_PORT=8443        # Standard alternative HTTPS
```

**Note:** Ports <1024 require root privileges.

### Docker Network Modes

**Current: Bridge Mode (Recommended)**
```yaml
network_mode: bridge
ports:
  - "${DASHBOARD_PORT:-60000}:${DASHBOARD_PORT:-60000}"
  - "${P2P_PORT:-60001}:${P2P_PORT:-60001}"
```

**Advantages:**
- ✅ Port mapping flexibility
- ✅ Change ports without rebuilding
- ✅ Multiple containers on same host
- ✅ Better security isolation

**Alternative: Host Mode** (not recommended)
```yaml
network_mode: host
```

**Advantages:**
- ✅ Direct network access
- ✅ Better performance

**Disadvantages:**
- ❌ Ports hardcoded (can't remap)
- ❌ Can't run multiple containers
- ❌ Less security isolation

### Environment Variables Reference

```bash
# Port Configuration
DASHBOARD_PORT=60000  # Dashboard web interface
P2P_PORT=60001        # P2P mesh synchronization

# P2P Mesh
PEER_URLS=https://peer1:60001,https://peer2:60101
PEER_NAME=home-main
P2P_SYNC_ENABLED=true
P2P_SYNC_INTERVAL=180  # Seconds between syncs

# Optional APIs
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

### Verification

**Check container logs for ports:**
```bash
docker compose logs | grep "Dashboard:\|P2P Sync:"
# Should show your configured ports:
# 📊 Dashboard: http://localhost:60000
# 🌐 P2P Sync: https://localhost:60001
```

**Test dashboard access:**
```bash
curl http://localhost:60000
# Should return HTML (dashboard page)
```

**Test P2P port (from another machine):**
```bash
curl -k https://your-ip:60001/api/p2p/status
# Should return: {"status": "ok", ...}
```

---

## �📚 Documentation

- **[PRIVACY.md](PRIVACY.md)** - Complete privacy-preserving P2P guide (355 lines)
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Privacy verification & quick commands
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Technical implementation report
- **[PORT_CONFIGURATION.md](PORT_CONFIGURATION.md)** - Advanced port configuration guide

---

**Built with brilliance. Small, effective, unstoppable.**

🌐 **When A gets attacked, B and C learn.**  
🚀 **The network gets smarter every hour.**
