# 🛡️ AI-Powered Network Security System

**Enterprise-grade threat detection with self-learning AI and global threat sharing network.**

🤖 **Self-Learning AI** - Trains on 46,948 real exploits from ExploitDB  
🌍 **Global Threat Network** - All clients learn from each other's attacks (encrypted)  
⚡ **Real-Time Detection** - VirusTotal integration (70+ security vendors)  
🕷️ **12 Threat Crawlers** - Continuous learning from CVE, MalwareBazaar, OTX, URLhaus & more  
🎯 **Attack Signatures** - Detects nmap, sqlmap, nikto, burp, metasploit  
🔒 **Encrypted Sharing** - HTTPS/TLS + API key authentication  
📊 **Live Dashboard** - Real-time threat feed with geolocation & scrollable logs  
🏢 **Enterprise Ready** - SIEM/SOC integration via REST API

---

## 🚀 Quick Start - 3 Deployment Modes

### Mode 1: Standalone (Fastest)

**For:** Testing, single site, no global sharing

```bash
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security
./setup.sh  # Linux/Mac
# OR
setup.bat   # Windows
```

Access: `http://localhost:5000`

**Done!** Single container protecting your network.

---

### Mode 2: Global Threat Network (Recommended)

**For:** Multiple customers, global learning, collective defense

**Architecture:** 1 central server (you host) + N client containers (customers deploy)

**Step 1 - Deploy Central Server (Once):**
```bash
cd central_server
docker compose up -d
# Get master API key from logs
```

**Step 2 - Deploy Clients (Each Customer):**
```bash
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security

# Edit .env:
# CENTRAL_SERVER_URL=https://your-server:5001
# CENTRAL_SERVER_API_KEY=<get from registration>
# SYNC_ENABLED=true

./setup.sh
```

**Result:** When Client A is attacked, B, C, D all learn instantly!

📖 **Full Guide:** See [GLOBAL_SETUP.md](GLOBAL_SETUP.md) and [ARCHITECTURE.md](ARCHITECTURE.md)

---

### Mode 3: Horizontal Scaling

**For:** High-traffic networks, enterprise scale

Deploy same client container on multiple servers, add load balancer.

**See:** [README.md - Deployment & Scaling](#💼-deployment--scaling)

---

### Prerequisites
- **Docker Desktop** (Windows/Mac) or **Docker Engine** (Linux)
- 4GB+ RAM, 10GB+ disk space
- Internet connection

### Installation

#### **Windows:**
```bash
# 1. Clone repository
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security

# 2. Run setup (ONE COMMAND)
setup.bat
```

#### **Linux/Mac:**
```bash
# 1. Clone repository
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security

# 2. Run setup (ONE COMMAND)
chmod +x setup.sh
./setup.sh
```

**That's it!** The script automatically:
- ✅ Checks Docker installation
- ✅ Downloads ExploitDB database (46,948 exploits)
- ✅ Creates configuration files
- ✅ Builds Docker images
- ✅ Starts all services
- ✅ Opens dashboard in browser

### Access Dashboard

**Local:** http://localhost:5000  
**Network:** http://YOUR_IP:5000

### Get VirusTotal API Key (Optional but Recommended)

1. Visit: https://www.virustotal.com/gui/join-us
2. Sign up (free account)
3. Go to: Profile → API Key
4. Copy your API key (64 characters)
5. Edit `.env` file and paste your key
6. Restart: `cd server && docker compose restart`

✅ **Done!** Your AI security system is now protecting your network.

---

## 📋 What This System Does

### Real-Time Protection

✅ **Port Scan Detection** - Detects network reconnaissance (nmap, masscan)  
✅ **DDoS Prevention** - Identifies and blocks flood attacks  
✅ **SQL Injection Detection** - 100+ attack patterns  
✅ **XSS Prevention** - Cross-site scripting protection  
✅ **Brute Force Protection** - Auto-blocks failed login attempts  
✅ **Tool Detection** - Identifies hacking tools by signature  
✅ **IP Reputation** - Checks attackers against 70+ security vendors  
✅ **Geolocation Tracking** - Shows where attacks come from  
✅ **IP Whitelisting** - Permanent whitelist for trusted IPs (GitHub, Google Cloud, etc.)  
✅ **Smart IP Management** - Interactive UI to unblock, whitelist, or keep IPs blocked  

### AI Learning & Threat Intelligence

The system continuously learns from **12 automated crawlers** monitoring:

**1. Local Database (Pre-loaded)**
   - **ExploitDB** (46,948 exploits, 1,066 shellcodes) ✅ Active
     - SQL injection techniques
     - XSS vulnerabilities
     - Buffer overflows, RCE patterns
     - Authentication bypasses

**2. Live Threat Intelligence Sources**
   - **CVE Database** (MITRE) - 200K+ vulnerability identifiers
   - **NVD (NIST)** - CVSS scores, CPE data, comprehensive analysis
   - **MalwareBazaar** - 1M+ malware samples with hashes & families
   - **AlienVault OTX** - 100K+ threat pulses, 30M+ IOCs
   - **URLhaus** - 500K+ malicious URLs, phishing, C&C servers
   - **AttackerKB** - Expert vulnerability analysis & PoC code
   - **VirusTotal** - 70+ AV engines, file/URL/IP reputation
   - **AbuseIPDB** - 5M+ abuse reports with confidence scores
   - **GitHub Advisories** - 50K+ software security advisories
   - **SANS ISC** - Real-time global threat statistics
   - **MISP Feeds** - 100+ IOC sharing feeds

**3. Real-Time Analysis**
   - **Your Network** - Live attack patterns & behavior
   - **Honeypots** - 8 fake endpoints for threat collection
   - **Attack Tool Detection** - User-Agent signatures

### Automatic Actions

⚙️ **Every Second**: Monitors network packets with Scapy  
⚙️ **Every Attack**: 
   - Checks VirusTotal for IP reputation
   - Validates against whitelist
   - Geolocation & anonymization detection  
⚙️ **Every 5 Attacks**: Retrains ML models with new data  
⚙️ **Every 6 Hours**: Updates ML models automatically  
⚙️ **Every 24 Hours**: Refreshes ExploitDB signatures  
⚙️ **On Demand**: Crawls threat intelligence sources  
⚙️ **On Threat**: Auto-blocks malicious IPs (unless whitelisted)  

---

## 🎯 Configuration

### Required: VirusTotal API Key

Edit `.env` file:

```bash
VIRUSTOTAL_API_KEY=your_64_character_key_here
```

Get free key: https://www.virustotal.com/gui/join-us (4 requests/minute)

### Optional Settings

```bash
# Optional: AbuseIPDB key (community IP blacklist)
ABUSEIPDB_API_KEY=

# Timezone (change to your location)
TZ=Asia/Kuala_Lumpur

# Auto-blocking
AUTO_BLOCK_ENABLED=true
MAX_BLOCKED_IPS=10000

# AI Learning
AI_LEARNING_ENABLED=true
AUTO_TRAIN_THRESHOLD=5
```

After editing `.env`:
```bash
cd server
sudo docker compose restart
```

---

## 📊 Dashboard Features

Access at: **http://localhost:5000**

### Real-Time Threat Monitor (Scrollable)
- Live attack log with auto-refresh (30 seconds)
- **Scrollable table** - View all threats (latest 100 events)
- Sticky headers for easy navigation
- Threat severity levels (SAFE → CRITICAL)
- Attack tool signatures (nmap, sqlmap, etc.)
- Geolocation of attackers (country, city, ISP)
- IP reputation scores from VirusTotal
- Anonymization detection (VPN/Tor/Proxy)

### Smart IP Management
**Interactive controls for every blocked IP:**
- **🔓 Unblock** - Remove from block list (can be blocked again if detected)
- **✅ Whitelist** - Permanently allow IP (never blocked again)
- **🔒 Keep Blocked** - Leave as is

**Recommended for whitelisting:**
- GitHub (140.82.x.x) - Git operations, webhooks, Dependabot
- Google Cloud (AS396982) - Cloud services
- Microsoft Azure (AS8075) - Cloud infrastructure
- Your trusted servers and monitoring services

### AI Threat Intelligence Crawlers
**12 automated crawlers** visible on dashboard:
- Visual status indicators (Active/Ready/API Configured)
- Direct links to each threat intelligence source
- Live statistics for each crawler
- One-click access to external resources

### API Endpoints
- **GET** `/api/whitelist` - List all whitelisted IPs
- **POST** `/api/whitelist/add` - Add IP to permanent whitelist
- **POST** `/api/whitelist/remove` - Remove from whitelist
- **POST** `/api/unblock/<ip>` - Unblock specific IP
- **GET** `/api/blocked-ips` - List all blocked IPs

### Data Management
- **Export Data**: Download threats as JSON
- **Clear Data**: Remove old logs (by date range)
  - Clear all data
  - Clear threats only
  - Clear blocked IPs only
- **Statistics**: Attack counts, top attackers, threat types
- **ML Model Retraining**: Force retrain on demand

---

## 🏢 Enterprise Integration

### REST API Endpoints

**1. Check IP Reputation**
```bash
curl -X POST http://your-server:5000/api/v1/threat-check \
  -H "X-API-Key: YOUR_ENTERPRISE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4"}'
```

**2. Get Threat Feed**
```bash
curl http://your-server:5000/api/v1/threats \
  -H "X-API-Key: YOUR_ENTERPRISE_KEY"
```

**3. Submit Threat Data**
```bash
curl -X POST http://your-server:5000/api/v1/submit-threat \
  -H "X-API-Key: YOUR_ENTERPRISE_KEY" \
  -d '{"ip": "1.2.3.4", "attack_type": "port_scan"}'
```

**4. IP Whitelist Management**
```bash
# Add IP to whitelist
curl -X POST http://localhost:5000/api/whitelist/add \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "140.82.114.21"}'

# Remove from whitelist
curl -X POST http://localhost:5000/api/whitelist/remove \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "140.82.114.21"}'

# Get all whitelisted IPs
curl http://localhost:5000/api/whitelist
```

**5. Unblock IP**
```bash
curl -X POST http://localhost:5000/api/unblock/1.2.3.4
```

**Get Enterprise API Key**:
```bash
sudo docker compose logs | grep "Demo API Key"
```

### Threat Intelligence Crawler

Run manual crawl to collect latest threats:

```bash
# From host system
python3 AI/threat_crawler.py

# From Docker container
sudo docker exec -it enterprise-security-ai python3 AI/threat_crawler.py
```

**Output**: `AI/ml_models/threat_intelligence_crawled.json`

**Crawled data includes:**
- Latest CVEs with CVSS scores
- Recent malware samples (SHA256, MD5, signatures)
- Threat pulses from OTX
- Malicious URLs from URLhaus
- Vulnerability assessments from AttackerKB

### SIEM/SOC Integration

Compatible with:
- **Splunk** - Forward threat logs via syslog
- **QRadar** - REST API integration
- **ArcSight** - CEF format export
- **Elasticsearch** - JSON bulk import
- **Firewalls** - iptables, pfSense, FortiGate
- **IDS/IPS** - Snort, Suricata rule generation

---

## 💼 Deployment & Scaling

### Mode 1: Standalone (Default)

**Single container**, no central server - ideal for testing or small deployments:

```bash
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security
./setup.sh
```

Runs independently - all learning is local.

---

### Mode 2: Global Threat Sharing Network (Recommended)

**Architecture:** 1 central server + multiple client containers  
**Benefit:** All clients learn from each other's attacks in real-time  
**Encryption:** HTTPS/TLS with API key authentication

```
┌─────────────────────────────────────────┐
│   Central Server (Your Infrastructure)  │
│   • Aggregates all threats              │
│   • Distributes global threat feed      │
│   • Encrypted HTTPS + API key auth      │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┼─────────┐
        │         │         │
    ┌───▼───┐ ┌──▼───┐ ┌──▼───┐
    │Client1│ │Client2│ │Client3│
    │Company│ │ Home  │ │Branch│
    │   A   │ │   B   │ │   C  │
    └───────┘ └──────┘ └──────┘
```

#### Step 1: Deploy Central Server (One-Time)

```bash
cd central_server
docker compose up -d
```

Get master API key:
```bash
docker compose logs | grep "master API key"
```

**Output:**
```
Generated new master API key: abc123xyz789...
SAVE THIS KEY - it will not be shown again!
```

#### Step 2: Register Client Nodes

Each company/home deploying your system registers:

```bash
curl -k -X POST https://your-server-ip:5001/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Company ABC HQ",
    "client_info": {
      "location": "New York",
      "network_size": "500 users"
    }
  }'
```

**Response:**
```json
{
  "client_id": "a1b2c3d4e5f6g7h8",
  "api_key": "xyz789abc123def456...",
  "message": "Registration successful. SAVE YOUR API KEY!"
}
```

#### Step 3: Configure Client Containers

On **each client machine** (company/home), edit `.env`:

```bash
# Central threat intelligence server
CENTRAL_SERVER_URL=https://your-central-server-ip:5001
CENTRAL_SERVER_API_KEY=xyz789abc123def456...
SYNC_ENABLED=true
SYNC_INTERVAL=300  # Sync every 5 minutes
```

Deploy client:
```bash
cd enterprise-security
./setup.sh
# Container automatically connects to central server
```

#### How It Works

**When Client A detects an attack:**
1. Local AI blocks the attacker
2. Threat data (IP, attack type, severity) sent to central server (encrypted)
3. Central server distributes to all clients (B, C, D...)
4. All clients update their ML models with this new attack pattern
5. Next time any client sees this attacker, they block instantly

**Privacy:** Only threat metadata is shared (IP, attack type), not internal network data.

**Resilience:** Clients continue working if central server is down (standalone mode).

---

### Mode 3: Horizontal Scaling (Large Enterprise)

**Current setup runs 1 Docker container** that handles:
- Packet capture + threat detection
- ML model training + inference
- Web dashboard + REST API
- ExploitDB + threat intelligence

**Capacity**: 10,000+ packets/sec, 1000s of users

**Ideal for:**
- Small-Medium Business (1-500 employees)
- Startups and growing companies
- Branch offices
- Development teams

### Horizontal Scaling (Large Enterprise)

**For 10K+ users or high-traffic networks:**

1. **Load Balancer** (use existing F5/HAProxy/Nginx)
   - Route traffic to multiple instances
   - Health checks on port 5000

2. **Multiple Containers** (same image, different servers)
   ```bash
   # Server 1
   docker compose up -d
   
   # Server 2
   docker compose up -d
   
   # Server 3
   docker compose up -d
   ```

3. **Shared Storage** (for threat logs)
   - NFS mount for `server/json/`
   - Or use S3/Azure Blob for backups
   - Each node can run independently

4. **Optional: External Database**
   - Modify `pcs_ai.py` to use PostgreSQL instead of JSON
   - Share threat data across nodes
   - Only needed for 100K+ events/day

**Benefits:**
- Same simple Docker image
- No complex orchestration
- Use your existing infrastructure
- Scale by adding servers

### Commercial Pricing

**Basic** - $99/month
- 1 server instance
- 1,000 API calls/day
- Email alerts

**Professional** - $299/month
- 3 server instances
- 10,000 API calls/day
- SIEM integration
- IP whitelist management

**Enterprise** - Custom pricing
- Unlimited instances
- Unlimited API calls
- Custom ML training
- Dedicated support  

---

## 🔧 Maintenance

### Update ExploitDB Database

```bash
cd AI/exploitdb
git pull
cd ../../server
sudo docker compose restart
```

### Run Threat Intelligence Crawlers

```bash
# Manual crawl
python3 AI/threat_crawler.py

# Schedule with cron (daily at 2 AM)
0 2 * * * cd /path/to/enterprise-security && python3 AI/threat_crawler.py >> logs/crawler.log 2>&1
```

### Whitelist Management

```bash
# Add trusted IPs (GitHub example)
curl -X POST http://localhost:5000/api/whitelist/add \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "140.82.114.21"}'

# View all whitelisted IPs
curl http://localhost:5000/api/whitelist | python3 -m json.tool
```

### View System Logs

```bash
cd server
sudo docker compose logs -f
```

### Backup Data

```bash
cp server/json/threat_log.json ~/backup/
cp server/json/blocked_ips.json ~/backup/
cp server/json/whitelist.json ~/backup/
cp AI/ml_models/threat_intelligence_crawled.json ~/backup/
cp -r AI/ml_models ~/backup/
```

---

## 🛠️ Troubleshooting

**"VirusTotal API error"**
- Check your API key in `.env` file
- Verify key is 64 characters (no quotes)
- Free tier limited to 4 requests/minute

**"GitHub/Cloud IPs blocked"**
- These are false positives from legitimate services
- Use dashboard to whitelist: **✅ Whitelist** button
- Or via API: `curl -X POST http://localhost:5000/api/whitelist/add -d '{"ip_address":"140.82.114.21"}'`
- GitHub IPs: 140.82.x.x range
- Google Cloud: Check AS396982
- Microsoft Azure: Check AS8075

**"Threat crawler errors"**
- Some APIs require authentication (free accounts available)
- Check `AI/ml_models/threat_intelligence_crawled.json` for results
- Most errors are normal (rate limits, API changes)

**"No network traffic detected"**
- Must run with `sudo`
- Check `network_mode: host` in docker-compose.yml

**"Port 5000 already in use"**
```bash
sudo lsof -ti:5000 | xargs kill -9
```

**"ExploitDB not found"**
```bash
cd AI && ./setup_exploitdb.sh && cd ../server
sudo docker compose restart
```

---

## 📁 Project Structure

```
enterprise-security/
├── AI/
│   ├── pcs_ai.py                    # Core AI engine with whitelist
│   ├── threat_intelligence.py       # VirusTotal integration
│   ├── threat_crawler.py            # 12 threat intelligence crawlers
│   ├── exploitdb_scraper.py         # Learning from exploits
│   ├── inspector_ai_monitoring.html # Dashboard UI (scrollable logs)
│   ├── ml_models/
│   │   ├── threat_intelligence_crawled.json  # Crawler results
│   │   └── [ML model files]
│   └── exploitdb/                   # 46,948 exploits
├── server/
│   ├── server.py                    # Flask web server + whitelist API
│   ├── network_monitor.py           # Packet capture
│   ├── docker-compose.yml           # Container orchestration
│   └── json/
│       ├── threat_log.json          # Attack history
│       ├── blocked_ips.json         # Blocked IPs
│       └── whitelist.json           # Permanently whitelisted IPs
├── .env                             # Configuration (API keys)
└── README.md                        # This file
```

---

## 🔒 Security Notes

⚠️ **Runs with elevated privileges** (required for packet capture)  
⚠️ **Keep `.env` file private** (contains API keys)  
⚠️ **Regular updates recommended** (ExploitDB, system packages)  

---

## 📈 Performance & Capacity

**Single Container Performance:**
- **RAM**: ~500MB (idle), ~1GB (active learning)
- **CPU**: 5-10% (monitoring), 20-30% (under attack)
- **Disk**: ~5GB (with ExploitDB), +500MB (crawler cache)
- **Detection Speed**: <250ms per threat
- **Whitelist Check**: <1ms (in-memory)
- **Crawler Speed**: ~5 minutes for all 12 sources
- **Network Throughput**: 10,000+ packets/second
- **Concurrent Users**: 1000s of dashboard users

**Scaling Options:**
- **Single server**: Handles most SMB deployments (up to 500 employees)
- **Multi-server**: Add more containers behind load balancer for 10K+ users
- **External DB**: Optional PostgreSQL for 100K+ events/day (requires code modification)

---

## 🔄 How It Works

### 1. **Network Monitoring** (Real-time)
   - Scapy captures all network packets
   - Pattern matching against 46,948 exploit signatures
   - Behavioral analysis with ML models

### 2. **Threat Detection** (AI-Powered)
   - **IsolationForest** - Anomaly detection
   - **RandomForest** - Threat classification
   - **GradientBoosting** - IP reputation scoring
   - Attack tool signature matching (User-Agent analysis)

### 3. **Whitelist Validation** (Pre-block check)
   - Checks IP against permanent whitelist
   - Prevents blocking of trusted services
   - In-memory cache for instant validation

### 4. **Reputation Check** (VirusTotal API)
   - Queries 70+ security vendors
   - Aggregates malicious verdicts
   - Geolocation & ASN lookup

### 5. **Action Decision**
   - **Whitelisted** → ✅ Allow (never blocked)
   - **Low confidence** → 👁️ Monitor only
   - **Medium confidence** → ⚠️ Log & watch
   - **High confidence** → 🚫 Block immediately

### 6. **Continuous Learning**
   - Retrains ML models every 5 attacks
   - Updates from crawler data
   - Learns from false positives (via whitelist feedback)

---

**Built with**: Python • Flask • Scapy • scikit-learn • Docker • VirusTotal • ExploitDB • CVE • MalwareBazaar • OTX

**Protect your network with AI.** 🛡️
