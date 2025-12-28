# 🛡️ AI-Powered Global Threat Intelligence Network

**Enterprise-grade security with collective AI defense - when one client is attacked, all clients learn.**

🤖 **Self-Learning AI** - Trains on 46,948 real exploits from ExploitDB  
🌍 **Global Threat Network** - All clients learn from each other (encrypted HTTPS/TLS)  
⚡ **Real-Time Detection** - VirusTotal integration (70+ security vendors)  
🕷️ **12 Threat Crawlers** - CVE, NVD, MalwareBazaar, OTX, URLhaus & more  
🎯 **Attack Signatures** - Detects nmap, sqlmap, nikto, burp, metasploit  
🔒 **Encrypted Sharing** - API key authentication + self-signed SSL  
📊 **Live Dashboard** - Real-time threat feed with scrollable logs  

---

## 🚀 Quick Start - Choose Your Role

### For Service Provider (YOU)

**Deploy central server once:**

```bash
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security
./setup_central.sh
```

This creates the central threat aggregation server that all clients connect to.

**What you get:**
- Central server running on port 5001 (HTTPS)
- Master API key for admin operations
- Dashboard showing all connected clients
- Global threat database

---

### For Companies & Homes (YOUR CUSTOMERS)

**Deploy client container:**

```bash
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security
./setup_client.sh
```

The script will:
1. ✅ Check Docker installation
2. ✅ Download ExploitDB database (46,948 exploits)
3. ✅ Ask for VirusTotal API key (optional)
4. ✅ Ask to connect to central server (optional)
5. ✅ Auto-register with central server
6. ✅ Build and start container
7. ✅ Open dashboard in browser

**Access:** http://localhost:5000

**What they get:**
- Local network monitoring
- AI-powered threat detection
- Auto-blocking malicious IPs
- Learning from global network attacks
- Web dashboard

---

## 📊 How Global Learning Works

```
Company A detects port scan from 1.2.3.4
         ↓
Blocks IP locally + uploads threat (encrypted)
         ↓
Central Server receives threat
         ↓
┌────────┼────────┐
│        │        │
Company B  Home C  Branch D
│        │        │
All update ML models
         ↓
Next time attacker tries Company B → INSTANT BLOCK
(B was never attacked, but learned from A's experience!)
```

**Sync Frequency:** Every 5 minutes  
**Privacy:** Only threat metadata shared (IP, attack type, severity)  
**Encryption:** HTTPS/TLS with API key authentication  

---

## 🏗️ Architecture

### Containers

**Total: 2 container types**

1. **Central Server** (1 instance - service provider hosts)
   - Port: 5001 (HTTPS)
   - Purpose: Aggregate threats from all clients
   - Tech: Python 3.11 + Flask + SSL/TLS
   - Storage: JSON (scalable to PostgreSQL)
   - RAM: ~200MB

2. **Client Container** (N instances - one per customer)
   - Port: 5000 (HTTP dashboard)
   - Purpose: Monitor local network + share threats
   - Tech: Python 3.11 + Flask + scikit-learn + Scapy
   - Storage: JSON files for local data
   - RAM: ~500MB

### Data Flow

```
Client → Central Server: POST /api/v1/submit-threats
  • IP address
  • Attack type
  • Severity level
  • Timestamp
  • Geolocation

Central Server → Client: GET /api/v1/get-threats
  • Global threat feed
  • Attack patterns
  • Malicious IPs
  • ML training data
```

---

## 🔐 Security

### Encryption

✅ **HTTPS/TLS** - All client-server communication encrypted  
✅ **API Keys** - 32-byte secure tokens per client  
✅ **Self-signed cert** - Auto-generated (replace with real cert for production)  
✅ **Privacy-preserving** - No internal network data shared  

### Authentication Flow

1. Client registers → Central server generates API key
2. Client stores API key in `.env`
3. Every API request includes: `X-API-Key: <token>`
4. Central server validates before accepting/sending data

### Production SSL Setup

Replace self-signed cert with Let's Encrypt:

```bash
# Get real certificate
certbot certonly --standalone -d threat-intel.yourcompany.com

# Copy to central server
cp /etc/letsencrypt/live/yourcompany.com/fullchain.pem central_server/certs/cert.pem
cp /etc/letsencrypt/live/yourcompany.com/privkey.pem central_server/certs/key.pem

# Restart
cd central_server
docker compose restart
```

---

## 💰 Business Model

### Pricing Tiers

**Free Tier:**
- 1 client node
- Basic threat sharing
- Community support

**Professional - $99/month:**
- Up to 10 client nodes
- Priority threat distribution
- Email support
- API access

**Enterprise - $499/month:**
- Unlimited nodes
- Dedicated central server instance
- White-label option
- 24/7 support
- SLA guarantee

### Revenue Example

| Customers | Price/mo | Revenue/mo |
|-----------|----------|------------|
| 10 | $99 | $990 |
| 100 | $99 | $9,900 |
| 1,000 | $99 | $99,000 |
| 10,000 | $99 | $990,000 |

**Your Cost:** $50-500/month VPS (handles 10,000+ clients)

---

## 📖 Configuration

### Environment Variables (.env)

**Client Container:**
```bash
# VirusTotal API Key (get from https://www.virustotal.com/gui/join-us)
VIRUSTOTAL_API_KEY=your_64_char_key

# Central Server Connection
CENTRAL_SERVER_URL=https://your-server-ip:5001
CENTRAL_SERVER_API_KEY=<from registration>
SYNC_ENABLED=true
SYNC_INTERVAL=300  # Sync every 5 minutes

# Timezone
TZ=Asia/Kuala_Lumpur
```

**Central Server:**
```bash
# SSL Configuration
USE_SSL=true
SSL_CERT=/app/certs/cert.pem
SSL_KEY=/app/certs/key.pem
```

---

## 🎯 Features

### Client Features

✅ **Real-Time Threat Detection**
- Port scan detection (nmap, masscan)
- DDoS prevention
- SQL injection (100+ patterns)
- XSS attacks
- Brute force protection
- Tool detection (sqlmap, nikto, burp)

✅ **AI/ML Models**
- IsolationForest (anomaly detection)
- RandomForest (threat classification)
- GradientBoosting (IP reputation)
- Auto-retraining every 5 attacks

✅ **Threat Intelligence**
- VirusTotal (70+ AV engines)
- ExploitDB (46,948 exploits)
- 12 threat crawlers (CVE, MalwareBazaar, etc.)
- Geolocation tracking
- VPN/Tor detection

✅ **Smart IP Management**
- Auto-blocking malicious IPs
- Whitelist for trusted IPs (GitHub, cloud providers)
- Interactive dashboard management
- Unblock/Whitelist/Keep blocked actions

### Central Server Features

✅ **Threat Aggregation**
- Collects threats from all clients
- Deduplicates similar attacks
- Stores last 10,000 threats (JSON)
- Upgradable to PostgreSQL for millions

✅ **Client Management**
- Registration API with API key generation
- Client activity tracking
- Last seen timestamps
- Threat submission statistics

✅ **API Endpoints**
- `/api/v1/register` - Client registration
- `/api/v1/submit-threats` - Receive threats
- `/api/v1/get-threats` - Distribute threats
- `/api/v1/threat-patterns` - Attack patterns
- `/api/v1/stats` - Network statistics
- `/api/v1/clients` - List connected clients (admin)

---

## 📊 Dashboard

### Central Server Connection Status

The client dashboard shows:

🌍 **Global Threat Intelligence Network**
- ✅/❌ Connection status
- ⏰ Last sync time
- 📤 Threats shared (queued for upload)
- 📥 Global threats received

**Live updates every 30 seconds**

### If Not Connected

Dashboard shows:
- ⚠️ Standalone Mode warning
- 🌍 "Connect to Global Network" button
- Click to register with central server

---

## 🔧 Management

### Central Server

**View Logs:**
```bash
cd central_server
docker compose logs -f
```

**View Connected Clients:**
```bash
curl -k https://localhost:5001/api/v1/clients \
  -H "X-API-Key: YOUR_MASTER_KEY"
```

**Backup Data:**
```bash
tar -czf backup-$(date +%Y%m%d).tar.gz central_server/data/
```

### Client Container

**View Logs:**
```bash
cd server
docker compose logs -f
```

**Restart:**
```bash
cd server
docker compose restart
```

**Stop:**
```bash
cd server
docker compose down
```

---

## 📈 Scaling

### Current Capacity (JSON Storage)

| Metric | Capacity |
|--------|----------|
| Clients | 1,000+ |
| Threats/day | 100,000 |
| Sync latency | <5 minutes |
| Storage | ~10GB/year |
| Central RAM | 200MB |
| Client RAM | 500MB each |

### Upgrade to PostgreSQL (100K+ Clients)

Modify `central_server/server.py`:

```python
import psycopg2

# Replace JSON file operations with:
conn = psycopg2.connect("postgresql://user:pass@db:5432/threats")
cursor = conn.cursor()
cursor.execute("INSERT INTO threats (ip, type, severity) VALUES (%s, %s, %s)", ...)
```

**Schema:** See `central_server/README.md`

---

## 🛠️ Troubleshooting

**"Connection refused" on central server**
```bash
# Check if running
cd central_server && docker compose ps

# Check logs
docker compose logs

# Open firewall
sudo ufw allow 5001/tcp
```

**"SSL certificate verify failed" on client**
- Normal for self-signed certs
- Clients use `-k` flag in curl (already handled)
- For production, use real SSL cert

**"Not syncing" on client**
```bash
# Check .env
cat .env | grep SYNC

# Should show:
# SYNC_ENABLED=true
# CENTRAL_SERVER_URL=https://...
# CENTRAL_SERVER_API_KEY=...

# Check logs
cd server && docker compose logs | grep CENTRAL
```

**"Dashboard shows Standalone Mode"**
- Edit `.env` file
- Set `SYNC_ENABLED=true`
- Add server URL and API key
- Restart: `cd server && docker compose restart`

---

## 🎓 Learning Resources

### API Documentation

Full API reference: See `central_server/README.md`

### Architecture Details

System architecture diagram: See `ARCHITECTURE.md`

### Support

- GitHub Issues: https://github.com/yuhisern7/enterprise-security/issues
- Email: support@yourcompany.com

---

## 🚦 Project Status

✅ **Production Ready**
- Single container deployment (standalone)
- Global threat sharing network
- Encrypted HTTPS communication
- Dashboard with network status
- Auto-registration flow
- 46,948 ExploitDB signatures
- 12 threat intelligence crawlers
- VirusTotal integration
- ML model auto-training

📋 **Roadmap**
- [ ] PostgreSQL backend for 100K+ clients
- [ ] Prometheus metrics export
- [ ] Grafana dashboard templates
- [ ] Mobile app for alerts
- [ ] Slack/Teams integration
- [ ] Advanced analytics dashboard
- [ ] Threat report generation

---

## 📄 License

MIT License - Free for commercial use

---

## 🙏 Credits

Built with:
- Python 3.11
- Flask 3.0
- scikit-learn 1.3
- Scapy 2.5
- ExploitDB (Offensive Security)
- VirusTotal API
- Docker

**Protect your network with collective AI intelligence.** 🛡️
