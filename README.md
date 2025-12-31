# 🛡️ Battle-Hardened AI – Network Monitoring King

**AI-Powered Network Security. One Container Protects Your Entire Network. $25/month.**

## 💡 The Genius Solution

**One attack anywhere. Everyone protected everywhere.**

Autonomous **Network Monitor (IDS/IPS)** - watches ALL network traffic and blocks attackers before they reach your devices.

**How Global Mesh Works:**
- Attack detected anywhere → Logged to relay server → Broadcast to ALL subscribers globally
- Every container blocks attacker within seconds
- Relay AI retrains every 6 hours with 50,000+ worldwide attacks
- Subscribers receive updated ML models automatically (280 KB)
- **Zero manual work. No exploit payloads on your system. Pattern signatures only.**

## 🔐 What We Store: Signatures NOT Payloads

**✅ DEFENSIVE ARCHITECTURE (Military/Police Approved):**

**Relay Server Trains AI On:**
- **46,948 ExploitDB attack signatures** - Pattern indicators (e.g., "select", "union", "drop" keywords)
- **100,000+ malware behavior signatures** - Hash patterns, not executable files
- **10,000+ malicious URL patterns** - Domain/path indicators, not actual exploits
- **50,000+ global attack patterns** - Network behavior signatures from subscribers
- **Raw training data (825 MB)** - Stays on relay server, never distributed

**Subscribers Download:**
- **Pre-trained ML models ONLY (280 KB)** - Safe pattern-matching weights
- **Attack signature database** - Detection patterns, not exploit code
- **Network behavior indicators** - What attacks "look like", not how to execute them

**❌ What We DON'T Store:**
- Weaponized exploit code or payloads
- Executable malware samples
- Working attack scripts
- Dual-use offensive tools

**Like antivirus signatures (Symantec, McAfee) but for network traffic. Detection-only, not exploitation.**

**💰 Cost:** $25/month vs $10K-$500K/year enterprise tools (Palo Alto, CrowdStrike)  
**Deployment:** 5 minutes vs weeks/months  
**Suitable For:** Homes, businesses, governments, military, police, critical infrastructure


---

## 💎 Premium Relay Access – $25/month

**📞 Contact:** Yuhisern Navaratnam | WhatsApp: +60172791717 | Email: yuhisern@protonmail.com

**What You Get:**
- Global mesh access (100+ countries)
- Pre-trained ML models (280 KB auto-updates every 6h)
- Real-time threat intelligence from 50,000+ worldwide attacks
- Network performance monitoring + compliance reporting (PCI-DSS, HIPAA, GDPR, SOC 2)
- Advanced visualization (topology maps, attack flows, heatmaps)
- Cryptographic security (RSA-2048 + HMAC-SHA256)
- Priority support

**Free vs Premium:**

| Feature | Free | Premium |
|---------|------|---------|
| Network Protection | ✅ Full | ✅ Full |
| AI Training Data | ⚠️ Local only | ✅ 46K signatures + 100K malware + 50K global attacks |
| Global Mesh | ❌ | ✅ Worldwide |
| Model Updates | ⚠️ Manual | ✅ Auto every 6h |
| Compliance Reports | ❌ | ✅ PCI-DSS, HIPAA, GDPR, SOC 2 |
| Support | ❌ | ✅ Priority |

---

## 🚀 Quick Start

**Linux/Docker:**
```bash
git clone https://github.com/yuhisern7/battle-hardened-ai.git
cd battle-hardened-ai/server
# Edit .env: Set RELAY_URL (premium) or leave blank (free)
docker compose up -d
```

**Dashboard:** https://localhost:60000 (HTTPS - Self-signed cert)  
**Note:** Browser will show security warning - click "Advanced" → "Proceed to localhost"  
**Default:** Auto-detects network, starts monitoring ALL devices

---

## 🛡️ Architecture Overview

**Network-Level Defense (Not Antivirus):**
- Monitors ALL traffic at gateway/router level
- Detects attacks BEFORE they reach endpoints
- ML-based pattern matching (280 KB inference models)
- Blocks based on network behavior signatures
- Works with ANY device (Windows, Mac, Linux, IoT, phones)

**Signature Database Structure:**
```json
{
  "signatures": [
    {
      "exploit_id": "35342",
      "type": "sql_injection", 
      "indicators": ["select", "union", "drop", "insert", "delete"],
      "pattern": "(union\\s+select|select.*from.*where)",
      "severity": "MEDIUM"
    }
  ]
}
```

**We store PATTERNS (regex, keywords), NOT exploit code.**

---

## 🧠 AI/ML Architecture

**Training Pipeline (Relay Server):**
1. Collect 825 MB training data (ExploitDB signatures, malware hashes, global attacks)
2. Extract behavioral patterns and indicators
3. Train RandomForest + IsolationForest models (scikit-learn)
4. Export lightweight models (280 KB .pkl files)
5. Distribute to subscribers via HTTPS

**Inference Pipeline (Subscriber Containers):**
1. Download pre-trained models (280 KB)
2. Monitor network traffic in real-time
3. Extract features from packets (IP, ports, payload patterns)
4. Run ML inference (pattern matching)
5. Block if threat score > threshold

**Models:**
- `anomaly_detector.pkl` - IsolationForest for unknown threats
- `threat_classifier.pkl` - RandomForest for known attack signatures
- `network_performance.pkl` - LSTM for bandwidth anomalies

---

## 📊 Features

**Core Protection:**
- ARP scanning + device fingerprinting
- Port scanning (detects open services on all devices)
- Real-time threat detection (SQL injection, XSS, RCE, LFI, etc.)
- Auto-blocking with whitelist/blacklist
- Adaptive honeypot (deception technology)

**Enterprise Features:**
- Network performance monitoring (bandwidth, latency, packet loss)
- Compliance reporting (PCI-DSS, HIPAA, GDPR, SOC 2)
- Attack visualization (topology maps, heatmaps, flow diagrams)
- Device history tracking
- Forensic logging

**Dashboard:**
- Real-time threat feed
- Connected device management
- ML model performance metrics
- Compliance status overview
- Network performance graphs

---

## 🔐 Security Architecture

**Cryptographic Protection:**
- RSA-2048 key exchange
- HMAC-SHA256 message authentication
- Replay attack prevention (timestamp + nonce)
- Node fingerprinting (prevents spoofing)

**P2P Mesh (Premium):**
- Encrypted peer-to-peer threat sharing
- Geographic attack origin tracking
- Cross-border threat intelligence
- Tamper-proof signatures

---

## 🎯 Use Cases

**Military/Police/Government:**
- ✅ Signature-based detection (no weaponized payloads)
- ✅ Defensive architecture (compliant with cybersecurity laws)
- ✅ Network-level monitoring (sees all devices/traffic)
- ✅ Forensic logging for investigations
- ✅ Pattern matching like Snort/Suricata IDS

**Enterprise/SMB:**
- Auto-generate compliance reports
- Monitor all endpoints from one container
- Block attacks before they reach endpoints
- No per-device licensing costs

**Home Users:**
- Protect ALL devices (IoT, phones, laptops, cameras)
- No configuration needed
- Works alongside existing antivirus
- Blocks network-level attacks antivirus misses

---

## 📚 Technical Docs

**File Structure:**
```
AI/
├── learned_signatures.json      # Attack signatures (patterns only)
├── pcs_ai.py                    # ML threat detection
├── exploitdb_scraper.py         # Signature extraction
├── threat_intelligence.py       # External threat feeds
└── compliance_reporting.py      # Auto compliance reports

server/
├── server.py                    # Flask API + dashboard
├── device_scanner.py            # ARP scanning + port detection
├── network_monitor.py           # Traffic analysis
└── device_blocker.py            # Firewall rules

relay/
├── relay_server.py              # Central training server
├── gpu_trainer.py               # GPU-accelerated training
└── ai_training_materials/       # 825 MB training data (server-only)
```

**Environment Variables (.env):**
```bash
RELAY_URL=https://your-relay-server.com  # Premium only
