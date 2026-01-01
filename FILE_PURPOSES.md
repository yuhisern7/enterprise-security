# 📁 File Purposes Guide

Complete reference for every file in the Battle-Hardened AI Enterprise Security system.

---

## 🖥️ Server Core Files

### **server/server.py** (2,205 lines)
**Purpose:** Main Flask API server  
**What it does:**
- Serves 50+ REST API endpoints for the dashboard
- Routes requests to AI/pcs_ai.py for threat detection
- Manages authentication and session handling
- Serves static files (dashboard HTML)
- Handles device blocking/unblocking operations

**When to edit:**
- Adding new API endpoints
- Modifying security middleware
- Changing port configuration

---

### **server/device_scanner.py**
**Purpose:** Network device discovery engine  
**What it does:**
- Scans local network for connected devices (ARP, ICMP)
- Identifies device types (router, phone, IoT, computer)
- Detects MAC addresses and manufacturers
- Monitors device connectivity status
- Stores results in `json/connected_devices.json`

**When to edit:**
- Customizing device detection logic
- Adding new device type classifications
- Changing scan intervals

---

### **server/device_blocker.py**
**Purpose:** Device-level access control  
**What it does:**
- Blocks devices by MAC address (iptables rules)
- Maintains blocked device list
- Enforces whitelist/blacklist policies
- Stores blocking rules in `json/blocked_devices.json`

**When to edit:**
- Changing blocking mechanisms
- Adding exception rules
- Implementing time-based blocks

---

### **server/network_monitor.py**
**Purpose:** Real-time network traffic monitoring  
**What it does:**
- Captures network packets (scapy)
- Analyzes traffic patterns
- Detects bandwidth anomalies
- Monitors per-device traffic statistics
- Saves state to `json/network_monitor_state.json`

**When to edit:**
- Adjusting monitoring thresholds
- Adding new traffic metrics
- Customizing packet inspection

---

### **server/report_generator.py**
**Purpose:** Security report generation  
**What it does:**
- Generates PDF/HTML security reports
- Compiles threat statistics
- Creates compliance reports (PCI-DSS, HIPAA, GDPR)
- Exports threat intelligence data

**When to edit:**
- Adding new report types
- Customizing report templates
- Changing export formats

---

### **server/test_system.py**
**Purpose:** System testing and validation  
**What it does:**
- Runs automated tests on core components
- Validates API endpoints
- Tests threat detection accuracy
- Checks system health

**When to edit:**
- Adding new test cases
- Debugging system issues
- Validating new features

---

## 🧠 AI/ML Core Files

### **AI/pcs_ai.py** (3,721 lines)
**Purpose:** Main AI threat detection engine  
**What it does:**
- Analyzes HTTP requests for attack patterns
- Runs ML models (RandomForest, IsolationForest)
- Detects SQL injection, XSS, command injection, etc.
- Implements false positive filtering (5-gate pipeline)
- Manages threat log and blocked IPs
- Extracts attack signatures (patterns only)
- Coordinates with relay server for threat sharing

**When to edit:**
- Adjusting detection sensitivity
- Adding new attack pattern recognition
- Modifying ML model parameters
- Customizing blocking behavior

**Critical Functions:**
- `assess_request_pattern()` - Main threat detection
- `_log_threat()` - Stores confirmed attacks
- `_block_ip()` - IP blocking logic
- `_train_ml_models_from_history()` - AI training

---

### **AI/false_positive_filter.py** (512 lines)
**Purpose:** 5-gate false positive elimination pipeline  
**What it does:**
- Filters out noise and false alarms
- Requires multiple independent signals to confirm attacks
- Implements 5-gate validation:
  - Gate 1: Sanity & Context (whitelists, internal IPs)
  - Gate 2: Behavior Consistency (3+ repetitions)
  - Gate 3: Temporal Correlation (5-minute window)
  - Gate 4: Cross-Signal Agreement (2+ signal types)
  - Gate 5: Confidence Scoring (≥75% threshold)
- Ensures ONLY confirmed attacks reach training data

**When to edit:**
- Adjusting confidence thresholds
- Adding new gate logic
- Changing signal type requirements

**Critical Variables:**
- `min_signals_for_confirmation = 2`
- `min_confidence_threshold = 0.75`
- `temporal_window = 300` (5 minutes)

---

### **AI/signature_extractor.py** (385 lines)
**Purpose:** Attack pattern extraction (defensive)  
**What it does:**
- Extracts ONLY patterns from attacks (NOT exploit code)
- Identifies encoding schemes (base64, hex, URL encoding)
- Detects attack keywords and regex patterns
- **DELETES attack payloads immediately**
- Creates signatures for ML training
- Saves to `learned_signatures.json`

**When to edit:**
- Adding new encoding detection
- Customizing keyword extraction
- Changing signature format

**Privacy Guarantee:**
- NEVER stores actual exploit code
- NEVER stores attack payloads
- Only stores patterns (safe for AI training)

---

### **AI/signature_uploader.py** (245 lines)
**Purpose:** Upload signatures to relay server  
**What it does:**
- Connects to relay server via WebSocket
- Sends extracted signatures (patterns only)
- Validates NO prohibited data is sent
- Receives confirmation from relay
- Tracks upload statistics

**When to edit:**
- Changing relay server URL
- Modifying signature validation rules
- Adjusting upload frequency

---

## 🍯 Honeypot System

### **AI/adaptive_honeypot.py**
**Purpose:** Adaptive deception system  
**What it does:**
- Simulates 8 vulnerable services (SSH, FTP, HTTP, etc.)
- AI-trained service personas
- Learns attacker tactics
- Captures attack attempts without exposing real services
- Provides high-confidence attack detection

**When to edit:**
- Adding new service simulations
- Customizing honeypot behavior
- Adjusting response patterns

---

## 🌐 Network Synchronization

### **AI/relay_client.py**
**Purpose:** Relay server client connection  
**What it does:**
- Maintains WebSocket connection to relay server
- Sends local threat signatures to global network
- Receives threat intelligence from other nodes
- Downloads ML model updates
- Handles peer-to-peer coordination

**When to edit:**
- Changing relay server configuration
- Modifying message formats
- Adjusting reconnection logic

---

### **AI/p2p_sync.py**
**Purpose:** Peer-to-peer threat synchronization  
**What it does:**
- Direct node-to-node threat sharing
- Decentralized mesh networking
- Reduces relay server dependency
- Real-time attack pattern distribution

**When to edit:**
- Configuring P2P discovery
- Changing sync protocols
- Adjusting peer connection limits

---

### **AI/central_sync.py**
**Purpose:** Centralized coordination  
**What it does:**
- Coordinates training data synchronization
- Manages model version distribution
- Handles configuration updates
- Synchronizes threat intelligence

**When to edit:**
- Modifying sync schedules
- Changing coordination logic
- Adding new sync targets

---

## 🔍 Threat Intelligence

### **AI/threat_intelligence.py**
**Purpose:** External threat intelligence integration  
**What it does:**
- Integrates with VirusTotal API
- Queries AbuseIPDB for IP reputation
- Checks ExploitDB signatures
- Aggregates threat intelligence
- Provides threat scoring

**When to edit:**
- Adding new threat intel sources
- Changing API integrations
- Customizing threat scoring

---

### **AI/threat_crawler.py**
**Purpose:** Threat data web crawler  
**What it does:**
- Scrapes threat intelligence from web sources
- Extracts attack patterns from security blogs
- Collects CVE information
- Updates threat database

**When to edit:**
- Adding new crawling targets
- Changing extraction patterns
- Adjusting crawl frequency

---

### **AI/exploitdb_scraper.py**
**Purpose:** ExploitDB signature extraction  
**What it does:**
- Downloads ExploitDB database
- Extracts attack signatures
- Converts exploits to detection patterns
- Populates learned_signatures.json
- Runs via `setup_exploitdb.sh`

**When to edit:**
- Changing ExploitDB source
- Modifying signature extraction logic
- Customizing pattern generation

---

## 📊 Visualization & Monitoring

### **AI/inspector_ai_monitoring.html** (4,173 lines)
**Purpose:** Main security dashboard (frontend)  
**What it does:**
- 17-section interactive dashboard
- Real-time threat monitoring
- Network device management
- Attack visualization (charts, maps, heatmaps)
- System health monitoring
- Uses Chart.js for visualizations

**Sections:**
1. Introduction & System Info
2. AI Training Status
3. Network Devices
4. Blocked Devices
5. Whitelist Management
6. Security Overview
7. Geolocation Tracking
8. IP Blocking Controls
9. Attack Patterns
10. Network Performance
11. Live Threat Monitor
12. Attack Heatmap
13. Signature Extraction
14. System Health
15. Compliance Reporting
16. Adaptive Honeypot
17. Threat Intelligence

**When to edit:**
- Adding new dashboard sections
- Customizing visualizations
- Changing UI layout

---

### **AI/advanced_visualization.py**
**Purpose:** Advanced data visualization engine  
**What it does:**
- Generates network topology maps
- Creates attack flow diagrams
- Produces geographic threat heatmaps
- Visualizes attack patterns
- Exports visualization data

**When to edit:**
- Adding new visualization types
- Customizing chart styles
- Changing data aggregation

---

### **AI/network_performance.py**
**Purpose:** Network performance metrics  
**What it does:**
- Monitors bandwidth usage
- Tracks latency and packet loss
- Detects performance anomalies
- Provides system health metrics
- Saves to `json/network_performance.json`

**When to edit:**
- Adding new metrics
- Changing performance thresholds
- Customizing alert triggers

---

### **AI/compliance_reporting.py**
**Purpose:** Regulatory compliance monitoring  
**What it does:**
- Tracks PCI-DSS compliance
- Monitors HIPAA requirements
- Checks GDPR compliance
- Generates SOC 2 reports
- Provides audit trails

**When to edit:**
- Adding new compliance standards
- Customizing compliance checks
- Changing report formats

---

## 🔐 Security & Cryptography

### **AI/crypto_security.py**
**Purpose:** Cryptographic operations  
**What it does:**
- RSA-2048 message signing
- HMAC-SHA256 authentication
- Replay attack protection
- Nonce tracking
- Timestamp validation

**When to edit:**
- Changing encryption algorithms
- Adjusting key sizes
- Modifying validation windows

---

### **AI/node_fingerprint.py**
**Purpose:** Node identification and fingerprinting  
**What it does:**
- Generates unique node identifiers
- Detects OS and system type
- Calculates compatibility scores
- Enables federated learning grouping

**When to edit:**
- Customizing fingerprint generation
- Adding new system detection
- Changing compatibility logic

---

## 🔄 Relay Server Files

### **relay/relay_server.py** (335 lines)
**Purpose:** Central relay server (WebSocket)  
**What it does:**
- Accepts connections from unlimited nodes worldwide
- Broadcasts threat intelligence to all connected nodes
- Stores signatures to `ai_training_materials/` (file-based)
- Manages peer connections
- Coordinates global AI training

**When to edit:**
- Changing WebSocket configuration
- Modifying broadcast logic
- Adjusting connection limits

---

### **relay/signature_sync.py** (305 lines)
**Purpose:** Signature synchronization service  
**What it does:**
- Receives attack signatures from nodes
- Validates signatures (NO exploit code allowed)
- Stores DIRECTLY to JSON files (no database)
- Saves to `ai_training_materials/learned_signatures.json`
- Saves to `ai_training_materials/global_attacks.json`
- Tracks duplicate signatures

**When to edit:**
- Changing validation rules
- Modifying file storage logic
- Adjusting deduplication

**Critical:** NO DATABASE - Everything is file-based!

---

### **relay/ai_retraining.py** (343 lines)
**Purpose:** AI model retraining scheduler  
**What it does:**
- Reads attack data from JSON files
- Trains ML models every 6 hours
- Merges ExploitDB + global attacks
- Saves models to `ai_training_materials/ml_models/`
- Distributes updated models to nodes

**When to edit:**
- Changing training schedule
- Adjusting model parameters
- Modifying data sources

**Training Sources:**
- `ai_training_materials/learned_signatures.json`
- `ai_training_materials/global_attacks.json`
- `ai_training_materials/exploitdb/`

---

### **relay/gpu_trainer.py** (361 lines)
**Purpose:** GPU-accelerated model training  
**What it does:**
- Detects GPU (CUDA/TensorFlow)
- Loads training data from files
- Trains neural networks on GPU
- Exports lightweight models (.pkl, .h5)
- Supports TensorFlow and PyTorch

**When to edit:**
- Changing model architectures
- Adjusting training parameters
- Adding new ML frameworks

---

### **relay/training_sync_api.py**
**Purpose:** Training materials distribution API  
**What it does:**
- HTTP server for downloading ML models
- Serves files from `ai_training_materials/`
- Provides model version info
- Handles authenticated downloads

**When to edit:**
- Adding authentication
- Changing file serving logic
- Modifying API endpoints

---

### **relay/start_services.py**
**Purpose:** Relay server startup orchestrator  
**What it does:**
- Starts relay_server.py
- Launches ai_retraining.py scheduler
- Initializes training_sync_api.py
- Manages service health checks

**When to edit:**
- Adding new services
- Changing startup order
- Modifying health checks

---

## 📊 Data Storage Files

### **server/json/threat_log.json** (428 KB)
**Purpose:** Local threat event log  
**Contains:**
- All attacks detected on YOUR network
- Timestamps, IP addresses, attack types
- Geolocation data
- VPN/Tor detection results
- NEVER shared with relay server

---

### **server/json/blocked_ips.json**
**Purpose:** Blocked IP addresses  
**Contains:**
- IPs auto-blocked by AI
- Block timestamps
- Block reasons
- NEVER shared with relay server

---

### **server/json/whitelist.json**
**Purpose:** Trusted IP whitelist  
**Contains:**
- Whitelisted IP addresses
- Internal network ranges
- Trusted service IPs
- NEVER shared with relay server

---

### **server/json/connected_devices.json**
**Purpose:** Network device inventory  
**Contains:**
- All devices on your network
- MAC addresses, IP addresses
- Device types and manufacturers
- Connection timestamps
- NEVER shared with relay server

---

### **server/json/device_history.json**
**Purpose:** Device connection history  
**Contains:**
- Historical device connections
- Connection/disconnection events
- Device behavior patterns
- NEVER shared with relay server

---

### **server/json/peer_threats.json** (100 KB)
**Purpose:** Shared threat intelligence  
**Contains:**
- Threats received from other nodes
- Anonymous attack patterns
- No source network information
- Used for AI training only

---

### **relay/ai_training_materials/learned_signatures.json** (41,018 lines)
**Purpose:** Global attack signature database  
**Contains:**
- 3,066+ attack signatures from ExploitDB
- Real-world attack patterns from all nodes
- Keywords, encodings, regex patterns
- NO exploit code, NO payloads
- Used for AI training

**Format:**
```json
{
  "signatures": [
    {
      "pattern_hash": "abc123...",
      "attack_type": "SQL Injection",
      "keywords": ["select", "union", "from"],
      "encodings": ["url_encoded"],
      "first_seen": "2026-01-01T12:00:00Z",
      "global_occurrence_count": 42
    }
  ]
}
```

---

### **relay/ai_training_materials/global_attacks.json**
**Purpose:** Complete attack event log (global)  
**Contains:**
- Full attack events from all nodes worldwide
- Attack metadata (type, severity, timestamp)
- Geographic distribution (anonymous)
- NO customer network information
- Used for AI training

---

### **relay/ai_training_materials/ml_models/**
**Purpose:** Trained ML model storage  
**Contains:**
- `anomaly_detector.pkl` - IsolationForest model (280 KB)
- `threat_classifier.pkl` - RandomForest model
- `network_performance.pkl` - LSTM model
- Model metadata and versions

---

## 🛠️ Configuration & Setup

### **.env**
**Purpose:** Environment variables  
**Contains:**
- API keys (VirusTotal, AbuseIPDB)
- Server ports (60000, 60001, 60002)
- Relay server URL
- Database credentials (if using database - optional)
- Feature flags

**Example:**
```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
RELAY_URL=wss://your-relay-server:60001
SERVER_PORT=60000
```

---

### **server/requirements.txt**
**Purpose:** Python dependencies for server  
**Contains:**
- Flask (API server)
- scikit-learn (ML models)
- scapy (network monitoring)
- numpy, pandas (data processing)
- requests (API calls)

---

### **relay/requirements.txt**
**Purpose:** Python dependencies for relay  
**Contains:**
- websockets (relay server)
- psycopg2 (PostgreSQL - optional, not used)
- tensorflow/pytorch (GPU training)
- numpy, pandas (data processing)

---

### **server/docker-compose.yml**
**Purpose:** Docker container orchestration (server)  
**What it does:**
- Defines security server container
- Network configuration
- Volume mounts
- Port mappings
- Environment variables

---

### **relay/docker-compose.yml**
**Purpose:** Docker container orchestration (relay)  
**What it does:**
- Defines relay server container
- WebSocket port (60001)
- Training API port (60002)
- Volume mounts for ai_training_materials

---

## 📜 Setup Scripts

### **server/installation/install.sh**
**Purpose:** Automated server installation (Linux)  
**What it does:**
- Installs Docker and dependencies
- Creates directory structure
- Configures firewall rules
- Starts containers
- Sets up systemd services

---

### **server/installation/QUICKSTART_WINDOWS.bat**
**Purpose:** Windows quick setup  
**What it does:**
- Checks Docker Desktop
- Configures WSL 2
- Starts containers
- Opens dashboard

---

### **relay/setup.sh**
**Purpose:** Relay server setup (Linux)  
**What it does:**
- Installs relay server
- Configures firewall
- Detects public IP
- Starts relay services

---

### **relay/setup-macos.sh**
**Purpose:** Relay server setup (macOS)  
**What it does:**
- Checks Docker Desktop
- Configures networking
- Starts relay server
- Shows connection info

---

### **relay/setup.bat**
**Purpose:** Relay server setup (Windows)  
**What it does:**
- Checks Docker Desktop
- Configures WSL 2
- Starts relay containers
- Displays status

---

### **AI/setup_exploitdb.sh**
**Purpose:** ExploitDB database download  
**What it does:**
- Clones ExploitDB repository
- Runs exploitdb_scraper.py
- Extracts signatures
- Populates learned_signatures.json

**Run once during setup:**
```bash
cd AI
./setup_exploitdb.sh
```

---

## 📖 Documentation

### **README.md** (1,039 lines)
**Purpose:** Main project documentation  
**Contains:**
- Quick start guide
- Architecture overview
- Feature list
- Privacy guarantees
- False positive filtering explanation
- Deployment guides

---

### **DASHBOARD_FILES.md** (176 lines)
**Purpose:** Dashboard file reference  
**Contains:**
- Frontend/backend file listing
- API endpoint reference
- Data flow diagrams
- Configuration details

---

### **FILE_PURPOSES.md** (this file)
**Purpose:** Complete file reference guide  
**Contains:**
- Purpose of every file
- What each file does
- When to edit each file
- Critical variables and functions

---

### **STRUCTURE.txt**
**Purpose:** Project directory structure  
**Contains:**
- Complete folder tree
- File organization
- Module relationships

---

### **HOW-TO-UPDATE.txt**
**Purpose:** Update instructions  
**Contains:**
- How to update the system
- Version management
- Migration guides

---

### **SECTION_ALIGNMENT_REPORT.md**
**Purpose:** Dashboard section documentation  
**Contains:**
- Dashboard section breakdown
- Component alignment
- Feature tracking

---

## 🧪 Testing & Automation

### **test_automated_workflow.py**
**Purpose:** Automated testing workflow  
**What it does:**
- Tests core functionality
- Validates API endpoints
- Checks data integrity
- Generates test reports

---

### **reorder_sections.py**
**Purpose:** Dashboard section reorganization  
**What it does:**
- Reorders dashboard sections
- Updates HTML structure
- Maintains consistency

---

## 🚀 Deployment Scripts

### **cloud-deploy.sh**
**Purpose:** Cloud deployment automation  
**What it does:**
- Deploys to cloud providers (AWS, GCP, Azure)
- Configures cloud networking
- Sets up load balancing
- Manages SSL certificates

---

### **view-dashboard.sh**
**Purpose:** Dashboard launcher  
**What it does:**
- Opens dashboard in browser
- Handles HTTPS certificate warnings
- Shows connection info

---

## 🔑 Key Concepts

### **Privacy Architecture**
- **Local Storage:** Customer data stays in `server/json/` (NEVER shared)
- **Shared Data:** Only attack patterns go to relay (NO payloads, NO device info)
- **File-Based:** Relay uses JSON files (NO database, NO credentials)

### **False Positive Filtering**
- **5-Gate Pipeline:** Ensures ONLY confirmed attacks reach training data
- **High Confidence:** ≥75% threshold required
- **Clean Training:** No noise in AI models

### **Defensive Design**
- **NO exploit code stored** anywhere
- **NO attack payloads** stored anywhere
- **Patterns ONLY** for AI learning

---

## 📞 Quick Reference

**Want to...**
- **Add new attack detection?** → Edit `AI/pcs_ai.py`
- **Adjust false positive filtering?** → Edit `AI/false_positive_filter.py`
- **Change dashboard UI?** → Edit `AI/inspector_ai_monitoring.html`
- **Add API endpoint?** → Edit `server/server.py`
- **Modify relay server?** → Edit `relay/relay_server.py`
- **Change AI training?** → Edit `relay/ai_retraining.py`
- **Add new threat source?** → Edit `AI/threat_intelligence.py`
- **Customize honeypot?** → Edit `AI/adaptive_honeypot.py`

---

**Last Updated:** January 1, 2026  
**Total Files Documented:** 50+  
**Project:** Battle-Hardened AI Enterprise Security
