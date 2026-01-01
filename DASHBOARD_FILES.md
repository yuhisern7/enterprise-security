# 📊 Dashboard Associated Files

## 🖥️ Frontend
- **AI/inspector_ai_monitoring.html** (4,173 lines)
  - Main dashboard interface with 17 sections
  - Uses Chart.js for visualizations
  - Real-time data updates via fetch API

## 🔌 Backend API Server
- **server/server.py** (2,205 lines)
  - Flask application serving 50+ API endpoints
  - Routes dashboard data to frontend
  - Integrates with AI detection engine

## 🧠 AI/ML Processing
- **AI/pcs_ai.py** (3,721 lines)
  - Core threat detection engine
  - Machine learning models (RandomForest, IsolationForest)
  - Signature extraction system
  - VPN/Tor de-anonymization

## 📊 Advanced Visualization Modules
- **AI/advanced_visualization.py**
  - Network topology mapping
  - Attack flow visualization
  - Heatmap generation
  - Geographic threat maps

- **AI/network_performance.py**
  - System health metrics
  - Network performance monitoring
  - Resource utilization tracking

- **AI/compliance_reporting.py**
  - PCI-DSS compliance checks
  - HIPAA compliance tracking
  - GDPR compliance monitoring
  - SOC 2 compliance reporting

## 🍯 Honeypot System
- **AI/adaptive_honeypot.py**
  - 8 AI-trained service personas
  - Attack pattern learning
  - Deception tactics

## 🌐 P2P & Relay Integration
- **AI/relay_client.py**
  - Connects to relay server
  - Shares threat intelligence
  - Receives ML model updates

- **AI/p2p_sync.py**
  - Peer-to-peer threat sharing
  - Decentralized network mesh

- **AI/central_sync.py**
  - Centralized coordination
  - Training data synchronization

## 🔍 Threat Intelligence
- **AI/threat_intelligence.py**
  - ExploitDB integration
  - Threat crawler management
  - Signature database

- **AI/threat_crawler.py**
  - Web scraping for threat data
  - Pattern extraction
  - Intelligence gathering

## 📁 Data Storage (Local JSON)
**Location:** `server/json/`
- **threat_log.json** (428 KB) - All detected threats
- **blocked_ips.json** - Auto-blocked attackers
- **whitelist.json** - Trusted IP addresses
- **connected_devices.json** - Network device inventory
- **device_history.json** - Device connection history
- **network_monitor_state.json** - Current monitoring state
- **network_performance.json** - Performance metrics
- **peer_threats.json** (100 KB) - Shared threat intelligence
- **device_blocker.py metadata** - Blocking rules

## 🔗 API Endpoints Used by Dashboard

### Section 1-2: Introduction & AI Training
- `/api/p2p/status` - P2P network status
- `/api/models/sync` - ML model synchronization
- `/api/relay/status` - Relay server connection

### Section 3: Network Devices
- `/api/connected-devices` - Live device list
- `/api/device-history` - Connection history
- `/api/device/block` - Block a device
- `/api/device/unblock` - Unblock a device

### Section 6: Security Overview
- `/api/stats` - Security statistics
- `/api/system-status` - System health

### Section 8-9: IP Management
- `/api/unblock/<ip>` - Unblock IP address
- `/api/whitelist` - Get whitelist
- `/api/whitelist/add` - Add to whitelist

### Section 11: Live Threat Monitor
- `/api/threat_log` - Real-time threat events

### Section 13: Signature Extraction
- `/api/signatures/extracted` - Extracted attack patterns

### Section 14: System Health
- `/api/performance/metrics` - Performance data
- `/api/current-time` - Server time
- `/api/current-ports` - Port configuration

### Section 15: Compliance
- `/api/compliance/summary` - Compliance status

### Section 16: Adaptive Honeypot
- `/api/adaptive_honeypot/status` - Honeypot status
- `/api/adaptive_honeypot/personas` - Service personas
- `/api/adaptive_honeypot/configure` - Configure honeypot
- `/api/adaptive_honeypot/stop` - Stop honeypot
- `/api/adaptive_honeypot/attacks` - Honeypot attacks

### Section 17: Threat Intelligence
- `/api/visualization/all` - All visualizations

### Utility Endpoints
- `/api/update-api-key` - Update API keys
- `/api/update-timezone` - Set timezone
- `/api/update-ports` - Configure ports
- `/api/generate-env-file` - Generate .env file
- `/inspector/ai-monitoring/clear-all` - Clear all data
- `/inspector/ai-monitoring/clear-threats` - Clear threats
- `/inspector/ai-monitoring/clear-blocked-ips` - Clear blocked IPs
- `/inspector/ai-monitoring/export` - Export data

## 🔐 External Dependencies
- **Chart.js 4.4.0** - Visualization library (CDN)
- **VirusTotal API** - File/IP reputation checks
- **AbuseIPDB API** - IP abuse reports

## 🐳 Docker Integration
- **server/Dockerfile** - Container image
- **server/docker-compose.yml** - Service orchestration
- **server/requirements.txt** - Python dependencies

## 📝 Configuration Files
- **.env** - Environment variables (API keys, ports)
- **server/installation/** - Setup scripts
- **STRUCTURE.txt** - Project organization

## 🔄 Data Flow
```
User Browser
    ↓
AI/inspector_ai_monitoring.html (Frontend)
    ↓
Flask API (server/server.py)
    ↓
AI/pcs_ai.py (Threat Detection)
    ↓
AI/false_positive_filter.py (5-Gate Pipeline)
    ├─ Gate 1: Sanity & Context Filter
    ├─ Gate 2: Behavior Consistency
    ├─ Gate 3: Temporal Correlation
    ├─ Gate 4: Cross-Signal Agreement
    └─ Gate 5: Confidence Scoring (≥75%)
    ↓
✅ CONFIRMED Attacks Only
    ↓
server/json/*.json (Data Storage)
    ↓
AI/signature_extractor.py (Extract Patterns)
    ↓
AI/relay_client.py (Share Patterns)
    ↓
Relay Server → ai_training_materials/*.json
    ↓
AI Training (File-Based, No Database)
```

**Filter Rejection:** False positives are BLOCKED and never reach JSON files or AI training.

## 🛡️ Privacy Architecture
- **Local Storage:** All customer data stays in `server/json/`
- **Shared Data:** Only attack signatures (patterns, NOT payloads)
- **Database:** Future centralized storage for attack patterns only
- **Zero Exploit Storage:** All attack payloads deleted immediately
