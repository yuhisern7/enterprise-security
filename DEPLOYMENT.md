# DEPLOYMENT ARCHITECTURE

## FOLDER STRUCTURE & DEPLOYMENT

### 🔒 RELAY FOLDER (YOUR PRIVATE SERVER - NOT FOR CUSTOMERS)
```
/relay/
├── docker-compose.yml  ← Uses relay/.env
├── .env                ← Relay server configuration
├── Dockerfile
└── ai_training_materials/  ← 825MB training data
```

**Build command (on your VPS/central server):**
```bash
cd relay
docker compose up -d
```

**Services:**
- Port 60001: WebSocket relay (P2P mesh hub)
- Port 60002: Model distribution API
- Port 5432: PostgreSQL (attack signatures)

**Environment:** Uses `relay/.env`

---

### 📦 SERVER FOLDER (CUSTOMER DEPLOYMENT)
```
/server/
├── docker-compose.yml  ← Uses server/.env
├── .env                ← Customer dashboard configuration
├── Dockerfile
└── json/               ← Local threat logs
```

**Build command (given to customers):**
```bash
cd server
docker compose up -d
```

**Services:**
- Port 60000: HTTPS Dashboard (Flask)

**Environment:** Uses `server/.env`

**Customers get:**
- ✅ `/server/` folder
- ✅ `/AI/` folder (detection modules)
- ❌ `/relay/` folder (NOT provided - your private training infrastructure)

---

## ENVIRONMENT FILES

### relay/.env (Private - Your Server Only)
```env
RELAY_PORT=60001        # WebSocket P2P mesh
API_PORT=60002          # Model distribution
DB_PASSWORD=...         # PostgreSQL password
CRYPTO_ENABLED=true     # Message verification
```

### server/.env (Customer Deployment)
```env
DASHBOARD_PORT=60000    # HTTPS dashboard
RELAY_URL=wss://your-vps:60001  # Connect to YOUR relay
RELAY_ENABLED=true      # Enable P2P mesh
VIRUSTOTAL_API_KEY=...  # Customer's own API key
```

---

## BUILD PROCESS

### Your Central Server (VPS):
```bash
cd /path/to/enterprise-security/relay
docker compose build
docker compose up -d
```

### Customer Deployment:
```bash
# Customer only gets server/ and AI/ folders
cd /path/to/enterprise-security/server
docker compose build
docker compose up -d
```

---

## VERIFICATION

### Check Relay Server (Your VPS):
```bash
# Port 60001 (WebSocket relay)
netstat -tuln | grep 60001

# Port 60002 (Model API)
netstat -tuln | grep 60002

# Check logs
docker logs security-relay-server --tail=50
```

### Check Customer Dashboard:
```bash
# Port 60000 (Dashboard)
netstat -tuln | grep 60000

# Check logs
docker logs enterprise-security-ai --tail=50

# Test dashboard
curl -k https://localhost:60000
```

---

## DATA FLOW

```
┌─────────────────────────────────────┐
│  YOUR RELAY SERVER (VPS)            │
│  relay/                             │
│  ├─ Port 60001: WebSocket P2P       │
│  ├─ Port 60002: Model distribution  │
│  └─ ai_training_materials/ (825MB)  │
└─────────────────────────────────────┘
           ▲                ▼
           │ WebSocket      │ HTTPS
           │ (signed msgs)  │ (models)
           │                │
┌──────────┴────────────────┴─────────┐
│  CUSTOMER DEPLOYMENT                │
│  server/ + AI/                      │
│  ├─ Port 60000: Dashboard           │
│  ├─ AI/ml_models/ (downloaded)      │
│  └─ Connects to relay via WS        │
└─────────────────────────────────────┘
```

---

## IMPORTANT RULES

1. ✅ **relay/.env** controls relay server ports and settings
2. ✅ **server/.env** controls customer dashboard and connection to relay
3. ❌ Customers NEVER get the `/relay/` folder
4. ✅ Each docker-compose.yml uses its own local .env file
5. ✅ Build context is `..` but .env is always local to the folder
