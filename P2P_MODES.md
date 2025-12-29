# P2P Modes Comparison - Choose Your Architecture

## 🎯 Quick Decision Guide

**Are all your containers on the SAME WiFi network?**
- ✅ YES → Use **Direct P2P** (Mode 1) - Free, zero setup
- ❌ NO → Use **Relay Server** (Mode 2) - $5/month, works everywhere

---

## Mode 1: Direct P2P (Same Network Only)

### Configuration
```bash
# server/.env
P2P_SYNC_ENABLED=true
PEER_URLS=https://192.168.0.119:60001,https://192.168.0.101:60001
RELAY_ENABLED=false
```

### Architecture
```
Container A (192.168.0.119) ←──────────→ Container B (192.168.0.101)
                           Direct HTTPS
```

### ✅ Pros
- **FREE** - No VPS required
- **Low latency** - Direct connection (~5-10ms)
- **Simple** - Just set peer IPs
- **Private** - No third-party relay

### ❌ Cons
- **Same network ONLY** - Must be on same WiFi/LAN
- **Port forwarding required** if on different networks
- **Limited peers** - Managing many direct connections gets complex
- **Firewall issues** - Corporate firewalls block incoming connections

### 💡 Best For
- Home/Office with 2-5 containers on same network
- Lab/Testing environments
- No budget constraints
- Full network control

---

## Mode 2: Relay Server (Global Mesh)

### Configuration
```bash
# server/.env (on all containers)
RELAY_ENABLED=true
RELAY_URL=wss://relay.yourdomain.com:60001
P2P_SYNC_ENABLED=false

# relay/.env (on VPS)
RELAY_HOST=0.0.0.0
RELAY_PORT=60001
```

### Architecture
```
Container 1 (Tokyo)     ──┐
Container 2 (London)    ──┤
Container 3 (NYC)       ──┼──→  Relay Server (VPS)
Container 4 (Sydney)    ──┤     wss://relay:60001
Container 1000 (Mumbai) ──┘
```

### ✅ Pros
- **Unlimited containers** worldwide
- **No port forwarding** - Outbound connections only
- **Firewall-friendly** - Works behind corporate firewalls
- **Scalable** - 1000+ containers on $5 VPS
- **Enterprise-ready** - Centralized management

### ❌ Cons
- **Cost** - $5-6/month VPS
- **Single point** - Relay down = no sync (mitigate with redundancy)
- **Latency** - +50-150ms vs direct P2P
- **VPS management** - Need to maintain relay server

### 💡 Best For
- Multiple offices/locations
- Remote workers
- Corporate environments (firewall-friendly)
- 10+ containers
- Different networks (home + office + cloud)
- MSP/multi-tenant deployments

---

## Mode 3: Hybrid (Advanced)

### Configuration
```bash
# Local containers use direct P2P
P2P_SYNC_ENABLED=true
PEER_URLS=https://192.168.0.101:60001

# AND relay for remote containers
RELAY_ENABLED=true
RELAY_URL=wss://relay.yourdomain.com:60001
```

### Architecture
```
Local Cluster A:
  Container 1 ←─→ Container 2 (Direct P2P)
          ↓
       Relay Server
          ↓
Local Cluster B:
  Container 3 ←─→ Container 4 (Direct P2P)
```

### ✅ Pros
- **Best of both worlds** - Local speed + global reach
- **Redundancy** - Multiple sync methods
- **Flexible** - Adapt to network changes

### ❌ Cons
- **Complex** - More configuration
- **Duplicate messages** - Some threats sent twice

### 💡 Best For
- Large deployments (100+ containers)
- Multiple data centers
- High availability requirements

---

## 📊 Feature Comparison Table

| Feature | Direct P2P | Relay Server | Hybrid |
|---------|-----------|--------------|--------|
| **Cost** | $0 | $5-6/month | $5-6/month |
| **Setup Time** | 2 minutes | 5 minutes | 10 minutes |
| **Max Containers** | 2-10 | 1000+ | Unlimited |
| **Latency** | 5-10ms | 50-150ms | 5-150ms |
| **Same Network** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Different Networks** | ⚠️ Port forwarding | ✅ Yes | ✅ Yes |
| **Behind Firewall** | ❌ No | ✅ Yes | ✅ Yes |
| **Behind CGNAT** | ❌ No | ✅ Yes | ✅ Yes |
| **Port Forwarding** | ⚠️ Required | ✅ Not needed | ✅ Not needed |
| **Single Point of Failure** | ❌ No | ⚠️ Yes | ⚠️ Relay only |
| **Bandwidth** | Low | Medium | Medium |
| **Management** | Easy | VPS admin | Complex |

---

## 🔄 Switching Between Modes

### Direct P2P → Relay Server

```bash
# 1. Deploy relay server (see RELAY_SETUP.md)
ssh root@YOUR-VPS
cd relay && docker compose up -d

# 2. Update all containers
nano server/.env

# Change:
P2P_SYNC_ENABLED=false  # Disable direct P2P
RELAY_ENABLED=true       # Enable relay
RELAY_URL=wss://YOUR-VPS-IP:60001

# 3. Restart
docker compose down && docker compose up -d
```

### Relay Server → Direct P2P

```bash
# Edit server/.env
P2P_SYNC_ENABLED=true
PEER_URLS=https://192.168.0.101:60001,https://192.168.0.119:60001
RELAY_ENABLED=false

# Restart
docker compose down && docker compose up -d
```

---

## 💰 Cost Breakdown

### Direct P2P
- VPS: **$0**
- Total: **$0/month**
- Max containers: 2-10 (same network)

### Relay Server
- VPS (DigitalOcean/Linode): **$5-6/month**
- Handles: **1000+ containers**
- Per-container cost: **$0.005/month** (if using 1000)

### Example: 50 Containers
- Direct P2P: Impossible on different networks
- Relay Server: **$6/month** ($0.12 per container)

---

## 🎯 Recommended Configurations

### Home Lab (2-3 containers)
```bash
Mode: Direct P2P
Cost: $0
Setup: 2 minutes
```

### Small Office (5-10 containers)
```bash
Mode: Direct P2P (same network) OR Relay (different networks)
Cost: $0 or $6/month
Setup: 2-5 minutes
```

### Multi-Location Office (10-50 containers)
```bash
Mode: Relay Server
Cost: $6/month
Setup: 5 minutes
Reason: Firewall-friendly, no port forwarding
```

### Enterprise/MSP (100+ containers)
```bash
Mode: Hybrid (Direct + Relay)
Cost: $12/month (2 relay servers for redundancy)
Setup: 30 minutes
Reason: High availability, global distribution
```

---

## 🚀 Quick Start Commands

### Check Current Mode

```bash
# View configuration
cat server/.env | grep -E "P2P_SYNC_ENABLED|RELAY_ENABLED"

# View logs
docker logs enterprise-security-server | grep -E "P2P|RELAY"
```

### Test Relay Connection

```bash
# From any container
telnet YOUR-VPS-IP 60001

# Or with websocket
python3 -c "import websockets; import asyncio; asyncio.run(websockets.connect('ws://YOUR-VPS-IP:60001'))"
```

### Monitor Sync Status

```bash
# Dashboard API
curl http://localhost:60000/api/p2p/status | jq

# Expected:
# {
#   "relay_enabled": true,
#   "connected": true,
#   "active_peers": 27,
#   "threats_sent": 142,
#   "threats_received": 89
# }
```

---

## 📚 Additional Resources

- **Relay Setup Guide:** [RELAY_SETUP.md](RELAY_SETUP.md)
- **Quick Start:** [QUICKSTART.md](QUICKSTART.md)
- **Main README:** [README.md](README.md)

---

**Need help choosing? Ask yourself:**
1. Are containers on the same network? → **Direct P2P**
2. Different networks with budget? → **Relay Server**
3. Enterprise with 100+ containers? → **Hybrid**
