# 🏗️ System Architecture

## Overview

**2 Docker containers total:**
1. **Central Server** (1 container) - Threat aggregation hub
2. **Client Container** (N instances) - Deployed at customer sites

---

## Architecture Diagram

```
                    INTERNET
                        │
        ────────────────┼────────────────
        │               │               │
        │               │               │
   ┌────▼─────┐   ┌────▼─────┐   ┌────▼─────┐
   │ Company A │   │ Company B │   │  Home C  │
   │ (Client)  │   │ (Client)  │   │ (Client) │
   │           │   │           │   │          │
   │ 🐳 1      │   │ 🐳 1      │   │ 🐳 1     │
   │Container  │   │Container  │   │Container │
   └─────┬─────┘   └─────┬─────┘   └─────┬────┘
         │               │               │
         │ HTTPS + API Key (Encrypted)   │
         │               │               │
         └───────────────┼───────────────┘
                         │
                    ┌────▼─────┐
                    │YOUR SERVER│
                    │ (Central) │
                    │           │
                    │ 🐳 1      │
                    │Container  │
                    └───────────┘
```

---

## Container Breakdown

### Container 1: Client (Deployed at Each Customer)

**What it does:**
- Monitors local network for attacks
- Trains AI models on local threats
- Blocks malicious IPs automatically
- **Sends** detected threats to central server (encrypted)
- **Receives** global threats from other clients
- Runs web dashboard on port 5000

**Tech stack:**
- Python 3.11 + Flask
- scikit-learn ML models
- Scapy packet capture
- ExploitDB signatures (46,948 exploits)
- VirusTotal integration

**Size:** ~2GB image, ~500MB RAM

**Deploy:**
```bash
git clone https://github.com/yourrepo/enterprise-security.git
cd enterprise-security
./setup.sh
```

---

### Container 2: Central Server (Deployed on Your Infrastructure)

**What it does:**
- Receives threats from all clients
- Aggregates and deduplicates
- Distributes global threat feed
- Manages client registrations
- Provides statistics dashboard

**Tech stack:**
- Python 3.11 + Flask
- HTTPS/TLS encryption
- API key authentication
- JSON storage (upgradable to PostgreSQL)

**Size:** ~500MB image, ~200MB RAM

**Deploy:**
```bash
cd enterprise-security/central_server
docker compose up -d
```

---

## Data Flow

### Attack Detection Flow

```
1. Attacker (1.2.3.4) → Client A
                         │
2. Client A detects port scan
                         │
3. Client A blocks 1.2.3.4 locally
                         │
4. Client A → Central Server (HTTPS)
   {
     "ip": "1.2.3.4",
     "attack_type": "port_scan",
     "severity": "high"
   }
                         │
5. Central Server stores + distributes
                         │
   ┌────────────────────┼────────────────────┐
   │                    │                    │
6. Client B         Client C            Client D
   │                    │                    │
7. All update ML models with new pattern
                         │
8. Attacker tries Client B → BLOCKED (never attacked B before!)
```

---

## Communication

### Client → Central Server

**Frequency:** Every 5 minutes (configurable)

**Endpoint:** `POST /api/v1/submit-threats`

**Payload:**
```json
{
  "threats": [
    {
      "ip": "1.2.3.4",
      "attack_type": "port_scan",
      "severity": "high",
      "timestamp": "2025-12-28T10:00:00",
      "country": "Unknown",
      "asn": "AS12345"
    }
  ]
}
```

**Authentication:** `X-API-Key: <client_api_key>`

**Encryption:** HTTPS/TLS

---

### Central Server → Client

**Frequency:** Every 5 minutes (configurable)

**Endpoint:** `GET /api/v1/get-threats?since=2025-12-28T09:55:00`

**Response:**
```json
{
  "threats": [
    {
      "ip": "5.6.7.8",
      "attack_type": "sql_injection",
      "severity": "critical",
      "client_id": "abc123",
      "received_at": "2025-12-28T09:56:30"
    }
  ],
  "total": 150,
  "global_total": 50000
}
```

---

## Privacy & Security

### What's Shared

✅ Attacker IP address  
✅ Attack type (port_scan, sql_injection, etc.)  
✅ Severity level  
✅ Timestamp  
✅ Geolocation (country, ISP)

### What's NOT Shared

❌ Internal network topology  
❌ Victim IP addresses  
❌ Application logs  
❌ User data  
❌ Business logic

### Encryption

- **In Transit:** HTTPS/TLS 1.3
- **At Rest:** File permissions (chmod 600)
- **Authentication:** 32-byte API keys per client

---

## Scaling Numbers

### Current Capacity (JSON Storage)

| Metric | Capacity |
|--------|----------|
| Clients | 1,000+ |
| Threats/day | 100,000 |
| Sync latency | <5 minutes |
| Storage | ~10GB/year |

### With PostgreSQL (Future)

| Metric | Capacity |
|--------|----------|
| Clients | 100,000+ |
| Threats/day | 10,000,000 |
| Sync latency | <30 seconds |
| Storage | PostgreSQL managed |

---

## Deployment Scenarios

### Scenario 1: Startup (1-10 Customers)

```
1 Central Server (Your VPS)
  ↓
10 Clients (Customer sites)
```

**Cost:** $10/month VPS + $0/client (they host their own)

---

### Scenario 2: Growing Business (100 Customers)

```
1 Central Server (Dedicated server)
  ↓
100 Clients (Customer sites)
```

**Cost:** $50/month dedicated + $0/client

**Revenue:** 100 × $99/month = $9,900/month

---

### Scenario 3: Enterprise (10,000 Customers)

```
3 Central Servers (Load balanced)
  ↓
10,000 Clients (Customer sites)
```

**Cost:** $500/month infrastructure + PostgreSQL

**Revenue:** 10,000 × $99/month = $990,000/month

---

## Operational Simplicity

### For YOU (Service Provider)

**Deploy once:**
```bash
cd central_server
docker compose up -d
```

**Monitor:**
```bash
docker compose logs -f
```

**Backup:**
```bash
tar -czf backup.tar.gz central_server/data/
```

**That's it.** No complex orchestration, no Kubernetes, no microservices hell.

---

### For CUSTOMERS

**Deploy once:**
```bash
git clone <your-repo>
./setup.sh
```

**Configure:**
- Add VirusTotal API key
- Add central server URL + API key
- Restart

**Forget about it.** Container runs forever, auto-updates ML models.

---

## Why This is Better Than 11 Containers

| Feature | 11 Containers | 2 Containers |
|---------|---------------|--------------|
| Complexity | Very High | Very Low |
| Deploy time | 30+ minutes | 2 minutes |
| RAM usage | 4GB+ | 700MB |
| Network setup | Complex mesh | Simple client-server |
| Debugging | Nightmare | `docker logs` |
| Scaling | Orchestrator needed | Just run more |
| Customer adoption | 0% | High |

---

## Summary

**You run:** 1 central server container  
**Customers run:** 1 client container each  
**Total:** 2 container types, N+1 instances  
**Communication:** Encrypted HTTPS with API keys  
**Result:** Global threat network where everyone learns from everyone

**Simple. Scalable. Secure.**
