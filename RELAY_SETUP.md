# Battle-Hardened AI - Relay Server Setup Guide

## Centralized AI Training for All Customers

This guide sets up a relay server so ALL customers learn from the SAME AI models.

---

## Architecture

```
Customer A (Japan)  ─┐
Customer B (USA)    ─┼─→  Relay Server (Your VPS)  ←─ ExploitDB (43,971 exploits)
Customer C (Europe) ─┘         │
                               ↓
                     Centralized AI Models
                     (Everyone downloads same models)
```

**Result:** Customer subscribing on Day 1 = same intelligence as customer subscribing 1 year later

---

## Step 1: Deploy Relay Server (One-Time Setup)

### Prerequisites:
- VPS or cloud server (Ubuntu/Debian recommended)
- Public IP address
- Ports 60001 (WebSocket) and 60002 (API) open

### Installation:

```bash
# SSH into your VPS
ssh root@your-vps-ip

# Clone repository
git clone https://github.com/yourusername/battle-hardened-ai.git
cd battle-hardened-ai/relay

# Start relay server
docker compose up -d

# Monitor ExploitDB download (takes 5-10 minutes)
docker compose logs -f | grep "ExploitDB"

# Should see:
# [EXPLOITDB] Downloading 43,971 exploits...
# [EXPLOITDB] ✅ Downloaded 43,971 exploits (825 MB)
# [RELAY] Ready to serve models
```

### Verify Relay is Running:

```bash
# Check status
docker compose ps

# Should show:
# NAME                  STATUS
# relay-server          Up 5 minutes
# training-api          Up 5 minutes

# Test API
curl -k https://your-vps-ip:60002/health

# Should return:
# {"status": "healthy", "exploits": 43971}
```

---

## Step 2: Configure Customer Machines

### Option A: Environment Variables (Recommended)

Create `.env` file in `server/` directory on each customer machine:

```bash
# server/.env
RELAY_ENABLED=true
RELAY_URL=wss://YOUR_VPS_IP:60001
RELAY_API_URL=https://YOUR_VPS_IP:60002
CUSTOMER_ID=customer-unique-id-here
PEER_NAME=customer-location-name
```

### Option B: Edit docker-compose.yml

```yaml
environment:
  - RELAY_ENABLED=true
  - RELAY_URL=wss://YOUR_VPS_IP:60001
  - RELAY_API_URL=https://YOUR_VPS_IP:60002
  - CUSTOMER_ID=customer-123
  - PEER_NAME=japan-office
```

### Deploy on Customer Machine:

```bash
cd server/
docker compose build --no-cache
docker compose up -d
```

---

## Step 3: Verify Centralized Training

### Check Customer Logs:

```bash
docker compose logs --tail=100 | grep "AI\|RELAY"

# SUCCESS indicators:
# [AI] 🌐 Requesting training from relay server (43,971 ExploitDB exploits)...
# [AI] ✅ Relay trained models using 43971 exploits
# [AI] 📥 Downloading trained models from relay...
# [AI] ✅ Downloaded anomaly detector (280 KB)
# [AI] ✅ Downloaded threat classifier (280 KB)
# [AI] ✅ Downloaded IP reputation model (280 KB)

# FAILURE indicators (means relay not configured):
# [AI] ⚠️  Relay training failed, falling back to local training
# [AI] 🎓 AUTO-TRAINING locally with 100 historical threat events...
```

### Check Model Files:

```bash
# On customer machine
docker compose exec battle-hardened-ai ls -lh /app/ml_models/

# Should show models downloaded from relay:
# -rw-r--r-- 1 root root 280K Jan 9 12:34 anomaly_detector.pkl
# -rw-r--r-- 1 root root 280K Jan 9 12:34 threat_classifier.pkl
# -rw-r--r-- 1 root root 280K Jan 9 12:34 ip_reputation.pkl
```

---

## How It Works

### Day 1: Customer A Subscribes

```
1. Customer A starts container
2. Checks: No local models exist
3. Calls: RELAY_API_URL/train
4. Relay trains models using 43,971 ExploitDB exploits (3-5 min)
5. Customer downloads 3 model files (280 KB each)
6. Customer A AI now knows 43,971 attack patterns ✅
```

### Day 30: Customer A Gets Attacked 1,000 Times

```
1. Attacks detected and logged locally
2. Attack signatures sent to relay via WebSocket
3. Relay adds to global database: 43,971 + 1,000 = 44,971
4. Relay retrains models overnight
5. Next time ANY customer requests training, they get 44,971 patterns
```

### Month 3: Customer B Subscribes

```
1. Customer B starts container
2. Checks: No local models exist
3. Calls: RELAY_API_URL/train
4. Relay already has 44,971 patterns (includes Customer A's experience!)
5. Customer B downloads models
6. Customer B AI now knows 44,971 patterns ✅ (INSTANT EXPERT!)
```

### Year 1: Customer C Subscribes

```
1. Customer C starts container
2. Relay now has 43,971 + 100,000 real-world attacks
3. Customer C downloads models trained on EVERYTHING
4. Customer C AI knows 143,971 patterns ✅ (BEST PROTECTION!)
```

---

## Testing the Setup

### Test 1: Verify Relay Connection

```bash
# On customer machine
docker compose logs | grep "Relay connected"

# Should see:
# [RELAY] ✅ Connected to relay server wss://your-vps-ip:60001
# [RELAY] Registered as: customer-123
```

### Test 2: Force Retrain

```bash
# On customer machine - trigger manual training request
curl -k -X POST https://localhost:60000/inspector/ai-monitoring/retrain-ml

# Check logs
docker compose logs --tail=20 | grep "RELAY"

# Should see relay training activity
```

### Test 3: Check Dashboard

Open: `https://localhost:60000`

**Section 4 - ML Model Stats:**
- Training Data Size: Should show 43,971+ (not 100-1000)
- Last Trained: Recent timestamp
- Models Status: All showing "TRAINED ✅"

---

## Troubleshooting

### Issue: "Relay training failed, falling back to local"

**Cause:** Can't connect to RELAY_API_URL

**Fix:**
```bash
# Test connection from customer machine
curl -k https://YOUR_VPS_IP:60002/health

# If fails, check:
# 1. VPS firewall allows port 60002
# 2. Docker container is running on VPS
# 3. RELAY_API_URL is correct in .env
```

### Issue: Training Data Shows 100-1000 (not 43,971)

**Cause:** Using local training, not relay

**Fix:**
```bash
# Check environment variables
docker compose exec battle-hardened-ai env | grep RELAY

# Should show:
# RELAY_ENABLED=true
# RELAY_API_URL=https://your-vps-ip:60002

# If empty, update .env and restart
docker compose down
docker compose up -d
```

### Issue: Models Not Updating

**Cause:** Relay server needs to retrain

**Fix:**
```bash
# On relay server VPS
cd relay/
docker compose exec training-api python -c "from ai_retraining import trigger_retrain; trigger_retrain()"

# Check logs
docker compose logs --tail=50 | grep "TRAIN"
```

---

## Scaling

### Single Relay (100-1,000 customers)
- 1 VPS with 4 CPU, 8 GB RAM
- Handles ~1,000 concurrent connections
- Cost: ~$20-40/month

### Multi-Region Relay (1,000-10,000 customers)
- Deploy relay servers in 3 regions (US, EU, Asia)
- Use DNS round-robin or GeoDNS
- Each relay syncs with others

### Enterprise (10,000+ customers)
- Load balancer in front of relay cluster
- Redis for WebSocket session management
- Dedicated training server (GPU-accelerated)

---

## Security

**Relay Server:**
- ✅ HTTPS (TLS encryption)
- ✅ WebSocket Secure (WSS)
- ✅ IP whitelisting (optional)
- ✅ Rate limiting on API
- ✅ No customer PII stored (only attack patterns)

**Customer Data:**
- ✅ Local threat_log.json stays on customer machine (FULL data)
- ✅ Only sanitized signatures sent to relay (NO IPs, NO payloads)
- ✅ Models are mathematical weights (no raw data)

---

## Monitoring

### Relay Server Metrics:

```bash
# On relay VPS
docker compose logs --tail=100 | grep "STATS"

# Should show:
# [STATS] Connected customers: 150
# [STATS] Total attacks in database: 234,567
# [STATS] Models last trained: 2026-01-09 12:34:56
# [STATS] WebSocket messages/sec: 45
```

### Customer Dashboard:

Open: `https://localhost:60000`

**Section 31 - Relay Status:**
- Connection: ✅ Connected
- Last Sync: < 1 second ago
- Shared Attacks: 234,567 patterns
- Model Version: v1.2.3 (2026-01-09)

---

## Summary

**Without Relay (Current Default):**
- Customer A: 100 attacks → AI knows 100 patterns
- Customer B: 200 attacks → AI knows 200 patterns
- Customer C: 50 attacks → AI knows 50 patterns
- **Result:** INCONSISTENT protection ❌

**With Relay (Configured):**
- Customer A: Downloads 43,971 patterns on Day 1
- Customer B: Downloads 43,971+ patterns on Month 3
- Customer C: Downloads 100,000+ patterns on Year 1
- **Result:** EVERYONE protected equally (or better) ✅

**Setup Time:**
- Relay server: 15 minutes
- Each customer: 2 minutes
- **Total:** 17 minutes for unlimited customers

**Your customers get instant expert-level AI protection from day one.**
