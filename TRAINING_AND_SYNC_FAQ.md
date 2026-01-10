# Battle-Hardened AI - Training & Sync FAQ

## Issue 1: Training Data Shows 0 on Kali, 1000 on Windows

**Root Cause:** Fresh Kali installation has no threat_log.json yet (created on first attack)

**Windows has 1000 because:** You've been testing attacks on Windows, populating threat_log.json

**Solution:** 
- Attack your Kali server to populate threat_log.json
- Or manually copy threat_log.json from Windows to Kali

```bash
# On Kali - after rebuilding with request interceptor fix
curl -k "https://localhost:60000/test?id=1'%20OR%20'1'='1"
curl -k "https://localhost:60000/test?name=<script>alert(1)</script>"
# Repeat 10-20 times to build training data
```

---

## Issue 2: How to Verify Relay Server Training

**Current Status:** RELAY_ENABLED=true but RELAY_API_URL is EMPTY

**To enable relay training:**

```bash
# Edit server/.env file
RELAY_ENABLED=true
RELAY_API_URL=https://your-relay-server-ip:60002
RELAY_URL=wss://your-relay-server-ip:60001

# Or in docker-compose.yml
environment:
  - RELAY_ENABLED=true
  - RELAY_API_URL=https://relay:60002  # If relay in same docker network
```

**Verification - Check Container Logs:**

```bash
docker compose logs --tail=100 | grep -i "relay\|train"

# Should see:
# [AI] 🌐 Requesting training from relay server (43,971 ExploitDB exploits)...
# [AI] ✅ Relay trained models using 43971 exploits
# [AI] 📥 Downloading trained models from relay...
# [AI] ✅ Downloaded anomaly detector
```

**Without relay server:**
```bash
# Falls back to local training
# [AI] ⚠️  Relay training failed, falling back to local training
# [AI] 🎓 AUTO-TRAINING locally with 1000 historical threat events...
```

---

## Issue 3: Training Schedule

**Auto-Retrain Frequency** (based on threat_log size):

1. **< 1,000 threats:** Every **6 hours** (rapid learning phase)
2. **1,000 - 5,000 threats:** Every **12 hours** (stabilization)
3. **> 5,000 threats:** Every **24 hours** (mature model)

**Code Location:** AI/pcs_ai.py lines 1590-1612

**Manual Trigger:**
- Dashboard Section 4 → "Force Retrain" button
- Immediately retrains regardless of schedule

---

## Issue 4: Worldwide Attack Sync Speed

**P2P Mesh Network Sync:**

**Real-time (< 1 second):**
- Attack detected → Immediately sent to WebSocket relay
- Relay broadcasts to all connected peers
- Peers receive and log attack (added to their threat_log.json)

**Training Propagation:**
- New attack logged → Triggers retrain on next schedule (6-24 hours)
- Or relay server retrains → Clients download updated models (5 min timeout)

**Verification:**

```bash
# Check P2P status
docker compose logs | grep "P2P"

# Should see:
# [P2P] Connected to 2 peer containers
# [P2P] When A gets attacked, B and C learn automatically 🌐
# [RELAY] 📥 Received threat from peer-node-2: SQL Injection - IP: 1.2.3.4
```

**Network Flow:**
```
Customer A attacked (China)
  ↓ WebSocket (< 1 sec)
Relay Server receives
  ↓ Broadcast (< 1 sec)
Customer B receives (USA)
Customer C receives (Europe)
  ↓ Log to threat_log.json
  ↓ Next retrain cycle (6-24 hrs)
ML models updated with new pattern
```

---

## Issue 5: Force Retrain Button Not Working

**Status:** ✅ Endpoint exists but needs testing

**Endpoint:** `/inspector/ai-monitoring/retrain-ml` (POST)

**Test manually:**

```bash
# From Kali
curl -k -X POST https://localhost:60000/inspector/ai-monitoring/retrain-ml

# Expected response:
{
  "success": true,
  "training_samples": 1000,
  "trained_at": "2026-01-09T12:34:56",
  "models_trained": ["anomaly_detector", "threat_classifier", "ip_reputation"]
}
```

**If button doesn't work:**
1. Check browser console (F12) for JavaScript errors
2. Verify button is calling `forceRetrain()` function
3. Check CORS/network errors

---

## Quick Setup for Full Relay Training

**1. Start Relay Server:**

```bash
cd relay/
docker compose up -d

# Wait for ExploitDB download (43,971 exploits)
docker compose logs -f | grep "ExploitDB"
```

**2. Configure Client (Kali/Windows):**

```bash
cd server/

# Create .env file
cat > .env << EOF
RELAY_ENABLED=true
RELAY_URL=wss://YOUR_VPS_IP:60001
RELAY_API_URL=https://YOUR_VPS_IP:60002
EOF

# Rebuild
docker compose build --no-cache
docker compose up -d
```

**3. Verify Training:**

```bash
# Check if models downloaded from relay
docker compose exec battle-hardened-ai ls -lh /app/ml_models/

# Should see:
# anomaly_detector.pkl (280 KB from relay)
# threat_classifier.pkl (280 KB from relay)
# ip_reputation.pkl (280 KB from relay)
```

**4. Force Retrain Test:**

```bash
# From browser: Click "Force Retrain" button
# Or via curl:
curl -k -X POST https://localhost:60000/inspector/ai-monitoring/retrain-ml

# Check logs
docker compose logs --tail=20 | grep "TRAIN\|ML"
```

---

## Summary

**Current State:**
- ✅ Relay enabled in docker-compose.yml
- ❌ RELAY_API_URL is empty (not configured)
- ❌ Kali has 0 training data (no attacks logged yet)
- ✅ Auto-retrain: 6-24 hours based on data size
- ✅ P2P sync: < 1 second worldwide
- ✅ Force retrain button endpoint exists

**To Fix:**
1. Configure RELAY_API_URL environment variable
2. Attack Kali server to populate threat_log.json
3. Test force retrain button
4. Verify relay connection in logs
