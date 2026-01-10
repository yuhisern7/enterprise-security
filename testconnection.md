# Relay Connection Troubleshooting Guide

## 🚀 Quick Connection Test (Run This First)

### Windows
```powershell
# Test relay connection
Invoke-RestMethod -Uri "https://localhost:60000/api/relay/status" -SkipCertificateCheck | ConvertTo-Json

# Expected: "connected": true
```

### Linux (Kali/Ubuntu)
```bash
# Test relay connection
curl -k https://localhost:60000/api/relay/status | jq

# Expected: "connected": true
```

---

## ⚠️ If NOT Connected - Run This

### Step 1: Check Client Logs
```bash
# Linux
sudo docker logs battle-hardened-ai 2>&1 | grep RELAY | tail -20

# Windows
docker logs battle-hardened-ai | Select-String "RELAY" | Select-Object -Last 20
```

**Look for:**
- ✅ `[RELAY] ✅ Connected to relay server` = SUCCESS
- ❌ `[Errno 111] Connect call failed` = Firewall blocking
- ❌ `⏳ Connection in progress...` = Still connecting (wait 30s)

---

### Step 2: Test VPS Connectivity
```bash
# Test if port is reachable
telnet 165.22.108.8 60001

# Windows alternative:
Test-NetConnection -ComputerName 165.22.108.8 -Port 60001
```

**Expected:** Connection should succeed  
**If FAILED:** Firewall issue (see firewall fix below)

---

## 🔧 Firewall Fix

### Linux (Kali/Ubuntu)
```bash
# Allow outbound to VPS
sudo ufw allow out to 165.22.108.8 port 60001 proto tcp
sudo ufw reload

# Restart container
cd ~/Downloads/battle-hardened-ai/server
sudo docker compose restart
```

### Windows (Run PowerShell as Administrator)
```powershell
# Allow outbound to VPS
New-NetFirewallRule -DisplayName "Battle-Hardened AI Relay" `
    -Direction Outbound `
    -RemoteAddress 165.22.108.8 `
    -RemotePort 60001 `
    -Protocol TCP `
    -Action Allow

# Restart container
cd server
docker compose restart
```

---

## 🖥️ VPS Relay Server Diagnostics (Most Important)

### ⚠️ CRITICAL: Deploy Latest Relay Server Code

**If clients can't connect, first deploy the FIXED relay server code:**

```bash
# From Windows PowerShell (transfer fixed code to VPS)
scp relay\relay_server.py root@165.22.108.8:~/battle-hardened-ai/relay/

# Restart relay server on VPS
ssh root@165.22.108.8 "cd battle-hardened-ai/relay && docker compose restart"

# Wait 10 seconds
Start-Sleep -Seconds 10

# Verify relay is running
ssh root@165.22.108.8 "docker logs security-relay-server --tail 20"
```

---

### Test 1: Check VPS Relay Server Status
```bash
ssh root@165.22.108.8

# Check if relay container is running
docker ps | grep relay

# Expected: security-relay-server container status "Up"
```

---

### Test 2: Check Active Connections on VPS
```bash
ssh root@165.22.108.8

# View recent connections
docker logs security-relay-server --tail 50 | grep "connected"

# Look for:
# ✅ New container connected: 118.100.245.156:58352 (Total: 1)
# ✅ New container connected: 192.168.0.119:42156 (Total: 2)
```

---

### Test 3: Real-Time Connection Monitoring
```bash
ssh root@165.22.108.8

# Watch connections in real-time
docker logs security-relay-server --follow

# Press Ctrl+C to stop
```

---

### Test 4: Check WebSocket Port on VPS
```bash
ssh root@165.22.108.8

# Verify port 60001 is listening
netstat -tlnp | grep 60001

# Expected: tcp 0 0 0.0.0.0:60001 0.0.0.0:* LISTEN
```

---

### Test 5: Test WebSocket from VPS Itself
```bash
ssh root@165.22.108.8

# Test WebSocket handshake
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  http://localhost:60001

# Should return: HTTP/1.1 101 Switching Protocols
```

---

### Test 6: Check VPS Firewall
```bash
ssh root@165.22.108.8

# Check if ports are allowed
ufw status | grep 60001

# If NOT shown, add firewall rules:
sudo ufw allow 60001/tcp
sudo ufw allow 60002/tcp
sudo ufw reload
```

---

### 🚀 Quick VPS Fix (Complete Restart)

```bash
# Run this command from Windows/Linux to restart everything on VPS
ssh root@165.22.108.8 << 'ENDSSH'
cd ~/battle-hardened-ai/relay
docker compose down
docker compose up -d
sleep 5
docker logs security-relay-server --tail 30
echo "=== Relay Status ==="
docker ps | grep relay
netstat -tlnp | grep 60001
ENDSSH
```

---

### Issue 3: Wrong RELAY_URL or Missing Crypto Keys

**Symptoms:**
- Container shows `RELAY_URL not set`
- SSL/TLS errors in logs

**Solution:**
```bash
# Check .env file has correct values
cat server/.env | grep RELAY

# Should show:
# RELAY_ENABLED=true
# RELAY_URL=wss://165.22.108.8:60001

# Verify crypto key exists
ls -lh server/crypto_keys/shared_secret.key
```

---

## � Test HMAC Cryptographic Authentication

### Step 1: Verify Shared Secret Exists

**On Windows Client:**
```powershell
# Check if crypto key exists
Get-Item server\crypto_keys\shared_secret.key

# View key size (should be 32 bytes)
(Get-Item server\crypto_keys\shared_secret.key).Length
```

**On Kali Client:**
```bash
# Check if crypto key exists
ls -lh ~/Downloads/battle-hardened-ai/server/crypto_keys/shared_secret.key

# View key size (should be 32 bytes)
wc -c ~/Downloads/battle-hardened-ai/server/crypto_keys/shared_secret.key
```

**On VPS Relay Server:**
```bash
ssh root@165.22.108.8

# Check if crypto key exists
ls -lh ~/battle-hardened-ai/relay/crypto_keys/shared_secret.key

# View key size (should be 32 bytes)
wc -c ~/battle-hardened-ai/relay/crypto_keys/shared_secret.key
```

---

### Step 2: Test HMAC Signature in Logs

**On Windows Client:**
```powershell
# Check for HMAC-related log messages
docker logs battle-hardened-ai 2>&1 | Select-String "HMAC|signature|crypto" | Select-Object -Last 20
```

**On Kali Client:**
```bash
# Check for HMAC-related log messages
sudo docker logs battle-hardened-ai 2>&1 | grep -i "hmac\|signature\|crypto" | tail -20
```

**Expected:**
- `✅ HMAC signature verified` = HMAC working
- `❌ HMAC verification failed` = Key mismatch
- `⚠️ RELAY_CRYPTO_ENABLED=false` = Crypto disabled

---

### Step 3: Send Test Threat with HMAC

**Windows:**
```powershell
# Send test threat alert (will be HMAC-signed)
docker exec battle-hardened-ai python3 -c "
from AI.relay_client import relay_client
import asyncio

async def test():
    if relay_client and relay_client.connected:
        await relay_client.send_threat({
            'type': 'test_alert',
            'source_ip': '192.0.2.1',
            'attack_type': 'HMAC_CONNECTION_TEST',
            'timestamp': '2026-01-10T00:00:00Z',
            'severity': 'info'
        })
        print('✅ Test threat sent with HMAC signature')
    else:
        print('❌ Not connected to relay')

asyncio.run(test())
"
```

**Kali:**
```bash
# Send test threat alert (will be HMAC-signed)
sudo docker exec battle-hardened-ai python3 -c "
from AI.relay_client import relay_client
import asyncio

async def test():
    if relay_client and relay_client.connected:
        await relay_client.send_threat({
            'type': 'test_alert',
            'source_ip': '192.0.2.1',
            'attack_type': 'HMAC_CONNECTION_TEST',
            'timestamp': '2026-01-10T00:00:00Z',
            'severity': 'info'
        })
        print('✅ Test threat sent with HMAC signature')
    else:
        print('❌ Not connected to relay')

asyncio.run(test())
"
```

---

### Step 4: Verify HMAC on VPS

**Check VPS Logs for HMAC Verification:**
```bash
ssh root@165.22.108.8

# Watch for incoming threat with HMAC verification
docker logs security-relay-server --follow | grep -i "threat\|hmac\|signature"

# You should see:
# ✅ HMAC signature verified
# 📊 Threat shared: HMAC_CONNECTION_TEST
```

---

### Step 5: Check HMAC Statistics

**VPS Relay Server:**
```bash
ssh root@165.22.108.8

# Check message/threat counters
docker logs security-relay-server --tail 100 | grep "📊 Stats"

# Should show:
# Active: 2, Messages: X, Threats: X (X should increase after test)
```

**Windows Client:**
```powershell
# Check relay statistics
Invoke-RestMethod -Uri "https://localhost:60000/api/relay/status" -SkipCertificateCheck | ConvertTo-Json

# Look for:
# "threats_sent": X (should increase after sending test)
```

---

### Common HMAC Issues

**Issue: HMAC verification failed**
```
Solution: Keys don't match between client and VPS
1. Compare key hashes:
   # Windows
   Get-FileHash server\crypto_keys\shared_secret.key
   
   # VPS
   sha256sum ~/battle-hardened-ai/relay/crypto_keys/shared_secret.key

2. If different, copy Windows key to VPS:
   scp server\crypto_keys\shared_secret.key root@165.22.108.8:~/battle-hardened-ai/relay/crypto_keys/
```

**Issue: No HMAC logs appear**
```
Solution: RELAY_CRYPTO_ENABLED might be false
1. Check .env file:
   cat server/.env | grep CRYPTO
   
2. Should show:
   RELAY_CRYPTO_ENABLED=true
   
3. If false or missing, add and restart:
   echo "RELAY_CRYPTO_ENABLED=true" >> server/.env
   docker compose restart
```

---

## �📋 Pre-Deployment Checklist

Before deploying to production:

- [ ] VPS relay server running LATEST relay_server.py (SCP command above)
- [ ] VPS firewall allows ports 60001-60002
- [ ] Client .env has RELAY_URL=wss://165.22.108.8:60001
- [ ] Client has shared_secret.key in crypto_keys/
- [ ] Test: `curl -k https://localhost:60000/api/relay/status`
- [ ] Dashboard shows "Connected" status (green)

---

## ✅ Success Indicators

**Client Logs:**
```
[RELAY] ✅ Connected to relay server
[RELAY] Active peers: 1
```

**VPS Logs:**
```
✅ New container connected: 118.100.245.156:58352 (Total: 1)
```

**API Response:**
```json
{"connected": true, "active_peers": 1}
```

---

## 🆘 Still Not Working?

1. **Deploy FIXED relay_server.py** (see VPS section above)
2. **Restart VPS relay** (Quick VPS Fix command)  
3. **Restart clients** (Windows + Kali)
4. **Wait 30 seconds** for connection
5. **Check logs** on both client and VPS

**Most common issue:** Old relay code on VPS. Always SCP the latest `relay_server.py` first.
