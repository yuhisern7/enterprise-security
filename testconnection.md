# Relay Connection Troubleshooting Guide

## Quick Status Check

### Linux (Kali/Ubuntu/Debian)
```bash
# Check relay connection status
sudo docker exec battle-hardened-ai python3 -c "
from AI.relay_client import get_relay_status
import json
status = get_relay_status()
print(json.dumps(status, indent=2))
print('\n' + '='*50)
if status.get('connected'):
    print('✅ CONNECTED TO RELAY SERVER!')
else:
    print('❌ Not connected')
    print(f\"Connection errors: {status.get('connection_errors', 0)}\")
"

# Check recent relay logs
sudo docker logs battle-hardened-ai 2>&1 | grep -E "RELAY" | tail -20
```

### Windows (PowerShell)
```powershell
# Check relay connection status
docker exec battle-hardened-ai python3 -c "from AI.relay_client import get_relay_status; import json; status = get_relay_status(); print(json.dumps(status, indent=2)); print('\n' + '='*50); print('✅ CONNECTED TO RELAY SERVER!' if status.get('connected') else '❌ Not connected - Errors: ' + str(status.get('connection_errors', 0)))"

# Check recent relay logs
docker logs battle-hardened-ai | Select-String "RELAY" | Select-Object -Last 20
```

### macOS (Terminal)
```bash
# Check relay connection status
docker exec battle-hardened-ai python3 -c "
from AI.relay_client import get_relay_status
import json
status = get_relay_status()
print(json.dumps(status, indent=2))
print('\n' + '='*50)
if status.get('connected'):
    print('✅ CONNECTED TO RELAY SERVER!')
else:
    print('❌ Not connected')
    print(f\"Connection errors: {status.get('connection_errors', 0)}\")
"

# Check recent relay logs
docker logs battle-hardened-ai 2>&1 | grep -E "RELAY" | tail -20
```

---

## Common Error: "Errno 111 - Connection Refused"

**Symptom:**
```
Relay connection error: [Errno 111] Connect call failed ('165.22.108.8', 60001)
```

**Cause:** Client firewall blocking outbound connections to VPS port 60001

**Solution depends on your operating system:**

---

## Firewall Configuration

### Linux (Kali/Ubuntu/Debian)

**Step 1: Allow outbound connections to VPS**
```bash
# Add iptables rules to allow outbound to relay server
sudo iptables -A OUTPUT -p tcp -d 165.22.108.8 --dport 60001 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -d 165.22.108.8 --dport 60002 -j ACCEPT

# Verify rules were added
sudo iptables -L OUTPUT -n | grep 165.22.108.8

# Save iptables rules (persist across reboots)
sudo mkdir -p /etc/iptables
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Alternative: If using ufw instead of iptables
sudo ufw allow out to 165.22.108.8 port 60001 proto tcp
sudo ufw allow out to 165.22.108.8 port 60002 proto tcp
sudo ufw reload
```

**Step 2: Restart container after firewall update**
```bash
cd ~/Downloads/battle-hardened-ai/server
sudo docker compose restart

# Wait for container to fully start
sleep 15

# Verify connection
sudo docker logs battle-hardened-ai 2>&1 | grep -E "RELAY" | tail -10
```

**Expected after fix:**
```
[RELAY] ✅ Connected to relay server
[RELAY] Peer: my-container
[RELAY] Active peers: 3
```

---

### Windows (PowerShell as Administrator)

**Step 1: Allow outbound connections through Windows Firewall**
```powershell
# Allow outbound TCP connections to VPS ports 60001-60002
New-NetFirewallRule -DisplayName "Battle-Hardened AI Relay Outbound" `
    -Direction Outbound `
    -RemoteAddress 165.22.108.8 `
    -RemotePort 60001,60002 `
    -Protocol TCP `
    -Action Allow

# Verify rule was created
Get-NetFirewallRule -DisplayName "Battle-Hardened AI Relay Outbound" | Format-List
```

**Step 2: Restart container after firewall update**
```powershell
cd C:\Users\<YourUsername>\workspace\battle-hardened-ai\server
docker compose restart

# Wait for container to fully start
Start-Sleep -Seconds 15

# Verify connection
docker logs battle-hardened-ai | Select-String "RELAY" | Select-Object -Last 10
```

**Expected after fix:**
```
[RELAY] ✅ Connected to relay server
[RELAY] Peer: windows-node
[RELAY] Active peers: 3
```

---

### macOS (Terminal)

**Step 1: Allow outbound connections through macOS Firewall**

**Option A: Using System Preferences (Recommended)**
```bash
# Check if firewall is enabled
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# If enabled, add Docker to allowed applications
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /Applications/Docker.app
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /Applications/Docker.app
```

**Option B: Using pfctl (Advanced)**
```bash
# Create pf rule file for relay outbound connections
sudo tee /etc/pf.anchors/battle-hardened-ai > /dev/null <<EOF
# Allow outbound connections to Battle-Hardened AI relay server
pass out proto tcp from any to 165.22.108.8 port {60001, 60002}
EOF

# Load the anchor into pf.conf if not already present
if ! sudo grep -q "battle-hardened-ai" /etc/pf.conf; then
    echo "load anchor \"battle-hardened-ai\" from \"/etc/pf.anchors/battle-hardened-ai\"" | sudo tee -a /etc/pf.conf
fi

# Enable and reload pf
sudo pfctl -e -f /etc/pf.conf 2>/dev/null || sudo pfctl -f /etc/pf.conf
```

**Step 2: Restart container after firewall update**
```bash
cd ~/workspace/battle-hardened-ai/server
docker compose restart

# Wait for container to fully start
sleep 15

# Verify connection
docker logs battle-hardened-ai 2>&1 | grep -E "RELAY" | tail -10
```

**Expected after fix:**
```
[RELAY] ✅ Connected to relay server
[RELAY] Peer: macos-node
[RELAY] Active peers: 3
```

---

## Diagnostic Tests

### Test 1: Basic Connectivity to VPS

**Linux:**
```bash
# Test if port 60001 is reachable (should connect if open)
telnet 165.22.108.8 60001
# Press Ctrl+C to exit if connected

# Alternative: Use netcat
nc -zv 165.22.108.8 60001

# Test HTTPS port 60002 (Model Distribution API)
curl -k -v https://165.22.108.8:60002/stats
```

**Windows:**
```powershell
# Test if port 60001 is reachable
Test-NetConnection -ComputerName 165.22.108.8 -Port 60001

# Test HTTPS port 60002
Invoke-WebRequest -Uri "https://165.22.108.8:60002/stats" -SkipCertificateCheck
```

**macOS:**
```bash
# Test if port 60001 is reachable (should connect if open)
nc -zv 165.22.108.8 60001

# Alternative: Use telnet (may need to install: brew install telnet)
telnet 165.22.108.8 60001
# Press Ctrl+] then type 'quit' to exit if connected

# Test HTTPS port 60002 (Model Distribution API)
curl -k -v https://165.22.108.8:60002/stats
```

**Expected Results:**
- Port 60001: Connection should succeed
- Port 60002: Should return JSON statistics
- **If FAILED:** Network routing issue or firewall blocking outbound

---

### Test 2: Verify Environment Variables

**Linux:**
```bash
# Check if RELAY_URL is set correctly inside container
sudo docker exec battle-hardened-ai env | grep RELAY

# Expected output:
# RELAY_ENABLED=true
# RELAY_URL=wss://165.22.108.8:60001
# RELAY_CRYPTO_ENABLED=true
# PEER_NAME=my-container (or linux-node)
```

**Windows:**
```powershell
# Check if RELAY_URL is set correctly inside container
docker exec battle-hardened-ai env | Select-String "RELAY"

# Expected output:
# RELAY_ENABLED=true
# RELAY_URL=wss://165.22.108.8:60001
# RELAY_CRYPTO_ENABLED=true
# PEER_NAME=windows-node
```

**macOS:**
```bash
# Check if RELAY_URL is set correctly inside container
docker exec battle-hardened-ai env | grep RELAY

# Expected output:
# RELAY_ENABLED=true
# RELAY_URL=wss://165.22.108.8:60001
# RELAY_CRYPTO_ENABLED=true
# PEER_NAME=macos-node
```

---

### Test 3: Check Firewall Rules

**Linux:**
```bash
# Check current iptables OUTPUT rules
sudo iptables -L OUTPUT -n -v | grep 165.22.108.8

# Expected: Should show ACCEPT rules for ports 60001 and 60002
# Example:
# ACCEPT     tcp  --  *  *  0.0.0.0/0  165.22.108.8  tcp dpt:60001

# Check ufw status (if using ufw)
sudo ufw status verbose | grep 165.22.108.8
```

**Windows:**
```powershell
# Check Windows Firewall outbound rules
Get-NetFirewallRule -DisplayName "*Relay*" | Format-List DisplayName,Enabled,Direction,Action

# Check specific rule
Get-NetFirewallRule -DisplayName "Battle-Hardened AI Relay Outbound" | Get-NetFirewallPortFilter
```

**macOS:**
```bash
# Check if macOS firewall is enabled
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Check allowed applications
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps | grep -i docker

# Check pf rules (if using pfctl method)
sudo pfctl -sr 2>/dev/null | grep 165.22.108.8

# View loaded pf anchors
sudo pfctl -s Anchors 2>/dev/null
```

---

### Test 4: Python Socket Test (from inside container)

**Linux:**
```bash
# Test connectivity from INSIDE container using Python
sudo docker exec battle-hardened-ai python3 -c "
import socket
import sys

print('Testing connection to VPS 165.22.108.8:60001...')
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex(('165.22.108.8', 60001))
    sock.close()
    
    if result == 0:
        print('✅ SUCCESS: Port 60001 is REACHABLE from container')
        sys.exit(0)
    else:
        print(f'❌ FAILED: Port 60001 is BLOCKED (error code: {result})')
        sys.exit(1)
except Exception as e:
    print(f'❌ ERROR: {e}')
    sys.exit(1)
"
```

**Windows:**
```powershell
# Test connectivity from INSIDE container using Python
docker exec battle-hardened-ai python3 -c "import socket; import sys; print('Testing connection to VPS 165.22.108.8:60001...'); sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(5); result = sock.connect_ex(('165.22.108.8', 60001)); sock.close(); print('✅ SUCCESS: Port 60001 is REACHABLE' if result == 0 else f'❌ FAILED: Port 60001 is BLOCKED (code: {result})')"
```

**macOS:**
```bash
# Test connectivity from INSIDE container using Python
docker exec battle-hardened-ai python3 -c "
import socket
import sys

print('Testing connection to VPS 165.22.108.8:60001...')
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex(('165.22.108.8', 60001))
    sock.close()
    
    if result == 0:
        print('✅ SUCCESS: Port 60001 is REACHABLE from container')
        sys.exit(0)
    else:
        print(f'❌ FAILED: Port 60001 is BLOCKED (error code: {result})')
        sys.exit(1)
except Exception as e:
    print(f'❌ ERROR: {e}')
    sys.exit(1)
"
```

---

### Test 5: Check Your Public IP

**Linux:**
```bash
# Check your public IP address
curl ifconfig.me

# VPS sees Windows client as: 118.100.245.156
# Compare your IP - if different network, may need VPS firewall adjustment
```

**Windows:**
```powershell
# Check your public IP address
Invoke-RestMethod -Uri "https://ifconfig.me"

# Should match: 118.100.245.156 (if same network as working Windows client)
```

**macOS:**
```bash
# Check your public IP address
curl ifconfig.me

# VPS sees Windows client as: 118.100.245.156
# Compare your IP - if different network, may need VPS firewall adjustment
```

---

## Diagnostic Steps (Step-by-Step)

Run these commands on your client machine to identify the blocker:

### Step 1: Test Basic Connectivity
Run Test 1 (Basic Connectivity to VPS) from Diagnostic Tests section above

### Step 2: Check Firewall Rules
Run Test 3 (Check Firewall Rules) from Diagnostic Tests section above

### Step 3: Apply Firewall Fix
Run commands from Firewall Configuration section for your OS

### Step 4: Verify Environment Variables
Run Test 2 (Verify Environment Variables) from Diagnostic Tests section above

### Step 5: Test from Inside Container
Run Test 4 (Python Socket Test) from Diagnostic Tests section above

### Step 6: Check Public IP
Run Test 5 (Check Your Public IP) from Diagnostic Tests section above

### Step 7: Restart and Verify
Restart container and check logs using Quick Status Check commands at top of document

---

## Common Causes & Solutions

### Cause 1: Kali Linux Outbound Firewall Blocking Port 60001
**Solution:**
```bash
sudo ufw allow out to 165.22.108.8 port 60001 proto tcp
sudo ufw reload
```

### Cause 2: Docker Container Network Isolation
**Solution:** Ensure docker-compose.yml uses `network_mode: host` (already configured)

### Cause 3: ISP or Corporate Firewall Blocking Outbound WebSocket
**Solution:** Test with VPN or different network

### Cause 4: VPS Cloud Firewall Blocking Kali Linux IP
**Solution (on VPS):**
```bash
# Check DigitalOcean Cloud Firewall in dashboard
# Ensure inbound rules allow TCP 60001 from "All IPv4" not just specific IPs
```

### Cause 5: SSL Certificate Verification Failing
**Check relay_client.py:** Should have `ssl_context.check_hostname = False`

---

## Next Steps

1. **Run diagnostic tests above** to identify which layer is blocking
2. **Report results** - specifically output of `telnet 165.22.108.8 60001`
3. **Check Kali Linux public IP** - compare with Windows IP (118.100.245.156)
4. **Verify VPS Cloud Firewall** allows connections from Kali's IP

Once we identify the blocking layer, we can implement the fix.

---

## Success Criteria

After fix, Kali Linux logs should show:
```
[RELAY] ✅ Connected to relay server
```

And VPS logs should show:
```
✅ New container connected: <KALI_IP>:<PORT> (Total: 5)
```Issues & Solutions

### Issue 1: Client Firewall Blocking Outbound Connections
**Symptoms:**
- `[Errno 111] Connect call failed`
- `Connection refused`
- Telnet to port 60001 fails

**Solution:** Apply firewall configuration from section above for your OS (Linux or Windows)

---

### Issue 2: Docker Container Network Isolation
**Symptoms:**
- Container can't reach internet
- Python socket test fails
- DNS resolution fails

**Linux Solution:**
```bash
# Ensure docker-compose.yml uses host network mode
cat ~/Downloads/battle-hardened-ai/server/docker-compose.yml | grep network_mode
# Should show: network_mode: host

# If missing, add to docker-compose.yml and restart
sudo docker compose down
sudo docker compose up -d
```

**Windows Solution:**
```powershell
# Windows uses bridge mode - ensure ports are mapped
cat docker-compose.windows.yml | Select-String "ports:"
# Should show: - "60000:60000"

# Restart Docker Desktop if network issues persist
```

**macOS Solution:**
```bash
# macOS uses bridge mode - ensure ports are mapped
cat docker-compose.yml | grep -A 2 "ports:"
# Should show: - "60000:60000"

# Restart Docker Desktop if network issues persist
# From menu bar: Docker icon → Restart

# Or via command line:
osascript -e 'quit app "Docker"'
sleep 5
open -a Docker
```

---

### Issue 3: ISP or Corporate Firewall Blocking WebSocket
**Symptoms:**
- Port 60001 blocked even after client firewall configured
- Works on different network/VPN
- SSH (port 22) works but 60001 doesn't

**Solution:** 
- Test with VPN or mobile hotspot to confirm
- Contact network administrator to allow outbound TCP 60001-60002
- Alternative: Use VPN tunnel to bypass restrictions

---

### Issue 4: Wrong Environment Variables
**Symptoms:**
- RELAY_URL is empty or wrong
- RELAY_ENABLED=false
- Container logs show no relay initialization

**Linux Solution:**
```bash
# Check .env file
cat ~/Downloads/battle-hardened-ai/server/.env | grep RELAY

# Should contain:
# RELAY_ENABLED=true
# RELAY_URL=wss://165.22.108.8:60001
# RELAY_CRYPTO_ENABLED=true
# PEER_NAME=linux-node

# If missing or wrong, edit .env and restart
nano ~/Downloads/battle-hardened-ai/server/.env
sudo docker compose restart
```

**Windows Solution:**
```powershell
# Check .env file
Get-Content .env | Select-String "RELAY"

# Should contain:
# RELAY_ENABLED=true
# RELAY_URL=wss://165.22.108.8:60001
# RELAY_CRYPTO_ENABLED=true
# PEER_NAME=windows-node

# If missing or wrong, edit .env and restart
notepad .env
docker compose restart
```

**macOS Solution:**
```bash
# Check .env file
cat ~/workspace/battle-hardened-ai/server/.env | grep RELAY

# Should contain:
# RELAY_ENABLED=true
# RELAY_URL=wss://165.22.108.8:60001
# RELAY_CRYPTO_ENABLED=true
# PEER_NAME=macos-node

# If missing or wrong, edit .env and restart
nano ~/workspace/battle-hardened-ai/server/.env
# Or use: vim, open -e, or TextEdit
docker compose restart
```

---

### Issue 5: VPS Relay Server Issues
**Symptoms:**
- Client can reach VPS (telnet works)
- But WebSocket connection fails
- No errors in client logs

**Solution:** See `relay/firewall.md` for VPS-specific troubleshooting