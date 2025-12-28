# 🔌 Port Configuration Guide

## Overview

The P2P mesh network uses **2 configurable ports**:

| Port | Default | Protocol | Purpose | Access |
|------|---------|----------|---------|--------|
| **DASHBOARD_PORT** | 60000 | HTTP | Web dashboard | Local only |
| **P2P_PORT** | 60001 | HTTPS | P2P mesh sync | Worldwide |

**Why high ports (60000+)?**
- ✅ Less likely to conflict with existing services
- ✅ No root/admin privileges needed
- ✅ Safe range: 49152-65535 (IANA dynamic/private ports)

---

## Quick Start (Default Ports)

**Default configuration works out of the box:**
```bash
./setup_peer.sh
```

Dashboard: http://localhost:60000  
P2P Sync: https://your-ip:60001

---

## Custom Port Configuration

### Step 1: Check if Port is Available

**Linux/Mac:**
```bash
# Check if port 60000 is in use
sudo lsof -i :60000

# Check if port 60001 is in use
sudo lsof -i :60001

# If output is empty, port is FREE ✅
# If output shows a process, port is IN USE ❌
```

**Windows (PowerShell):**
```powershell
# Check if port is in use
netstat -ano | findstr :60000
netstat -ano | findstr :60001

# If no output, port is FREE ✅
```

### Step 2: Choose Different Ports (If Needed)

If ports 60000-60001 are already in use, pick alternative ports:

**Recommended port ranges:**
- `50000-50001` (alternative high ports)
- `55000-55001` (alternative high ports)
- `60000-60001` (default)
- `60100-60101` (if default conflicts)

**Avoid these ports (commonly used):**
- `80, 443` - Web servers
- `3000, 8080, 8443` - Development servers
- `5000, 5432` - PostgreSQL, Flask dev
- `3306, 27017` - MySQL, MongoDB

### Step 3: Configure Custom Ports

**Edit `.env` file** (create from `.env.example` if doesn't exist):

```bash
# Copy example if needed
cp .env.example .env

# Edit .env file
nano .env  # or use any text editor
```

**Add/modify these lines:**
```bash
# Port Configuration
DASHBOARD_PORT=60000  # Change to your desired dashboard port
P2P_PORT=60001        # Change to your desired P2P port
```

**Example: Using ports 55000-55001:**
```bash
DASHBOARD_PORT=55000
P2P_PORT=55001
```

### Step 4: Update Peer URLs

When connecting to other containers, use the **P2P_PORT** each peer is using:

**Example:** If 3 containers use different ports:
- Container A: P2P_PORT=60001
- Container B: P2P_PORT=60101  
- Container C: P2P_PORT=55001

**In Container A's `.env`:**
```bash
PEER_URLS=https://containerB-ip:60101,https://containerC-ip:55001
```

**In Container B's `.env`:**
```bash
PEER_URLS=https://containerA-ip:60001,https://containerC-ip:55001
```

**In Container C's `.env`:**
```bash
PEER_URLS=https://containerA-ip:60001,https://containerB-ip:60101
```

### Step 5: Rebuild Container

After changing ports in `.env`:
```bash
cd server
docker compose down
docker compose up -d
```

---

## Firewall Configuration

**Open your P2P_PORT on firewall** (for worldwide connections):

### Linux (UFW)
```bash
# Replace 60001 with your P2P_PORT
sudo ufw allow 60001/tcp
sudo ufw reload
```

### Linux (firewalld)
```bash
# Replace 60001 with your P2P_PORT
sudo firewall-cmd --permanent --add-port=60001/tcp
sudo firewall-cmd --reload
```

### Mac
```
System Preferences → Security & Privacy → Firewall → Firewall Options
Add rule for port 60001 (or your P2P_PORT)
```

### Windows
```
Windows Defender Firewall → Advanced Settings → Inbound Rules
New Rule → Port → TCP → Specific Port: 60001 (or your P2P_PORT)
```

### Router (Port Forwarding)
If connecting across different networks:
1. Log in to your router admin panel
2. Find "Port Forwarding" or "Virtual Server"
3. Forward external port → internal P2P_PORT → your machine's local IP

**Example:**
- External Port: 60001
- Internal Port: 60001
- Internal IP: 192.168.1.100 (your computer)

---

## Verification

### Check Container Logs
```bash
cd server
docker compose logs --tail=20

# You should see:
# 📊 Dashboard: http://localhost:60000
# 🌐 P2P Sync: https://localhost:60001
```

### Test Dashboard Access
```bash
# Replace 60000 with your DASHBOARD_PORT
curl http://localhost:60000
```

### Test P2P Port (from another machine)
```bash
# Replace your-ip and 60001 with your server's IP and P2P_PORT
curl -k https://your-ip:60001/api/p2p/status
```

---

## Port Conflict Scenarios

### Scenario 1: Port Already in Use During Startup

**Error:**
```
Error: Bind for 0.0.0.0:60000 failed: port is already allocated
```

**Solution:**
1. Find what's using the port:
   ```bash
   sudo lsof -i :60000  # Linux/Mac
   netstat -ano | findstr :60000  # Windows
   ```

2. Either:
   - Stop the conflicting service, OR
   - Change DASHBOARD_PORT/P2P_PORT in `.env` to different values

3. Rebuild container:
   ```bash
   docker compose down
   docker compose up -d
   ```

### Scenario 2: Multiple Containers on Same Machine

**Problem:** Can't run 2 containers with same ports on same machine.

**Solution:** Give each container unique ports:

**Container 1:**
```bash
DASHBOARD_PORT=60000
P2P_PORT=60001
```

**Container 2:**
```bash
DASHBOARD_PORT=60100
P2P_PORT=60101
```

**Container 3:**
```bash
DASHBOARD_PORT=60200
P2P_PORT=60201
```

### Scenario 3: Corporate Network Blocks High Ports

**Problem:** Some corporate firewalls block ports above 10000.

**Solution:** Use lower ports (requires admin/root):

```bash
# Use standard web ports (requires root)
DASHBOARD_PORT=8080
P2P_PORT=8443
```

**Note:** Ports below 1024 require root/admin privileges.

---

## Docker Network Modes

### Current: Bridge Mode (Recommended)

```yaml
network_mode: bridge
ports:
  - "${DASHBOARD_PORT:-60000}:${DASHBOARD_PORT:-60000}"
  - "${P2P_PORT:-60001}:${P2P_PORT:-60001}"
```

**Advantages:**
- ✅ Port mapping flexibility
- ✅ Can change ports without rebuilding image
- ✅ Multiple containers on same host
- ✅ Better security isolation

**Disadvantages:**
- ⚠️ Requires NET_ADMIN capability for packet capture

### Alternative: Host Mode

```yaml
network_mode: host
```

**Advantages:**
- ✅ Direct network access
- ✅ Better performance

**Disadvantages:**
- ❌ Ports hardcoded (can't remap)
- ❌ Can't run multiple containers on same host
- ❌ Less security isolation

---

## Environment Variables Reference

### Port Variables (.env)

```bash
# Dashboard web interface (HTTP)
DASHBOARD_PORT=60000

# P2P mesh synchronization (HTTPS)
P2P_PORT=60001

# Peer URLs (use each peer's P2P_PORT)
PEER_URLS=https://peer1:60001,https://peer2:60101,https://peer3:55001
```

### Docker Compose Variables

These are automatically passed from `.env`:
```yaml
environment:
  - DASHBOARD_PORT=${DASHBOARD_PORT:-60000}
  - P2P_PORT=${P2P_PORT:-60001}

ports:
  - "${DASHBOARD_PORT:-60000}:${DASHBOARD_PORT:-60000}"
  - "${P2P_PORT:-60001}:${P2P_PORT:-60001}"
```

**Syntax:** `${VAR:-default}` means "use VAR if set, otherwise use default"

---

## Troubleshooting

### Dashboard won't load

1. Check container is running:
   ```bash
   docker compose ps
   ```

2. Check logs for port errors:
   ```bash
   docker compose logs | grep -i "error\|port"
   ```

3. Verify correct port:
   ```bash
   # Should show your DASHBOARD_PORT
   docker compose logs | grep "Dashboard:"
   ```

### P2P connections failing

1. Check firewall allows P2P_PORT
2. Verify peer URLs use correct ports:
   ```bash
   cat .env | grep PEER_URLS
   ```

3. Test connectivity:
   ```bash
   curl -k https://peer-ip:60001/api/p2p/status
   ```

### Port conflicts after .env change

1. Restart container:
   ```bash
   docker compose down
   docker compose up -d
   ```

2. Verify new ports:
   ```bash
   docker compose logs --tail=20 | grep "Dashboard:\|P2P Sync:"
   ```

---

## Best Practices

1. **Use high ports (60000+)** to avoid conflicts
2. **Document your ports** in a team wiki/doc
3. **Keep ports consistent** across your organization (easier management)
4. **Open only P2P_PORT** on firewall (dashboard is local-only)
5. **Use HTTPS** for all P2P URLs (auto-encrypted)
6. **Test connectivity** before adding to PEER_URLS

---

## FAQ

**Q: Can I use port 80 or 443?**  
A: Yes, but requires root/admin. Not recommended (conflicts with web servers).

**Q: Do I need to open DASHBOARD_PORT on firewall?**  
A: No! Dashboard is for local access only. Only open P2P_PORT.

**Q: Can I change ports without rebuilding Docker image?**  
A: Yes! Just edit `.env` and run `docker compose restart`.

**Q: What if my ISP blocks port 60001?**  
A: Use a different port (e.g., 443, 8443) or VPN/tunneling service.

**Q: Can I run multiple containers on same machine?**  
A: Yes! Give each unique ports (60000/60001, 60100/60101, etc.)

**Q: How do I know which ports my peers are using?**  
A: Ask them! Or check their dashboard footer (shows P2P port).

---

**Remember:** P2P mesh = every container uses its own P2P_PORT. When connecting, specify each peer's port in PEER_URLS.
