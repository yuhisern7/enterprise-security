# 🌐 Gateway Deployment Guide — Linux Host as Network Gateway

This guide shows how to deploy Battle-Hardened AI as a **network gateway** with full traffic visibility using eBPF/XDP kernel telemetry. This is the same architecture used by enterprise firewalls, military sensors, and telecom probes.

---

## 🎯 Architecture Overview

```
[ Internet ]
     |
     |
[ Linux Gateway Host ]
  ├── IP Forwarding (kernel)
  ├── NAT/Firewall (iptables)
  ├── eBPF/XDP (kernel telemetry)
  └── Docker (AI/Dashboard)
     |
     |
[ Internal Network ]
  └── All devices route through gateway
```

**Key Principle:** Docker runs AI logic, Linux kernel routes packets.

---

## ✅ Prerequisites

- Linux host (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- 2+ network interfaces (WAN + LAN) OR single interface with VLAN
- Kernel 5.10+ (for eBPF/XDP support)
- 4GB+ RAM, 20GB+ disk
- Root/sudo access

**Check kernel version:**
```bash
uname -r  # Should be >= 5.10
```

---

## 🚀 Deployment Steps

### **STEP 1: Enable IP Forwarding**

Make Linux host a router:

```bash
# Enable immediately
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Persist across reboots
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-gateway.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.d/99-gateway.conf
sudo sysctl --system
```

**Verify:**
```bash
cat /proc/sys/net/ipv4/ip_forward  # Should output: 1
```

---

### **STEP 2: Configure NAT (Masquerade)**

**Identify your interfaces:**
```bash
ip link show
# Example output:
# eth0 → WAN (Internet-facing)
# eth1 → LAN (Internal network)
```

**Set up NAT forwarding:**
```bash
# Replace with your actual interface names
WAN=eth0  # Internet-facing
LAN=eth1  # Internal network

# Enable masquerading (NAT)
sudo iptables -t nat -A POSTROUTING -o $WAN -j MASQUERADE

# Allow forwarding from LAN to WAN
sudo iptables -A FORWARD -i $LAN -o $WAN -j ACCEPT

# Allow return traffic (established connections)
sudo iptables -A FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save rules (Ubuntu/Debian)
sudo apt install iptables-persistent -y
sudo netfilter-persistent save

# Save rules (RHEL/CentOS)
sudo service iptables save
```

**Verify NAT is active:**
```bash
sudo iptables -t nat -L -n -v
```

---

### **STEP 3: Configure Network Clients**

**Option A: LAN Devices (Wired Switch)**
- Set default gateway to Linux host's LAN IP
- Example: Gateway = `192.168.1.1` (your Linux host)

**Option B: Wi-Fi Router/AP**
- Set router to **bridge mode** or **AP mode**
- Configure DHCP to point gateway to Linux host
- OR disable router DHCP, run DHCP on Linux host

**Option C: Single Interface + VLAN (Advanced)**
- Use VLANs to separate WAN/LAN on single NIC
- Requires managed switch

**Test connectivity from client:**
```bash
ping 8.8.8.8  # Should work if routing is correct
traceroute 8.8.8.8  # Should show your gateway as first hop
```

---

### **STEP 4: Install eBPF/XDP Tools**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y linux-headers-$(uname -r) clang llvm libbpf-dev bpftool

# RHEL/CentOS
sudo yum install -y kernel-devel clang llvm libbpf-devel bpftool

# Verify eBPF support
bpftool feature | grep xdp
```

---

### **STEP 5: Deploy Battle-Hardened AI with Kernel Access**

**Clone repository:**
```bash
git clone https://github.com/yuhisern7/battle-hardened-ai.git
cd battle-hardened-ai/server
```

**Configure docker-compose.yml for gateway mode:**

Create/edit `docker-compose.override.yml`:

```yaml
services:
  battle-hardened-ai:
    privileged: true
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - BPF
      - PERFMON
    volumes:
      - /sys:/sys:ro
      - /proc:/proc:ro
      - /lib/modules:/lib/modules:ro
      - /sys/fs/bpf:/sys/fs/bpf
    environment:
      - EBPF_ENABLED=true
      - EBPF_INTERFACE=eth0  # Your WAN interface
      - GATEWAY_MODE=true
```

**Why these settings:**
- `network_mode: host` → See real network traffic (not Docker bridge)
- `privileged: true` → Access kernel features (eBPF maps)
- `/sys/fs/bpf` → eBPF filesystem for map pinning
- `/lib/modules` → Kernel symbols for eBPF verification

**Start the platform:**
```bash
docker compose up -d --build
```

**Verify eBPF attachment:**
```bash
# Check if XDP is attached
sudo ip link show eth0 | grep xdp

# View eBPF maps
sudo bpftool map list

# Monitor eBPF programs
sudo bpftool prog list
```

---

### **STEP 6: Access Dashboard**

```bash
# From any device on your network
https://<gateway-ip>:60000
```

**Default:** `https://192.168.1.1:60000`

---

## 🛡️ Enforcement Levels (Progressive Deployment)

### **Level 1: Observer Only (RECOMMENDED START)**

- eBPF runs in `XDP_PASS` mode
- Zero packet drops
- Full telemetry collection
- AI detection active
- Dashboard shows threats
- **No blocking** (safe testing)

**Enable:**
```bash
# Already default in our platform
# Set in server/.env:
ENFORCEMENT_MODE=observer
```

**Run this for 1-2 weeks to validate detection accuracy.**

---

### **Level 2: iptables/nftables Enforcement (PRODUCTION)**

- AI detects threats
- Applies firewall rules via iptables
- Fully auditable
- Rollback-friendly
- Industry standard approach

**Enable:**
```bash
# In server/.env:
ENFORCEMENT_MODE=firewall
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=0.75  # 75% confidence
```

**How it works:**
1. AI detects threat (confidence >75%)
2. API calls `iptables -I INPUT -s <malicious_ip> -j DROP`
3. Logged in audit trail
4. Auto-expires after configurable time

---

### **Level 3: XDP_DROP (ADVANCED - DO NOT USE YET)**

- Kernel-level packet drop (fastest)
- Requires 3-6 months validation
- Used only for DDoS mitigation
- Military/telco environments only

**⚠️ WARNING:** Can cause network outages if misconfigured.

**Enable (only after extensive testing):**
```bash
# In server/.env:
ENFORCEMENT_MODE=xdp_drop
```

---

## 📊 Validation & Testing

### **Test 1: Verify Routing**

From internal client:
```bash
# Should see your gateway as first hop
traceroute 8.8.8.8

# Should work
ping google.com
curl https://example.com
```

### **Test 2: Verify eBPF Telemetry**

On gateway host:
```bash
# Check packet counts
sudo bpftool map dump name packet_count

# View eBPF logs
docker logs -f battle-hardened-ai | grep eBPF
```

### **Test 3: Trigger Detection**

From internal client:
```bash
# SQL injection attempt (safe test)
curl "http://<some-server>/test?id=1' OR '1'='1"

# Port scan
nmap -p 1-100 scanme.nmap.org
```

**Check dashboard:** `https://<gateway-ip>:60000`
- Should see detections in Live Threat Feed
- Section 4: AI Detection Status should show signals active

---

## 🔧 Troubleshooting

### **Problem: No traffic visible in dashboard**

**Fix 1:** Check IP forwarding
```bash
cat /proc/sys/net/ipv4/ip_forward  # Must be 1
```

**Fix 2:** Verify NAT rules
```bash
sudo iptables -t nat -L -n -v  # Should see MASQUERADE
```

**Fix 3:** Check Docker network mode
```bash
docker inspect battle-hardened-ai | grep NetworkMode  # Must be "host"
```

**Fix 4:** Verify eBPF interface
```bash
# In server/.env, ensure EBPF_INTERFACE matches your WAN interface
ip link show  # Check actual interface names
```

---

### **Problem: eBPF attachment fails**

**Fix 1:** Check kernel version
```bash
uname -r  # Must be >= 5.10
```

**Fix 2:** Install kernel headers
```bash
sudo apt install linux-headers-$(uname -r)
```

**Fix 3:** Check capabilities
```bash
docker exec battle-hardened-ai capsh --print | grep bpf
```

---

### **Problem: Clients can't access internet**

**Fix 1:** Verify default gateway on clients
```bash
# On client
ip route show  # Default should point to gateway host
```

**Fix 2:** Check firewall rules
```bash
sudo iptables -L FORWARD -n -v  # Should see ACCEPT rules
```

**Fix 3:** Test from gateway host
```bash
# If this works, routing is fine
ping -I eth1 8.8.8.8  # From LAN interface
```

---

## 🚀 Production Hardening

### **1. Persistent iptables Rules**

```bash
# Ubuntu/Debian
sudo apt install iptables-persistent
sudo netfilter-persistent save

# RHEL/CentOS
sudo systemctl enable iptables
sudo service iptables save
```

### **2. Enable Auto-Start**

```bash
# Docker auto-start
docker update --restart unless-stopped battle-hardened-ai

# Systemd service (optional)
sudo systemctl enable docker
```

### **3. Backup Configuration**

```bash
# Save firewall rules
sudo iptables-save > /root/iptables-backup.rules

# Save Docker config
cp server/.env /root/battle-hardened-ai-env.backup
```

### **4. Monitoring**

```bash
# Real-time packet stats
watch -n 1 'sudo iptables -L -n -v'

# eBPF map monitoring
watch -n 1 'sudo bpftool map list'

# Docker logs
docker logs -f --tail 100 battle-hardened-ai
```

---

## 📈 Performance Tuning

### **For 1 Gbps Networks:**
- Default configuration works
- CPU: 2 cores, RAM: 4GB

### **For 10 Gbps Networks:**
- CPU: 8+ cores (eBPF per-core processing)
- RAM: 16GB
- NVMe storage for logs
- Enable XDP native mode (if NIC supports)

```bash
# Check if NIC supports XDP offload
ethtool -k eth0 | grep xdp
```

### **Tune receive buffers:**
```bash
sudo ethtool -G eth0 rx 4096
sudo ethtool -K eth0 gro on
sudo ethtool -K eth0 gso on
```

---

## 🔒 Security Considerations

**1. Secure Dashboard Access**
- Change default certificates (see HTTPS guide)
- Enable firewall on port 60000
- Use VPN for remote access

**2. Protect eBPF Maps**
```bash
# Restrict /sys/fs/bpf access
sudo chmod 700 /sys/fs/bpf
```

**3. Audit Logging**
- Enable comprehensive audit logs (Module J)
- Forward logs to SIEM
- Set retention policies

**4. Emergency Shutdown**
- Use kill-switch in dashboard (Section 32)
- Or disable via CLI:
```bash
docker stop battle-hardened-ai
```

---

## 📚 Related Documentation

- [EBPF_SETUP.md](EBPF_SETUP.md) - eBPF/XDP technical details
- [DEPLOYMENT.md](DEPLOYMENT.md) - Docker deployment architecture
- [README.md](README.md) - Platform features and capabilities

---

## 💼 Support

**Community:** GitHub Issues  
**Professional:** WhatsApp +60172791717 | yuhisern@protonmail.com  
**Enterprise Deployment:** Custom on-site setup available

---

**Built for production. Deployed like a fortress. Monitored at kernel level.** 🛡️
