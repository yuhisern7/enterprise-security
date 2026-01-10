# Security Whitelisting for Battle-Hardened AI on Windows

## Why Whitelisting is Necessary

Enterprise security solutions (Windows Defender, CrowdStrike, Symantec, McAfee, etc.) detect network monitoring tools as **potentially malicious** because:

1. **Promiscuous network capture** (Npcap/Scapy) = same technique used by packet sniffers
2. **Raw socket access** = used by network reconnaissance tools
3. **Behavioral analysis** = looks like threat hunting malware
4. **ML model execution** = can trigger behavioral detection
5. **Firewall automation** = modifies system security settings

**Without proper whitelisting:** Your security software will block, quarantine, or severely throttle Battle-Hardened AI.

---

## Current Exclusion Status

✅ **You already have:** `C:\Users\kidds\workspace` (workspace folder)

⚠️ **You still need:** Npcap driver, Python processes, and network monitoring exclusions

---

## Complete Whitelisting Configuration

### 1️⃣ Windows Defender Exclusions

Run these commands in **Administrator PowerShell**:

```powershell
# Workspace folder (you already have this)
Add-MpPreference -ExclusionPath "C:\Users\kidds\workspace\battle-hardened-ai"

# Npcap driver and installation
Add-MpPreference -ExclusionPath "C:\Program Files\Npcap"
Add-MpPreference -ExclusionPath "C:\Windows\System32\Npcap"
Add-MpPreference -ExclusionPath "C:\Windows\System32\drivers\npcap.sys"

# Python virtual environment
Add-MpPreference -ExclusionPath "C:\Users\kidds\workspace\battle-hardened-ai\.venv"

# Exclude Python processes performing network capture
Add-MpPreference -ExclusionProcess "python.exe"
Add-MpPreference -ExclusionProcess "pythonw.exe"

# Exclude Npcap processes
Add-MpPreference -ExclusionProcess "npcap.exe"
Add-MpPreference -ExclusionProcess "dumpcap.exe"

# Exclude file extensions used by Battle-Hardened AI
Add-MpPreference -ExclusionExtension ".pcap"
Add-MpPreference -ExclusionExtension ".pkl"
Add-MpPreference -ExclusionExtension ".keras"
Add-MpPreference -ExclusionExtension ".h5"
```

**Verify exclusions:**
```powershell
Get-MpPreference | Select-Object -Property ExclusionPath, ExclusionProcess, ExclusionExtension
```

---

### 2️⃣ Enterprise AV/EDR Whitelisting

If you use **CrowdStrike**, **Carbon Black**, **SentinelOne**, **Symantec**, **McAfee**, or similar:

#### A. Application Whitelisting (Add to Allowed Applications)

**Application Name:** Battle-Hardened AI Network Defense System  
**Executable Paths:**
```
C:\Users\kidds\workspace\battle-hardened-ai\.venv\Scripts\python.exe
C:\Program Files\Npcap\npcap.exe
C:\Program Files\Npcap\dumpcap.exe
```

**Process Hashes (if required):**
```powershell
# Get Python hash for whitelisting
Get-FileHash "C:\Users\kidds\workspace\battle-hardened-ai\.venv\Scripts\python.exe" -Algorithm SHA256
```

#### B. Behavior-Based Detection Exclusions

**Behaviors to Whitelist:**
- ✅ Raw socket creation (promiscuous mode)
- ✅ Network interface enumeration
- ✅ Packet capture and analysis
- ✅ Firewall rule modification (iptables automation)
- ✅ Outbound connections to threat intelligence feeds (VirusTotal, AbuseIPDB)
- ✅ High CPU/memory usage (ML model training)
- ✅ Large file writes (log rotation, PCAP storage)

**Suspicious Activities to Allow:**
- Network scanning from localhost (device discovery)
- Repeated connection attempts (reputation tracking)
- DNS enumeration (DNS analyzer)
- TLS/SSL inspection (TLS fingerprinting)

#### C. Network Monitoring Exclusions

**Allow these network activities:**
```
Source IP: 127.0.0.1, 192.168.68.111 (your Windows IP)
Destination: Any (network monitoring)
Ports: Any (packet capture)
Protocol: Any (all network traffic)
```

**Allow outbound connections to:**
- `virustotal.com` (threat intelligence)
- `abuseipdb.com` (IP reputation)
- `exploit-db.com` (signature updates)
- Your relay server IP (if using federated learning)

---

### 3️⃣ Windows Firewall Rules

**Allow Battle-Hardened AI services:**

```powershell
# Allow dashboard (port 60000)
New-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" `
    -Direction Inbound -Protocol TCP -LocalPort 60000 -Action Allow

# Allow P2P/Relay (port 60001)
New-NetFirewallRule -DisplayName "Battle-Hardened AI Relay" `
    -Direction Inbound -Protocol TCP -LocalPort 60001 -Action Allow

# Allow Python network monitoring
New-NetFirewallRule -DisplayName "Battle-Hardened AI Monitor" `
    -Direction Inbound -Program "C:\Users\kidds\workspace\battle-hardened-ai\.venv\Scripts\python.exe" `
    -Action Allow

# Allow Npcap packet capture
New-NetFirewallRule -DisplayName "Npcap Packet Capture" `
    -Direction Inbound -Program "C:\Program Files\Npcap\npcap.exe" `
    -Action Allow
```

**Verify firewall rules:**
```powershell
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Battle-Hardened*" -or $_.DisplayName -like "*Npcap*"}
```

---

### 4️⃣ Npcap Driver Permissions

**Ensure Npcap has proper permissions:**

```powershell
# Check Npcap service status
Get-Service npcap
sc.exe query npcap

# Start Npcap service (if stopped)
Start-Service npcap
sc.exe start npcap

# Set Npcap service to auto-start
Set-Service npcap -StartupType Automatic
sc.exe config npcap start= auto
```

**Verify Npcap driver is loaded:**
```powershell
Get-WindowsDriver -Online | Where-Object {$_.OriginalFileName -like "*npcap*"}
```

---

### 5️⃣ User Account Control (UAC) and Privileges

**Network monitoring requires Administrator privileges.**

**Option A: Run as Administrator (Recommended for Testing)**
```powershell
# Right-click PowerShell → Run as Administrator
cd C:\Users\kidds\workspace\battle-hardened-ai
python server\network_monitor.py
```

**Option B: Disable UAC Prompt (Not Recommended for Security)**
```powershell
# Only for dedicated security appliances, NOT for regular workstations
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
#     -Name "EnableLUA" -Value 0
```

**Option C: Create Scheduled Task (Production Deployment)**
```powershell
$action = New-ScheduledTaskAction -Execute "C:\Users\kidds\workspace\battle-hardened-ai\.venv\Scripts\python.exe" `
    -Argument "C:\Users\kidds\workspace\battle-hardened-ai\server\network_monitor.py" `
    -WorkingDirectory "C:\Users\kidds\workspace\battle-hardened-ai"

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask -TaskName "BattleHardenedAI" -Action $action -Trigger $trigger -Principal $principal
```

---

### 6️⃣ Enterprise-Specific Configurations

#### **CrowdStrike Falcon**
1. Go to **Prevention Policies** → **Machine Learning** → **Exclusions**
2. Add path: `C:\Users\kidds\workspace\battle-hardened-ai\**\*`
3. Add process: `python.exe` (with workspace path)
4. Add IOA exclusions: `Network Scanning`, `Packet Capture`

#### **Carbon Black**
1. **Reputation Override** → Add Python executable hash
2. **Behavioral Rules** → Exclude `Raw Socket Access` for Python
3. **Network Rules** → Allow `Promiscuous Mode` on Wi-Fi adapter

#### **SentinelOne**
1. **Exclusions** → **Path Exclusions** → Add workspace
2. **Exclusions** → **Process Exclusions** → Add `python.exe`
3. **Settings** → **Agent Capabilities** → Allow `Network Monitoring Tools`

#### **Symantec Endpoint Protection**
1. **Exceptions** → **Windows Exceptions** → Add workspace path
2. **Application and Device Control** → Allow `Npcap.exe`, `python.exe`
3. **Network Threat Protection** → Exclude local monitoring traffic

#### **McAfee Endpoint Security**
1. **Threat Prevention** → **Exclusions** → Add workspace
2. **Exploit Prevention** → Exclude `python.exe` from API monitoring
3. **Firewall** → Add rules for ports 60000, 60001

---

## Verification Checklist

After configuring whitelisting, verify everything works:

```powershell
# 1. Check Npcap is running
Get-Service npcap
# Expected: Status = Running

# 2. Test Python can import Scapy
python -c "from scapy.all import sniff; print('✅ Scapy working')"
# Expected: ✅ Scapy working

# 3. Test network interface access
python -c "from scapy.all import get_if_list; print(get_if_list())"
# Expected: List of network interfaces

# 4. Check Windows Defender exclusions
Get-MpPreference | Select-Object ExclusionPath
# Expected: Should include workspace and Npcap paths

# 5. Test firewall rules
Test-NetConnection -ComputerName 192.168.68.111 -Port 60000
# Expected: TcpTestSucceeded = True (if dashboard is running)

# 6. Run network monitor (requires Admin)
python server\network_monitor.py
# Expected: No AV blocks, packet capture starts
```

---

## Common Issues and Solutions

### Issue 1: "Permission Denied" or "Access Denied"
**Cause:** Not running as Administrator  
**Solution:** Right-click PowerShell → Run as Administrator

### Issue 2: Npcap Service Not Starting
**Cause:** Windows Defender blocking driver load  
**Solution:** Add `C:\Windows\System32\drivers\npcap.sys` to exclusions

### Issue 3: Scapy Cannot Find Interfaces
**Cause:** Npcap not installed in WinPcap compatibility mode  
**Solution:** Reinstall Npcap with "WinPcap API-compatible Mode" checked

### Issue 4: Enterprise AV Quarantines Python
**Cause:** ML model files (.pkl, .keras) flagged as suspicious  
**Solution:** Add file extension exclusions (.pkl, .keras, .h5)

### Issue 5: Network Monitoring Extremely Slow
**Cause:** EDR performing deep packet inspection on every packet  
**Solution:** Add behavioral exclusion for "Packet Capture" activity

### Issue 6: Firewall Blocks Outbound Connections
**Cause:** Threat intel API calls (VirusTotal, AbuseIPDB) blocked  
**Solution:** Add outbound firewall rules for specific domains

---

## Production Deployment Recommendations

### For Enterprise Networks:

**✅ Best Practice:**
1. Deploy Battle-Hardened AI on **dedicated security appliance** (not user workstations)
2. Use **service account** with minimum required privileges (not SYSTEM)
3. Configure **centralized logging** to SIEM (Splunk, QRadar, Sentinel)
4. Enable **read-only monitoring** (disable auto-block in production initially)
5. Whitelist in **central management console** (Group Policy, Intune)

**❌ Don't Do This:**
- Installing on every endpoint (use Linux gateway instead)
- Disabling all AV/EDR (only exclude Battle-Hardened AI paths)
- Running as SYSTEM without audit logging
- Auto-blocking without human review in production

---

## Summary: Minimum Required Exclusions

### Windows Defender (Minimum)
```powershell
Add-MpPreference -ExclusionPath "C:\Users\kidds\workspace\battle-hardened-ai"
Add-MpPreference -ExclusionPath "C:\Program Files\Npcap"
Add-MpPreference -ExclusionProcess "python.exe"
Add-MpPreference -ExclusionExtension ".pcap"
```

### Enterprise AV (Minimum)
- Whitelist workspace path
- Allow Python network monitoring behavior
- Exclude Npcap driver from deep inspection

### Firewall (Minimum)
- Allow inbound TCP 60000, 60001
- Allow Python.exe network access

**That's it. With these exclusions, Battle-Hardened AI will work alongside enterprise security without conflicts.**
