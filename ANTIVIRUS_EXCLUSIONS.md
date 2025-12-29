# Antivirus Exclusion Folders

**⚠️ CRITICAL: Add these folders to your antivirus exclusions to prevent false positives**

Machine learning models and exploit signatures will trigger antivirus warnings. These are **NOT malware** - they are security research data used for threat detection.

---

## **Windows Defender Exclusions**

Add these folders in **Windows Security → Virus & threat protection → Manage settings → Exclusions**:

```
C:\Users\<YourUsername>\enterprise-security\AI\ml_models\
C:\Users\<YourUsername>\enterprise-security\AI\exploitdb\
C:\Users\<YourUsername>\enterprise-security\server\json\
```

**PowerShell command (Run as Administrator):**
```powershell
Add-MpPreference -ExclusionPath "C:\Users\$env:USERNAME\enterprise-security\AI\ml_models"
Add-MpPreference -ExclusionPath "C:\Users\$env:USERNAME\enterprise-security\AI\exploitdb"
Add-MpPreference -ExclusionPath "C:\Users\$env:USERNAME\enterprise-security\server\json"
```

---

## **Linux (if using ClamAV or similar)**

Add to `/etc/clamav/clamd.conf`:
```
ExcludePath /home/<username>/Downloads/workspace/enterprise-security/AI/ml_models
ExcludePath /home/<username>/Downloads/workspace/enterprise-security/AI/exploitdb
ExcludePath /home/<username>/Downloads/workspace/enterprise-security/server/json
```

---

## **What's in these folders?**

### **AI/ml_models/** (~50MB)
- `anomaly_detector.pkl` - ML model for zero-day attack detection
- `threat_classifier.pkl` - RandomForest threat classification
- `ip_reputation.pkl` - IP reputation scoring model
- `feature_scaler.pkl` - Feature normalization
- `threat_intelligence_crawled.json` - Global threat data

### **AI/exploitdb/** (~700MB - if downloaded)
- **46,475 exploit proof-of-concepts** from Exploit-DB
- Shellcode database
- Vulnerability signatures
- Used for **signature matching**, not execution

### **server/json/** (Runtime data)
- `ml_training_data.json` - ML training buffer
- `peer_threats.json` - P2P threat intelligence
- `blocked_ips.json` - Blocked IP list
- `threat_log.json` - Security event logs
- `device_history.json` - Network device tracking
- `network_monitor_state.json` - Port scan tracking

---

## **Why these get flagged?**

1. **ML models (.pkl files)** - Contain binary data that looks suspicious
2. **ExploitDB** - Contains real exploit code (for DETECTION, not execution)
3. **Threat logs** - May contain malicious payloads that were BLOCKED

**These are security research tools, not malware!**

---

## **Docker-Specific (Windows)**

If using Docker Desktop, also exclude:
```
C:\Users\<YourUsername>\AppData\Local\Docker\wsl\data\
```

This prevents Windows Defender from scanning Docker volumes (which slows down container I/O).

---

## **Verification**

After adding exclusions, run:
```bash
# Check ML models exist
ls -lh AI/ml_models/

# Check ExploitDB (if downloaded)
ls -lh AI/exploitdb/exploits/ | wc -l

# Check training data
ls -lh server/json/ml_training_data.json
```

**All should exist without antivirus quarantine!**
