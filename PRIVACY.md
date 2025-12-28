# 🔒 Privacy-Preserving P2P Learning

## Overview

Each Docker container shows **ONLY its own attacks** on the dashboard, while the AI **learns from ALL attacks** across the entire P2P mesh network. This creates a privacy-preserving collective intelligence system.

## How It Works

### 🎯 The Problem We Solved

**Before (No Privacy):**
- Container A detects SQL injection attack → shown on Container A dashboard ✅
- Container A shares threat with Container B via P2P
- Container B's dashboard shows Container A's attack ❌ **PRIVACY VIOLATION**

**After (Privacy-Preserving):**
- Container A detects SQL injection attack → shown on Container A dashboard ✅
- Container A shares threat with Container B via P2P
- Container B's AI learns from it (better detection) ✅
- Container B's dashboard does NOT show Container A's attack ✅ **PRIVACY PRESERVED**

### 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTAINER A                              │
│                                                             │
│  ┌──────────────┐         ┌─────────────────────────────┐ │
│  │  Dashboard   │         │  AI Training Engine         │ │
│  │              │         │                             │ │
│  │  Shows:      │         │  Learns from:               │ │
│  │  • Local: 10 │◀────────│  • Local threats: 10        │ │
│  │  • Peer: 0   │         │  • Peer threats: 25         │ │
│  │              │         │  • Total: 35 samples        │ │
│  └──────────────┘         └─────────────────────────────┘ │
│         ▲                           ▲                      │
│         │                           │                      │
│         │                           │ P2P Sync             │
└─────────┼───────────────────────────┼──────────────────────┘
          │                           │
          │ PUBLIC                    │ PRIVATE
          │ (Dashboard)               │ (AI Training)
          │                           │
┌─────────┼───────────────────────────┼──────────────────────┐
│         │                           │                      │
│  ┌──────────────┐         ┌─────────────────────────────┐ │
│  │  Dashboard   │         │  AI Training Engine         │ │
│  │              │         │                             │ │
│  │  Shows:      │         │  Learns from:               │ │
│  │  • Local: 25 │◀────────│  • Local threats: 25        │ │
│  │  • Peer: 0   │         │  • Peer threats: 10         │ │
│  │              │         │  • Total: 35 samples        │ │
│  └──────────────┘         └─────────────────────────────┘ │
│                                                             │
│                    CONTAINER B                              │
└─────────────────────────────────────────────────────────────┘
```

## Technical Implementation

### 📊 Threat Storage Separation

```python
# Two separate threat storage locations:

_threat_log: List[Dict] = []     # LOCAL threats (public, shown on dashboard)
_peer_threats: List[Dict] = []   # PEER threats (private, AI training only)
```

### 🔐 Threat Logging

When a threat is detected or received, it's marked with its source:

```python
def _log_threat(threat_type, ip, details, severity, is_local: bool = True):
    """
    Log a threat event
    
    Args:
        is_local: True if detected locally, False if received from peer
    """
    event = {
        'timestamp': datetime.now().isoformat(),
        'type': threat_type,
        'ip': ip,
        'details': details,
        'severity': severity,
        'source': 'local' if is_local else 'peer'  # Track source
    }
    
    if is_local:
        _threat_log.append(event)  # Shown on dashboard, saved to disk
        _save_threat_log()
    else:
        _peer_threats.append(event)  # AI training only, memory-only
```

### 🧠 ML Training (Collective Intelligence)

The AI trains on **combined threats** from all sources:

```python
def train_ml_models():
    """Train ML models on ALL threat data (local + peer)"""
    
    # Combine local and peer threats for training
    all_threats = _threat_log + _peer_threats
    
    local_count = len(_threat_log)
    peer_count = len(_peer_threats)
    
    print(f"[AI] Training ML models with {len(all_threats)} threat events")
    print(f"     • Local threats: {local_count}")
    print(f"     • Peer threats: {peer_count}")
    print(f"[AI] 🔒 Privacy: Dashboard shows only {local_count} local threats")
    print(f"     but AI learns from all {len(all_threats)} threats")
    
    # Train on combined data
    model.fit(all_threats)
```

### 🌐 P2P Integration

When receiving threats from peers via P2P:

```python
@app.route('/api/p2p/threats', methods=['POST'])
def receive_peer_threats():
    """Receive threats from peer container"""
    data = request.get_json()
    threats = data.get('threats', [])
    
    for threat in threats:
        # Add to PEER threat log (AI training only, NOT dashboard)
        add_global_threat_to_learning(threat)  # is_local=False internally
```

### 📺 Dashboard Display

Dashboard shows **ONLY local threats**:

```python
@app.route('/')
def dashboard():
    """Render dashboard with local threats only"""
    return render_template('dashboard.html',
        threat_logs=pcs_ai._threat_log[-100:][::-1]  # Only local threats
    )
```

## Benefits

### 🔒 Privacy Protection
- **No data leakage**: Other containers' attack details remain private
- **Compliance**: Sensitive information not exposed publicly
- **Trust**: Organizations can join P2P mesh without privacy concerns

### 🧠 Collective Intelligence
- **Better detection**: AI learns from ALL attacks across the network
- **Faster adaptation**: New attack patterns learned immediately
- **Network effect**: More containers = smarter AI for everyone

### 📊 Transparency
- **Clear visibility**: Dashboard shows "35 samples: 10 local + 25 peer"
- **Source tracking**: Each threat marked as 'local' or 'peer'
- **Audit trail**: Local threats saved to disk, peer threats in memory

## Example Scenario

### Setup
- **Container A**: Home WiFi (192.168.1.100)
- **Container B**: Office Network (10.0.0.50)
- **Container C**: Cloud Server (203.0.113.10)

### Attack Sequence

1. **SQL Injection on Container A**
   ```
   Container A detects: SQL injection from 203.0.113.25
   ├─ Container A dashboard: ✅ Shows attack
   ├─ Container B dashboard: ❌ No visibility (privacy)
   ├─ Container C dashboard: ❌ No visibility (privacy)
   │
   └─ P2P Sync (background)
      ├─ Container A → shares threat with B and C
      ├─ Container B AI: ✅ Learns from attack
      └─ Container C AI: ✅ Learns from attack
   ```

2. **Similar Attack on Container B**
   ```
   Container B detects: SQL injection from 203.0.113.30
   ├─ Container B's AI: ✅ Recognizes pattern (learned from A)
   ├─ Container B: ✅ Blocks instantly (smart detection)
   └─ Container B dashboard: ✅ Shows its own attack only
   ```

3. **Dashboard Privacy Verification**
   ```
   Container A Dashboard:
   ┌─────────────────────────────────────────────┐
   │ Recent Threats (Showing: 1 local)          │
   ├─────────────────────────────────────────────┤
   │ • SQL Injection from 203.0.113.25          │
   │   Source: local | Time: 2025-12-28 21:15   │
   └─────────────────────────────────────────────┘
   
   Container B Dashboard:
   ┌─────────────────────────────────────────────┐
   │ Recent Threats (Showing: 1 local)          │
   ├─────────────────────────────────────────────┤
   │ • SQL Injection from 203.0.113.30          │
   │   Source: local | Time: 2025-12-28 21:16   │
   └─────────────────────────────────────────────┘
   
   Container A does NOT see Container B's attack ✅
   Container B does NOT see Container A's attack ✅
   
   But both AIs learned from BOTH attacks ✅
   ```

## ML Training Status Display

The dashboard now shows transparent ML training statistics:

```
ML Models: ✅ Active
├─ 3 models trained (35 samples: 10 local + 25 peer)
├─ IsolationForest: Anomaly detection
├─ RandomForest: Threat classification  
└─ GradientBoosting: IP reputation
```

This clearly shows:
- **Total training data**: 35 samples
- **Your attacks**: 10 local
- **Peer attacks**: 25 peer (private, AI training only)

## Data Persistence

### Local Threats (Saved to Disk)
```json
// /app/json/threat_log.json
[
  {
    "timestamp": "2025-12-28T21:15:32",
    "type": "SQL_INJECTION",
    "ip": "203.0.113.25",
    "source": "local"
  }
]
```

### Peer Threats (Memory Only)
```python
# Stored in _peer_threats list (not saved to disk)
# Privacy: Deleted when container restarts
# Purpose: AI training only during current session
```

## Security Considerations

### ✅ What IS Shared via P2P
- Threat type (e.g., "SQL_INJECTION")
- Attacking IP address
- Timestamp
- Severity level
- Detection patterns

### ❌ What is NOT Shared
- **Dashboard visibility**: Peer threats never shown
- **Disk persistence**: Peer threats not saved locally
- **API exposure**: No endpoints return peer threats
- **Log files**: Peer threats not in persistent logs

### 🔐 Privacy Guarantees
1. **Dashboard isolation**: Only YOUR attacks visible
2. **API isolation**: Endpoints return only local threats
3. **Storage isolation**: Peer threats never persisted to disk
4. **Memory-only**: Peer threats deleted on container restart

## Configuration

No additional configuration needed! Privacy is enabled by default in all containers.

### Verify Privacy is Working

Check the logs when the container starts:

```bash
docker logs enterprise-security-ai | grep Privacy
```

Expected output:
```
[AI] 🔒 Privacy: Dashboard shows only 10 local threats, but AI learns from all 35
```

## Benefits Summary

| Feature | Without Privacy | With Privacy |
|---------|----------------|--------------|
| **Dashboard** | Shows ALL threats from ALL containers | Shows ONLY your own threats ✅ |
| **AI Training** | Learns from all threats | Learns from all threats ✅ |
| **Data Leakage** | Other containers' attacks exposed ❌ | Other containers' attacks private ✅ |
| **Compliance** | Potential privacy violation ❌ | Privacy-preserving ✅ |
| **Trust** | Organizations hesitant to join | Organizations join confidently ✅ |
| **Intelligence** | Collective learning ✅ | Collective learning ✅ |

## FAQ

### Q: Why share threats with peers if they're not displayed?
**A:** The AI needs diverse training data to recognize new attack patterns. By sharing threat intelligence (without displaying it), all containers benefit from collective learning.

### Q: What if I want to see peer threats?
**A:** Privacy is a core security feature. Displaying peer threats would violate privacy and discourage participation in the P2P mesh.

### Q: Are peer threats saved to disk?
**A:** No. Peer threats are stored in memory only and deleted when the container restarts. This ensures privacy and compliance.

### Q: How many peer threats are stored?
**A:** Maximum 500 peer threats in memory (rolling buffer). Oldest threats are automatically removed when the limit is reached.

### Q: Can I disable privacy and see all threats?
**A:** Privacy protection is a core feature and cannot be disabled. This ensures consistent security and compliance across all P2P mesh participants.

### Q: Does privacy affect detection quality?
**A:** No! Your container's AI still learns from all threats (local + peer), so detection quality is **exactly the same** as if you could see peer threats. Privacy only affects **display**, not **detection**.

---

## Summary

**🔒 Privacy-Preserving P2P Learning** enables you to:

1. ✅ **See only YOUR attacks** on the dashboard (privacy)
2. ✅ **AI learns from EVERYONE** (collective intelligence)
3. ✅ **No data leakage** to other containers (compliance)
4. ✅ **Better detection** through shared learning (security)

**Result:** Privacy + Intelligence + Security = Trust in P2P collaboration

---

**Version:** 1.0  
**Last Updated:** 2025-12-28  
**Commit:** ba7e408
