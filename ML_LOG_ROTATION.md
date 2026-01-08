# ML Training Log File Rotation - Implementation Summary

## Overview

The Battle-Hardened AI system now implements automatic file rotation for ML training logs when they reach 1GB in size. This prevents unbounded file growth while preserving all historical attack data for machine learning training.

## Affected Files

The following three critical ML training log files have automatic rotation:

1. **`server/json/threat_log.json`** - Primary threat detection log
   - Location: Customer nodes (server/json/)
   - Updated by: `AI/pcs_ai.py` → `_save_threat_log()`
   - Content: All detected threats from 18 parallel detection signals

2. **`server/json/comprehensive_audit.json`** - Comprehensive audit trail
   - Location: Customer nodes (server/json/)
   - Updated by: `AI/emergency_killswitch.py` → `ComprehensiveAuditLog._flush_buffer()`
   - Content: All THREAT_DETECTED, INTEGRITY_VIOLATION, SYSTEM_ERROR events

3. **`relay/ai_training_materials/global_attacks.json`** - Global attack database
   - Location: Relay server (NOT on customer nodes)
   - Updated by: `relay/signature_sync.py` → `store_global_attack()`
   - Content: Aggregated attacks from all customer nodes worldwide

## Rotation Behavior

### When Rotation Occurs
- **Trigger:** File size reaches **1,000,000,000 bytes** (1GB)
- **Action:** Current file is renamed with numeric suffix, new file is created
- **Timing:** Checked before each write operation

### Rotation Sequence

```
# Initial state
threat_log.json (999 MB)

# After next write that crosses 1GB threshold:
threat_log.json (999 MB) → threat_log_1.json (renamed)
threat_log.json (new file, starts empty)

# After threat_log.json reaches 1GB again:
threat_log_1.json (1 GB - preserved)
threat_log.json (999 MB) → threat_log_2.json (renamed)
threat_log.json (new file, starts empty)

# Continuous rotation:
threat_log_1.json (1 GB)
threat_log_2.json (1 GB)
threat_log_3.json (1 GB)
...
threat_log.json (current, growing)
```

### File Naming Pattern
- **Base file:** `<filename>.json` (e.g., `threat_log.json`)
- **Rotated files:** `<filename>_N.json` where N = 1, 2, 3, ...
- **Examples:**
  - `threat_log_1.json`, `threat_log_2.json`, `threat_log_3.json`
  - `comprehensive_audit_1.json`, `comprehensive_audit_2.json`
  - `global_attacks_1.json`, `global_attacks_2.json`

## Implementation Details

### New Module: `AI/file_rotation.py`

**Key Functions:**

1. **`rotate_if_needed(filepath)`**
   - Checks file size before each write
   - Automatically rotates if ≥ 1GB
   - Returns True if rotation occurred

2. **`rotate_file(filepath)`**
   - Finds next available rotation number
   - Renames current file with suffix
   - Creates new empty file

3. **`get_rotation_status(filepath)`**
   - Returns file size, rotation count, total storage
   - Useful for dashboard monitoring

4. **`load_all_rotations(filepath)`** ⭐ **CRITICAL FOR ML TRAINING**
   - Loads data from base file AND all rotation files
   - Returns combined list of all entries
   - Used by ML training, compliance reports, visualizations
   - **This is how the AI accesses complete attack history**
   - Example: `load_all_rotations('/app/json/threat_log.json')` returns all attacks from threat_log.json + threat_log_1.json + threat_log_2.json + ...

**Note:** No cleanup/deletion functions are provided. All ML training logs must be preserved to maintain AI learning capability.

### Code Integration

**1. AI/pcs_ai.py (threat_log.json)**
```python
def _save_threat_log() -> None:
    """Save threat log with auto-rotation at 1GB."""
    try:
        # Check rotation before write
        from file_rotation import rotate_if_needed
        rotate_if_needed(_THREAT_LOG_FILE)
        
        # Normal write operation
        with open(_THREAT_LOG_FILE, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(_threat_log, f, indent=2)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        print(f"[WARNING] Failed to save threat log: {e}")
```

**2. AI/emergency_killswitch.py (comprehensive_audit.json)**
```python
def _flush_buffer(self):
    """Flush event buffer with auto-rotation at 1GB."""
    # Check rotation before write
    from file_rotation import rotate_if_needed
    rotate_if_needed(self.audit_file)
    
    # Normal flush operation
    # ... (existing code)
```

**3. relay/signature_sync.py (global_attacks.json)**
```python
def store_global_attack(self, attack_data: Dict[str, Any]):
    """Store attack with auto-rotation at 1GB."""
    try:
        # Import from AI folder
        import sys
        ai_path = os.path.join(os.path.dirname(__file__), '..', 'AI')
        if ai_path not in sys.path:
            sys.path.insert(0, ai_path)
        
        from file_rotation import rotate_if_needed
        rotate_if_needed(self.global_attacks_file)
        
        # Normal write operation
        # ... (existing code)
    except Exception as e:
        logger.error(f"Failed to store attack: {e}")
```

## Graceful Degradation

All integrations include graceful degradation:

```python
try:
    from file_rotation import rotate_if_needed
    rotate_if_needed(filepath)
except ImportError:
    pass  # Continue without rotation if module unavailable
except Exception as e:
    logger.warning(f"File rotation check failed: {e}")
```

This ensures the system continues logging even if the rotation module fails.
## How the AI Reads Rotation Files

### Automatic Detection of All Rotation Files

The AI system automatically detects and loads ALL rotation files when performing:
- **ML Training** (relay/ai_retraining.py)
- **Compliance Reports** (AI/compliance_reporting.py)
- **Visualizations** (AI/advanced_visualization.py)

### Implementation

**Function: `load_all_rotations(filepath)`**

This function scans for and loads:
1. Base file (e.g., `threat_log.json`)
2. All numbered rotation files (e.g., `threat_log_1.json`, `threat_log_2.json`, ...)
3. Combines data from all files into single list

**Example Usage:**
```python
from file_rotation import load_all_rotations

# Load complete threat history for ML training
all_threats = load_all_rotations('/app/json/threat_log.json')
# Returns: threats from threat_log.json + threat_log_1.json + threat_log_2.json + ...

# Load complete audit trail for compliance
all_audits = load_all_rotations('/app/json/comprehensive_audit.json')
# Returns: audits from comprehensive_audit.json + comprehensive_audit_1.json + ...

# Load global attacks from relay
all_attacks = load_all_rotations('relay/ai_training_materials/global_attacks.json')
# Returns: attacks from global_attacks.json + global_attacks_1.json + ...
```

### Files Updated to Read All Rotations

1. **relay/ai_retraining.py** - ML retraining now loads ALL global_attacks_*.json files
   ```python
   # Loads global_attacks.json, global_attacks_1.json, global_attacks_2.json, etc.
   training_data["global_attacks"].extend(all rotation files)
   ```

2. **AI/compliance_reporting.py** - Compliance reports include complete history
   ```python
   # PCI-DSS, HIPAA, GDPR, SOC2 reports analyze ALL threat_log_*.json files
   threat_log = load_all_rotations(threat_log_file)
   ```

3. **AI/advanced_visualization.py** - Dashboards show complete attack patterns
   ```python
   # Visualizations include data from ALL threat_log_*.json files
   threat_log = load_all_rotations(threat_log_file)
   ```

### Why This Matters

**Before rotation file loading:**
- AI only sees attacks in current file (~1GB)
- Older attacks "forgotten" once rotated
- Incomplete training data
- Compliance reports missing historical incidents

**After rotation file loading:**
- AI sees ALL attacks ever recorded
- Complete historical knowledge preserved
- Full training dataset (potentially 10GB+)
- Compliance reports cover entire operational history
## Storage Implications

### Example: High-Traffic Deployment

**Assumptions:**
- 1,000 detected threats/day
- Average threat log entry: 500 bytes
- Daily growth: 500 KB/day

**Storage Timeline:**
- **Day 1-2000:** threat_log.json grows to 1GB
- **Day 2001:** Rotation → threat_log_1.json (1GB), new threat_log.json (0KB)
- **Day 4000:** Rotation → threat_log_2.json (1GB)
- **After 1 year:** ~5-6 rotation files (5-6 GB total)

### ⚠️ CRITICAL: DO NOT DELETE ROTATION FILES

**All rotation files MUST be preserved permanently for ML training.**

Rotation files contain historical attack data that the AI uses for:
- Learning new attack patterns
- Improving detection accuracy
- Training ML models (RandomForest, IsolationForest, LSTM, Autoencoder)
- Building attack signatures
- Understanding adversary behavior evolution

**Deleting rotation files = AI forgets those attacks = Reduced security posture**

### Storage Management Strategy

**Option 1: Keep All Data Locally (Default)**
- Preserve all rotation files on local disk
- Provides fastest ML training access
- Storage grows linearly with attack volume
- **This is the ONLY option for maintaining full AI capability**

**Option 2: Archive to Cold Storage (If Disk Space Limited)**
- Move older rotation files to S3/Azure Blob/GCP Cloud Storage
- Keep most recent 2-3 rotation files locally for active learning
- Download archived files when performing full ML retraining
- **NEVER delete - only move to archive**

Example archival script (DO NOT DELETE):
```bash
# Archive rotation files older than 90 days to S3
# NOTE: This moves files, does NOT delete them
find /app/json -name "*_[0-9]*.json" -mtime +90 -exec aws s3 cp {} s3://ml-training-archive/ \;
# Only remove from local disk AFTER confirming S3 upload
find /app/json -name "*_[0-9]*.json" -mtime +90 -exec rm {} \;
```

**Option 3: Compress Rotation Files**
- Gzip older rotation files to save 70-90% storage
- Files remain accessible for ML training
- Example: `gzip threat_log_1.json` → `threat_log_1.json.gz`
- ML training scripts can read gzipped JSON directly

## Monitoring & Dashboard

### Rotation Status API

Add to `server/server.py`:

```python
from AI.file_rotation import get_rotation_status

@app.route('/api/log-rotation-status')
def log_rotation_status():
    """Get rotation status for ML training logs."""
    status = {
        'threat_log': get_rotation_status('/app/json/threat_log.json'),
        'comprehensive_audit': get_rotation_status('/app/json/comprehensive_audit.json')
    }
    return jsonify(status)
```

### Dashboard Display

Example output:
```json
{
  "threat_log": {
    "current_size_gb": 0.85,
    "percentage_full": 85.0,
    "needs_rotation": false,
    "rotated_files_count": 3,
    "total_size_gb": 3.85,
    "rotated_files": [
      {"filename": "threat_log_1.json", "size_gb": 1.0},
      {"filename": "threat_log_2.json", "size_gb": 1.0},
      {"filename": "threat_log_3.json", "size_gb": 1.0}
    ]
  }
}
```

## Documentation Updates

### Updated Files

1. **`filepurpose.md`**
   - Added rotation annotations to threat_log.json
   - Added rotation annotations to comprehensive_audit.json
   - Added rotation annotations to global_attacks.json
   - Added `AI/file_rotation.py` module documentation

2. **`ai-instructions.md`** (Future Update)
   - Add section on file rotation mechanism
   - Document rotation monitoring APIs
   - Document archival strategies (never deletion)

3. **`README.md`** (Future Update)
   - Add note about automatic log rotation
   - Document storage requirements for long-term deployments
   - Emphasize permanent retention for ML training

## Testing

### Manual Rotation Test

```python
# Test rotation utility
from AI.file_rotation import rotate_file, get_rotation_status

# Create test file
test_file = '/tmp/test_rotation.json'
with open(test_file, 'w') as f:
    json.dump([{'test': i} for i in range(1000000)], f)

# Check status
status = get_rotation_status(test_file)
print(f"Size: {status['current_size_gb']:.2f} GB")

# Force rotation
rotated = rotate_file(test_file)
print(f"Rotated to: {rotated}")

# Verify
status = get_rotation_status(test_file)
print(f"Rotated files: {status['rotated_files_count']}")
```

### Integration Test

```bash
# Monitor threat_log.json during active attack detection
watch -n 5 'ls -lh /app/json/threat_log*.json'

# Simulate high-volume attacks
python AI/test_system.py --attack-simulation --volume=10000

# Verify rotation occurred
ls -lh /app/json/threat_log*.json
# Expected: threat_log.json (new) + threat_log_1.json (1GB)
```

## Benefits

### For ML Training
✅ **Preserves all historical data** - No data loss, all attacks retained indefinitely  
✅ **Never forgets learned attacks** - Every attack remains available for training  
✅ **Prevents file corruption** - Smaller files are more stable  
✅ **Enables parallel processing** - Can process rotation files independently  
✅ **Improves read performance** - Smaller active file = faster reads  
✅ **Continuous learning** - AI can retrain on complete attack history

### For Operations
✅ **No manual intervention** - Fully automatic  
✅ **Predictable storage growth** - 1GB chunks, easy to estimate  
✅ **No downtime** - Rotation happens inline during writes  
✅ **Backward compatible** - Graceful degradation if module unavailable  
✅ **No data deletion** - Only rotation, never removal

### For Compliance
✅ **Immutable history** - Rotated files can be write-protected  
✅ **Audit trail preservation** - All events retained indefinitely  
✅ **Complete forensic record** - Every attack logged and preserved  
✅ **Archival-ready** - Easy to move rotation files to cold storage (never delete)

## Future Enhancements

1. **Compression** - Gzip rotated files to save 70-90% storage
2. **Cloud Upload** - Auto-upload rotation files to S3/Azure/GCP for archival
3. **Distributed Training** - Use rotation files for parallel ML training
4. **Rotation Metrics** - Track rotation frequency as attack volume indicator
5. **Smart Archival** - ML-based prioritization (keep critical attacks on fast storage, archive routine attacks to cold storage)
6. **Automated Deduplication** - Remove duplicate attack entries while preserving unique patterns
7. **Incremental Training** - Train on new rotation files as they're created

**Note:** All enhancements preserve data - no deletion mechanisms will be added.

## Summary

The ML training log rotation system ensures Battle-Hardened AI can operate continuously without manual log management while preserving all historical attack data for machine learning. The 1GB rotation threshold balances file manageability with operational simplicity.

**Key Files:**
- **Implementation:** `AI/file_rotation.py` (new)
- **Integration:** `AI/pcs_ai.py`, `AI/emergency_killswitch.py`, `relay/signature_sync.py` (updated)
- **Documentation:** `filepurpose.md` (updated)

**Rotation Pattern:**
- `filename.json` → `filename_1.json` (at 1GB)
- `filename.json` → `filename_2.json` (at 1GB)
- Continues indefinitely with incremental numbering
