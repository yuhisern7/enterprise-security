# 🗄️ Attack Signature Database Architecture

## Overview

Centralized PostgreSQL database at relay server stores **ONLY attack signatures** for ML training.

**Privacy Guarantee:** NO customer data, NO device info, NO network topology, NO exploit code.

---

## 📊 Database Schema

### Tables Created

1. **attack_signatures** - Extracted attack patterns (ML training data)
2. **threat_intelligence** - Aggregated statistics (anonymous)
3. **training_batches** - Versioned ML datasets
4. **signature_updates** - Distribution log
5. **payload_deletion_log** - Audit trail (proof payloads deleted)

---

## 🔄 Data Flow: Node → Relay Database

```
┌─────────────────────────────────────────────────────────────────┐
│  SECURITY NODE (Customer's Server)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Attack Detected                                             │
│     └─> pcs_ai.py detects SQL Injection attempt                │
│                                                                 │
│  2. Signature Extraction                                        │
│     └─> Extract keywords: ["SELECT", "UNION", "FROM"]          │
│     └─> Extract encodings: ["url_encoded"]                     │
│     └─> Extract ML features: {keyword_count: 3, ...}           │
│                                                                 │
│  3. PAYLOAD DELETION ❌                                         │
│     └─> DELETE attack payload immediately                      │
│     └─> DELETE exploit code                                    │
│     └─> Only keep pattern hash                                 │
│                                                                 │
│  4. Send Signature to Relay                                     │
│     └─> signature_uploader.py                                  │
│     └─> Validates NO prohibited data                           │
│     └─> Sends via WebSocket to relay:60001                     │
│                                                                 │
│     Message Format:                                             │
│     {                                                           │
│       "type": "signature_upload",                               │
│       "signature": {                                            │
│         "attack_type": "SQL Injection",                         │
│         "keywords": ["SELECT", "UNION"],                        │
│         "encodings": ["url_encoded"],                           │
│         "payload_length": 156,                                  │
│         "ml_features": {...}                                    │
│       }                                                         │
│     }                                                           │
│                                                                 │
│  ❌ NEVER SENT:                                                 │
│     - device_list                                               │
│     - network_topology                                          │
│     - ip_addresses (customer IPs)                               │
│     - blocked_ips                                               │
│     - whitelist                                                 │
│     - connected_devices                                         │
│     - exploit_code                                              │
│     - attack_payload                                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ WebSocket (ws://relay:60001)
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  RELAY SERVER (VPS)                                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  5. Receive Signature                                           │
│     └─> relay_server.py receives WebSocket message             │
│     └─> Extracts source IP (for anonymous region only)         │
│                                                                 │
│  6. Validate & Enrich                                           │
│     └─> signature_sync.py validates signature                  │
│     └─> Check for prohibited fields                            │
│     └─> Generate pattern_hash (SHA256)                         │
│     └─> Anonymize region: IP → "Asia" (NOT exact IP)           │
│     └─> Calculate complexity score                             │
│                                                                 │
│  7. Store in PostgreSQL                                         │
│     └─> database.py inserts into attack_signatures table       │
│     └─> Check for duplicates (by pattern_hash)                 │
│     └─> If duplicate: increment occurrence_count               │
│     └─> If new: insert with signature_id                       │
│                                                                 │
│  8. Audit Trail                                                 │
│     └─> Log to payload_deletion_log                            │
│     └─> Verify exploit_code_stored = FALSE                     │
│                                                                 │
│  9. Update Statistics                                           │
│     └─> Update threat_intelligence table                       │
│     └─> Aggregate attack_type counts                           │
│     └─> Calculate regional distribution                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ PostgreSQL
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  POSTGRESQL DATABASE                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  attack_signatures table:                                       │
│  ┌──────────────┬──────────────┬─────────────┬──────────────┐  │
│  │ signature_id │ pattern_hash │ attack_type │ keywords     │  │
│  ├──────────────┼──────────────┼─────────────┼──────────────┤  │
│  │ 1            │ a3f9b2c8...  │ SQL Inj     │ ["SELECT",   │  │
│  │ 2            │ 7e4d5f67...  │ XSS         │ ["<script>", │  │
│  │ 3            │ 9a1c3e5b...  │ Cmd Inj     │ ["eval(",    │  │
│  └──────────────┴──────────────┴─────────────┴──────────────┘  │
│                                                                 │
│  ✅ STORED:                                                     │
│     - Pattern hash (unique identifier)                          │
│     - Attack type classification                                │
│     - Keywords (NOT full payload)                               │
│     - Encodings (types, NOT content)                            │
│     - ML features (statistics)                                  │
│     - Anonymous region ("Asia", NOT IP)                         │
│     - Occurrence count (how many times seen)                    │
│                                                                 │
│  ❌ NOT STORED:                                                 │
│     - Customer ID                                               │
│     - Device lists                                              │
│     - Network topology                                          │
│     - Exact IP addresses                                        │
│     - Exploit code/payloads                                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Setup Instructions

### 1. Start Relay Server with Database

```bash
cd relay/
docker-compose up -d
```

This starts:
- PostgreSQL (port 5432)
- Relay server (port 60001)

### 2. Database Initialization

Database schema is created automatically on first start by `database.py`

To manually initialize:
```bash
docker exec -it attack-signature-db psql -U battlehardened -d attack_signatures
```

### 3. Configure Security Nodes

Each security node needs to send signatures to relay.

In `pcs_ai.py`, after signature extraction:

```python
from signature_uploader import upload_signature_sync

# After extracting signature
signature = {
    'attack_type': attack_type,
    'keywords': keywords_detected,
    'encodings': encodings_found,
    'payload_length': len(original_payload),
    'ml_features': ml_feature_vector
}

# Upload to relay (async, non-blocking)
upload_signature_sync(signature, relay_url="ws://your-vps-ip:60001")
```

---

## 📊 Database Queries

### Get Total Signatures
```sql
SELECT COUNT(*) FROM attack_signatures;
```

### Get Signatures by Type
```sql
SELECT attack_type, COUNT(*) as count
FROM attack_signatures
GROUP BY attack_type
ORDER BY count DESC;
```

### Get Most Common Keywords
```sql
SELECT 
    jsonb_array_elements_text(keywords) as keyword,
    COUNT(*) as frequency
FROM attack_signatures
GROUP BY keyword
ORDER BY frequency DESC
LIMIT 20;
```

### Get Regional Distribution
```sql
SELECT 
    source_region,
    COUNT(*) as attacks,
    COUNT(DISTINCT attack_type) as unique_types
FROM attack_signatures
GROUP BY source_region
ORDER BY attacks DESC;
```

### Verify NO Exploit Code Stored
```sql
SELECT COUNT(*) FROM payload_deletion_log WHERE exploit_code_stored = TRUE;
-- Should return: 0
```

---

## 🔒 Privacy Verification Checklist

- [ ] Database stores ONLY pattern hashes (no payloads)
- [ ] IP addresses anonymized to regions
- [ ] NO customer_id column exists
- [ ] NO device_list column exists
- [ ] NO network_topology column exists
- [ ] `exploit_code_stored` always FALSE in audit log
- [ ] Signature uploader validates prohibited fields
- [ ] Database accessible ONLY to relay server (firewall)

---

## 📈 Data Volume Estimates

**Current Status (Phase 1):**
- 743 real attacks detected
- ~200 bytes per signature
- **Total DB Size:** ~148 KB

**After 1 Month (100 nodes):**
- ~500,000 signatures
- ~200 bytes each
- **Total DB Size:** ~100 MB

**After 1 Year (1,000 nodes):**
- ~50 million signatures
- ~200 bytes each (+ indexes)
- **Total DB Size:** ~15 GB

**Conclusion:** PostgreSQL easily handles this volume.

---

## 🔄 Backup & Recovery

### Automated Backups
```bash
# Daily backup (add to cron)
docker exec attack-signature-db pg_dump -U battlehardened attack_signatures > backup_$(date +%Y%m%d).sql
```

### Restore from Backup
```bash
docker exec -i attack-signature-db psql -U battlehardened attack_signatures < backup_20260101.sql
```

---

## 🚀 Future Enhancements (Phase 2)

1. **Real-time Dashboard**
   - Live signature ingestion stats
   - Attack type distribution charts
   - Geographic heat maps (regions, not IPs)

2. **ML Training Pipeline**
   - Automated model retraining (every 6 hours)
   - Use signatures from database as training data
   - Distribute updated models to all nodes

3. **Threat Intelligence API**
   - `/api/signatures/search?type=SQL`
   - `/api/statistics/global`
   - `/api/patterns/trending`

4. **Signature Sharing Network**
   - Premium tier: Access to full signature database
   - Free tier: Access to own signatures + 10% sample

---

## 📝 Files Created

| File | Location | Purpose |
|------|----------|---------|
| `database.py` | relay/ | PostgreSQL schema & queries |
| `signature_sync.py` | relay/ | Signature ingestion service |
| `signature_uploader.py` | AI/ | Node-side signature uploader |
| `docker-compose.yml` | relay/ | PostgreSQL + Relay containers |
| `requirements.txt` | relay/ | Added psycopg2-binary |

---

## 🎯 Summary

**Database Created:** ✅ PostgreSQL at relay server  
**Schema:** ✅ 5 tables (attack_signatures, threat_intelligence, etc.)  
**Signature Upload:** ✅ WebSocket from nodes to relay  
**Privacy Compliant:** ✅ NO customer data, NO exploit code  
**Audit Trail:** ✅ payload_deletion_log verifies compliance  

**Data Flow:** Attack → Extract Signature → Delete Payload → Upload Hash → Store in DB → Train ML → Distribute Models

**Privacy:** Customer device lists, IPs, topology NEVER leave local server. Only anonymous attack patterns stored.
