# AI System Architecture & Implementation Guide

> **Purpose:** Technical implementation guide for developers. Explains how the 7-stage attack detection pipeline (documented in README) is implemented across AI modules, server components, and relay infrastructure.

---

## 0. Architecture Overview: 7-Stage Pipeline Implementation

**This system implements the README's 7-stage attack detection flow:**

```
Stage 1: Data Ingestion → Stage 2: 20 Parallel Detections → Stage 3: Ensemble Voting → 
Stage 4: Response Execution → Stage 5: Training Extraction → Stage 6: Relay Sharing → 
Stage 7: Continuous Learning
```

**Three deployment tiers:**

1. **Customer Node (server/ + AI/)** — Runs stages 1-5 locally, optionally connects to relay for stages 6-7
2. **AI Intelligence Layer (AI/)** — Implements all 20 detection signals and ensemble logic (stages 2-3)
3. **Central Relay (relay/)** — Operator-controlled training hub (stages 6-7, **NOT shipped to customers**)

---

## 1. Pipeline Implementation Map: README Flow → Code Modules

### Stage 1: Data Ingestion & Normalization

**README:** "📥 PACKET ARRIVES → 📊 Pre-processing (metadata extraction, normalization)"

**Implementation:**
- **Packet Capture:** `server/network_monitor.py` (eBPF/XDP or scapy-based)
- **Kernel Telemetry:** `AI/kernel_telemetry.py` (syscall correlation, Linux only)
- **System Logs:** `AI/system_log_collector.py` (auth logs, application logs)
- **Cloud APIs:** `AI/cloud_security.py` (AWS CloudTrail, Azure Activity, GCP Audit)
- **Device Discovery:** `server/device_scanner.py` (asset inventory)

**Data Flow:**
```
Raw packets → network_monitor.py → metadata extraction (IPs, ports, protocols, timestamps)
→ schema normalization → normalized event object
```

**JSON Persistence:** `server/json/` (or `/app/json/` in Docker)

**Stage 1 → Stage 2 Transition:**
1. Network monitor creates normalized event: `{"src_ip": "...", "dst_ip": "...", "src_port": ..., "protocol": "...", "timestamp": "...", ...}`
2. Event passed to `AI/pcs_ai.py` → `assess_threat(event)` method
3. `assess_threat()` orchestrates all 20 detection signals in parallel using the same event object
4. Each signal produces independent `DetectionSignal` object → fed into Stage 3 ensemble

---

### Stage 2: Parallel Multi-Signal Detection (20 Signals)

**README:** "⚡ 20 PARALLEL DETECTIONS (each signal produces independent threat assessment)"

**Implementation:** Each signal = independent AI module

**Primary Detection Signals (1-18):** Direct threat detection from network traffic and system events.

**Strategic Intelligence Layers (19-20):** Contextual analysis consuming outputs from signals 1-18.

| # | Signal | Module(s) | Model/Data | Output |
|---|--------|-----------|------------|--------|
| 1 | **Kernel Telemetry** | `AI/kernel_telemetry.py` | eBPF/XDP events | Syscall/network correlation |
| 2 | **Signatures** | `AI/threat_intelligence.py` | 3,066+ patterns | Pattern match confidence |
| 3 | **RandomForest** | `AI/pcs_ai.py` | `ml_models/threat_classifier.pkl` | Classification score |
| 4 | **IsolationForest** | `AI/pcs_ai.py` | `ml_models/anomaly_detector.pkl` | Anomaly score |
| 5 | **Gradient Boosting** | `AI/pcs_ai.py` | `ml_models/ip_reputation.pkl` | Reputation score |
| 6 | **Behavioral** | `AI/behavioral_heuristics.py` | 15 metrics + APT | Heuristic risk score |
| 7 | **LSTM** | `AI/sequence_analyzer.py` | `AI/ml_models/sequence_lstm.keras` | Kill-chain state |
| 8 | **Autoencoder** | `AI/traffic_analyzer.py` | `AI/ml_models/traffic_autoencoder.keras` | Reconstruction error |
| 9 | **Drift Detection** | `AI/drift_detector.py` | `drift_baseline.json` | KS/PSI drift score |
| 10 | **Graph Intelligence** | `AI/graph_intelligence.py` | `network_graph.json` | Lateral movement |
| 11 | **VPN/Tor Fingerprinting** | `AI/pcs_ai.py` | VPN/Tor statistics | De-anonymization |
| 12 | **Threat Intel** | `AI/threat_intelligence.py` | VirusTotal, AbuseIPDB | OSINT correlation |
| 13 | **False Positive Filter** | `AI/false_positive_filter.py` | FP config | 5-gate validation |
| 14 | **Reputation** | `AI/reputation_tracker.py` | `reputation.db` (SQLite) | Recidivism score |
| 15 | **Explainability** | `AI/explainability_engine.py` | Decision history | Transparency |
| 16 | **Predictive** | `AI/advanced_orchestration.py` | Threat predictions | 24-48h forecast |
| 17 | **Byzantine Defense** | `AI/byzantine_federated_learning.py` | Peer trust scores | Update rejection |
| 18 | **Integrity** | `AI/self_protection.py`, `AI/cryptographic_lineage.py` | Lineage chain | Tampering detection |
| 19 | **Causal Inference** | `AI/causal_inference.py` (new) | Config change logs, deployment events | Root cause classification |
| 20 | **Trust Degradation** | `AI/trust_graph.py` (new) | `trust_graph.json` (persistent) | Entity trust scores 0-100 |

**Orchestration:** `AI/pcs_ai.py` → `assess_threat()` → constructs `DetectionSignal` objects

**APT Enhancements:**
- **Behavioral (Signal #6):** `detect_low_and_slow()`, `detect_off_hours_activity()`, `detect_credential_reuse()`
- **LSTM (Signal #7):** Campaign pattern matching (slow_burn, smash_and_grab, lateral_spread)
- **Graph (Signal #10):** Weight increased 0.88→0.92 for lateral movement detection
- **Causal Inference (Signal #19):** Distinguishes APT "living off the land" (legitimate tools/timing) from actual attacks
- **Trust Degradation (Signal #20):** Persistent attacker tracking across IP rotation, VPN changes, and session resets

**Strategic Intelligence Layer Architecture:**

**Layer 19 (Causal Inference Engine):**
- **Position:** Runs AFTER signals 1-18, BEFORE final ensemble decision
- **Inputs:** DetectionSignal objects, system config change logs, deployment/CI events, identity events (login, privilege change), time-series metadata, network topology graph, cloud control-plane events
- **Forbidden Inputs:** Raw packet payloads, credentials, exploit code, PII
- **Core Logic:** Builds causal graphs (not correlations), tests counterfactuals ("Would this anomaly exist without this config change?"), classifies root cause
- **Causal Labels:** `LEGITIMATE_CAUSE`, `MISCONFIGURATION`, `AUTOMATION_SIDE_EFFECT`, `EXTERNAL_ATTACK`, `INSIDER_MISUSE`, `UNKNOWN_CAUSE`
- **Modulation:** Downgrade ensemble score if legitimate cause, boost if malicious cause, route to governance if misconfiguration, require human review if unknown
- **Output Format:** `CausalInferenceResult(causal_label, confidence, primary_causes[], non_causes[])`
- **Privacy:** Never directly blocks traffic, only modulates confidence and governance

**Layer 20 (Trust Degradation Graph):**
- **Position:** Influences Stage 4 response severity based on persistent entity trust state
- **Tracked Entities:** IP addresses, devices, user accounts, services, APIs, cloud roles, containers/workloads
- **Trust Score:** 0-100 per entity (internal starts at 100, external configurable baseline ~60)
- **Degradation Model:** Non-linear decay, event-weighted penalties (minor anomaly: -5, confirmed attack: -25, lateral movement: -30, integrity breach: -40)
- **Recovery:** +1 trust per 24h without incident (slow recovery, capped at initial baseline)
- **Trust Thresholds:** ≥80 (normal), 60-79 (increased monitoring), 40-59 (rate limiting), 20-39 (isolation/deny-by-default), <20 (quarantine + alert)
- **Integration Points:** Feeds from Historical Reputation (Layer 14), influenced by Behavioral (Layer 6), Graph Intelligence (Layer 10), Integrity Monitoring (Layer 18)
- **Output Format:** `TrustStateUpdate(entity_id, entity_type, previous_trust, current_trust, reason[], recommended_action)`
- **Policy:** All actions remain policy-governed, auditable, reversible

**Stage 2 Output Format:**
Each signal produces:
```python
DetectionSignal(
    signal_type=SignalType.SIGNATURE,  # or HONEYPOT, LSTM, etc.
    is_threat=True,  # Boolean: is this signal detecting a threat?
    confidence=0.92,  # Float 0.0-1.0: how confident is the signal?
    details={...}    # Dict: signal-specific metadata
)
```

**Stage 2 → Stage 3 Transition:**
1. Primary detection signals (1-18) complete analysis → produce list of `DetectionSignal` objects
2. Signals routed through `AI/false_positive_filter.py` (5-gate validation) → filters out low-confidence/whitelisted signals
3. **Layer 19 (Causal Inference)** analyzes filtered signals + system metadata → produces `CausalInferenceResult`:
   - Checks recent config changes, deployments, identity events
   - Builds causal graph to determine WHY event occurred
   - Classifies as legitimate, misconfiguration, automation side-effect, attack, insider misuse, or unknown
4. **Layer 20 (Trust Degradation)** retrieves entity trust state from persistent graph:
   - Looks up current trust score for source IP/device/account
   - Calculates trust degradation based on detected threats
   - Generates `TrustStateUpdate` with recommended action
5. Filtered signals + causal inference result + trust state → passed to `AI/meta_decision_engine.py` → weighted voting begins

---

### Stage 3: Ensemble Decision Engine (Weighted Voting)

**README:** "🎯 ENSEMBLE VOTING → Calculate weighted score → Authoritative boosting → Consensus → Threshold decision"

**Implementation:**
- **Module:** `AI/meta_decision_engine.py`
- **Input:** List of `DetectionSignal` objects from Stage 2
- **Algorithm:**
  ```python
  weighted_score = Σ (signal_weight × confidence × is_threat) / Σ signal_weight
  
  # Authoritative boosting
  if honeypot_confidence ≥ 0.7 or threat_intel_confidence ≥ 0.9:
      weighted_score = max(weighted_score, 0.90)
  
  # Causal inference adjustment (Layer 19)
  if causal_label == LEGITIMATE_CAUSE and causal_confidence ≥ 0.85:
      weighted_score -= 0.20  # Downgrade by 20%
  elif causal_label in [EXTERNAL_ATTACK, INSIDER_MISUSE] and causal_confidence ≥ 0.80:
      weighted_score += 0.15  # Boost by 15%
  elif causal_label == MISCONFIGURATION:
      route_to_governance_queue()  # Don't auto-block
  elif causal_label == UNKNOWN_CAUSE:
      require_human_review = True  # No auto-block even if score ≥ 75%
  
  # Trust state modulation (Layer 20)
  entity_trust = get_entity_trust_score(event.src_ip, event.user, event.device)
  if entity_trust < 40:
      block_threshold = 0.60  # Stricter threshold
  elif entity_trust < 20:
      return QUARANTINE  # Automatic quarantine regardless of score
  else:
      block_threshold = 0.75  # Normal threshold (or 0.70 in APT mode)
  
  # Threshold decision
  if weighted_score ≥ block_threshold:
      return BLOCK
  elif weighted_score ≥ 0.50:
      return LOG_THREAT
  else:
      return ALLOW
  ```

**Signal Weights (configurable):**
- Honeypot: 0.98 (highest - direct attacker interaction)
- Threat Intel: 0.95 (external validation)
- Graph Intelligence: 0.92 (APT lateral movement)
- Signature: 0.90 (known patterns)
- LSTM: 0.85 (kill-chain progression)
- Behavioral: 0.75 (statistical heuristics)
- Drift: 0.65 (model degradation warning)

**Configuration:** `server/json/meta_engine_config.json`
**Audit Trail:** `server/json/decision_history.json` (per-signal contributions)
**Output:** `EnsembleDecision(threat_level, should_block, weighted_score, reasons)`

**Stage 3 → Stage 4 Transition:**
1. Ensemble engine calculates `weighted_score` (0.0-1.0) from all filtered signals
2. Decision threshold applied:
   - `≥ 0.75` (or 0.70 in APT mode): `should_block=True` → Stage 4 firewall block
   - `≥ 0.50`: `should_block=False` but `threat_level=HIGH` → Stage 4 logs threat (no block)
   - `< 0.50`: `threat_level=LOW` → allow, minimal logging
3. `EnsembleDecision` object returned to `AI/pcs_ai.py` → triggers Stage 4 response actions

---

### Stage 4: Response Execution (Policy-Governed)

**README:** "🛡️ RESPONSE EXECUTION → Firewall block → Connection drop → Rate limiting → Logging → Alerts"

**Implementation:**

| Action | Module | Configuration |
|--------|--------|---------------|
| **Firewall Block** | `server/device_blocker.py` | iptables/nftables + TTL |
| **Connection Drop** | `server/network_monitor.py` | Active TCP session termination |
| **Rate Limiting** | `AI/pcs_ai.py` | 50-74% confidence attacks |
| **Logging** | Multiple modules | 10+ JSON audit surfaces |
| **Dashboard Update** | `server/server.py` | WebSocket real-time push |
| **Email/SMS Alerts** | `AI/alert_system.py` | SMTP/Twilio integration |
| **SOAR Integration** | `AI/soar_api.py` | REST API to external platforms |

**Multi-Surface Logging:**
- `threat_log.json` — Primary threat log *(auto-rotates at 1GB, see `AI/file_rotation.py`)*
- `comprehensive_audit.json` — All THREAT_DETECTED/INTEGRITY_VIOLATION/SYSTEM_ERROR events *(auto-rotates at 1GB)*
- `attack_sequences.json` — LSTM kill-chain progressions
- `lateral_movement_alerts.json` — Graph intelligence hop chains
- `behavioral_metrics.json` — Per-IP heuristics
- `dns_security.json` — DNS analyzer findings
- `tls_fingerprints.json` — TLS fingerprinting data
- `integrity_violations.json` — Self-protection events
- `forensic_reports/*.json` — Explainability outputs
- `decision_history.json` — Ensemble voting records
- `causal_analysis.json` — **Layer 19: Root cause analysis results**
- `trust_graph.json` — **Layer 20: Entity trust state tracking (persistent across restarts)**

**Note:** Files marked with *(auto-rotates at 1GB)* use `AI/file_rotation.py` to prevent unbounded growth. ML training reads all rotation files (`threat_log.json`, `threat_log_1.json`, `threat_log_2.json`, etc.) to preserve complete attack history. See `ML_LOG_ROTATION.md` for details.

**Policy Governance:**
- `AI/policy_governance.py` — Approval workflows
- `server/json/approval_requests.json` — Pending approvals
- `AI/emergency_killswitch.py` — SAFE_MODE override

**Stage 4 → Stage 5 Transition:**
1. Stage 4 writes attack details to `threat_log.json`, `comprehensive_audit.json`, and signal-specific logs
2. Background extraction jobs scan logs periodically (every hour):
   - `AI/signature_extractor.py` reads `threat_log.json` → extracts attack patterns → writes `extracted_signatures.json`
   - `AI/reputation_tracker.py` reads `threat_log.json` → updates `reputation.db` with attacker IPs
   - `AI/graph_intelligence.py` reads `lateral_movement_alerts.json` → updates `network_graph.json`
3. Extracted materials staged locally in `server/json/` → ready for Stage 6 relay push

---

### Stage 5: Training Material Extraction (Privacy-Preserving)

**README:** "🧬 TRAINING MATERIAL EXTRACTION → Signatures → Statistics → Reputation → Graph patterns → Model weights"

**Implementation:**

**Customer-Side Extraction (Local Staging):**

| Material Type | Module | Local Staging | Privacy Protection |
|--------------|--------|---------------|-------------------|
| **Signatures** | `AI/signature_extractor.py` | `server/json/extracted_signatures.json` | Patterns only, zero exploit code |
| **Behavioral Stats** | `AI/behavioral_heuristics.py` | `server/json/behavioral_metrics.json` | Connection rate, port entropy (anonymized) |
| **Reputation** | `AI/reputation_tracker.py` | `server/json/reputation.db` | SHA-256 hashed IPs (not raw) |
| **Graph Topology** | `AI/graph_intelligence.py` | `server/json/network_graph.json` | A→B→C labels (not real IPs) |

**Relay-Side Storage (After Stage 6 Push):**
- Signatures → `relay/ai_training_materials/ai_signatures/learned_signatures.json`
- Reputation → `relay/ai_training_materials/reputation_data/`
- Graph patterns → `relay/ai_training_materials/training_datasets/graph_topology.json`
- Attack records → `relay/ai_training_materials/global_attacks.json`

**Stage 5 → Stage 6 Flow:** Customer extracts materials locally → `AI/relay_client.py` pushes to relay (every hour) → relay aggregates into training datasets

**Privacy Guarantees:**
- ✅ No raw exploit payloads stored
- ✅ No PII/PHI retained
- ✅ IP addresses hashed (SHA-256)
- ✅ Packet content stripped (metadata only)
- ✅ Only statistical features shared

---

### Stage 6: Global Intelligence Sharing (Optional Relay)

**README:** "🌍 RELAY SHARING → Push local findings → Pull global intel → Merge knowledge"

**Implementation:**

**Push to Relay (every hour):**
- **Module:** `AI/relay_client.py`, `AI/signature_uploader.py`
- **Authentication:** HMAC (`AI/crypto_security.py`, `server/crypto_keys/`)
- **Protocol:** WebSocket/HTTP POST to `relay/relay_server.py`
- **Payload:** Sanitized attack records (no payloads)

**Relay Server:**
- **Module:** `relay/relay_server.py`, `relay/signature_sync.py`
- **Storage:**
  - `relay/ai_training_materials/global_attacks.json` (central attack log)
  - `relay/ai_training_materials/ai_signatures/learned_signatures.json` (signature deduplication)
  - `relay/ai_training_materials/attack_statistics.json` (aggregated trends)

**Pull from Relay (every 6 hours):**
- **Module:** `AI/training_sync_client.py`, `AI/signature_distribution.py`
- **Downloads:**
  - 3,000+ new signatures from worldwide nodes
  - Known bad IP/ASN reputation feed
  - Model updates (Byzantine-validated)
  - Emerging threat statistics (CVEs, attack trends)
- **Destination:** `ml_models/` (aligned with `AI/pcs_ai.py`)

**Merge & Integration:**
- New signatures → signature database
- Reputation feed → `AI/reputation_tracker.py`
- Model updates → `AI/byzantine_federated_learning.py` validation → replace local models

**Relay Infrastructure (NOT shipped to customers):**
- `relay/docker-compose.yml` — Separate deployment
- `relay/training_sync_api.py` — Model distribution API
- `relay/exploitdb_scraper.py` — ExploitDB integration (3,066+ patterns)
- `relay/threat_crawler.py` — OSINT aggregation (VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar)

**Stage 6 → Stage 7 Transition:**
1. Customer nodes push training materials to relay (every hour) → relay stores in `ai_training_materials/`
2. Relay aggregates data from all customer nodes worldwide:
   - Signatures merged into `learned_signatures.json` (deduplicated)
   - Attack records appended to `global_attacks.json` (grows continuously, rotates at 1GB)
   - Reputation data consolidated into `reputation_data/`
3. Aggregated dataset triggers Stage 7 retraining (weekly) → new models trained → distributed back to customers
4. **Critical:** `global_attacks.json` uses `AI/file_rotation.py` - ML training reads ALL rotation files (`global_attacks.json`, `global_attacks_1.json`, etc.) to preserve complete training history

---

### Stage 7: Continuous Learning Loop

**README:** "🔄 CONTINUOUS LEARNING → Signature updates → ML retraining → Reputation decay → Drift refresh"

**Implementation:**

**Hourly:** Signature auto-update
- **Module:** `AI/signature_distribution.py`
- **Action:** Pull new signatures from relay → merge into local database

**Weekly:** ML model retraining
- **Module:** `relay/ai_retraining.py`
- **Process:**
  1. Read `global_attacks.json` + `learned_signatures.json`
  2. Extract features → `training_datasets/attacks_features.csv`
  3. Train RandomForest/IsolationForest/GradientBoosting
  4. Store updated models → `ai_training_materials/ml_models/*.pkl`
  5. Push to relay API for global distribution
- **Optional:** `relay/gpu_trainer.py` for LSTM/autoencoder (GPU-accelerated)

**Daily:** Reputation decay
- **Module:** `AI/reputation_tracker.py`
- **Algorithm:** Half-life decay (30 days) → old attacks fade gradually

**Monthly:** Drift baseline refresh
- **Module:** `AI/drift_detector.py`
- **Trigger:** KS test p-value < 0.05 → schedule retraining
- **Action:** Update `drift_baseline.json` to current traffic distribution

**Continuous:** Byzantine validation
- **Module:** `AI/byzantine_federated_learning.py`
- **Accuracy:** 94% malicious update rejection
- **Logging:**
  - Local: `server/json/comprehensive_audit.json` (THREAT_DETECTED events)
  - Relay: `relay/ai_training_materials/global_attacks.json` (`attack_type="federated_update_rejected"`)

**Feedback Sources:**
- **Honeypot:** 100% confirmed attacks (highest quality training)
- **Human Validation:** SOC analyst confirms/rejects → ML improvement
- **False Positive Reports:** Whitelist updates → FP filter tuning
- **SOAR Playbook Results:** Successful remediation → reinforcement learning

**Stage 7 → Stage 1 Feedback Loop (Completes the 7-Stage Cycle):**
1. Relay retrains models using aggregated data → new `*.pkl` and `*.keras` models created
2. Models pushed to relay API → `relay/training_sync_api.py` serves updated models
3. Customer nodes pull updates (every 6 hours) via `AI/training_sync_client.py`:
   - New signatures downloaded → merged into local signature database
   - New ML models downloaded → replace old models in `ml_models/` and `AI/ml_models/`
   - `AI/byzantine_federated_learning.py` validates updates (94% malicious rejection rate)
4. Updated models loaded by Stage 2 detection signals → **improved accuracy for next packet analysis in Stage 1**
5. Cycle repeats: better detection → more accurate training data → better models → better detection...

**This continuous feedback loop enables the system to adapt to evolving threats without manual intervention.**

---

## 2. Dashboard Architecture: UI → API → AI Modules

**Dashboard:** `AI/inspector_ai_monitoring.html` (31 sections)
**Server:** `server/server.py` (Flask application with REST APIs)

### Section Mapping (Selected Examples)

| Section | Dashboard Area | API Endpoint | AI Modules |
|---------|----------------|--------------|------------|
| 1 | **AI Training Network** | `/api/p2p/status`, `/api/p2p/peers` | `AI/p2p_sync.py`, `AI/byzantine_federated_learning.py` |
| 2 | **Network Devices** | `/api/devices/connected`, `/api/devices/history` | `server/device_scanner.py`, `AI/asset_inventory.py` |
| 3 | **VPN/Tor De-Anonymization** | `/api/vpn_tor/stats` | `AI/pcs_ai.py` (VPN/Tor tracking) |
| 4 | **Real AI/ML Models** | `/api/ml/models`, `/api/ml/lineage` | `AI/pcs_ai.py`, `AI/cryptographic_lineage.py` |
| 5 | **Security Overview** | `/api/security/overview` | `AI/pcs_ai.py`, `AI/meta_decision_engine.py` |
| 7 | **IP Management** | `/api/threats/by_ip` | `AI/reputation_tracker.py`, `AI/threat_intelligence.py` |
| 14 | **Attack Chain (Graph)** | `/api/graph/topology`, `/api/graph/lateral_movement` | `AI/graph_intelligence.py` |
| 15 | **Explainability** | `/api/explainability/decisions` | `AI/explainability_engine.py` |
| 16 | **Adaptive Honeypot** | `/api/adaptive_honeypot/status`, `/api/adaptive_honeypot/attacks` | `AI/adaptive_honeypot.py` |
| 17 | **Traffic Analysis** | `/api/traffic/analysis` | `AI/traffic_analyzer.py`, `AI/tls_fingerprint.py` |
| 18 | **DNS & Geo Security** | `/api/dns/stats`, `/api/visualization/geographic` | `AI/dns_analyzer.py` |
| 31 | **Governance & Emergency** | `/api/killswitch/status`, `/api/governance/audit` | `AI/emergency_killswitch.py`, `AI/policy_governance.py` |

**Data Flow:**
```
Dashboard JavaScript fetch('/api/...') 
  → server/server.py Flask route 
  → AI module function call 
  → JSON file read/write (server/json/) 
  → Response JSON 
  → Dashboard UI update
```

---

## 3. File Structure & Path Conventions

### Docker Paths (Production)
```
/app/                               # Container root
├── json/                          # Runtime JSON data (mounted from server/json/)
│   ├── threat_log.json
│   ├── comprehensive_audit.json
│   ├── decision_history.json
│   ├── reputation.db
│   └── ...
├── ml_models/                     # Classical ML models (mounted)
│   ├── threat_classifier.pkl
│   ├── anomaly_detector.pkl
│   ├── ip_reputation.pkl
│   └── feature_scaler.pkl
├── AI/ml_models/                  # Deep learning models
│   ├── sequence_lstm.keras
│   └── traffic_autoencoder.keras
├── server/crypto_keys/            # HMAC keys for relay auth
└── relay/ai_training_materials/   # Relay-only (NOT in customer containers)
    ├── global_attacks.json
    ├── ai_signatures/
    ├── reputation_data/
    ├── ml_models/
    └── training_datasets/
```

### Native Development Paths
```
battle-hardened-ai/
├── server/
│   ├── json/                      # Runtime JSON (.gitignored)
│   └── crypto_keys/
├── AI/
│   ├── ml_models/                 # Deep learning
│   ├── adaptive_honeypot.py
│   ├── pcs_ai.py
│   └── ...
├── ml_models/                     # Classical ML (shared with relay sync)
└── relay/                         # Operator infrastructure only
    ├── ai_training_materials/
    └── ...
```

### Path Resolution Rules
- **JSON files:** Modules should use `server/json/` (native) or `/app/json/` (Docker)
- **ML models:** `AI/pcs_ai.py` uses `ml_models/` for classical ML, `AI/ml_models/` for deep learning
- **Relay sync:** `AI/training_sync_client.py` downloads to `ml_models/` (same as pcs_ai reads)
- **Relay training data:** Always under `relay/ai_training_materials/` (customer nodes never access this)

---

## 4. Privacy & Security Guarantees

### Data Residency
✅ **Customer JSON stays local by default**
- All runtime JSON (`threat_log.json`, device lists, decision history, etc.) written to `server/json/`
- No silent uploads to third-party cloud services
- Relay is **your own VPS/cloud**, not a vendor

✅ **Relay is operator-controlled infrastructure**
- `relay/` folder deployed only on infrastructure you operate
- Customers receive only `server/` + `AI/` (never `relay/`)
- Relay training materials inaccessible to customers

### Data Minimization
✅ **Training sync is explicit and limited**
- `AI/relay_client.py` sends only sanitized training summaries
- No raw JSON logs uploaded (only structured attack records)
- Replay server returns models/signatures (no customer data pulled)

✅ **Privacy-preserving extraction (Stage 5)**
- IP addresses hashed (SHA-256) before relay transmission
- No raw exploit payloads stored
- Packet content stripped (metadata only)
- PII/PHI never retained

### Auditability
✅ **Centralized external communication**
- Relay client/sync modules: `AI/relay_client.py`, `AI/training_sync_client.py`, `AI/central_sync.py`
- All outbound data flows documented and reviewable
- HMAC authentication: `AI/crypto_security.py`, `server/crypto_keys/`

### Compliance
✅ **GDPR/HIPAA/PCI-DSS ready**
- `AI/compliance_reporting.py` generates audit reports
- Configurable data retention policies
- Right-to-erasure support (IP reputation decay)
- Minimal data retention (no unnecessary logs)

---

## 5. Developer Guidelines: Adding New Detections

### Single Source of Truth Pattern
1. **New detection logic goes in `AI/pcs_ai.py`**
2. **Convert detection to `DetectionSignal` object**
3. **Route through `AI/false_positive_filter.py`** (multi-gate validation)
4. **Feed into `AI/meta_decision_engine.py`** (ensemble voting)

### Example: Adding Signal #19 (Causal Inference) & Signal #20 (Trust Degradation)

**Note:** Signals 19 and 20 are strategic intelligence layers, not primary detection signals. They consume outputs from signals 1-18.

```python
# In AI/causal_inference.py (new module)

from enum import Enum
from typing import List, Dict, Any

class CausalLabel(Enum):
    LEGITIMATE_CAUSE = "legitimate_cause"
    MISCONFIGURATION = "misconfiguration"
    AUTOMATION_SIDE_EFFECT = "automation_side_effect"
    EXTERNAL_ATTACK = "external_attack"
    INSIDER_MISUSE = "insider_misuse"
    UNKNOWN_CAUSE = "unknown_cause"

class CausalInferenceEngine:
    def analyze_root_cause(self, signals: List[DetectionSignal], event: Dict[str, Any]) -> CausalInferenceResult:
        """Determine WHY an event happened using causal graphs."""
        # Build causal graph
        recent_config_changes = self._get_recent_config_changes()
        recent_deployments = self._get_recent_deployments()
        identity_events = self._get_recent_identity_events()
        
        # Test counterfactuals
        if self._temporal_correlation(event, recent_deployments, window=120):  # 2 minutes
            return CausalInferenceResult(
                causal_label=CausalLabel.LEGITIMATE_CAUSE,
                confidence=0.89,
                primary_causes=["CI/CD deployment 2 min before anomaly"],
                non_causes=["External IP", "Attack pattern"]
            )
        
        if not recent_config_changes and not recent_deployments:
            if any(s.signal_type == SignalType.THREAT_INTEL and s.is_threat for s in signals):
                return CausalInferenceResult(
                    causal_label=CausalLabel.EXTERNAL_ATTACK,
                    confidence=0.91,
                    primary_causes=["No config change", "External IP with prior reputation"],
                    non_causes=["Scheduled maintenance"]
                )
        
        return CausalInferenceResult(
            causal_label=CausalLabel.UNKNOWN_CAUSE,
            confidence=0.50,
            primary_causes=[],
            non_causes=[]
        )

# In AI/trust_graph.py (new module)

from enum import Enum

class EntityType(Enum):
    IP_ADDRESS = "ip"
    DEVICE = "device"
    ACCOUNT = "account"
    SERVICE = "service"

class TrustDegradationGraph:
    def __init__(self):
        self.trust_scores = {}  # {entity_id: trust_score}
        self.trust_history = {}  # {entity_id: [(timestamp, score, reason)]}
        
    def get_trust_score(self, entity_id: str, entity_type: EntityType) -> int:
        """Get current trust score (0-100) for entity."""
        if entity_id not in self.trust_scores:
            # Initial trust
            if entity_type == EntityType.IP_ADDRESS:
                # Internal vs external detection logic
                return 100 if self._is_internal_ip(entity_id) else 60
            return 100  # Devices, accounts start at 100
        return self.trust_scores[entity_id]
    
    def degrade_trust(self, entity_id: str, event_severity: str, reason: str) -> TrustStateUpdate:
        """Apply trust degradation based on event."""
        previous_trust = self.get_trust_score(entity_id, EntityType.IP_ADDRESS)
        
        # Event-weighted penalties
        penalties = {
            "minor_anomaly": 5,
            "confirmed_attack": 25,
            "lateral_movement": 30,
            "integrity_breach": 40
        }
        penalty = penalties.get(event_severity, 10)
        
        current_trust = max(0, previous_trust - penalty)
        self.trust_scores[entity_id] = current_trust
        
        # Determine recommended action
        if current_trust >= 80:
            action = "NORMAL"
        elif current_trust >= 60:
            action = "INCREASED_MONITORING"
        elif current_trust >= 40:
            action = "RATE_LIMIT"
        elif current_trust >= 20:
            action = "ISOLATE"
        else:
            action = "QUARANTINE"
        
        return TrustStateUpdate(
            entity_id=entity_id,
            entity_type=EntityType.IP_ADDRESS,
            previous_trust=previous_trust,
            current_trust=current_trust,
            reason=[reason],
            recommended_action=action
        )
    
    def recover_trust(self, hours_without_incident: int = 24):
        """Slow trust recovery (+1 per 24h)."""
        for entity_id in self.trust_scores:
            if hours_without_incident >= 24:
                # Cap recovery at initial baseline
                max_trust = 100 if self._is_internal(entity_id) else 60
                self.trust_scores[entity_id] = min(max_trust, self.trust_scores[entity_id] + 1)

# In AI/pcs_ai.py (update assess_threat method)

def assess_threat(self, event):
    """Main orchestration (existing method with Layer 19 & 20 integration)."""
    signals = []
    
    # Existing signals 1-18...
    
    # Route through FP filter
    filtered_signals = self.fp_filter.filter(signals, event)
    
    # NEW: Layer 19 - Causal Inference
    causal_result = self.causal_engine.analyze_root_cause(filtered_signals, event)
    
    # NEW: Layer 20 - Trust Degradation
    entity_trust = self.trust_graph.get_trust_score(event["src_ip"], EntityType.IP_ADDRESS)
    
    # Ensemble decision (with Layer 19 & 20 modulation)
    decision = self.meta_engine.make_decision(
        filtered_signals, 
        event, 
        causal_result=causal_result,
        entity_trust=entity_trust
    )
    
    # Update trust graph if threat detected
    if decision.should_block:
        trust_update = self.trust_graph.degrade_trust(
            event["src_ip"], 
            "confirmed_attack",
            f"Ensemble score: {decision.confidence}"
        )
        # Log trust update
        self._log_trust_update(trust_update)
    
    # Log causal analysis
    self._log_causal_analysis(causal_result)
    
    return decision
```
```python
# In AI/pcs_ai.py

def _get_new_signal_score(self, event):
    """New detection logic (e.g., protocol anomaly)."""
    score = ... # Your detection algorithm
    confidence = ... # How confident you are (0.0-1.0)
    return score, confidence

def assess_threat(self, event):
    """Main orchestration (existing method)."""
    signals = []
    
    # Existing signals 1-18...
    
    # NEW: Signal #19
    score, confidence = self._get_new_signal_score(event)
    signals.append(DetectionSignal(
        signal_type=SignalType.NEW_SIGNAL,
        is_threat=(score > threshold),
        confidence=confidence,
        details={"score": score, "reason": "protocol_anomaly"}
    ))
    
    # Route through FP filter
    filtered_signals = self.fp_filter.filter(signals, event)
    
    # Ensemble decision
    decision = self.meta_engine.make_decision(filtered_signals, event)
    
    return decision
```

### Updating Meta Decision Engine
```python
# In AI/meta_decision_engine.py

class SignalType(Enum):
    # Existing signals 1-18...
    NEW_SIGNAL = 19  # Add new enum value

def __init__(self):
    self.signal_weights = {
        # Existing weights...
        SignalType.NEW_SIGNAL: 0.80,  # Set weight (0.65-0.98 range)
    }
```

### Path Conventions
- **JSON output:** Use `server/json/new_signal_data.json` (auto-created at runtime)
- **Models:** Classical ML → `ml_models/`, Deep learning → `AI/ml_models/`
- **Config:** Tunable parameters → `server/json/new_signal_config.json`

### Testing Checklist
- [ ] Signal fires independently in Stage 2
- [ ] FP filter gates work correctly
- [ ] Ensemble voting includes signal with correct weight
- [ ] Dashboard displays signal contribution (Section 4/15)
- [ ] Relay receives sanitized signal data (Stage 6)
- [ ] Documentation updated (README, ai-abilities.md)

---

## 6. Performance Considerations

### Real-Time Path (Latency-Critical)
**Goal:** Packet → Decision in <100ms

**Optimization Tips:**
- Batch ML inference where possible
- Use in-memory caching for reputation lookups
- Defer heavy analytics to background threads
- Keep `assess_threat()` pipeline synchronous and fast

### Background Analytics (Throughput-Optimized)
**Suitable for:**
- Graph topology computation
- LSTM sequence modeling (can lag by seconds)
- Forensic report generation
- Compliance report creation

### Model Loading
- **Lazy loading:** Load models on first use (not at startup)
- **Shared models:** Use singleton pattern for ML models
- **Model caching:** Keep loaded models in memory (don't reload per packet)

---

## 7. Common Pitfalls & Solutions

### Pitfall 1: Hardcoded Paths
❌ **Wrong:** `open("/home/user/server/json/threat_log.json")`
✅ **Correct:** Use environment-aware path resolution
```python
import os
json_dir = os.getenv('JSON_DIR', 'server/json')
threat_log_path = os.path.join(json_dir, 'threat_log.json')
```

### Pitfall 2: Whitelist Bypassing Honeypot
❌ **Wrong:** Whitelisted IPs bypass all detection (including honeypot)
✅ **Correct:** Honeypot hits are authoritative (never whitelisted)
```python
# In AI/false_positive_filter.py
if signal.signal_type == SignalType.HONEYPOT and signal.confidence >= 0.7:
    # NEVER suppress honeypot signals
    return True  # Always pass Gate 1
```

### Pitfall 3: Signal Weight Misconfiguration
❌ **Wrong:** All signals weighted equally
✅ **Correct:** Weight reflects signal reliability
```python
# Honeypot: 0.98 (direct attacker interaction)
# ML models: 0.75-0.85 (probabilistic)
# Drift: 0.65 (warning, not conclusive)
```

### Pitfall 4: Ignoring APT Mode
❌ **Wrong:** Always using 75% block threshold
✅ **Correct:** Check `APT_DETECTION_MODE` environment variable
```python
if os.getenv('APT_DETECTION_MODE') == 'true':
    block_threshold = 0.70
else:
    block_threshold = 0.75
```

### Pitfall 5: Dashboard API Shape Mismatch
❌ **Wrong:** Changing API response without updating dashboard JavaScript
✅ **Correct:** Maintain consistent API contracts or version endpoints
```python
# server/server.py
@app.route('/api/threats/summary')
def threats_summary():
    return {
        "total_threats": ...,
        "blocked": ...,
        "logged": ...,
        # NEVER remove fields without updating inspector_ai_monitoring.html
    }
```

---

## 8. Quick Reference

### Key Modules by Stage
- **Stage 1:** `server/network_monitor.py`, `AI/kernel_telemetry.py`, `AI/system_log_collector.py`
- **Stage 2:** `AI/pcs_ai.py` (orchestrator), all 20 detection modules:
  - Primary signals 1-18 (see Section 1 table)
  - Strategic intelligence: `AI/causal_inference.py` (Layer 19), `AI/trust_graph.py` (Layer 20)
- **Stage 3:** `AI/meta_decision_engine.py`, `AI/false_positive_filter.py`, Layer 19 & 20 modulation
- **Stage 4:** `server/device_blocker.py`, `AI/alert_system.py`, `AI/file_rotation.py` (logging infrastructure)
- **Stage 5:** `AI/signature_extractor.py`, `AI/reputation_tracker.py`, `AI/graph_intelligence.py` (extraction)
- **Stage 6:** `AI/relay_client.py`, `AI/signature_uploader.py`, `relay/relay_server.py`, `relay/signature_sync.py`
- **Stage 7:** `relay/ai_retraining.py`, `relay/gpu_trainer.py`, `AI/drift_detector.py`, `AI/signature_distribution.py` (pulls updates)

### Critical JSON Files
- `threat_log.json` — Primary threat log (Stage 4 output) *(rotates at 1GB, ML reads all rotation files)*
- `comprehensive_audit.json` — All THREAT_DETECTED/INTEGRITY_VIOLATION events *(rotates at 1GB)*
- `decision_history.json` — Ensemble voting records (Stage 3)
- `reputation.db` — SQLite cross-session reputation (Stage 2 signal #14)
- `meta_engine_config.json` — Signal weights (Stage 3 configuration)
- `global_attacks.json` — Relay central attack log (Stage 6) *(rotates at 1GB on relay server)*
- `extracted_signatures.json` — Customer-side signature staging (Stage 5)
- `network_graph.json` — Graph topology (Stage 2 signal #10, Stage 5 extraction)
- `behavioral_metrics.json` — Per-IP heuristics (Stage 2 signal #6, Stage 5 extraction)
- `causal_analysis.json` — **Layer 19: Root cause analysis results (Stage 3 strategic intelligence)**
- `trust_graph.json` — **Layer 20: Entity trust state tracking (persistent, survives restarts)**

**File Rotation:** See `AI/file_rotation.py` and `ML_LOG_ROTATION.md` - rotation files (`*_1.json`, `*_2.json`, etc.) are never deleted, ensuring ML training has complete attack history.

### Environment Variables
- `APT_DETECTION_MODE=true` — Lower block threshold to 70%
- `BLOCK_THRESHOLD=0.65` — Custom threshold override
- `AUTO_KILLSWITCH_ON_INTEGRITY=true` — SAFE_MODE on integrity violations
- `JSON_DIR=/app/json` — Docker JSON path override
- `TZ=America/New_York` — Timezone for off-hours APT detection

---

**For detailed test procedures, see:** `ai-abilities.md` (10-stage validation checklist)
**For architecture overview, see:** `README.md` (7-stage pipeline with diagrams)
