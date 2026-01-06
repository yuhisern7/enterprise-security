# AI Abilities – Test Checklist

This file is a **test checklist** for every major AI ability in the platform, organized by the same logical flow used in the README's attack detection pipeline.

**Testing validates end-to-end flow:**
- Each ability fires on the customer node → local JSON + dashboard
- Relay/central server receives **sanitized log/signature** (when enabled)
- **False-positive filter and meta-decision engine** behave correctly (block/log/ignore decisions)

**Legend:**
- [ ] Not tested yet
- [x] Tested (local + relay logs verified)

> **Testing Rule:** Tick the box **only after confirming** local JSON, dashboard UI, and relay/global logs all show correct data.

---

## Testing Strategy: 10-Stage Progressive Validation

Tests follow the same **7-stage pipeline** from the README, plus 3 additional validation stages. Each stage builds on previously verified infrastructure:

## Stage Overview: Progressive Validation (10 Stages)

**Stages 1-7 mirror the README's attack detection pipeline.** Each validates one major pipeline component:

### Core Pipeline Stages (README Flow)

**Stage 1: Data Ingestion & Normalization**
- **Test:** HMAC/key setup, relay connectivity, packet capture
- **Goal:** Verify network_monitor captures traffic → normalizes metadata → feeds into detection signals
- **Validates README:** "Stage 1: Data Ingestion & Normalization" (packet capture, metadata extraction)

**Stage 2: Parallel Multi-Signal Detection (18 Signals)**
- **Test:** Core detection pipeline (signatures, ML models, behavioral, LSTM, autoencoder, drift, graph, VPN/Tor, threat intel, FP filter, reputation, explainability, predictive, Byzantine, integrity)
- **Goal:** All 18 signals fire independently → produce threat assessments → visible in local JSON
- **Validates README:** "Stage 2: Parallel Multi-Signal Detection" (all 18 detection systems)

**Stage 3: Ensemble Decision Engine (Weighted Voting)**
- **Test:** Meta-decision engine combines signals → weighted consensus → threshold decisions (block/log/allow)
- **Goal:** Verify ensemble voting calculation → authoritative boosting → consensus checks → final verdict in threat_log.json
- **Validates README:** "Stage 3: Ensemble Decision Engine" (weighted voting, 75% block threshold, APT mode 70%)

**Stage 4: Response Execution (Policy-Governed)**
- **Test:** Automated responses (firewall blocks, connection drops, rate limiting, logging, alerts, SOAR integration)
- **Goal:** Verify policy-governed actions execute → local logging → dashboard updates → alert delivery
- **Validates README:** "Stage 4: Response Execution" (immediate actions, logging, alerts)

**Stage 5: Training Material Extraction (Privacy-Preserving)**
- **Test:** Honeypot-to-signature pipeline, attack pattern extraction, behavioral statistics, reputation updates, graph topology anonymization
- **Goal:** Verify high-confidence attacks → sanitized training materials (no payloads/PII) → stored locally
- **Validates README:** "Stage 5: Training Material Extraction" (signatures, statistics, reputation, graph patterns, model weights)

**Stage 6: Global Intelligence Sharing (Optional Relay)**
- **Test:** Relay push/pull, signature distribution, model updates, Byzantine validation, global reputation feeds
- **Goal:** Verify local findings → relay server → global_attacks.json + learned_signatures.json → other nodes pull updates
- **Validates README:** "Stage 6: Relay Sharing" (push/pull protocol, global intelligence, privacy-preserving federation)

**Stage 7: Continuous Learning Loop**
- **Test:** Signature extraction, ML retraining, reputation decay, drift baseline updates, Byzantine validation, feedback integration
- **Goal:** Verify system improves over time → models retrain weekly → baselines adapt → false positives decrease
- **Validates README:** "Stage 7: Continuous Learning" (automated improvement, feedback mechanisms)

---

### Validation Stages (Extended Testing)

**Stage 8: Enterprise Integration & Cloud Posture**
- **Test:** SOAR workflows, enterprise integrations, cloud security posture (CSPM), IAM risk detection
- **Goal:** Verify enterprise features integrate with core pipeline → incidents flow to relay as `soar_incident` / `cloud_misconfiguration`

**Stage 9: Resilience, Backup & Compliance**
- **Test:** Backup status monitoring, ransomware resilience, compliance reporting (PCI/HIPAA/GDPR), breach notifications
- **Goal:** Verify backup/compliance issues → comprehensive_audit.json → relay as `backup_issue` / `compliance_issue`

**Stage 10: Explainability, Visualization & Dashboard**
- **Test:** Decision explanations, advanced visualizations (topology/heatmaps/geo), dashboard API endpoints, error handling
- **Goal:** Verify UI correctly reflects all pipeline stages → API failures logged as `SYSTEM_ERROR` events

---

**For every stage:** Validate complete flow → **trigger → local JSON → dashboard → relay JSON** (Logging & Central Capture Checklist).

---

## 0. Quick Reference: 18 Detection Signals → Implementation Files

This maps each of the **18 parallel detection signals** (from README Stage 2) to their implementing modules.

This maps each of the **18 active detection signals** from the README to the concrete files/modules that implement or feed that signal.

1. **eBPF Kernel Telemetry**  
   Files: AI/kernel_telemetry.py; server/network_monitor.py; server/docker-compose.yml (Linux capabilities and host networking); AI/pcs_ai.py (orchestration and signal wiring).

2. **Signature Matching**  
   Files: AI/threat_intelligence.py; AI/signature_extractor.py; AI/signature_distribution.py; AI/signature_uploader.py; AI/pcs_ai.py; relay/signature_sync.py; relay/exploitdb_scraper.py; relay/threat_crawler.py; relay/ai_training_materials/ai_signatures/; relay/ai_training_materials/exploitdb/.

3. **RandomForest (supervised classifier)**  
   Files: AI/pcs_ai.py (loads and uses RF pickles); ml_models/ (RandomForest model pickles such as anomaly_detector/threat_classifier); relay/ai_retraining.py (trains and exports updated RF models to ai_training_materials/ml_models/); relay/gpu_trainer.py (optional GPU training backend).

4. **IsolationForest (unsupervised anomaly)**  
   Files: AI/pcs_ai.py; ml_models/ (IsolationForest pickle); relay/ai_retraining.py; relay/gpu_trainer.py.

5. **Gradient Boosting (reputation modeling)**  
   Files: AI/pcs_ai.py; ml_models/ (gradient boosting/reputation model); relay/ai_retraining.py; relay/gpu_trainer.py.

6. **Behavioral Heuristics**  
   Files: AI/behavioral_heuristics.py; AI/pcs_ai.py (uses heuristic scores as detection signals); server/network_monitor.py (feeds per-IP events into the heuristics engine); server/json/behavioral_metrics.json (persistence, when enabled).

7. **LSTM (sequential kill-chain analysis)**  
   Files: AI/sequence_analyzer.py; AI/ml_models/sequence_lstm.keras; AI/pcs_ai.py (calls sequence analysis); server/json/attack_sequences.json (sequence export, when enabled); relay/ai_retraining.py (may incorporate sequence history into retraining).

8. **Autoencoder (zero-day anomaly detection)**  
   Files: AI/traffic_analyzer.py; AI/ml_models/traffic_autoencoder.keras; AI/network_performance.py; AI/pcs_ai.py; server/json/network_performance.json; relay/ai_retraining.py; relay/gpu_trainer.py.

9. **Drift Detection**  
   Files: AI/drift_detector.py; AI/pcs_ai.py (invokes drift checks and flags); server/json/drift_baseline.json; server/json/drift_reports.json; relay/ai_retraining.py (uses history/drift context for when to retrain).

10. **Graph Intelligence (lateral movement / C2)**  
	Files: AI/graph_intelligence.py; AI/advanced_visualization.py (renders graph outputs); AI/advanced_orchestration.py (can export topology/training views); AI/pcs_ai.py; server/json/network_graph.json; server/json/lateral_movement_alerts.json; relay/ai_training_materials/training_datasets/graph_topology.json.

11. **VPN/Tor Fingerprinting**  
	Files: AI/pcs_ai.py (get_vpn_tor_statistics and related tracking); server/server.py (vpn_stats wiring into dashboard sections); server/json/threat_log.json (stores VPN/Tor-related attacker_intel entries).

12. **Threat Intelligence Feeds (OSINT correlation)**  
	Files: relay/threat_crawler.py; relay/exploitdb_scraper.py; relay/ai_training_materials/threat_intelligence/; relay/ai_training_materials/reputation_data/; AI/threat_intelligence.py; AI/reputation_tracker.py; AI/pcs_ai.py.

13. **False Positive Filter (multi-gate)**  
	Files: AI/false_positive_filter.py; AI/meta_decision_engine.py (consumes FP-filtered signals); AI/pcs_ai.py; server/json/decision_history.json (records final ensemble decisions and FP-filter outcomes).

14. **Historical Reputation**  
	Files: AI/reputation_tracker.py; AI/pcs_ai.py; server/json/reputation.db (SQLite DB backing for long-term reputation); relay/ai_training_materials/reputation_data/ (aggregated global reputation, when exported).

15. **Explainability Engine (decision transparency)**  
	Files: AI/explainability_engine.py; AI/pcs_ai.py; server/report_generator.py (uses explainability data for reports); server/json/forensic_reports/; relay/ai_training_materials/explainability_data/ (when full repo is present for training).

16. **Predictive Modeling (short-term threat forecasting)**  
	Files: AI/advanced_orchestration.py (ThreatPrediction logic and export to orchestration_data); AI/pcs_ai.py (can integrate forecast results into decisions); relay/ai_training_materials/orchestration_data/.

17. **Byzantine Defense (poisoned update rejection)**  
	Files: AI/byzantine_federated_learning.py; AI/training_sync_client.py; relay/ai_retraining.py; relay/gpu_trainer.py; relay/ai_training_materials/ml_models/ (aggregated models after Byzantine-safe updates); server/json/comprehensive_audit.json; relay/ai_training_materials/global_attacks.json (when relay is present).

18. **Integrity Monitoring (model & telemetry tampering)**  
	Files: AI/self_protection.py; AI/emergency_killswitch.py; AI/cryptographic_lineage.py; AI/crypto_security.py; AI/policy_governance.py; server/json/integrity_violations.json; server/json/comprehensive_audit.json and audit_archive/ (governance/integrity + cryptographic lineage audit trail); AI/pcs_ai.py (routes integrity/self-protection and lineage/drift signals into the ensemble).

---

## 0.1 Planned Changes per Ability & File

This section tracks **which files will change** and **what the change is** for each of the 18 abilities (focused on making attacks/signatures consistent and ML-friendly).

> Convention: if a file is listed under multiple abilities, we centralize schema logic there and keep others as thin mappers into that schema.

### 1) eBPF Kernel Telemetry

Files that may change:
- [ ] AI/kernel_telemetry.py — ensure any detections promoted to “attacks” include canonical fields (attack_type, severity, vector="kernel", source="kernel_telemetry").
- [ ] AI/pcs_ai.py — wire kernel_telemetry-derived signals into the same DetectionSignal taxonomy used by other abilities; tag them with the shared attack_type labels when elevated to attacks.

### 2) Signature Matching

Files that will change:
- [ ] AI/signature_extractor.py — emit signatures that strictly follow the SignatureSyncService schema (attack_type, encodings, ml_features, pattern_hash, optional mitre_tactic/technique).
- [ ] AI/signature_uploader.py — send signatures/attacks to the relay using that canonical schema (no payload fields; no customer IDs), with clear source tags (e.g., "honeypot", "network_monitor").
- [ ] relay/signature_sync.py — treat itself as the **single source of truth** for:
	- ai_training_materials/ai_signatures/learned_signatures.json (normalized signature records).  
	- ai_training_materials/global_attacks.json (attack records referencing signatures via pattern_hash and attack_type).  
	Enforce schema validation and deduplication here.
- [ ] relay/exploitdb_scraper.py — normalize ExploitDB-derived patterns into the same signature schema (attack_type, indicators, pattern_hash) and write through SignatureSyncService (instead of bespoke JSON shapes).
- [ ] relay/threat_crawler.py — when emitting training material from crawlers (URLhaus, MalwareBazaar, CVEs), map them into normalized attack/signature records compatible with global_attacks/signature schema.

### 3–5) RandomForest / IsolationForest / Gradient Boosting

Shared files that will change:
- [ ] AI/pcs_ai.py — ensure the feature vectors and labels used for these models come from the same normalized training_datasets produced from global_attacks/signatures; annotate model outputs with the canonical attack_type/subtype.
- [ ] relay/ai_retraining.py — add an explicit ETL step:
	- Read global_attacks.json + learned_signatures.json.  
	- Produce feature tables (e.g., training_datasets/attacks_features.csv) with attack_type labels.  
	- Train RF/IF/GBM models from those tables and store to ai_training_materials/ml_models/.
- [ ] relay/gpu_trainer.py — update its dataset loading to expect the new standardized training_datasets (shared schema/features) rather than ad-hoc CSV/JSON layouts.

### 6) Behavioral Heuristics

Files that may change:
- [ ] AI/behavioral_heuristics.py — expose a compact export method that summarizes high-risk entities into attack-like records (e.g., type="behavioral_suspicion", features only), without duplicating full threat_log entries.
- [ ] AI/pcs_ai.py — when a behavior-only signal is escalated to a full attack, wrap it into the canonical attack record before sending to SignatureSync/relay.

### 7) LSTM (Kill-Chain)

Files that may change:
- [ ] AI/sequence_analyzer.py — define a small JSON schema for attack_sequences (sequence_id, stages, attack_type, score) and align it with attack_type/kill_chain_stage used elsewhere.
- [ ] AI/pcs_ai.py — map sequence outputs into ensemble decisions and, if converted to training data, into the same training_datasets feature space.

### 8) Autoencoder (Traffic Anomaly)

Files that may change:
- [ ] AI/traffic_analyzer.py — standardize anomaly outputs to include vector="network", anomaly_score, and optional derived attack_type (e.g., "volumetric_anomaly"), so downstream storage remains consistent.
- [ ] AI/network_performance.py — ensure anomaly metrics logged to JSON (network_performance.json) include fields that can be easily joined into the training_datasets schemas.

### 9) Drift Detection

Files that may change:
- [ ] AI/drift_detector.py — output drift events with explicit link back to model IDs and feature sets used in training_datasets, so retraining decisions in relay/ai_retraining.py can be data-driven.
- [ ] relay/ai_retraining.py — optionally read drift reports (if present) and gate retraining decisions or label training snapshots with the drift context.

### 10) Graph Intelligence

Files that may change:
- [ ] AI/graph_intelligence.py — guarantee lateral movement alerts include attack_type (e.g., "lateral_movement"), kill_chain_stage, and graph-specific features that can be exported into training_datasets/graph_topology.json.
- [ ] AI/advanced_visualization.py — keep its read-only role but ensure it expects the normalized graph JSON shape for consistent visualizations.
- [ ] AI/advanced_orchestration.py — when exporting topology/orchestration_data, include references to attack_type and node/edge threat scores used by the ML pipeline.

### 11) VPN/Tor Fingerprinting

Files that may change slightly:
- [ ] AI/pcs_ai.py — expose VPN/Tor detections as explicit signals with a defined subtype (e.g., "vpn_exit_node", "tor_exit_node") and tag any attacks sourced from these as such.
- [ ] server/server.py — no logic change; only ensure dashboard sections continue to read the updated vpn_tor_statistics structure if we add new fields.

### 12) Threat Intelligence Feeds

Files that will change in line with Signature Matching:
- [ ] relay/threat_crawler.py — normalize all crawled items into a common intel schema (indicator_type, indicator, source, tags), and when used for ML, map them into attack/signature records compatible with the rest of the system.
- [ ] relay/ai_training_materials/threat_intelligence/ (data only) — keep using JSON/CSV, but with the new normalized fields.
- [ ] AI/threat_intelligence.py; AI/reputation_tracker.py — align their export/import functions with the shared intel/attack schema so reputation and intel-enhanced attacks use the same vocabulary.

### 13) False Positive Filter

Files that may change minimally:
- [ ] AI/false_positive_filter.py — add awareness of the standardized attack_type and authoritative signals, so FP decisions can be logged in a structured way (e.g., per-ability contribution scores).
- [ ] AI/meta_decision_engine.py — persist richer decision_history entries referencing attack_type and per-signal weights, for better training/analysis.

### 14) Historical Reputation

Files that may change:
- [ ] AI/reputation_tracker.py — ensure exports (e.g., reputation_export.json, reputation.db) include normalized keys (entity_id, entity_type, attack_type_counts) for easy downstream use.
- [ ] relay/ai_training_materials/reputation_data/ — keep as data-only but generated via a consistent export function in reputation_tracker.

### 15) Explainability Engine

Files that may change:
- [ ] AI/explainability_engine.py — ensure every explanation references the canonical attack_type and lists contributions per ability (matching the 18-signal list) so training and audits can align on terminology.
- [ ] server/report_generator.py — expect/use the enriched explanation structure for enterprise reports.

### 16) Predictive Modeling

Files that may change:
- [ ] AI/advanced_orchestration.py — base ThreatPrediction inputs on the same normalized attack/signature records (from training_datasets), and output predictions annotated with attack_type and forecasted kill_chain_stage.
- [ ] AI/pcs_ai.py — integrate predictive outputs into ensemble decisions via a standardized signal (e.g., "forecast_risk_score").

### 17) Byzantine Defense

Files that now change the live flow:
- [ ] AI/byzantine_federated_learning.py — rejected federated updates are appended to an in‑memory log **and** mirrored into server/json/comprehensive_audit.json as `THREAT_DETECTED` events from `byzantine_defender`, and (when the relay tree is present) into relay/ai_training_materials/global_attacks.json as sanitized `attack_type="federated_update_rejected"` records for Stage 7 training.
- [ ] AI/training_sync_client.py — keep updates tagged with stable peer/model IDs so aggregation, reputation, and audit records can be correlated.
- [ ] relay/ai_retraining.py; relay/gpu_trainer.py — continue to label trained models/snapshots with provenance so Byzantine stats, lineage, and training data stay aligned.

### 18) Integrity Monitoring

Files that now change the live flow:
- [ ] AI/self_protection.py; AI/emergency_killswitch.py — integrity/self‑protection violations are written to server/json/integrity_violations.json, mirrored into server/json/comprehensive_audit.json as `INTEGRITY_VIOLATION` (and related) events, and for critical cases (when AUTO_KILLSWITCH_ON_INTEGRITY=true) can drive the kill‑switch into SAFE_MODE.
- [ ] AI/cryptographic_lineage.py — lineage integrity and lineage‑based drift/poisoning are surfaced via `get_model_lineage_stats()` and logged into comprehensive_audit.json as `THREAT_DETECTED` events from `cryptographic_lineage`.
- [ ] AI/crypto_security.py; AI/policy_governance.py — continue to anchor key material and governance rules that feed into the same audit and enforcement path.
- [ ] server/json/comprehensive_audit.json; audit_archive/ — remain the central, append‑only record of integrity, governance, lineage, and federated events, backing Sections 6, 7, and 31 on the dashboard.

---

## 0.2 Relay Output Files by Stage (Summary)

This summarizes which **relay JSON files** are expected to receive events when each stage is exercised and relay is enabled:

- **Stage 1 – Plumbing & Relay Channel**  
	- `relay/ai_training_materials/global_attacks.json` — central attack/event log when a real signed attack message is sent through the HMAC channel.

- **Stage 2 – Core Detection & Scoring**  
	- `relay/ai_training_materials/global_attacks.json` — all elevated attacks from the core pipeline (including ML, VPN/Tor, DNS tunneling, TLS C2 once promoted by pcs_ai).
	- `relay/ai_training_materials/attack_statistics.json` — aggregated counts and trends computed from global_attacks.json.

- **Stage 3 – Deception & Honeypots**  
	- `relay/ai_training_materials/global_attacks.json` — honeypot-sourced attacks promoted to the global view.  
	- `relay/ai_training_materials/ai_signatures/learned_signatures.json` — privacy-preserving signatures and patterns derived from honeypot hits and ExploitDB (no raw exploits).

- **Stage 4 – Network, Devices & Behavioral Analytics**  
	- `relay/ai_training_materials/global_attacks.json` — network/behavioral/graph/DNS/TLS/zero‑trust violations once pcs_ai elevates them to attacks.  
	- `relay/ai_training_materials/attack_statistics.json` — updated statistics including these NDR and UEBA events.

- **Stage 5 – Threat Intelligence & Signatures**  
	- `relay/ai_training_materials/ai_signatures/learned_signatures.json` — central store for all normalized signatures.  
	- `relay/ai_training_materials/threat_intelligence/` — OSINT / feed JSONs maintained by crawlers.  
	- `relay/ai_training_materials/reputation_data/` — aggregated global reputation exports.  
	- `relay/ai_training_materials/global_attacks.json` — attacks enriched with intel/reputation context.

- **Stage 6 – Policy, Governance & Self-Protection**  
	- `relay/ai_training_materials/global_attacks.json` — policy violations and self‑protection events that the ensemble promotes as attacks.

- **Stage 7 – Cryptography, Lineage & Federated / Relay**  
	- `relay/ai_training_materials/global_attacks.json` — training/federation-related security incidents recorded as attacks.  
	- `relay/ai_training_materials/ai_signatures/learned_signatures.json` + `relay/ai_training_materials/global_attacks.json` — input training materials for `relay/ai_retraining.py`.

- **Stage 8 – Enterprise, Cloud & SOAR**  
	- `relay/ai_training_materials/global_attacks.json` — incidents raised from SOAR or cloud posture checks that are shared globally.

- **Stage 9 – Resilience, Backup & Compliance**  
	- `relay/ai_training_materials/global_attacks.json` — any ransomware/backup/compliance‑related incidents escalated as attacks.

- **Stage 10 – Explainability, Visualization & Dashboard**  
	- No new relay files; reuses:  
		- `relay/ai_training_materials/global_attacks.json` — attacks already logged in earlier stages.  
		- `relay/ai_training_materials/ai_signatures/learned_signatures.json` — signatures already logged.  
	- Additional logging surface for this stage:  
		- `server/json/comprehensive_audit.json` — SYSTEM_ERROR events from dashboard/explainability/visualization APIs when those paths fail.

Use this as a quick cross-check when validating that a given stage’s detections are visible both **locally** (server/json) and at the **relay** (ai_training_materials).

---

## Stage 1: Data Ingestion & Normalization

**README Alignment:** Validates "Stage 1: Data Ingestion & Normalization" (packet capture → metadata extraction → pre-processing)

**What This Tests:**
- Network packet capture (eBPF/XDP or scapy)
- Metadata extraction (IPs, ports, protocols, timestamps)
- Normalization to common schema
- HMAC-protected relay connectivity
- Baseline traffic flow

### Tests

- [ ] Ability: Secure message signing & relay connectivity  
	Modules: AI/crypto_security.py, server/crypto_keys/, relay/ai_training_materials/crypto_keys/, relay/relay_server.py  
	Test: Use the testconnection.md flow to sign a message on the customer node and verify the relay accepts it only when the HMAC is valid and records a sanitized entry (no raw payload) in its logs.
	Relay output files for this stage: ai_training_materials/global_attacks.json (central attack/event log, when a real attack message is sent).

---

## Stage 2: Parallel Multi-Signal Detection (18 Signals)

**README Alignment:** Validates "Stage 2: Parallel Multi-Signal Detection" (all 18 independent detection systems)

**What This Tests:**
- All 18 detection signals fire in parallel
- Each signal produces independent threat assessment
- Signals operate independently (no single-point failure)
- APT enhancements (low-and-slow, campaign patterns, off-hours detection)

### Tests

- [ ] Ability: Multi-signal threat scoring  
	Modules: AI/pcs_ai.py, AI/meta_decision_engine.py, AI/false_positive_filter.py  
	Test: Trigger a clear malicious source (e.g., obvious scan or bad IP), verify threat appears in server/json/threat_log.json, is visible on the dashboard, and relay logs a **sanitized attack/global entry** (no raw payload).

- [ ] Ability: Sequence / kill-chain analysis  
	Modules: AI/sequence_analyzer.py, AI/pcs_ai.py  
	Test: Generate a sequence of events (scan → auth attempts → suspicious traffic) and check the sequence model contributes to an elevated score rather than isolated low-level alerts.

- [ ] Ability: Traffic anomaly detection (autoencoder)  
	Modules: AI/traffic_analyzer.py, AI/network_performance.py  
	Test: Generate abnormal traffic volume or patterns in your environment and confirm anomaly flags in network_performance.json and corresponding entries in threat_log.json.

- [ ] Ability: DNS tunneling & DGA detection (NDR-only)  
	Modules: AI/dns_analyzer.py, server/network_monitor.py, server/server.py, AI/pcs_ai.py  
	Test: Generate suspicious DNS behavior (e.g., long/high-entropy subdomains or DNS tunneling patterns) and verify: (1) dns_security.json shows increased total_queries and suspicious/tunneling counts for the source IP, (2) high-confidence DNS abuse is promoted into threat_log.json via pcs_ai, (3) the dashboard DNS Security card in Section 18 reflects the analyzer metrics, and (4) relay ai_training_materials/global_attacks.json and attack_statistics.json contain sanitized DNS-attack entries when relay is enabled.

- [ ] Ability: Drift detection  
	Modules: AI/drift_detector.py  
	Test: Feed unusual distributions (features or labels) and verify drift status is tracked and, if configured, that retraining flags are raised.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (all elevated attacks from the core pipeline).
- ai_training_materials/attack_statistics.json (aggregated counts and trends computed by relay_server.py).

---

### Appendix S1 – Stage 1 Relay Plumbing Runbook

1. **Prepare keys on server and relay**  
	- Ensure matching HMAC keys exist under [server/crypto_keys](server/crypto_keys) on the customer node and [relay/ai_training_materials/crypto_keys](relay/ai_training_materials/crypto_keys) on the relay.  
	- If rotating keys, restart both server and relay so AI/crypto_security.py and relay_server.py reload them.

2. **Send a signed test message**  
	- Follow [testconnection.md](testconnection.md) or your existing test script to construct a small JSON message and sign it using AI/crypto_security.py.  
	- POST or WebSocket-send this message to the relay endpoint exposed by relay_server.py.

3. **Verify relay acceptance and sanitization**  
	- On the relay, check its logs and [relay/ai_training_materials/global_attacks.json](relay/ai_training_materials/global_attacks.json) (if you send a real attack event).  
	- Confirm the relay:  
		- Rejects messages with an invalid HMAC.  
		- Accepts valid ones and records only sanitized metadata (no raw payloads or PII).

---

## Stage 3: Ensemble Decision Engine (Weighted Voting)

**README Alignment:** Validates "Stage 3: Ensemble Decision Engine" (weighted voting → consensus → final verdict)

**What This Tests:**
- Weighted voting calculation (signal_weight × confidence × is_threat)
- Threshold decisions (≥75% block, ≥50% log, <50% allow)
- APT mode threshold adjustment (70% in critical infrastructure mode)
- Authoritative signal boosting (honeypot/threat intel override)
- Consensus strength classification (unanimous/strong/divided)

### Tests

- [ ] Ability: Ensemble weighted voting  
	Modules: AI/meta_decision_engine.py, AI/false_positive_filter.py  
	Test: Generate attack with mixed signal confidence scores, verify weighted score calculation matches formula, threshold-based decision (block/log/allow) is correct, and decision_history.json records per-signal contributions.

- [ ] Ability: APT detection mode  
	Modules: AI/meta_decision_engine.py  
	Test: Set APT_DETECTION_MODE=true, verify block threshold lowers from 75% to 70%, test borderline attack (72% score) blocks in APT mode but only logs in normal mode.

- [ ] Ability: Authoritative signal boosting  
	Modules: AI/meta_decision_engine.py  
	Test: Trigger honeypot interaction (confidence ≥0.7) or threat intel match (confidence ≥0.9), verify final weighted score forced to 90%+ regardless of other signals, confirm auto-block decision.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (ensemble decisions with weighted scores and final verdicts)

---

## Stage 4: Response Execution (Policy-Governed)

**README Alignment:** Validates "Stage 4: Response Execution" (immediate actions → logging → alerts)

**What This Tests:**
- Firewall blocking (iptables/nftables with TTL)
- Active connection termination
- Rate limiting (50-74% confidence attacks)
- Multi-surface logging (threat_log.json + 10+ audit files)
- Real-time dashboard WebSocket updates
- Alert delivery (email/SMS/SOAR/SIEM)

### Tests

- [ ] Ability: Automated firewall blocking  
	Modules: AI/pcs_ai.py, server/network_monitor.py  
	Test: Generate attack exceeding 75% threshold, verify firewall rule added (check iptables/nftables), connection dropped, block persists for TTL duration, unblocks after expiry.

- [ ] Ability: Rate limiting for medium-confidence threats  
	Modules: AI/pcs_ai.py  
	Test: Generate attack scoring 60-74%, verify rate limiting applied instead of full block, connection throttled but not terminated, threat_log.json shows rate_limited action.

- [ ] Ability: Multi-surface audit logging  
	Modules: AI/pcs_ai.py, server/server.py  
	Test: Trigger diverse attacks, verify each writes to: threat_log.json, comprehensive_audit.json, attack_sequences.json (LSTM), lateral_movement_alerts.json (graph), behavioral_metrics.json (heuristics), dns_security.json (DNS), tls_fingerprints.json (TLS).

- [ ] Ability: Real-time dashboard updates  
	Modules: server/server.py (WebSocket)  
	Test: Generate attack while dashboard is open, verify threat appears in UI within 2 seconds, Security Overview counters increment, Attack Type Breakdown chart updates, IP Management table adds new row.

- [ ] Ability: Alert delivery (email/SMS/SOAR)  
	Modules: AI/alert_system.py, AI/soar_api.py  
	Test: Configure alerts, trigger critical threat (severity ≥ DANGEROUS), verify alert sent via configured channels (check email inbox, SMS logs, SOAR incident created).

Relay output files for this stage:
- ai_training_materials/global_attacks.json (response actions recorded: blocked, rate_limited, alerted)

---

## Stage 5: Training Material Extraction (Privacy-Preserving)

**README Alignment:** Validates "Stage 5: Training Material Extraction" (sanitized signatures/statistics/reputation → no payloads/PII)

**What This Tests:**
- Signature extraction (patterns only, zero exploit code)
- Behavioral statistics anonymization
- IP reputation hashing (SHA-256, not raw IPs)
- Graph topology anonymization (A→B→C labels, not real IPs)
- ML model weight deltas (not full models)

### Tests

- [ ] Ability: Deception & honeypot signatures

- [ ] Ability: Adaptive honeypot personas  
	Modules: AI/adaptive_honeypot.py  
	Test: Start the honeypot on a chosen persona/port, hit it from an external client, confirm honeypot_attacks.json is updated, pcs_ai records a honeypot_* threat, and signature_extractor/signature_uploader prepare a **signature only** (no raw exploit payload) for the relay.

- [ ] Ability: Honeypot → signature pipeline  
	Modules: AI/signature_extractor.py, AI/signature_uploader.py, relay/signature_sync.py  
	Test: After honeypot hits, verify a new pattern_hash/signature is appended in relay/ai_training_materials/ai_signatures/learned_signatures.json with metadata only (no exploit code).

Relay output files for this stage:
- ai_training_materials/global_attacks.json (honeypot attacks promoted to global view).
- ai_training_materials/ai_signatures/learned_signatures.json (stored attack patterns/signatures).

---

### Appendix S3 – Stage 3 Honeypot & Signature Runbook

1. **Start a honeypot persona**  
	- Configure and start AI/adaptive_honeypot.py with a chosen persona/port on a non-critical host or test segment.  
	- Confirm the honeypot is listening and reachable from a separate test machine.

2. **Generate a controlled honeypot hit**  
	- From the test machine, connect to the honeypot port using a simple tool (e.g., curl, netcat, or an RDP/SSH client depending on persona).  
	- Open the relevant local JSONs and verify:  
		- Honeypot events are added to the honeypot_attacks or equivalent JSON file.  
		- AI/pcs_ai.py has produced a honeypot_* entry in [server/json/threat_log.json](server/json/threat_log.json).

3. **Verify signature extraction and relay export**  
	- Run the signature extraction/uploader path (AI/signature_extractor.py → AI/signature_uploader.py).  
	- On the relay host, open [relay/ai_training_materials/ai_signatures/learned_signatures.json](relay/ai_training_materials/ai_signatures/learned_signatures.json) and check for a new signature/pattern_hash corresponding to your honeypot event, containing metadata/features only (no exploit payload).

---

## Stage 4 – Network, Devices & Behavioral Analytics

- [ ] Ability: Network attack detection (scans/floods/ARP)  
	Modules: server/network_monitor.py, AI/pcs_ai.py  
	Test: Run a controlled port scan / SYN flood / ARP spoof from a test host, confirm detection entries in threat_log.json and appropriate actions (block / monitor) without crashing packet capture.

- [ ] Ability: Device discovery & inventory  
	Modules: server/device_scanner.py, AI/asset_inventory.py, AI/node_fingerprint.py  
	Test: Scan the LAN, verify connected_devices.json + device_history.json and asset_inventory stats, and confirm devices show up correctly on the dashboard map.

- [ ] Ability: Behavioral heuristics (per-IP scoring)  
	Modules: AI/behavioral_heuristics.py, server/network_monitor.py  
	Test: Generate abusive behavior (high connection rate, retries, auth failures) from a single IP and verify a rising heuristic_score and associated risk_factors as network_monitor feeds flow events into the heuristics engine.

- [ ] Ability: Graph-based lateral movement / C2  
	Modules: AI/graph_intelligence.py, server/network_monitor.py, AI/advanced_visualization.py  
	Test: Create a small set of multi-hop connections in your environment (e.g., attacker → pivot → internal target) and confirm network_graph.json and lateral_movement_alerts.json are updated, and the dashboard graph/kill-chain views reflect the suspicious paths.

- [ ] Ability: Encrypted C2 / TLS fingerprinting  
	Modules: AI/tls_fingerprint.py, server/network_monitor.py, server/server.py, AI/pcs_ai.py  
	Test: Produce TLS-like traffic on non-standard ports or with high fan-out from a single source IP; verify tls_fingerprints.json records suspicious TLS usage, high-confidence encrypted-C2 style events appear in threat_log.json, the Traffic Analysis (Section 17) Encrypted Traffic card shows `encrypted_percent / N suspicious` when appropriate, and relay ai_training_materials/global_attacks.json and attack_statistics.json include sanitized encrypted-C2 attack entries when relay is enabled.

- [ ] Ability: Zero Trust posture  
	Modules: AI/zero_trust.py, AI/policy_governance.py  
	Test: Define a simple trust policy and violate it with a device or user; confirm policy violation is logged and, if configured, leads to a block/quarantine recommendation.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (network/behavior/zero-trust violations escalated as attacks).
- ai_training_materials/attack_statistics.json (updated statistics including these events).

---

## Stage 5 – Threat Intelligence & Signatures

- [ ] Ability: Local threat intelligence aggregation  
	Modules: AI/threat_intelligence.py, AI/reputation_tracker.py  
	Test: Feed known bad indicators (IP/domain/hash) via `ThreatIntelligence.ingest_indicator(...)`, confirm they appear in `server/json/local_threat_intel.json`, that `AI/reputation_tracker.py` reflects them in reputation/export data, and that subsequent `check_ip_reputation(ip)` calls for those entities show boosted threat_score and LocalIntel/ReputationTracker details.

- [ ] Ability: Signature distribution from relay  
	Modules: AI/signature_distribution.py, AI/relay_client.py, relay/training_sync_api.py  
	Test: Place a model/signature on the relay, ensure the customer node pulls it successfully and that pcs_ai starts using it in decisions.

Relay output files for this stage:
- ai_training_materials/ai_signatures/learned_signatures.json (central signature store).
- ai_training_materials/threat_intelligence/ (OSINT / threat feed JSON files maintained by crawlers).
- ai_training_materials/reputation_data/ (aggregated global reputation exports).
- ai_training_materials/global_attacks.json (attacks enriched by intel/reputation).

---

### Appendix S5 – Stage 5 Intel & Signature Runbook

1. **Seed local threat intelligence**  
	- From a trusted admin shell on the server, call `ThreatIntelligence.ingest_indicator(...)` in AI/threat_intelligence.py for a known-bad IP or domain (use something from a real OSINT feed or your lab list).  
	- Confirm [server/json/local_threat_intel.json](server/json/local_threat_intel.json) contains the new indicator with correct metadata.

2. **Verify reputation and scoring behaviour**  
	- Query `check_ip_reputation(ip)` for the same entity and verify:  
		- The `threat_score` is higher than for a benign IP.  
		- LocalIntel and ReputationTracker sections are populated in the result.  
	- Generate traffic from that IP (or simulate via pcs_ai event injection) and confirm the threat appears with elevated severity in [server/json/threat_log.json](server/json/threat_log.json).

3. **Confirm relay intel/signature export**  
	- On the relay host, inspect:  
		- [relay/ai_training_materials/reputation_data](relay/ai_training_materials/reputation_data) for updated reputation exports.  
		- [relay/ai_training_materials/ai_signatures/learned_signatures.json](relay/ai_training_materials/ai_signatures/learned_signatures.json) for any relevant signatures tied to this indicator.  
		- [relay/ai_training_materials/global_attacks.json](relay/ai_training_materials/global_attacks.json) for attacks enriched with intel/reputation fields.

---

## Stage 6 – Policy, Governance & Self-Protection

- [ ] Ability: Formal threat model + governance  
	Modules: AI/formal_threat_model.py, AI/policy_governance.py  
	Test: Define a scenario in the formal model and ensure policy decisions are honored (e.g., require approval before certain actions), that pending/approved/rejected requests appear in server/json/approval_requests.json, and that governance_audit.json records the lifecycle (created/approved/rejected) of those decisions.

- [ ] Ability: Self-protection & kill-switch  
	Modules: AI/self_protection.py, AI/emergency_killswitch.py  
	Test: Trigger a controlled integrity/self-protection event in your environment (e.g., deliberate model tampering or telemetry suppression) and verify: (1) server/json/integrity_violations.json records the violation with severity and recommended_action, (2) server/json/comprehensive_audit.json receives a matching INTEGRITY_VIOLATION event, and (3) when AUTO_KILLSWITCH_ON_INTEGRITY=true and severity is critical, the kill-switch mode moves into SAFE_MODE and is visible on the dashboard.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (policy violations and self‑protection events that are promoted to global attacks).

---

### Appendix S6 – Stage 6 Governance & Self-Protection Runbook

1. **Exercise governance approvals**  
	- Use AI/policy_governance.py to create at least one approval request (e.g., for a sensitive configuration change).  
	- Confirm:  
		- [server/json/approval_requests.json](server/json/approval_requests.json) shows the pending request.  
		- [server/json/governance_audit.json](server/json/governance_audit.json) records request creation and the eventual approve/reject decision.

2. **Trigger a controlled integrity/self-protection event**  
	- In a non-production environment, deliberately modify a watched file or model (following AI/self_protection.py guidance), or call a self-protection check with a known-bad state.  
	- Verify:  
		- [server/json/integrity_violations.json](server/json/integrity_violations.json) records the violation with severity and recommended_action.  
		- [server/json/comprehensive_audit.json](server/json/comprehensive_audit.json) gains an `INTEGRITY_VIOLATION` event with matching details.

3. **Check kill-switch and relay behaviour**  
	- If `AUTO_KILLSWITCH_ON_INTEGRITY=true` and severity is critical, confirm the kill-switch goes into SAFE_MODE via its status API/dashboard.  
	- On the relay (if enabled), confirm [relay/ai_training_materials/global_attacks.json](relay/ai_training_materials/global_attacks.json) includes any policy/self-protection events that the ensemble promoted as global attacks (sanitized metadata only).

---

## Stage 7 – Cryptography, Lineage & Federated / Relay

- [ ] Ability: Cryptographic lineage & model provenance  
	Modules: AI/cryptographic_lineage.py, relay/ai_retraining.py  
	Test: After a training cycle on the relay, confirm models are signed/attributed correctly and customers can see lineage info via the lineage stats API (chain depth, sources, signatures). Then deliberately introduce a bad lineage condition (e.g., break a parent_hash or inject an out-of-order checkpoint) and verify: (1) `get_model_lineage_stats` reports `chain_integrity.issues` and/or `lineage_drift.drift_detected=true`, and (2) `server/json/comprehensive_audit.json` contains new `THREAT_DETECTED` events from `cryptographic_lineage` describing the integrity/drift issues.

- [ ] Ability: Byzantine-resilient federated aggregation  
	Modules: AI/byzantine_federated_learning.py, AI/training_sync_client.py, relay/ai_retraining.py  
	Test: Run multiple peers with one deliberately bad update and verify: (1) the Byzantine defender stats (`get_byzantine_defense_stats`) show non-zero `rejected_updates` and updated peer trust scores, (2) `server/json/comprehensive_audit.json` records `THREAT_DETECTED` events from `byzantine_defender` with `action="federated_update_rejected"`, and (3) when the `relay/` tree is present, `relay/ai_training_materials/global_attacks.json` gains sanitized `attack_type="federated_update_rejected"` entries tagged with `source="relay_federated_defense"`.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (training/federation-related security incidents surfaced as `federated_update_rejected` attacks when the relay stack is present).
- ai_training_materials/global_attacks.json + ai_training_materials/ai_signatures/learned_signatures.json are also the input training materials consumed by ai_retraining.py.

---

## Stage 8 – Enterprise, Cloud & SOAR

- [ ] Ability: Enterprise integrations  
	Modules: AI/enterprise_integration.py, AI/soar_api.py, AI/soar_workflows.py  
	Test: Trigger a representative incident and confirm that the expected SOAR workflow and external integration calls fire, that the case is written to server/json/soar_incidents.json, and that a corresponding THREAT_DETECTED entry appears in server/json/comprehensive_audit.json (with high/critical incidents also visible as `soar_incident` records in relay/ai_training_materials/global_attacks.json when the relay is present).

- [ ] Ability: Cloud posture checks (CSPM)  
	Modules: AI/cloud_security.py  
	Test: With cloud CLIs available, run posture checks and verify misconfigurations and IAM issues show up in server/json/cloud_findings.json and dashboard metrics, and that high/critical misconfigurations and public exposures generate THREAT_DETECTED entries in server/json/comprehensive_audit.json and `cloud_misconfiguration` incidents in relay/ai_training_materials/global_attacks.json when the relay stack is present.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (incidents raised from SOAR/cloud posture that are shared globally).

---

### Appendix S8 – Stage 8 Enterprise & Cloud Runbook

1. **Create and escalate a SOAR incident**  
	- Use AI/soar_workflows.py (directly or via your API) to create a new incident with type and severity (e.g., `critical` for a controlled test).  
	- Confirm:  
		- [server/json/soar_incidents.json](server/json/soar_incidents.json) contains the new case.  
		- [server/json/comprehensive_audit.json](server/json/comprehensive_audit.json) records a `THREAT_DETECTED` event from `soar_workflows` with `action="incident_created"`.  
		- When relay is present and severity is high/critical, [relay/ai_training_materials/global_attacks.json](relay/ai_training_materials/global_attacks.json) has a new `attack_type="soar_incident"` entry.

2. **Run a cloud posture scan**  
	- With relevant cloud CLIs installed (aws/az/gcloud), invoke AI/cloud_security.py get_stats() from the server context.  
	- Verify:  
		- [server/json/cloud_findings.json](server/json/cloud_findings.json) is updated with current misconfigurations/IAM issues.  
		- Any high/critical misconfigs or public exposures create `THREAT_DETECTED` events from `cloud_security` in comprehensive_audit.json.  
		- When relay is enabled, matching `attack_type="cloud_misconfiguration"` incidents appear in global_attacks.json.

---

## Stage 9 – Resilience, Backup & Compliance

- [ ] Ability: Backup & ransomware resilience  
	Modules: AI/backup_recovery.py  
	Test: Run backup directory checks and a controlled restore test in your environment; confirm server/json/backup_status.json and server/json/recovery_tests.json reflect realistic RTO/RPO and resilience scores, and that any failed/overdue backups and low ransomware resilience generate THREAT_DETECTED entries in server/json/comprehensive_audit.json and corresponding `backup_issue` / `ransomware_resilience_low` records in relay/ai_training_materials/global_attacks.json when the relay stack is present.

- [ ] Ability: Compliance & reporting  
	Modules: AI/compliance_reporting.py, server/report_generator.py  
	Test: Generate an enterprise security report and verify the compliance/controls sections reflect current telemetry and SBOM data; for PCI-DSS, HIPAA, and GDPR, intentionally drive at least one non‑COMPLIANT or breach‑notification condition and confirm that a corresponding compliance_issue event appears in server/json/comprehensive_audit.json and relay/ai_training_materials/global_attacks.json.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (any ransomware/backup/compliance‑related incidents that are escalated as attacks).

---

## Stage 10 – Explainability, Visualization & Dashboard

- [ ] Ability: Explainable decisions  
	Modules: AI/explainability_engine.py, AI/pcs_ai.py  
	Test: For a non-trivial detection, capture the explanation output and confirm it lists the contributing signals and reasoning. In a controlled negative test (for example, by temporarily disabling the explainability backend or calling `/api/explainability/decisions` while models are unavailable), verify that the API returns a structured error and that `server/json/comprehensive_audit.json` records a `SYSTEM_ERROR` event from `dashboard_api` with `target="/api/explainability/decisions"`.

- [ ] Ability: Advanced visualizations  
	Modules: AI/advanced_visualization.py, AI/advanced_orchestration.py  
	Test: Generate the visualization_data.json set and confirm the dashboard renders topology, heatmaps, timelines, and geo views without errors. In a controlled failure test (for example, by pointing visualization code at an invalid JSON or temporarily removing a required input file), call `/api/visualization/topology`, `/api/visualization/heatmap`, or `/api/visualization/geographic` and confirm that failures are mirrored into `server/json/comprehensive_audit.json` as `SYSTEM_ERROR` events from `dashboard_api` with `target` matching the failing endpoint.

- [ ] Ability: Dashboard & API surface  
	Modules: AI/inspector_ai_monitoring.html, AI/swagger_ui.html, server/server.py, AI/dns_analyzer.py, AI/tls_fingerprint.py  
	Test: Load the monitoring UI and (optionally) the Swagger UI, confirming endpoints and data wiring are correct. Pay special attention to Section 17 (Traffic Analysis & Inspection) and Section 18 (DNS & Geo Security) to verify that `/api/traffic/analysis` and `/api/dns/stats` surface the TLS and DNS analyzer metrics from tls_fingerprints.json and dns_security.json, and that suspicious DNS/TLS activity appears consistently with earlier stage tests.

Relay output files for this stage:
- No additional JSON beyond the same central files used by earlier stages:
	ai_training_materials/global_attacks.json (attacks already logged).
	ai_training_materials/ai_signatures/learned_signatures.json (signatures already logged).

---

### Appendix S10 – Stage 10 Explainability & Dashboard Runbook

1. **Exercise a healthy explainability path**  
	- In a test window, trigger a non-trivial detection (for example, a controlled scan or honeypot hit that the ensemble will score as THREAT/BLOCK).  
	- From the dashboard or via `/api/explainability/decisions`, fetch recent decisions and confirm:  
		- The returned object includes `decisions` with `final_verdict`, `threat_score`, and per-signal contributions.  
		- At least one entry shows a rich breakdown (primary threat type, attack stage, consensus, recommendations) matching the event you triggered.

2. **Verify explainability failure is audited**  
	- In a non-production environment, temporarily break the explainability path (for example, by stopping the backend that serves decisions or by forcing `get_explainability_decisions` to raise an error).  
	- Call `/api/explainability/decisions` and confirm:  
		- The API returns a structured error JSON with safe defaults.  
		- `server/json/comprehensive_audit.json` contains a new `SYSTEM_ERROR` event with `actor="dashboard_api"`, `action="endpoint_error"`, and `target="/api/explainability/decisions"`.

3. **Exercise visualization and dashboard APIs**  
	- With normal data present (threat_log.json, connected_devices.json, etc.), call `/api/visualization/topology`, `/api/visualization/heatmap`, `/api/visualization/geographic`, and `/api/visualization/all` from the UI or via curl.  
	- Confirm each endpoint returns `status="success"` and that the dashboard renders topology, heatmaps, and geo cards without errors.

4. **Verify visualization failures are audited**  
	- Create a controlled visualization failure (for example, temporarily move or corrupt `server/json/threat_log.json` or `server/json/connected_devices.json` on a lab node).  
	- Re-call the affected visualization endpoint(s) and confirm:  
		- The API returns a JSON payload with `status="error"`.  
		- `server/json/comprehensive_audit.json` records corresponding `SYSTEM_ERROR` events from `dashboard_api` with `target` set to the failing endpoint (such as `/api/visualization/topology` or `/api/visualization/geographic`).

---

## Logging & Central Capture Checklist (Applies to All Stages)

For every test above, explicitly verify:

- [ ] Local JSON logging is correct (server/json/*, AI-specific JSON files).  
- [ ] Dashboard renders the new data (cards, charts, tables updated as expected).  
- [ ] If relay is configured:
	- [ ] HMAC-protected messages are accepted by relay_server.py.  
	- [ ] relay/ai_training_materials/global_attacks.json and ai_signatures/learned_signatures.json contain **only sanitized metadata and signatures**, not raw exploit payloads.  
	- [ ] SignatureSyncService (relay/signature_sync.py) increments counts and deduplicates correctly.

Use this section as a final gate before marking any of the abilities above as "tested".

---

## Appendix A – DNS & TLS End-to-End Test Runbook

This appendix gives a concrete, step-by-step runbook to validate the **DNS analyzer** and **TLS fingerprinting** paths from raw traffic → AI modules → JSON → dashboard → relay.

> Assumptions:
> - The server container is running and capturing traffic on the relevant interface.
> - The relay stack is running and correctly configured in the server `.env` (for relay checks).
> - You can generate traffic **from another host on the same network** toward the sensor.

### A.1 DNS Analyzer Path (dns_analyzer → pcs_ai → dashboard → relay)

1. **Generate baseline DNS traffic**
	 - From a test host, run a few normal lookups so you can see non-suspicious baselines:
		 - Windows: `nslookup example.com <your_DNS_server>`
		 - Linux/macOS: `dig example.com @<your_DNS_server>`
	 - Confirm that:
		 - `server/json/dns_security.json` is created and contains an entry for the source IP under `sources[<ip>].total_queries`.
		 - Section 18 (DNS & Geo Security) on the dashboard shows a non-zero **DNS Queries Analyzed** count.

2. **Generate suspicious-looking DNS patterns**
	 - From the same test host, issue queries with:
		 - Long, high-entropy subdomains.
		 - Repeated random-looking labels.
	 - Examples (replace `<your_DNS_server>` and domain as needed):
		 - Windows:
			 - `nslookup aaaaaaaa11111111bbbbbbbb22222222.mydomain.test <your_DNS_server>`
			 - `nslookup qwe9zxc8asd7rty6fgh5vbn4.mydomain.test <your_DNS_server>`
		 - Linux/macOS:
			 - `dig aaaaaaaa11111111bbbbbbbb22222222.mydomain.test @<your_DNS_server>`
			 - `dig qwe9zxc8asd7rty6fgh5vbn4.mydomain.test @<your_DNS_server>`

3. **Check local DNS analyzer metrics**
	 - Open `server/json/dns_security.json` and verify for the attacking IP:
		 - `total_queries` increased.
		 - `suspicious_queries` (or equivalent suspicious/tunneling counter) increased.
	 - Confirm that entries reflect the time of your test.

4. **Check local threat log for DNS-derived threats**
	 - Open `server/json/threat_log.json` and look for recent entries where:
		 - `threat_type` or `attack_type` indicates DNS tunneling/DGA/abuse.
		 - `details.reasons` (or similar field) mentions DNS analyzer reasons.

5. **Check dashboard – Section 18 (DNS & Geo Security)**
	 - In the UI (Section 18):
		 - Confirm **DNS Queries Analyzed** matches (roughly) the aggregated `total_queries` from dns_security.json.
		 - If your test triggered high-confidence DNS abuse, verify any **tunneling/suspicious** indicators increase.

6. **Check relay global view (if relay enabled)**
	 - On the relay host, open:
		 - `relay/ai_training_materials/global_attacks.json`
		 - `relay/ai_training_materials/attack_statistics.json`
	 - Verify that new entries exist with:
		 - `sensor_id` matching the customer node.
		 - `threat_type`/`attack_type` consistent with DNS tunneling/DGA-style events.
		 - No raw packet payloads (metadata only).

### A.2 TLS Fingerprinting Path (tls_fingerprint → pcs_ai → dashboard → relay)

1. **Generate normal HTTPS traffic (baseline)**
	 - From a test host, send some regular HTTPS requests to typical ports (443):
		 - `curl https://example.com/`
		 - Browse HTTPS sites through the monitored gateway.
	 - Confirm that:
		 - `server/json/tls_fingerprints.json` is created with an entry for the source IP (total_flows, unique_dests, etc.).
		 - Section 17 (Traffic Analysis & Inspection) shows a reasonable **Encrypted Traffic** percentage.

2. **Generate non-standard TLS traffic**
	 - From the test host, target the sensor or another internal service on unusual TLS-like ports (e.g., 8443, 9443):
		 - `curl -k https://<sensor_ip>:8443/` (if a TLS listener exists)
		 - Or run a simple TLS server on a high port in your environment, then:
			 - `curl -k https://<server_ip>:9443/`
	 - Alternatively, use OpenSSL if available:
		 - `openssl s_client -connect <sensor_ip>:8443`

3. **Check local TLS fingerprint metrics**
	 - Open `server/json/tls_fingerprints.json` and verify for the attacking IP:
		 - `total_flows` increased.
		 - `nonstandard_tls_ports` includes the high ports you used.
		 - Any internal `suspicious`/confidence flags or counters increased.

4. **Check local threat log for encrypted-C2 style threats**
	 - Open `server/json/threat_log.json` and look for recent entries where:
		 - `threat_type` or `attack_type` indicates encrypted C2 / suspicious TLS.
		 - `details.reasons` mention TLS fingerprint anomalies (non-standard ports, fan-out, beaconing).

5. **Check dashboard – Section 17 (Traffic Analysis & Inspection)**
	 - In the UI, locate the **Encrypted Traffic** card:
		 - When `suspicious_tls_sources == 0`, it should show just `<percent>%`.
		 - After your anomalous TLS tests, verify it can show `<percent>% / N suspicious` where `N` is the number of suspicious TLS sources.

6. **Check relay global view (if relay enabled)**
	 - On the relay host, inspect:
		 - `relay/ai_training_materials/global_attacks.json`
		 - `relay/ai_training_materials/attack_statistics.json`
	 - Confirm that new records exist for the test IP with:
		 - `threat_type`/`attack_type` reflecting encrypted C2 / TLS anomaly.
		 - `sensor_id` identifying the sending customer node.
		 - Only metadata/features (no raw TLS payloads), suitable for training.

---

## Appendix B – Stage 9 Backup & Compliance Runbook

This appendix gives concrete steps to validate that **Stage 9** backup/ransomware and compliance events are wired from local checks → JSON → audit log → relay.

### B.1 Backup & Ransomware Resilience Path (backup_recovery → audit → relay)

1. **Run backup status check**
	 - From the server container/host, run the existing backup status path (for example via the dashboard API or a direct call into backup_recovery.get_stats()).
	 - Confirm that:
		 - [server/json/backup_status.json](server/json/backup_status.json) exists and lists your backup locations with `last_backup`, `hours_since_backup`, and `status`.
		 - [server/json/recovery_tests.json](server/json/recovery_tests.json) contains at least one recent test (you can trigger `test_backup_restore("TEST")` in a controlled environment if needed).

2. **Create a controlled "overdue" backup condition**
	 - Pick a non-critical backup path (for example a test backup directory) and ensure its `last_backup` timestamp is older than your acceptable RPO (e.g., > 48 hours) or temporarily move/disable that backup directory.
	 - Re-run the backup status function so that at least one entry comes back with `status != "success"` and a large `hours_since_backup`.

3. **Verify backup incidents in the audit log**
	 - Open [server/json/comprehensive_audit.json](server/json/comprehensive_audit.json) and search for recent entries where:
		 - `actor` is `backup_recovery`.
		 - `action` is `backup_issue_detected` or `ransomware_resilience_low`.
	 - Confirm that `details` includes the affected `location` and `hours_since_backup` (for backup_issue) or the low resilience score (for ransomware_resilience_low).

4. **Verify relay/global view (if relay enabled)**
	 - On the relay host, open [relay/ai_training_materials/global_attacks.json](relay/ai_training_materials/global_attacks.json).
	 - Confirm that new records exist with:
		 - `attack_type` set to `backup_issue` or `ransomware_resilience_low`.
		 - Backup-related fields only (location, hours_since_backup, resilience_score) with no raw file contents.
		 - `source` equal to `backup_recovery`.

### B.2 Compliance Issue Path (compliance_reporting → audit → relay)

1. **Generate compliance reports**
	 - From the server environment, run the compliance reporting helper (e.g., generate_all_compliance_reports()) or whatever API surface you expose for PCI/HIPAA/GDPR.
	 - Confirm that JSON reports are written under [server/json/compliance_reports](server/json/compliance_reports).

2. **Drive a non-COMPLIANT or breach-notification condition**
	 - In a controlled environment, re-run reports with a period that includes known critical incidents, or temporarily adjust thresholds so that:
		 - PCI-DSS sets `compliance_status` to `NEEDS_ATTENTION` or `NEEDS_IMPROVEMENT`, or
		 - HIPAA / GDPR mark a breach notification as required.

3. **Verify compliance issues in the audit log**
	 - Open [server/json/comprehensive_audit.json](server/json/comprehensive_audit.json) and search for recent entries where:
		 - `actor` is `compliance_reporting`.
		 - `action` is `compliance_issue_detected`.
	 - Confirm that `details.standard` is one of `PCI-DSS`, `HIPAA`, or `GDPR`, and that the `status`/summary matches the report.

4. **Verify relay/global view for compliance issues (if relay enabled)**
	 - On the relay host, inspect [relay/ai_training_materials/global_attacks.json](relay/ai_training_materials/global_attacks.json).
	 - Confirm that new records exist with:
		 - `attack_type` set to `compliance_issue`.
		 - `standard` equal to `PCI-DSS`, `HIPAA`, or `GDPR`.
		 - Only metadata about the issue (no underlying PII/PHI or raw log contents).

