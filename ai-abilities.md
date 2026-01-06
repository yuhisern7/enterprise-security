# AI Abilities – Test Checklist

This file is now a **test checklist** for every major type of AI ability in the platform.

- We will use it to verify that:
	- Each ability actually fires on the customer node (local JSON + dashboard).
	- The relay / central server correctly receives the **sanitized log/signature**, when enabled.
	- The **false-positive filter and meta-decision engine** behave as expected (what is blocked, what is only logged, what is ignored).

Legend:
- [ ] Not tested yet
- [x] Tested (local + relay logs verified)

> When you test, tick the box **only when you have confirmed**: local JSON, UI, and (if relay is configured) global/central side all look correct.

---
We organize the tests into **10 stages** (Stage 1–Stage 10). Each stage builds on the previous one.

## Stage Overview (10 Stages)

Follow this order so each stage builds on already-verified plumbing and relay logging:

1. **Stage 1 – Plumbing & Relay Channel**  
	- Test HMAC / key setup and basic relay connectivity.  
	- Goal: prove the customer node can send a signed, sanitized message that the relay accepts and writes.

2. **Stage 2 – Core Detection Pipeline**  
	- Run the Core Detection & Scoring tests end‑to‑end using a simple scan/attack.  
	- Goal: confirm network_monitor → pcs_ai → threat_log.json → dashboard → relay/global_attacks.json all line up.

3. **Stage 3 – Deception & Honeypots**  
	- Run the honeypot and honeypot→signature pipeline tests.  
	- Goal: exercise honeypot → signature_extractor → signature_uploader → relay/signature_sync flow and see a new pattern_hash in learned_signatures.json.

4. **Stage 4 – Network, Devices & Behavioral Analytics**  
	- Run the network, device discovery, heuristics, and zero trust tests.  
	- Goal: confirm device discovery, behavioral scores, and zero-trust policy events all travel through pcs_ai and appear locally and (when relevant) in relay logs.

5. **Stage 5 – Threat Intelligence & Signatures**  
	- Run the local threat intel and signature distribution tests.  
	- Goal: validate that intel and reputation affect scoring, and that relay‑distributed signatures/models are actually pulled and used by pcs_ai.

6. **Stage 6 – Policy, Governance & Self-Protection**  
	- Run the formal threat model, governance, and self‑protection tests.  
	- Goal: ensure policy decisions, approvals, and self‑protection events are logged locally and, when escalated, represented as structured events for the relay.

7. **Stage 7 – Crypto, Lineage & Federated / Relay**  
	- Run secure signing, cryptographic lineage, and federated / Byzantine tests.  
	- Goal: confirm secure messaging, model provenance, and federated stats are consistent between customer and relay.

8. **Stage 8 – Enterprise, Cloud & SOAR**  
	- Run the enterprise integration and cloud posture tests.  
	- Goal: verify incidents raised by the core pipeline trigger the right SOAR/workflow and any cloud posture findings are visible.

9. **Stage 9 – Resilience, Backup & Compliance**  
	- Run the backup/ransomware resilience and compliance/reporting tests.  
	- Goal: confirm backup, restore, and compliance reporting use the same telemetry and that outputs are consistent.

10. **Stage 10 – Explainability, Visualization & Dashboard**  
	- Run the explainability, advanced visualization, and dashboard/API tests.  
	- Goal: ensure explanations, advanced visualizations, and dashboard views correctly reflect all the earlier tests and signals.

For **every** stage above, pair the tests with the Logging & Central Capture Checklist to validate that the complete logical flow – trigger → local JSON → dashboard → relay JSON – works for that stage.

---

## 0. Mapping of 18 Detection Abilities to Files

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
	Files: AI/byzantine_federated_learning.py; AI/training_sync_client.py; relay/ai_retraining.py; relay/gpu_trainer.py; relay/ai_training_materials/ml_models/ (aggregated models after Byzantine-safe updates).

18. **Integrity Monitoring (model & telemetry tampering)**  
	Files: AI/self_protection.py; AI/emergency_killswitch.py; AI/cryptographic_lineage.py; AI/crypto_security.py; AI/policy_governance.py; server/json/comprehensive_audit.json and audit_archive/ (governance/integrity audit trail); AI/pcs_ai.py (routes integrity/self-protection signals into the ensemble).

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

Files that may change:
- [ ] AI/byzantine_federated_learning.py — no schema change; only ensure logging of rejected/accepted updates includes model IDs that match those used in ai_retraining/gpu_trainer.
- [ ] AI/training_sync_client.py — tighten how it sends/receives model updates so they’re always associated with the normalized model IDs and metadata.
- [ ] relay/ai_retraining.py; relay/gpu_trainer.py — label trained models and snapshots with provenance so Byzantine stats and lineage align.

### 18) Integrity Monitoring

Files that may change:
- [ ] AI/self_protection.py; AI/emergency_killswitch.py; AI/cryptographic_lineage.py; AI/crypto_security.py; AI/policy_governance.py — when integrity/self-protection events occur, emit them as structured records into a dedicated integrity log (and/or global_attacks.json with type="integrity_violation"), following the same canonical schema.
- [ ] server/json/comprehensive_audit.json; audit_archive/ — ensure they capture the enriched integrity events with clear links to affected models, configs, and abilities.

---
## Stage 1 – Plumbing & Relay Channel

- [ ] Ability: Secure message signing & relay connectivity  
	Modules: AI/crypto_security.py, server/crypto_keys/, relay/ai_training_materials/crypto_keys/, relay/relay_server.py  
	Test: Use the testconnection.md flow to sign a message on the customer node and verify the relay accepts it only when the HMAC is valid and records a sanitized entry (no raw payload) in its logs.
	Relay output files for this stage: ai_training_materials/global_attacks.json (central attack/event log, when a real attack message is sent).

---

## Stage 2 – Core Detection & Scoring

- [ ] Ability: Multi-signal threat scoring  
	Modules: AI/pcs_ai.py, AI/meta_decision_engine.py, AI/false_positive_filter.py  
	Test: Trigger a clear malicious source (e.g., obvious scan or bad IP), verify threat appears in server/json/threat_log.json, is visible on the dashboard, and relay logs a **sanitized attack/global entry** (no raw payload).

- [ ] Ability: Sequence / kill-chain analysis  
	Modules: AI/sequence_analyzer.py, AI/pcs_ai.py  
	Test: Generate a sequence of events (scan → auth attempts → suspicious traffic) and check the sequence model contributes to an elevated score rather than isolated low-level alerts.

- [ ] Ability: Traffic anomaly detection (autoencoder)  
	Modules: AI/traffic_analyzer.py, AI/network_performance.py  
	Test: Simulate abnormal traffic volume or pattern, confirm anomaly flags in network_performance.json and corresponding entries in threat_log.json.

- [ ] Ability: Drift detection  
	Modules: AI/drift_detector.py  
	Test: Feed unusual distributions (features or labels) and verify drift status is tracked and, if configured, that retraining flags are raised.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (all elevated attacks from the core pipeline).
- ai_training_materials/attack_statistics.json (aggregated counts and trends computed by relay_server.py).

---

## Stage 3 – Deception & Honeypots

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

## Stage 4 – Network, Devices & Behavioral Analytics

- [ ] Ability: Network attack detection (scans/floods/ARP)  
	Modules: server/network_monitor.py, AI/pcs_ai.py  
	Test: Run a port scan / SYN flood / ARP spoof lab, confirm detection entries in threat_log.json and appropriate actions (block / monitor) without crashing packet capture.

- [ ] Ability: Device discovery & inventory  
	Modules: server/device_scanner.py, AI/asset_inventory.py, AI/node_fingerprint.py  
	Test: Scan the LAN, verify connected_devices.json + device_history.json and asset_inventory stats, and confirm devices show up correctly on the dashboard map.

- [ ] Ability: Behavioral heuristics (per-IP scoring)  
	Modules: AI/behavioral_heuristics.py  
	Test: Simulate abusive behavior (high connection rate, retries, auth failures) from a single IP and verify a rising heuristic_score and associated risk_factors.

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
	Test: Feed known bad indicators (IP/domain/hash) and verify they update local reputation and influence scoring decisions.

- [ ] Ability: Signature distribution from relay  
	Modules: AI/signature_distribution.py, AI/relay_client.py, relay/training_sync_api.py  
	Test: Place a model/signature on the relay, ensure the customer node pulls it successfully and that pcs_ai starts using it in decisions.

Relay output files for this stage:
- ai_training_materials/ai_signatures/learned_signatures.json (central signature store).
- ai_training_materials/threat_intelligence/ (OSINT / threat feed JSON files maintained by crawlers).
- ai_training_materials/reputation_data/ (aggregated global reputation exports).
- ai_training_materials/global_attacks.json (attacks enriched by intel/reputation).

---

## Stage 6 – Policy, Governance & Self-Protection

- [ ] Ability: Formal threat model + governance  
	Modules: AI/formal_threat_model.py, AI/policy_governance.py  
	Test: Define a scenario in the formal model and ensure policy decisions are honored (e.g., require approval before certain actions) and logged in approval_requests.json.

- [ ] Ability: Self-protection & kill-switch  
	Modules: AI/self_protection.py, AI/emergency_killswitch.py  
	Test: Trigger a simulated self-protection event and verify that dangerous actions are downgraded or stopped, and that the kill-switch state is visible on the dashboard.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (policy violations and self‑protection events that are promoted to global attacks).

---

## Stage 7 – Cryptography, Lineage & Federated / Relay

- [ ] Ability: Cryptographic lineage & model provenance  
	Modules: AI/cryptographic_lineage.py, relay/ai_retraining.py  
	Test: After a training cycle on the relay, confirm models are signed/attributed correctly and customers can see lineage info.

- [ ] Ability: Byzantine-resilient federated aggregation  
	Modules: AI/byzantine_federated_learning.py, AI/training_sync_client.py, relay/ai_retraining.py  
	Test: Simulate multiple peers with one “bad” update and verify the aggregator rejects or down-weights the malicious update (check byzantine stats).

Relay output files for this stage:
- ai_training_materials/global_attacks.json (any training/federation-related security incidents recorded as attacks).
- ai_training_materials/global_attacks.json + ai_training_materials/ai_signatures/learned_signatures.json are also the input training materials consumed by ai_retraining.py.

---

## Stage 8 – Enterprise, Cloud & SOAR

- [ ] Ability: Enterprise integrations  
	Modules: AI/enterprise_integration.py, AI/soar_api.py, AI/soar_workflows.py  
	Test: Trigger a representative incident and confirm that the expected SOAR workflow and external integration calls fire (even if mocked in dev).

- [ ] Ability: Cloud posture checks (CSPM)  
	Modules: AI/cloud_security.py  
	Test: With cloud CLIs available, run posture checks and verify misconfigurations and IAM issues show up in cloud_findings.json and dashboard metrics.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (incidents raised from SOAR/cloud posture that are shared globally).

---

## Stage 9 – Resilience, Backup & Compliance

- [ ] Ability: Backup & ransomware resilience  
	Modules: AI/backup_recovery.py  
	Test: Run backup directory checks and a simulated restore test; confirm backup_status.json and recovery_tests.json reflect realistic RTO/RPO and resilience scores.

- [ ] Ability: Compliance & reporting  
	Modules: AI/compliance_reporting.py, server/report_generator.py  
	Test: Generate an enterprise security report and verify the compliance/controls sections reflect current telemetry and SBOM data.

Relay output files for this stage:
- ai_training_materials/global_attacks.json (any ransomware/backup/compliance‑related incidents that are escalated as attacks).

---

## Stage 10 – Explainability, Visualization & Dashboard

- [ ] Ability: Explainable decisions  
	Modules: AI/explainability_engine.py, AI/pcs_ai.py  
	Test: For a non-trivial detection, capture the explanation output and confirm it lists the contributing signals and reasoning.

- [ ] Ability: Advanced visualizations  
	Modules: AI/advanced_visualization.py, AI/advanced_orchestration.py  
	Test: Generate the visualization_data.json set and confirm the dashboard renders topology, heatmaps, timelines, and geo views without errors.

- [ ] Ability: Dashboard & API surface  
	Modules: AI/inspector_ai_monitoring.html, AI/swagger_ui.html, server/server.py  
	Test: Load the monitoring UI and (optionally) the Swagger UI, confirming endpoints and data wiring are correct.

Relay output files for this stage:
- No additional JSON beyond the same central files used by earlier stages:
	ai_training_materials/global_attacks.json (attacks already logged).
	ai_training_materials/ai_signatures/learned_signatures.json (signatures already logged).

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

