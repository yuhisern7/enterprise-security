# AI System Architecture & Instructions

> NOTE: This document is written for the full Battle-Hardened AI platform. It describes how the AI, server, relay, and dashboard work together, and annotates the main code files so the AI (and humans) have a clear mental model.

---

## 0. High-Level Architecture

### 0.1 Components

- **Customer Node (server/)**
  - Runs the **Enterprise Security AI** dashboard and detectors on the customer network.
  - Main process: `server/server.py` (Flask/WSGI app, APIs + HTML dashboard serving).
  - Uses **AI modules in AI/** for detection, scoring, orchestration, and deception.
  - Persists logs and state under `server/json/` (threats, devices, performance, configs, AI decisions).
  - Deployed via Docker using `server/docker-compose.yml` and `server/Dockerfile`.

- **AI Intelligence Layer (AI/)**
  - All core detection, scoring, heuristics, ML models, honeypot logic, policy engines.
  - Stateless-ish modules that **read/write** JSON, models, and logs, orchestrated by `AI/pcs_ai.py` and `AI/meta_decision_engine.py`.
  - Exposed to the dashboard and server via Python imports from `server/server.py`.

- **Central Relay / Training Hub (relay/)**
  - **Not shipped to customers**. Lives on your controlled VPS/cloud.
  - Handles **federated learning**, model distribution, exploit DB scraping, and AI retraining.
  - Deployed with its own `relay/docker-compose.yml` and `relay/Dockerfile`.
  - Customer nodes connect to the relay via P2P / WebSocket to share anonymized training data and receive new models/signatures.

- **Dashboard (AI/inspector_ai_monitoring.html + server/server.py)**
  - Single-page HTML UI with 30+ sections mapping to AI abilities.
  - Uses `fetch()` to call server APIs (in `server/server.py`), which in turn delegate to AI modules.
  - Visualizes threats, devices, models, honeypots, compliance, and performance.

### 0.2 Data Flow & Paths Overview

1. **Traffic & Events Ingestion (Server/Customer Node)**
   - `server/network_monitor.py` captures network events and pcap segments.
   - Kernel telemetry (eBPF/XDP) is processed by `AI/kernel_telemetry.py` (when enabled).
   - System logs, device data, user actions, and threat feeds are ingested via server and AI helpers.
   - All persistent JSON written by server-side code ends up under:
     - **Docker:** `/app/json/...` (mounted from `server/json/`).
     - **Native:** `server/json/...` relative to the repo.

2. **Feature Extraction & Detection Signals (AI/ on customer node)**
   - `AI/pcs_ai.py` orchestrates:
     - Signature matches (ExploitDB and custom patterns via `AI/threat_intelligence.py`, `AI/signature_extractor.py`).
     - Behavioral heuristics via `AI/behavioral_heuristics.py`.
     - LSTM and sequence models via `AI/sequence_analyzer.py` (model at `AI/ml_models/sequence_lstm.keras`).
     - Traffic autoencoder anomalies via `AI/traffic_analyzer.py` (model at `AI/ml_models/traffic_autoencoder.keras`).
     - Classical ML models (IsolationForest, RandomForest, GradientBoosting) using pickles in **`ml_models/`** (not `AI/ml_models/`):
       - `_ML_MODELS_DIR = "ml_models"` → in Docker this is `/app/ml_models`.
       - These are created/loaded by `_initialize_ml_models`, `_load_ml_models`, `_save_ml_models` in `AI/pcs_ai.py`.
     - Reputation via `AI/reputation_tracker.py` (SQLite DB now stored under `/app/json/reputation.db` in Docker, `server/json/reputation.db` natively).
     - Honeypot hits via `AI/adaptive_honeypot.py`.

2b. **DNS/TLS Metadata Flow (NDR-only, from network_monitor)**

- `server/network_monitor.py` observes raw TCP/UDP packets via Scapy and, in addition to basic port-scan/flood/ARP rules, now feeds:
  - Per-flow events into `AI/behavioral_heuristics.py` (for connection-rate, fan-out, entropy, etc.).
  - Connection edges into `AI/graph_intelligence.py` (for lateral movement and C2 graph patterns).
  - DNS UDP packets (ports 53/5353) into `AI/dns_analyzer.py`, which:
    - Evaluates domains for tunneling/DGA/exfil patterns.
    - Updates per-IP aggregates in `dns_security.json`.
    - Promotes high-confidence DNS abuse as threats via `pcs_ai._log_threat`, which then log to `threat_log.json` and the relay’s `global_attacks.json`.
  - TLS-like TCP flows into `AI/tls_fingerprint.py`, which:
    - Tracks non-standard TLS ports, high TLS fan-out, and beacon-like patterns.
    - Writes per-IP statistics to `tls_fingerprints.json`.
    - Raises high-confidence encrypted-C2 style threats via `pcs_ai._log_threat` when confidence is high.

- These DNS/TLS threats follow the same downstream path as other threats:
  - They pass through `pcs_ai` (and, where configured, FP filter + meta-engine) into `server/json/threat_log.json`.
  - They are sent to the relay via `AI/relay_client.py` and stored in `relay/ai_training_materials/global_attacks.json` and `attack_statistics.json`.

3. **Meta Decision, Explainability & Graph Intelligence**
   - Raw detection signals are aggregated into an **ensemble decision**:
     - `AI/false_positive_filter.py`: 5-gate pipeline to eliminate noisy positives.
     - `AI/meta_decision_engine.py`:
       - Config file now resolved at runtime:
         - **Docker:** `/app/json/meta_engine_config.json`.
         - **Native:** `server/json/meta_engine_config.json`.
       - Decision history written via `save_decision_history()` to:
         - **Docker:** `/app/json/decision_history.json`.
         - **Native:** `server/json/decision_history.json`.
       - Performs weighted voting, boosts authoritative signals (honeypot, threat intel, FP filter), and returns final `EnsembleDecision` (threat level, should_block, reasons).
     - `AI/explainability_engine.py`:
       - Forensic reports export to:
         - **Docker:** `/app/json/forensic_reports/*.json`.
         - **Native:** `server/json/forensic_reports/*.json`.
       - Also mirrors forensic exports into `relay/ai_training_materials/explainability_data/` when running from the full repo (for training, not for customers).
     - `AI/graph_intelligence.py`:
       - Network graph and lateral movement alerts stored in:
         - **Docker:** `/app/json/network_graph.json` and `/app/json/lateral_movement_alerts.json`.
         - **Native:** `server/json/network_graph.json` and `server/json/lateral_movement_alerts.json`.
       - Graph topology training export written under `relay/ai_training_materials/training_datasets/graph_topology.json` when the relay tree is present.

4. **Actions & Response**
   - `server/server.py` and `server/device_blocker.py` enforce decisions:
     - Block IPs, drop connections, adjust firewall rules.
     - Trigger alerts via `AI/alert_system.py`.
     - Invoke orchestrations / SOAR playbooks via `AI/soar_api.py` and `AI/soar_workflows.py`.
   - Honeypot actions are controlled via `AI/adaptive_honeypot.py` and surfaced through APIs.

5. **Persistence & Learning (Server vs Relay)**
   - **Customer node (server/ + AI/):**
     - Threat logs and decisions written to `server/json/` (or `/app/json/` in Docker) via pcs_ai and server code.
     - Honeypot logs persisted via `AI/adaptive_honeypot.py` into JSON (bounded history) under the same JSON path pattern.
     - Sequence and traffic models persist under `AI/ml_models/` (LSTM + autoencoder), while classical ML pickles live in `ml_models/`.
   - **Relay node (relay/ on your VPS/cloud, not shipped to customers):**
     - All heavy training data, signatures, and global attacks live under the mounted volume:
       - **Container:** `/app/relay/ai_training_materials/`.
       - **Host:** `relay/ai_training_materials/`.
     - `relay/relay_server.py` and `relay/signature_sync.py` write to:
       - `ai_training_materials/global_attacks.json`.
       - `ai_training_materials/ai_signatures/learned_signatures.json`.
     - `relay/training_sync_api.py` and `relay/ai_retraining.py` read/write models in `ai_training_materials/ml_models/`.
     - `relay/gpu_trainer.py` reads from `/app/relay/ai_training_materials` inside its container.
     - ExploitDB lives in `relay/ai_training_materials/exploitdb/`, populated by `relay/setup_exploitdb.sh`:
       - The script now downloads into `relay/exploitdb/` (local to relay/) and you copy that into `relay/ai_training_materials/`.

6. **Model Sync from Relay to Customers**
   - `AI/training_sync_client.py` pulls **only** pre-trained models (no raw training data) from the relay Model API (`relay/training_sync_api.py`).
   - Download location has been aligned with the AI engine:
     - `TrainingSyncClient.local_ml_dir = "ml_models"` → same directory used by `AI/pcs_ai.py` for `_ML_MODELS_DIR`.
     - In Docker this resolves to `/app/ml_models`, which is where the server image copies/uses ML pickles.
   - This fix ensures that models pulled from the relay are actually picked up by the running AI engine without extra path tweaks.

### 0.3 Data Residency & Privacy Guarantees

- **Customer JSON and telemetry stay local by default.**
  - All runtime JSON (threat logs, device lists, decision history, honeypot logs, graph data, forensic reports, etc.) is written under `server/json/` (or `/app/json/...` inside the server container).
  - No module silently uploads these JSON files to any third-party cloud service.
- **Relay is your own VPS/cloud, not a vendor cloud.**
  - The `relay/` tree is deployed only on infrastructure you operate and control (e.g., your VPS/cloud instance).
  - Customers receive only `server/` + `AI/`; they do **not** run `relay/` and have no direct access to your relay-side training materials.
- **Training sync is explicit and limited.**
  - When enabled, `AI/training_sync_client.py`, `AI/central_sync.py`, and `AI/relay_client.py` send **selected, structured training summaries** (and optionally anonymized features) **from customer nodes to your relay APIs**.
  - The relay returns updated models/signatures back to the customer nodes; it does not pull full raw JSON logs unless you explicitly implement and enable such behavior.
- **Auditability and compliance.**
  - External communication paths are centralized in well-defined modules (relay client/sync code, relay APIs), making them easy to review.
  - When extending the system, new outbound data flows should follow this pattern and document what leaves the node, to preserve privacy and compliance guarantees.

---

## 1. Repository Tree & File Purposes

> This is based on the original `enterprise-security` workspace structure. The same logical content now lives in this `battle-hardened-ai` workspace. Each file is annotated with its primary purpose.

### 1.1 Root Level

- `README.md` — Main project overview, marketing-level and technical summary of abilities and dashboard sections.
- `crawlers.md` — Documentation about threat intelligence crawlers and data sources.
- `battle-hardened-ai.code-workspace` — VS Code workspace configuration for this project.
- `ai-abilities.md` — Checklist of AI-related modules, with `[x]/[ ]` to track which have been fully reviewed/improved.
- `ai-instructions.md` (this file) — Deep architecture and file-purpose documentation for AI and system components.

### 1.2 AI/ — Core AI Modules

- `AI/adaptive_honeypot.py` — Adaptive, multi-persona honeypot engine.
  - Listens on configurable ports, mimics services like SSH/FTP/HTTP/SMB/etc.
  - Logs attacker inputs, calculates suspicion scores, categories, and persona stats.
  - Persists attack logs across restarts; exposes status/metrics via helper functions for the server.
- `AI/advanced_orchestration.py` — High-level orchestration logic and runbooks (planned/experimental advanced automation).
- `AI/advanced_visualization.py` — Back-end helpers for advanced visualization (graphs, timeline views) used by the dashboard.
- `AI/alert_system.py` — Central alerting logic (email/SMS/notifications integration for triggered events).
- `AI/asset_inventory.py` — Maintains inventory of assets/devices discovered on the network.
- `AI/backup_recovery.py` — Monitors backup jobs, integrity checks, and recovery readiness.
- `AI/behavioral_heuristics.py` — Implements heuristic rules and behavioral scoring for IPs/sessions.
- `AI/byzantine_federated_learning.py` — Federated learning aggregation with Byzantine-resilient algorithms (Krum, Trimmed Mean, etc.).
- `AI/central_sync.py` — Handles synchronization to/from the central relay (models, signatures, stats).
- `AI/cloud_security.py` — Cloud security posture management (CSPM) logic; integrates cloud account data and misconfiguration checks.
- `AI/compliance_reporting.py` — Generates compliance reports (GDPR, HIPAA, PCI-DSS, SOC2), including summarized AI decisions.
- `AI/crypto_security.py` — Cryptographic hardening routines, key validation, and secure crypto usage guidance.
- `AI/cryptographic_lineage.py` — Model and data lineage: signing, hashing, and provenance tracking for ML artifacts.
- `AI/deterministic_evaluation.py` — Deterministic evaluation and cryptographic proof-of-evaluation for ML models.
- `AI/drift_detector.py` — Measures feature and label drift over time (KS tests, PSI, etc.), surfacing when models go stale.
- `AI/emergency_killswitch.py` — Manages emergency modes (ACTIVE, MONITORING_ONLY, SAFE_MODE, DISABLED) and kill-switch behavior.
- `AI/enterprise_integration.py` — Enterprise tooling integration (ticketing systems, SIEM, ITSM platforms).
- `AI/explainability_engine.py` — Builds explanations for AI decisions (which signals contributed, why something was blocked).
- `AI/false_positive_filter.py` — 5-gate false-positive reduction pipeline.
  - Gate 1: sanity/context (whitelist, internal IPs, coarse checks).
  - Gate 2: behavior consistency (repetition and diversity of signals).
  - Gate 3: temporal correlation (pacing and persistence).
  - Gate 4: cross-signal agreement (multi-signal consensus, with special handling for honeypots).
  - Gate 5: final confidence scoring.
  - Now **honeypot-aware**: honeypot hits are not bypassed by whitelists and can stand alone as strong evidence.
    - Tunable via optional JSON config:
      - Docker: `/app/json/fp_filter_config.json`.
      - Native: `server/json/fp_filter_config.json`.
      - Fields:
        - `min_signals_for_confirmation` — minimum distinct signal types required (default: 2).
        - `min_confidence_threshold` — minimum combined confidence 0.0–1.0 (default: 0.75).
        - `temporal_window` — correlation window in seconds (default: 300).
        - `behavior_repeat_threshold` — repetitions needed for strong behavior score (default: 3).
      - You can also override the config path via `FP_FILTER_CONFIG` env var.
- `AI/file_analyzer.py` — File scanning, metadata extraction, and static analysis hooks (e.g., for sandbox detonation).
- `AI/formal_threat_model.py` — Encodes the formal threat model (policies, risk levels, conditions) used by the AI.
- `AI/graph_intelligence.py` — Graph-based analysis of network entities for lateral movement, C2, and pivot detection.
- `AI/inspector_ai_monitoring.html` — The main HTML dashboard page.
  - Contains the 31 sections of the dashboard, all UI layout and styling, and front-end JavaScript calling back-end `/api/...` endpoints.
- `AI/kernel_telemetry.py` — Processes kernel telemetry (eBPF/XDP) events and converts them into AI-friendly features.
- `AI/meta_decision_engine.py` — Phase 5 meta engine combining detection signals into a final decision.
  - Performs weighted voting based on signal weights and confidences.
  - Boosts **authoritative signals** (honeypot, high-confidence threat intel, high-confidence FP filter) to drive auto-block decisions.
  - Maintains metrics and decision history; can export performance stats per signal type.
- `AI/network_performance.py` — Network performance monitoring and anomaly detection (latency, throughput, error rates).
- `AI/node_fingerprint.py` — Derives device/node fingerprints from traffic and telemetry.
- `AI/p2p_sync.py` — P2P synchronization of models and signatures among nodes, often via the relay.
- `AI/pcap_capture.py` — Utilities for capturing and saving PCAP slices for offline analysis.
- `AI/pcs_ai.py` — Primary AI coordinator.
  - Ties together all models and heuristics into a single `assess_threat` pipeline.
  - Reads/writes JSON logs via the established pattern:
    - **Docker:** `/app/json/...` (mounted from `server/json/`).
    - **Native:** `server/json/...`.
  - Uses:
    - Keras models from `AI/ml_models/sequence_lstm.keras` and `AI/ml_models/traffic_autoencoder.keras`.
    - Classical ML pickles from `ml_models/*.pkl` (`anomaly_detector.pkl`, `threat_classifier.pkl`, `ip_reputation.pkl`, `feature_scaler.pkl`).
  - Constructs DetectionSignals for the meta engine and FP filter.
  - When logging threats to the relay, includes a stable `sensor_id` (from `AI/node_fingerprint.py` when available, otherwise hostname) and both `threat_type` and canonical `attack_type` for global correlation.
- `AI/policy_governance.py` — Manages security policies, approvals, and governance workflows.
- `AI/relay_client.py` — Client-side code for talking to the relay server over HTTP/WebSocket.
- `AI/reputation_tracker.py` — Tracks and updates IP/domain reputation over time.
  - Stores long-term history in a SQLite DB under `/app/json/reputation.db` (Docker) or `server/json/reputation.db` (native).
  - Exposes `record_attack()` and `query_reputation()` to attach cross-session risk (recidivism, severity, geolocation) to entities.
  - Exports training-friendly snapshots into `server/json/reputation_export.json` and `relay/ai_training_materials/reputation_data/` for Stage 5.
- `AI/self_protection.py` — Detects tampering, log deletion anomalies, and self-protective behavior.
  - Maintains integrity baselines and violations under `server/json/integrity_baseline.json` and `server/json/integrity_violations.json`.
  - On each recorded violation, writes a structured `INTEGRITY_VIOLATION` event into the comprehensive audit log (`server/json/comprehensive_audit.json`) so Section 6/31 can see integrity incidents in the compliance views.
  - When `AUTO_KILLSWITCH_ON_INTEGRITY=true` and a violation exceeds the critical severity threshold, it will nudge the emergency kill-switch into `SAFE_MODE` via `AI/emergency_killswitch.py` to prevent further automated blocking until an operator reviews the situation.
- `AI/sequence_analyzer.py` — LSTM and sequence-based modeling of kill chains and temporal patterns.
- `AI/signature_distribution.py` — Handles distribution of signatures to other nodes/relay (including ExploitDB-derived signatures via P2P).
- `AI/signature_extractor.py` — Extracts new signatures from observed malicious traffic.
- `AI/signature_uploader.py` — Uploads new signatures to the relay or central servers.
- `AI/soar_api.py` — Defines SOAR-related API endpoints consumed by external systems.
- `AI/soar_workflows.py` — SOAR playbooks and workflows, mapping AI decisions to automated actions.
- `AI/swagger_ui.html` — Swagger/OpenAPI UI for interacting with the REST APIs.
- `AI/system_log_collector.py` — Collects and normalizes system logs for AI analysis and forensics.
- `AI/threat_intelligence.py` — Threat intel ingestion (OSINT feeds, local DB, ExploitDB helpers) and enrichment.
  - Wraps external IP reputation (VirusTotal, AbuseIPDB) with local context: threat scores are now a blend of VT/AbuseIPDB, local indicators, and the persistent reputation tracker.
  - Provides `ThreatIntelligence.ingest_indicator(value, indicator_type, source, confidence, tags)` for Stage 5 "Local threat intelligence aggregation":
    - Maintains an in-memory map of indicators (IP/domain/hash/CVE/URL) with first_seen/last_seen, sources, tags, times_seen, and max_confidence.
    - For IPs/domains, forwards high-confidence indicators into `AI/reputation_tracker.py` via `record_attack()` so cross-session reputation reflects TI feeds.
    - Persists a JSON view at `server/json/local_threat_intel.json` with a list of locally ingested indicators (no raw customer data beyond the indicator itself).
  - `check_ip_reputation(ip)` now also:
    - Adds a `local_intel` block when the IP matches a locally ingested indicator.
    - Adds a `reputation` block when the entity exists in the reputation DB.
    - Caps a combined 0–100 threat_score that pcs_ai uses for auto-blocking and dashboard stats (Section 3 and 5–7).
- `AI/dns_analyzer.py` — DNS security analyzer (tunneling/DGA/exfil patterns) that tracks per-IP DNS behavior and writes aggregated metrics to `dns_security.json`, and promotes high-confidence DNS abuse as threats via `pcs_ai`.
- `AI/tls_fingerprint.py` — TLS/encrypted-flow fingerprinting (metadata-only) that tracks per-IP encrypted flows and suspicious non-standard TLS usage, writing metrics to `tls_fingerprints.json` for both detection and dashboard use.
- `AI/traffic_analyzer.py` — Traffic autoencoder logic and anomaly scoring.
- `AI/training_sync_client.py` — Client for syncing training data/models to the relay.
- `AI/user_tracker.py` — Tracks user behavior, sessions, and potential insider activity.
- `AI/vulnerability_manager.py` — Vulnerability and SBOM management (ties into `server/json/sbom.json`).
- `AI/zero_trust.py` — Implements Zero Trust logic (per-request/user/device trust evaluations).
- `AI/ml_models/` — Directory for serialized ML models (LSTM, autoencoder, RF, etc.).
- `AI/exploitdb/` — Local ExploitDB mirror for free-mode users (when used).
- `AI/learned_signatures.json` — JSON of automatically learned signatures.

### 1.3 server/ — Customer Node Runtime

- `server/Dockerfile` — Container image definition for the server (customer node).
- `server/docker-compose.yml` — Docker Compose configuration (Linux) for running the server container.
- `server/docker-compose.windows.yml` — Windows variant of Docker Compose.
- `server/.env` / `.env.linux` / `.env.windows` — Environment configuration (ports, TZ, keys, feature flags).
- `server/server.py` — Main Flask/WSGI application.
  - Serves the dashboard UI (inspector AI HTML).
  - Exposes `/api/...` endpoints for:
    - Threat logs, device lists, network stats.
    - Honeypot endpoints (status, configure, stop, attacks, history).
    - Timezone, API keys, configuration management.
    - AI decision preview/testing.
- `server/device_blocker.py` — Applies blocks/isolation (iptables, firewall rules, device-level actions).
- `server/device_scanner.py` — Performs network scanning and device enumeration.
- `server/network_monitor.py` — Monitors network flows and passes them to AI modules.
- `server/pcap/` — Storage for captured PCAP files.
- `server/json/` — Runtime JSON data lake for the node (empty in Git, populated at runtime only):
  - Git tracks the `server/json/` folder (via `.gitkeep`) but **all `*.json` files under it are ignored** by `.gitignore` and created only at runtime.
  - Threats & decisions:
    - `threat_log.json` — Main threat log.
    - `decision_history.json` — Meta-engine decision history (if saved).
  - Devices & network state:
    - `connected_devices.json` — Current devices.
    - `device_history.json` — Historical device states.
    - `network_monitor_state.json` — Network monitor state.
    - `network_performance.json` — Performance metrics.
    - `network_graph.json`, `lateral_movement_alerts.json` — Graph intelligence outputs.
  - Governance & audit:
    - `approval_requests.json` — Policy approval requests.
    - `governance_policies.json` — Governance and approval rules.
    - `governance_audit.json` — Governance/audit trail from policy engine.
    - `comprehensive_audit.json` — Kill-switch comprehensive audit log (with archives in `audit_archive/`).
    - `audit_archive/` — Archived audit JSON files (rotated out of `comprehensive_audit.json`).
  - Explainability & forensics:
    - `forensic_reports/` — Folder of forensic report JSON files generated by the Explainability Engine.
  - Other analytics:
    - `dns_security.json` — Aggregated DNS behavior metrics and suspicious query counts produced by `AI/dns_analyzer.py` from live traffic.
    - `tls_fingerprints.json` — Aggregated TLS/encrypted-flow metrics per source IP produced by `AI/tls_fingerprint.py` (non-payload metadata only).
    - `sbom.json` — SBOM & vulnerability data.
    - `behavioral_metrics.json`, `attack_sequences.json`, `crypto_mining.json`, `drift_baseline.json`, `drift_reports.json`, `formal_threat_model.json`, `reputation_export.json`, etc.
- `server/crypto_keys/` — Local cryptographic keys for signing, encryption.
- `server/installation/` — Installation helpers and scripts.
- `server/report_generator.py` — Generates human-readable reports (PDF/HTML) from logs and AI outputs.
- `server/test_system.py` — Local test harness for the system.
- `server/entrypoint.sh` — Container entrypoint script.
- `server/requirements.txt` — Python dependencies for the server image.

### 1.4 relay/ — Central Relay / Training Hub (NOT for Customers)

> **Important:** The relay folder is **not** shipped to customers. It is meant for the operator’s own infrastructure (VPS/cloud) and runs on a separate Docker deployment.

- `relay/Dockerfile` — Container image for the relay server.
- `relay/docker-compose.yml` — Docker Compose stack for the relay (ports for P2P, model distribution, training APIs).
- `relay/.env.relay` — Environment configuration for the relay node.
- `relay/relay_server.py` — Main relay server handling:
  - P2P mesh (WebSocket) coordination.
  - Model distribution endpoints.
  - Aggregation of training data.
- `relay/ai_retraining.py` — Runs AI retraining jobs (using data from `ai_training_materials/`).
- `relay/training_sync_api.py` — API endpoints for clients to upload training data and pull new models.
- `relay/signature_sync.py` — Handles signature synchronization across nodes.
- `relay/threat_crawler.py` — Orchestrates external threat data crawling (feeds for ExploitDB, OSINT, etc.).
- `relay/exploitdb_scraper.py` — Scrapes or syncs ExploitDB data.
- `relay/gpu_trainer.py` — GPU-accelerated training job runner (for deep models).
- `relay/ai_training_materials/` — Local folder containing training datasets, labels, and artifacts (not for customers).
  - Mounted into the relay container at `/app/relay/ai_training_materials/`.
  - Holds ExploitDB mirror, global attacks, learned signatures, and relay-side trained models.
- `relay/requirements.txt` — Python dependencies for relay image.
- `relay/setup.sh`, `setup-macos.sh`, `setup.bat`, `setup_exploitdb.sh` — Convenience scripts to bootstrap relay and exploit DB.
- `relay/start_services.py` — Starts multiple relay services together as needed.

---

## 2. Dashboard Sections and Back-End Linkage

The dashboard is implemented primarily in `AI/inspector_ai_monitoring.html` and served by `server/server.py`. Each section calls one or more back-end APIs, which in turn use AI modules.

Below is a high-level mapping (not exhaustive, but focused on important sections):

### 2.1 Section 1 – AI Training Network (P2P / Federated Learning)

- **Frontend:**
  - `AI/inspector_ai_monitoring.html` — Section 1 (`#p2p-network-status`).
  - Uses JavaScript functions to query P2P status, connected peers, and federated learning metrics.
- **Backend:**
  - `server/server.py` — `/api/p2p/status`, `/api/p2p/peers` endpoints.
  - `AI/p2p_sync.py` — provides sync logic and status.
  - `AI/byzantine_federated_learning.py` — describes/implements robust aggregation.
  - `AI/relay_client.py` — actual communication to relay.

### 2.2 Section 2 – Network Devices & Ports (Consolidated)

- **Frontend:** Section 2 in `AI/inspector_ai_monitoring.html`.
  - Shows live devices, port scan results, and history tabs.
- **Backend:**
  - `server/device_scanner.py` — scanning and discovery.
  - `server/network_monitor.py` — live network info.
  - JSON state: `server/json/connected_devices.json`, `server/json/device_history.json`.
  - AI enrichment: `AI/asset_inventory.py`, `AI/network_performance.py` for deeper metrics.

### 2.3 Section 3 – VPN/Tor De-Anonymization

- **Frontend:** Section 3 (`Attackers VPN/Tor De-Anonymization Statistics`).
- **Backend:**
  - `server/server.py` — endpoints exposing VPN/Tor stats.
  - `AI/sequence_analyzer.py`, `AI/behavioral_heuristics.py` — detect suspicious VPN/Tor patterns.
  - `AI/reputation_tracker.py` and `AI/threat_intelligence.py` — map IPs to VPN/Tor providers and risk.

### 2.4 Section 4 – Real AI/ML Models

- **Frontend:** Section 4 (`Real AI/ML Models - Machine Learning Intelligence`).
- **Backend:**
  - `AI/pcs_ai.py` — orchestrates all ML models.
  - `AI/traffic_analyzer.py`, `AI/sequence_analyzer.py`, ML components (RandomForest, IsolationForest, GradientBoosting).
  - `AI/drift_detector.py` & `AI/graph_intelligence.py` — support models shown here.
  - `AI/deterministic_evaluation.py`, `AI/cryptographic_lineage.py` — surfaces lineage and deterministic testing info.

### 2.5 Section 5–7 – Security Overview, Threat Analysis by Type, IP Management

- **Frontend:** Sections 5–7 in the HTML; charts and stats.
- **Backend:**
  - `server/server.py` — threat stats endpoints.
  - `server/json/threat_log.json` — raw data.
  - `AI/pcs_ai.py` — writes threat log entries.
  - `AI/meta_decision_engine.py` — provides aggregated decisions.
  - `AI/reputation_tracker.py`, `AI/threat_intelligence.py` — enrich IP/entity data.

### 2.6 Section 9 – Failed Logins, Section 10 – Attack Type Breakdown

- **Frontend:** Sections around failed logins and attack types (from threat log, auth log, etc.).
- **Backend:**
  - `server/server.py` — endpoints that slice threat log and auth-related events.
  - `AI/system_log_collector.py` — ingests auth/system logs, normalizes to events.
  - `AI/behavioral_heuristics.py` — classifies events by attack type.

### 2.7 Section 11 – Automated Signature Extraction

- **Frontend:** Section 11 in HTML.
- **Backend:**
  - `AI/signature_extractor.py` — extracts patterns from traffic/logs.
  - `AI/signature_distribution.py` — shows distribution state.
  - `server/json/learned_signatures.json` or `AI/learned_signatures.json` — stored signatures.

### 2.8 Section 14 – Attack Chain Visualization (Graph Intelligence)

- **Frontend:** Section 14 in HTML (kill chain / graph view).
- **Backend:**
  - `AI/graph_intelligence.py` — constructs attack chains & graph metrics.
  - `AI/sequence_analyzer.py` — time-ordered events.
  - `server/server.py` — graph data endpoint.

### 2.9 Section 15 – Decision Explainability

- **Frontend:** Section 15 in HTML (explainability engine view).
- **Backend:**
  - `AI/explainability_engine.py` — composes explanations from signals.
  - `AI/meta_decision_engine.py` — contributions per signal type.
  - `AI/false_positive_filter.py` — gate-level reasons.

### 2.10 Section 16 – Adaptive Honeypot (AI Training Sandbox)

- **Frontend:** Section 15 in the latest HTML you were editing (labelled as Adaptive Honeypot, sometimes Section 15/16 depending on counting).
  - Uses JavaScript functions:
    - `loadHoneypotStatus()` → `/api/adaptive_honeypot/status`
    - `startHoneypot()` → `/api/adaptive_honeypot/configure`
    - `stopHoneypot()` → `/api/adaptive_honeypot/stop`
    - `loadHoneypotAttacks()` → `/api/adaptive_honeypot/attacks`
    - `toggleHoneypotHistory()` → `/api/adaptive_honeypot/attacks/history`
- **Backend:**
  - `server/server.py` — implements all `/api/adaptive_honeypot/...` endpoints.
  - `AI/adaptive_honeypot.py` — actual honeypot implementation and persistence.
  - `AI/false_positive_filter.py` and `AI/meta_decision_engine.py` — use honeypot hits as strong signals.

### 2.11 Compliance, Governance, & Emergency Sections

- **Frontend:** Compliance/governance/emergency sections in the lower part of the HTML (e.g. “Compliance & Governance,” “Kill Switch”).
- **Backend:**
  - `AI/compliance_reporting.py` — compliance view data.
  - `AI/policy_governance.py` — approvals, policies.
  - `AI/emergency_killswitch.py` — kill-switch modes and state.
  - `server/json/approval_requests.json` and related JSON files.

> Many other sections follow the same pattern: HTML section → `fetch('/api/...')` → `server/server.py` route → AI module(s) or JSON files.

### 2.12 Section 17 – Traffic Analysis & Inspection (Encrypted Traffic & TLS Fingerprints)

- **Frontend:** Section 17 in `AI/inspector_ai_monitoring.html` (Traffic Analysis & Inspection).
  - Shows deep packet inspection counts, application blocks, and an **Encrypted Traffic** metric card.
- **Backend:**
  - `server/server.py` — `/api/traffic/analysis` endpoint.
    - Uses `AI/traffic_analyzer.py` for overall packet/protocol stats and encrypted percentage.
    - Enriches the response with TLS metadata derived from `tls_fingerprints.json` when present.
  - `AI/tls_fingerprint.py` — Maintains `tls_fingerprints.json` from live flows via `server/network_monitor.py`, including counts of suspicious TLS sources/flows.
  - Dashboard wiring:
    - The Encrypted Traffic card displays `encrypted_percent` alone when no suspicious TLS sources are seen, or `encrypted_percent / N suspicious` when `suspicious_tls_sources > 0`.

### 2.13 Section 18 – DNS & Geo Security (DNS Analyzer)

- **Frontend:** Section 18 in `AI/inspector_ai_monitoring.html` (DNS & Geo Security).
  - DNS Security card shows total DNS queries analyzed.
  - Geo-IP table shows attacks per country and threat level.
- **Backend:**
  - `server/server.py` — `/api/dns/stats` endpoint.
    - Prefers analyzer-generated metrics by reading `dns_security.json` (from `AI/dns_analyzer.py`) to compute `total_queries` and `tunneling_detected` (suspicious DNS patterns).
    - Falls back to a psutil-based estimate if analyzer metrics are unavailable.
  - `server/server.py` — `/api/visualization/geographic` for geographic attack distribution.
  - `AI/dns_analyzer.py` — Populates `dns_security.json` and raises high-confidence DNS threats via `pcs_ai` so they appear in `threat_log.json` and relay `global_attacks.json`.

---

## 3. Relay Folder and Deployment Note (Customer vs Operator)

- The **`relay/` folder is NOT shipped to or run by customers.**
- Customers only run the **`server/` container**, which includes the AI logic and dashboard.
- The relay is intended for **your own centralized infrastructure**:
  - Deployed separately using `relay/docker-compose.yml` and `relay/Dockerfile`.
  - Exposes different ports and APIs (P2P mesh, training APIs, model distribution).
  - May have GPU requirements and store large training datasets.
- Customer nodes are configured (via `server/.env`) with the relay URL and optional API keys; they send anonymized statistics / training data upwards and receive models/signatures downwards.

This separation ensures:

- Customers are not exposed to the complexity or data volume of the relay.
- You keep control over training data, model IP, and advanced analytics.

---

## 4. Important Details for the AI to Understand

This section is meant as “hints” for any AI agent working in this repo:

1. **Single Source of Truth for Threat Decisions**
   - `AI/pcs_ai.py` is the **main orchestration layer**.
   - It should be the default entry point for any new detection capability.
   - New signals should be converted into DetectionSignals and fed into:
     - `AI/false_positive_filter.py` (for multi-gate validation).
     - `AI/meta_decision_engine.py` (for final ensemble decisions).

2. **Honeypot is Authoritative**
   - `AI/adaptive_honeypot.py` is a **high-confidence signal**.
   - Honeypot hits must **not** be suppressed by whitelists.
   - Honeypot signals can be used alone to drive high confidence in the meta engine and FP filter.

3. **False Positive Filter as Gatekeeper**
   - Any new detector that produces noisy outputs should be routed through `AI/false_positive_filter.py`.
   - When enhancing detection, consider how it impacts Gates 2–4:
     - Behavior consistency.
     - Temporal correlation.
     - Cross-signal agreement.

4. **Meta Decision Engine is the Policy Brain**
   - `AI/meta_decision_engine.py` should aggregate **all** meaningful signals.
   - If you add a new signal type, update:
     - `SignalType` enum.
     - `self.signal_weights` for its default weight.
     - Any boosting logic in `_boost_authoritative_signals` if it’s authoritative.
   - Ensemble thresholds (`threat_threshold`, `block_threshold`) should be changed carefully.

5. **JSON & Model Paths Are Centralized and Docker-Aware**
  - AI modules should **not** hardcode ad-hoc paths; use the shared patterns:
    - **Server JSON:** `/app/json/...` in Docker, `server/json/...` natively.
    - **Relay training materials:** `/app/relay/ai_training_materials/...` in Docker, `relay/ai_training_materials/...` on host.
    - **Sequence/autoencoder models:** `AI/ml_models/sequence_lstm.keras`, `AI/ml_models/traffic_autoencoder.keras`.
    - **Classical ML pickles:** `ml_models/*.pkl` (aligned between `AI/pcs_ai.py` and `AI/training_sync_client.py`).
    - **Reputation DB & meta-engine config/history:**
     - Default to `/app/json/...` inside containers.
     - Default to `server/json/...` when running from the monorepo.
  - This was explicitly audited and fixed so that container paths (`/app/...`) and monorepo paths (`server/...`, `relay/...`) always match the Dockerfiles and mounted volumes.

6. **Relay Code is Optional for Local Development**
   - You can run and test the AI and dashboard locally **without** the relay by:
     - Commenting out or stubbing P2P/relay calls.
     - Using local JSON logs and dummy models.

7. **Dashboard → API → AI Flow Must Remain Stable**
   - When changing APIs in `server/server.py`, ensure:
     - The corresponding JavaScript in `AI/inspector_ai_monitoring.html` is updated.
     - Any AI modules used by that endpoint still behave as the UI expects (response shape, field names).

8. **Tests & Sanity Checks**
   - `server/test_system.py` can be used as a place to add quick integration checks.
   - Where possible, new AI logic should have minimal regression tests or at least be exercised via a dedicated endpoint.

9. **Security & Compliance First**
   - When adding new logging or data fields, consider:
     - PII exposure.
     - Compliance requirements (GDPR right-to-erasure, minimal data retention).
     - Whether data needs to be anonymized or aggregated.

10. **Performance Considerations**
    - Heavy ML or graph operations should be batched or run asynchronously if possible.
    - The real-time path (packet → decision) should remain low-latency (tens of ms).

---

With this file plus `ai-abilities.md`, you have:

- A high-level architecture map.
- A per-file purpose index for AI, server, and relay.
- A mapping from dashboard sections to back-end modules.
- Clear notes on what’s shipped to customers vs what stays on the operator side.

You can now move `ai-instructions.md` into the `battle-hardened-ai` repo and start a fresh AI chat there, having this as the reference for future improvements.
