# File Purpose Overview

This document briefly explains the purpose of each file in the core folders: `AI/`, `server/`, and `relay/`.

---

## Critical JSON & Audit Surfaces by Stage

This table summarizes the most important JSON/audit surfaces exercised by the Stage 1–10 tests (see ai-abilities.md):

| Stage | Local JSON / Audit (server/) | Relay JSON (relay/ai_training_materials/) |
|-------|------------------------------|--------------------------------------------|
| 1 – Plumbing & Relay | crypto_keys/, HMAC-signed messages (no persistent JSON beyond logs) | global_attacks.json (when sending real signed attack messages) |
| 2 – Core Detection | json/threat_log.json; json/dns_security.json; json/tls_fingerprints.json | global_attacks.json; attack_statistics.json |
| 3 – Deception & Honeypots | honeypot_* JSONs; json/threat_log.json | global_attacks.json; ai_signatures/learned_signatures.json |
| 4 – Network, Devices & Behavioral | json/connected_devices.json; json/device_history.json; json/network_performance.json; json/dns_security.json; json/tls_fingerprints.json; json/network_graph.json; json/lateral_movement_alerts.json | global_attacks.json; attack_statistics.json |
| 5 – Threat Intel & Signatures | json/local_threat_intel.json; reputation.db; json/threat_log.json | threat_intelligence/; reputation_data/; ai_signatures/learned_signatures.json; global_attacks.json |
| 6 – Governance & Self‑Protection | json/approval_requests.json; json/governance_audit.json; json/integrity_violations.json; json/comprehensive_audit.json | global_attacks.json (policy/self‑protection events promoted as attacks) |
| 7 – Crypto, Lineage & Federated | json/comprehensive_audit.json (cryptographic_lineage, byzantine_defender) | global_attacks.json (e.g., federated_update_rejected) |
| 8 – Enterprise, Cloud & SOAR | json/soar_incidents.json; json/cloud_findings.json; json/comprehensive_audit.json | global_attacks.json (soar_incident, cloud_misconfiguration) |
| 9 – Backup & Compliance | json/backup_status.json; json/recovery_tests.json; json/compliance_reports/; json/comprehensive_audit.json | global_attacks.json (backup_issue, ransomware_resilience_low, compliance_issue) |
| 10 – Explainability & Dashboard | json/forensic_reports/; json/comprehensive_audit.json (SYSTEM_ERROR from dashboard/explainability/visualization APIs) | Reuses global_attacks.json and ai_signatures/learned_signatures.json from earlier stages |

Use this as a quick index when you want to jump from a stage to the on-disk JSONs and relay views that its runbooks exercise.

---

## AI Folder

- AI/adaptive_honeypot.py — Adaptive multi-persona honeypot that mimics various services (HTTP admin, FTP, SSH, DB, etc.) and feeds honeypot hits into the AI threat log.
- AI/advanced_orchestration.py — Advanced orchestration engine for predictive threat modeling, automated responses, custom alert rules, topology export, and training/orchestration data export.
- AI/advanced_visualization.py — Generates network topology, attack flows, heatmaps, geo maps, and timelines from JSON logs for use in dashboards.
- AI/alert_system.py — Configurable email/SMS alerting system with SMTP/Twilio-style integration and severity-based threat notifications.
- AI/asset_inventory.py — Builds a hardware/software asset inventory from local scans and connected_devices.json, tracking EOL and shadow IT risks.
- AI/backup_recovery.py — Monitors backup locations, estimates ransomware resilience, tracks recovery tests, writes backup_status.json/recovery_tests.json, and logs backup_issue/ransomware_resilience_low posture issues into the comprehensive audit log and (when present) relay global_attacks.json.
- AI/behavioral_heuristics.py — Behavioral engine that tracks per-entity connection/auth patterns and computes heuristic risk scores.
- AI/byzantine_federated_learning.py — Byzantine-resilient federated learning aggregator (Krum, Multi-Krum, trimmed mean, median) with peer reputation and audit/relay logging for rejected/poisoned updates.
- AI/central_sync.py — Optional central server sync client that uploads sanitized threat summaries and ingests global threat patterns.
- AI/cloud_security.py — Cloud security posture checks for AWS/Azure/GCP using CLIs, with misconfig, IAM, encryption, and exposure summaries, persisting snapshots to cloud_findings.json and escalating high/critical issues into the comprehensive audit log and relay global_attacks.json.
- AI/compliance_reporting.py — Generates PCI/HIPAA/GDPR/SOC2 compliance reports and control-mapping views from local telemetry and SBOM/asset data, writing JSON reports under server/json/compliance_reports and logging compliance_issue events into the comprehensive audit log and relay global_attacks.json.
- AI/cryptographic_lineage.py — Tracks cryptographic provenance, key usage, and signature lineage for auditability, and surfaces lineage integrity/drift issues into the comprehensive audit log (and, when configured, relay global_attacks.json).
- AI/crypto_security.py — Central cryptography helper (HMAC, signing, verification, key handling) used by server and relay for secure messaging.
- AI/deterministic_evaluation.py — Provides deterministic evaluation harnesses and scoring for AI models using fixed datasets.
- AI/drift_detector.py — Monitors model input/output statistics over time to detect data/model drift and trigger retraining.
- AI/emergency_killswitch.py — Implements emergency kill switches to safely disable or downgrade AI actions under operator control and hosts the central comprehensive_audit.json log used by other modules for THREAT_DETECTED/ACTION_TAKEN/INTEGRITY_VIOLATION/SYSTEM_ERROR events.
- AI/enterprise_integration.py — Bridges to enterprise tools (SIEM, ticketing, ITSM) and external APIs for incident/alert integration.
- AI/explainability_engine.py — Builds human-readable explanations and feature attributions for AI decisions and threat scores, maintains decision history, and emits forensic_reports JSON plus optional explainability_data for training.
- AI/exploitdb — Placeholder/path used for local ExploitDB-related resources on the customer side (complements relay ExploitDB usage).
- AI/false_positive_filter.py — Filters noisy detections using heuristics and metadata to reduce false positives before reaching the dashboard.
- AI/file_analyzer.py — Analyzes files and artifacts (hashing, type, basic features) for use in malware/intel workflows.
- AI/formal_threat_model.py — Encodes a higher-level formal threat model, mapping signals and components into structured attack scenarios.
- AI/graph_intelligence.py — Builds and queries graph-based views of entities, connections, and attacks for graph-driven reasoning.
- AI/inspector_ai_monitoring.html — Main HTML dashboard template rendered by server.py to show AI monitoring and visualizations.
- AI/kernel_telemetry.py — Handles kernel/eBPF/XDP telemetry ingestion and feature extraction on supported hosts.
- AI/meta_decision_engine.py — Core meta-decision engine that fuses multiple signals/detections into final threat decisions and actions.
- AI/ml_models/sequence_lstm.keras — Saved Keras sequence LSTM model used for time-series or sequence-based anomaly detection.
- AI/ml_models/traffic_autoencoder.keras — Saved Keras autoencoder model used for network traffic anomaly detection.
- AI/network_performance.py — Tracks per-IP bandwidth, performance metrics, and network health, writing into network_performance.json.
- AI/node_fingerprint.py — Creates device/node fingerprints from observed behavior and attributes for long-term identification.
- AI/p2p_sync.py — Handles peer-to-peer sync logic for nodes in the mesh (metadata/state exchange between peers).
- AI/pcap_capture.py — Packet capture helper for saving traffic (pcap) samples for offline analysis or training.
- AI/pcs_ai.py — Central AI orchestrator and source of truth: wires together models, detection modules (including DNS/TLS analyzers), logs, and the dashboard API, tags relay-bound threats with a stable sensor_id, and routes integrity/lineage/federated/cloud/backup/compliance signals into the audit/relay paths.
- AI/policy_governance.py — Models security policies, approvals, and governance workflows around automated actions.
- AI/relay_client.py — Client-side relay connector used by customer nodes to talk to the relay WebSocket and model API.
- AI/reputation_tracker.py — Maintains local IP/domain reputation, aggregating stats from threat logs and external intel.
- AI/self_protection.py — Implements self-protection checks so the AI/agent can detect tampering or local compromise, writing violations into integrity_violations.json and comprehensive_audit.json and optionally triggering the kill switch.
- AI/sequence_analyzer.py — Sequence analysis utilities for logs/traffic, feeding sequence models like the LSTM.
- AI/signature_distribution.py — Manages downloading and applying signatures/models distributed from the relay or central sources.
- AI/signature_extractor.py — Extracts signatures and patterns from attacks/honeypot hits for later training and sharing.
- AI/signature_uploader.py — Prepares and uploads privacy-preserving signatures to the relay/signature_sync service.
- AI/soar_api.py — API interface for SOAR-like workflows, exposing actions and playbooks to orchestration.
- AI/soar_workflows.py — Library of automated SOAR workflows/runbooks for incidents and playbook steps that persists cases into soar_incidents.json, logs incident/playbook activity into the comprehensive audit log, and mirrors high/critical incidents into relay global_attacks.json as soar_incident entries.
- AI/swagger_ui.html — Embedded Swagger UI HTML used to expose and document the local API when enabled.
- AI/system_log_collector.py — Collects system logs and events into structured JSON for analysis by other AI modules.
- AI/threat_intelligence.py — Local threat intelligence aggregator that merges external feeds and local observations.
- AI/dns_analyzer.py — DNS security analyzer that uses metadata-only heuristics (tunneling/DGA/exfil) to score DNS activity and write aggregated metrics into dns_security.json.
- AI/tls_fingerprint.py — TLS/encrypted-flow fingerprinting engine that tracks non-standard TLS ports and suspicious encrypted C2 patterns, writing per-IP metrics into tls_fingerprints.json.
- AI/traffic_analyzer.py — Higher-level traffic analysis module that combines metrics and detections from network monitors.
- AI/training_sync_client.py — Customer-side client for syncing models/training artifacts with the relay’s training API.
- AI/user_tracker.py — Tracks user accounts and behavior patterns (logins, anomalies) on the protected environment.
- AI/vulnerability_manager.py — Manages vulnerability findings and risk views, tying CVEs/scan data into the dashboard.
- AI/zero_trust.py — Implements zero-trust style checks and posture scoring for devices/users/services.

---

## Server Folder

- server/.dockerignore — Excludes unneeded files from the server Docker build context.
- server/.env — Main environment file for the server container (ports, relay URLs, feature flags, API keys, etc.).
- server/.env.linux — Example/server env template tuned for Linux/host-network deployments.
- server/.env.windows — Example/server env template tuned for Windows Docker deployments.
- server/crypto_keys/ — Holds cryptographic material (e.g., shared_secret.key) used for HMAC between customer and relay.
- server/device_blocker.py — Implements ARP-based device blocking and unblocking, persisting blocked_devices.json.
- server/device_scanner.py — Scans the local network for devices, classifies them by vendor/type, and populates connected_devices.json and device_history.json.
- server/docker-compose.yml — Docker Compose definition for the Linux/host-network server deployment with required capabilities.
- server/docker-compose.windows.yml — Docker Compose definition for Windows deployments using bridged networking and port mappings.
- server/Dockerfile — Builds the server container image, installing dependencies, copying AI code, and wiring HTTPS/gunicorn.
- server/entrypoint.sh — Container entrypoint that launches server.py and gunicorn with TLS certificates.
- server/installation/cloud-deploy.sh — One-shot script to install Docker on a VPS, clone the repo, and deploy the server stack in the cloud.
- server/installation/install.sh — Local/Unix installer that prepares JSON directories and launches the server container via docker compose.
- server/installation/QUICKSTART_WINDOWS.bat — Windows quickstart to set up env/json directories and start the Windows Docker stack.
- server/json/.gitkeep — Placeholder file ensuring the json directory exists in version control.
- server/json/approval_requests.json — Persists operator approval/exception requests for governance and change control.
- server/json/audit_archive/ — Storage for archived audit reports and historical compliance outputs.
- server/json/blocked_ips.json — Current list of blocked IPs chosen by AI/operator actions.
- server/json/connected_devices.json — Snapshot of currently known network devices and their attributes.
- server/json/crypto_mining.json — Time series and summary of crypto-mining detection activity and risk levels.
- server/json/device_history.json — Historical device inventory with ports/types over time for forensics and trend analysis.
- server/json/forensic_reports/ — Folder for structured forensic reports generated by AI or operators.
- server/json/network_monitor_state.json — Persistent state for the live network monitor (counters, trackers, thresholds).
- server/json/network_performance.json — Historical bandwidth and performance metrics per IP recorded by network_performance.py.
- server/json/dns_security.json — Aggregated DNS behavior metrics and suspicious query counts written by AI/dns_analyzer.py from live DNS traffic.
- server/json/tls_fingerprints.json — Aggregated TLS/encrypted-flow fingerprints per source IP written by AI/tls_fingerprint.py.
- server/json/comprehensive_audit.json — Central append-only audit log for security, governance, integrity, lineage, federated, backup, cloud, compliance, and dashboard/API events, maintained by EmergencyKillSwitch and consumed across Stages 6–10.
- server/json/integrity_violations.json — Records integrity and self-protection violations detected by AI/self_protection.py.
- server/json/soar_incidents.json — Persists SOAR/incidents and case metadata created by AI/soar_workflows.py.
- server/json/cloud_findings.json — Stores recent cloud security posture snapshots and misconfiguration findings from AI/cloud_security.py.
- server/json/backup_status.json — Summaries of backup jobs, freshness, and status from AI/backup_recovery.py.
- server/json/recovery_tests.json — Results of recovery/restore tests used to estimate ransomware resilience in AI/backup_recovery.py.
- server/json/compliance_reports/ — Directory for JSON compliance reports (PCI, HIPAA, GDPR, SOC2) written by AI/compliance_reporting.py.
- server/json/sbom.json — Software bill of materials (SBOM) for the deployment, listing packages and versions.
- server/json/threat_log.json — Main threat log of detections and actions generated by AI and network monitor.
- server/json/tracked_users.json — Storage for tracked user accounts and related behavioral data.
- server/network_monitor.py — Scapy-based live network sniffer that detects scans, floods, ARP spoofing, and now feeds behavioral heuristics, graph intelligence, DNS analyzer, TLS fingerprinting, and pcs_ai.
- server/report_generator.py — Standalone HTML/JSON report generator for enterprise-style security reports that stitches together threat statistics, explainability data, and compliance summaries.
- server/requirements.txt — Python dependency list for building the server image.
- server/server.py — Flask dashboard/API server that renders inspector_ai_monitoring.html and exposes REST/JSON endpoints (traffic, DNS/TLS, explainability, audit, visualization, compliance), including logging dashboard/API failures as SYSTEM_ERROR events into comprehensive_audit.json.
- server/test_system.py — System-level test harness for validating that core services and integrations are functioning.

---

## Relay Folder

- relay/.env.relay — Env configuration for the relay server (ports, training flags, paths, logging, crypto enable).
- relay/ai_retraining.py — Relay-side retraining manager that consumes ai_training_materials and exports updated models.
- relay/ai_training_materials/ — On-disk training corpus for the relay (global_attacks, signatures, ExploitDB, models, datasets).
- relay/ai_training_materials/ai_signatures/ — Stores learned_signatures.json created by ExploitDB scraper and signature_sync.
- relay/ai_training_materials/crypto_keys/ — Holds the relay’s copy of shared_secret.key used for HMAC validation.
- relay/ai_training_materials/exploitdb/ — Local checkout of ExploitDB (CSV and exploits) used by exploitdb_scraper.py.
- relay/ai_training_materials/README.md — Explains the layout/usage of the relay training materials directory.
- relay/ai_training_materials/reputation_data/ — Stores aggregate reputation/intel data derived from crawlers and attacks.
- relay/ai_training_materials/threat_intelligence/ — Stores raw/int-derived threat intel from crawlers for training.
- relay/ai_training_materials/trained_models/ — Archive of trained model artifacts produced by relay training runs.
- relay/ai_training_materials/training_datasets/ — Prepared feature/label datasets ready for model training or GPU training.
 - relay/ai_training_materials/global_attacks.json — Central sanitized global attack/event log aggregated from customer nodes across all stages (core, honeypot, federated, SOAR, cloud, backup, compliance, etc.).
 - relay/ai_training_materials/attack_statistics.json — Aggregated statistics and trends derived from global_attacks.json, used for dashboards and analytics.
- relay/docker-compose.yml — Compose file to run the relay server on a VPS with host networking and mounted training data.
- relay/Dockerfile — Builds the relay container image with WebSocket relay, training API, and training tools.
- relay/exploitdb_scraper.py — Scrapes a local/remote ExploitDB CSV to derive attack patterns and export learned_signatures.json.
- relay/gpu_trainer.py — Optional GPU-accelerated training pipeline using TensorFlow/PyTorch on ai_training_materials datasets.
- relay/README.md — Relay-specific documentation describing roles, architecture, and deployment examples.
- relay/relay_server.py — WebSocket relay for the security mesh; verifies HMAC, relays messages, and logs global attacks/stats.
- relay/requirements.txt — Python dependency list for the relay image (websockets, Flask, ML stack).
- relay/setup.sh — Convenience script to install Docker/firewall rules and launch the relay stack on a VPS.
- relay/setup_exploitdb.sh — Helper script that clones the full ExploitDB repo locally for use by exploitdb_scraper.py.
- relay/signature_sync.py — File-based signature and global attack synchronization service used by relay_server for storage.
- relay/start_services.py — Orchestration script that launches relay_server.py and training_sync_api.py as parallel services.
- relay/threat_crawler.py — Threat intel crawler suite for CVEs, MalwareBazaar, AlienVault OTX, URLhaus, and sample AttackerKB data.
- relay/training_sync_api.py — Flask-based model distribution API that serves only pre-trained models and training stats to subscribers.
