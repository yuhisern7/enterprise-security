# File Purpose Overview

This document briefly explains the purpose of each file in the core folders: `AI/`, `server/`, and `relay/`.

---

## AI Folder

- AI/adaptive_honeypot.py — Adaptive multi-persona honeypot that mimics various services (HTTP admin, FTP, SSH, DB, etc.) and feeds honeypot hits into the AI threat log.
- AI/advanced_orchestration.py — Advanced orchestration engine for predictive threat modeling, automated responses, custom alert rules, topology export, and training data export.
- AI/advanced_visualization.py — Generates network topology, attack flows, heatmaps, geo maps, and timelines from JSON logs for use in dashboards.
- AI/alert_system.py — Configurable email/SMS alerting system with SMTP/Twilio-style integration and severity-based threat notifications.
- AI/asset_inventory.py — Builds a hardware/software asset inventory from local scans and connected_devices.json, tracking EOL and shadow IT risks.
- AI/backup_recovery.py — Monitors backup locations, estimates ransomware resilience, tracks recovery tests, and reports backup/RTO status.
- AI/behavioral_heuristics.py — Behavioral engine that tracks per-entity connection/auth patterns and computes heuristic risk scores.
- AI/byzantine_federated_learning.py — Byzantine-resilient federated learning aggregator (Krum, Multi-Krum, trimmed mean, median) with peer reputation.
- AI/central_sync.py — Optional central server sync client that uploads sanitized threat summaries and ingests global threat patterns.
- AI/cloud_security.py — Cloud security posture checks for AWS/Azure/GCP using CLIs, with misconfig, IAM, encryption, and exposure summaries.
- AI/compliance_reporting.py — Generates compliance and control-mapping views (PCI/NIST/etc.) from local telemetry and SBOM/asset data.
- AI/cryptographic_lineage.py — Tracks cryptographic provenance, key usage, and signature lineage for auditability.
- AI/crypto_security.py — Central cryptography helper (HMAC, signing, verification, key handling) used by server and relay for secure messaging.
- AI/deterministic_evaluation.py — Provides deterministic evaluation harnesses and scoring for AI models using fixed datasets.
- AI/drift_detector.py — Monitors model input/output statistics over time to detect data/model drift and trigger retraining.
- AI/emergency_killswitch.py — Implements emergency kill switches to safely disable or downgrade AI actions under operator control.
- AI/enterprise_integration.py — Bridges to enterprise tools (SIEM, ticketing, ITSM) and external APIs for incident/alert integration.
- AI/explainability_engine.py — Builds human-readable explanations and feature attributions for AI decisions and threat scores.
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
- AI/pcs_ai.py — Central AI orchestrator and source of truth: wires together models, detection modules, logs, and the dashboard API.
- AI/policy_governance.py — Models security policies, approvals, and governance workflows around automated actions.
- AI/relay_client.py — Client-side relay connector used by customer nodes to talk to the relay WebSocket and model API.
- AI/reputation_tracker.py — Maintains local IP/domain reputation, aggregating stats from threat logs and external intel.
- AI/self_protection.py — Implements self-protection checks so the AI/agent can detect tampering or local compromise.
- AI/sequence_analyzer.py — Sequence analysis utilities for logs/traffic, feeding sequence models like the LSTM.
- AI/signature_distribution.py — Manages downloading and applying signatures/models distributed from the relay or central sources.
- AI/signature_extractor.py — Extracts signatures and patterns from attacks/honeypot hits for later training and sharing.
- AI/signature_uploader.py — Prepares and uploads privacy-preserving signatures to the relay/signature_sync service.
- AI/soar_api.py — API interface for SOAR-like workflows, exposing actions and playbooks to orchestration.
- AI/soar_workflows.py — Library of automated SOAR workflows/runbooks for incidents and playbook steps.
- AI/swagger_ui.html — Embedded Swagger UI HTML used to expose and document the local API when enabled.
- AI/system_log_collector.py — Collects system logs and events into structured JSON for analysis by other AI modules.
- AI/threat_intelligence.py — Local threat intelligence aggregator that merges external feeds and local observations.
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
- server/json/sbom.json — Software bill of materials (SBOM) for the deployment, listing packages and versions.
- server/json/threat_log.json — Main threat log of detections and actions generated by AI and network monitor.
- server/json/tracked_users.json — Storage for tracked user accounts and related behavioral data.
- server/network_monitor.py — Scapy-based live network sniffer that detects scans, floods, and ARP spoofing, feeding pcs_ai.
- server/report_generator.py — Standalone HTML report generator for enterprise-style security reports.
- server/requirements.txt — Python dependency list for building the server image.
- server/server.py — Flask dashboard/API server that renders inspector_ai_monitoring.html and exposes export/reporting endpoints.
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
