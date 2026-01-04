# AI Abilities & Module Checklist

This document tracks all major AI-related modules and abilities in the project so we can review and improve them one by one.

Legend:
- [x] Completed / recently reviewed
- [ ] Pending review / improvement

Currently tracked:
- 47 checklist entries total
- 46 unique AI modules (AI/threat_intelligence.py appears in two sections)
- 2/47 entries marked as completed so far

---

## Core AI Orchestration

- [ ] AI/pcs_ai.py — Core AI engine, threat scoring, ensemble integration
- [ ] AI/meta_decision_engine.py — Phase 5 meta decision engine (ensemble of signals)
- [x] AI/false_positive_filter.py — 5-gate false-positive reduction pipeline (HONEYPOT-aware, improved)
- [ ] AI/sequence_analyzer.py — LSTM sequence analysis (kill chain modeling)
- [ ] AI/traffic_analyzer.py — Traffic autoencoder and anomaly detection
- [ ] AI/drift_detector.py — Model drift tracking and feature distribution monitoring
- [ ] AI/graph_intelligence.py — Lateral movement and network-graph based threats
- [ ] AI/kernel_telemetry.py — eBPF/XDP kernel telemetry processing

## Deception & Honeypots

- [x] AI/adaptive_honeypot.py — Adaptive multi-persona honeypot, persistence, and dashboard integration (COMPLETED)
- [ ] AI/threat_intelligence.py — Legacy honeypot crawler and ExploitDB integration

## Reputation & History

- [ ] AI/reputation_tracker.py — Persistent IP reputation and recidivism tracking
- [ ] AI/system_log_collector.py — System log ingestion for long-term analysis
- [ ] AI/user_tracker.py — User behavior and identity monitoring

## Policy, Governance, and Self-Protection

- [ ] AI/formal_threat_model.py — Policy-based threat model and enforcement
- [ ] AI/policy_governance.py — Policy lifecycle, approvals, and governance logic
- [ ] AI/self_protection.py — Self-protection, integrity checks, and tamper detection
- [ ] AI/emergency_killswitch.py — Emergency kill-switch and safe modes

## Cryptography & Lineage

- [ ] AI/crypto_security.py — Cryptographic hardening and key handling
- [ ] AI/cryptographic_lineage.py — Model lineage, signing, and provenance

## Federated Learning & P2P

- [ ] AI/byzantine_federated_learning.py — Byzantine-resilient federated learning
- [ ] AI/p2p_sync.py — P2P synchronization of signatures and models
- [ ] AI/training_sync_client.py — Client-side training data and model sync

## Threat Intelligence & Signatures

- [ ] AI/threat_intelligence.py — Threat intel ingestion, crawlers, and signatures
- [ ] AI/signature_extractor.py — Automated extraction of signatures from traffic/logs
- [ ] AI/signature_distribution.py — Distribution of learned signatures
- [ ] AI/signature_uploader.py — Uploading signatures to relay/central services

## Network, Devices, and Performance

- [ ] AI/network_performance.py — Network performance and anomaly monitoring
- [ ] AI/asset_inventory.py — Device and asset inventory
- [ ] AI/node_fingerprint.py — Device and node fingerprinting
- [ ] AI/pcap_capture.py — PCAP capture and analysis helpers

## Enterprise & Cloud Integrations

- [ ] AI/enterprise_integration.py — Enterprise workflows and integrations
- [ ] AI/cloud_security.py — Cloud posture and CSPM logic
- [ ] AI/soar_api.py — SOAR API endpoints and orchestration
- [ ] AI/soar_workflows.py — Playbooks and automated workflows
- [ ] AI/central_sync.py — Centralized sync with relay/backend
- [ ] AI/relay_client.py — Client for talking to relay services

## Compliance, Reporting, and Visualization

- [ ] AI/compliance_reporting.py — Compliance reports (GDPR, HIPAA, PCI, SOC2)
- [ ] AI/advanced_orchestration.py — High-level orchestration and runbooks
- [ ] AI/advanced_visualization.py — Advanced visualizations for dashboard
- [ ] AI/alert_system.py — Alerting logic (email/SMS/other channels)

## Specialized Security Modules

- [ ] AI/backup_recovery.py — Backup integrity and recovery checks
- [ ] AI/file_analyzer.py — File scanning and analysis
- [ ] AI/vulnerability_manager.py — Vulnerability and supply-chain management
- [ ] AI/zero_trust.py — Zero Trust policies and enforcement
- [ ] AI/behavioral_heuristics.py — Behavioral heuristic detection

## Dashboard & Front-End

- [ ] AI/inspector_ai_monitoring.html — Inspector dashboard (frontend for all AI modules)
- [ ] AI/swagger_ui.html — API documentation UI

---

You can use this file as a roadmap: pick a module, open its source, and mark it `[x]` once we’ve reviewed and improved it. Currently, `AI/adaptive_honeypot.py` is marked as completed.
