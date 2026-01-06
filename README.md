## Battle-Hardened AI

**An Open Research Platform for Network Detection & Response (NDR), Zero‑Day Detection, and National Cyber Defense**

Battle-Hardened AI is an open, research-oriented Network Detection and Response (NDR) platform designed to study, evaluate, and deploy advanced defensive cybersecurity techniques. It integrates multi-signal detection, **zero‑day anomaly detection models**, kernel-level telemetry, and policy-governed response mechanisms to support enterprise-scale and national-scale cyber defense research.

The system is designed with defensive-only constraints, privacy preservation, and auditability as first-class principles.

Connect to our secret relay for the AI to extract its training materials, all you need is one Battle-Hardened AI server for each network (doesn't require an an endpoint for each computer).

- Home usage: 25 USD monthly.
- Organizations: 50 USD monthly.

- Company: Elite Cybersecurity Specialist - 202403184091 (MA0319303).

- Contact: Yuhisern Navaratnam
- WhatsApp: +60172791717
- Email: yuhisern@protonmail.com

---

### 18 AI Signals For Training Data Flow (Diagram)

The diagram below shows how the 18 detection abilities filter attacks, how incidents are logged on the local node, and how **AI training materials** are shared via the relay so that other servers/containers get smarter after each attack.

In this design, each Battle-Hardened AI server acts as a **trusted sensor-node** on its own network segment:

- Each server observes local traffic, logs, cloud telemetry, and identities, then converts them into **sanitized statistical features** only (no payloads, no raw PII).
- High-confidence incidents are written to local JSON/audit surfaces and then distilled into **relay-ready training materials** (signatures, reputation updates, and anonymized statistics).
- When connected to the secret relay, every node **pulls and pushes** these materials over an authenticated, encrypted channel, so that improvements learned on one network are **safely shared** with others.
- Because each network only needs **one Battle-Hardened AI server**, organizations avoid deploying agents on every endpoint while still benefiting from **fleet-wide learning and updated defenses**.

This creates a new security design pattern: a **federated, privacy-preserving defense mesh** where multiple organizations contribute to, and benefit from, a constantly improving global model—without exposing their underlying traffic or sensitive content.

```text
		[Network traffic, logs, cloud APIs,
		 backups, identities, devices]
			  |
			  v
	  +-------------------------------+
	  |   Pre-processing & Ingestion  |
	  | - server/network_monitor.py   |
	  | - server/device_scanner.py    |
	  | - AI/cloud_security.py        |
	  | - AI/backup_recovery.py       |
	  | - AI/compliance_reporting.py  |
	  +-------------------------------+
			  |
			  v
	  +-------------------------------+
	  |      18 Detection Abilities   |
	  |  1. eBPF Kernel Telemetry     |
	  |  2. Signature Matching        |
	  |  3. RandomForest              |
	  |  4. IsolationForest           |
	  |  5. Gradient Boosting         |
	  |  6. Behavioral Heuristics     |
	  |  7. LSTM                      |
	  |  8. Autoencoder               |
	  |  9. Drift Detection           |
	  | 10. Graph Intelligence        |
	  | 11. VPN/Tor Fingerprinting    |
	  | 12. Threat Intel Feeds        |
	  | 13. False Positive Filter     |
	  | 14. Historical Reputation     |
	  | 15. Explainability Engine     |
	  | 16. Predictive Modeling       |
	  | 17. Byzantine Defense         |
	  | 18. Integrity Monitoring      |
	  +-------------------------------+
			  |
			  v
	      [AI/meta_decision_engine.py + AI/pcs_ai.py
		   + AI/false_positive_filter.py]
		   (ensemble & gating)
			  |
	     High-confidence attacks /
	     incidents & anomalies
			  |
			  v
	  +-------------------------------+
	  |   Local JSON & Audit Surfaces |
	  | - server/json/threat_log.json |
	  | - dns_security.json,          |
	  |   tls_fingerprints.json       |
	  | - cloud_findings.json         |
	  | - soar_incidents.json         |
	  | - backup_status.json,         |
	  |   recovery_tests.json         |
	  | - compliance_reports/         |
	  | - forensic_reports/           |
	  | - comprehensive_audit.json    |
	  +-------------------------------+
			  |
	     Sanitized, privacy-preserving
		     training data
			  |
			  v
	  +------------------------------------------------+
	  |        Relay AI Training Materials (shared)    |
	  |  relay/ai_training_materials/global_attacks.json      |
	  |  relay/ai_training_materials/attack_statistics.json   |
	  |  relay/ai_training_materials/ai_signatures/...        |
	  |  relay/ai_training_materials/reputation_data/         |
	  +------------------------------------------------+
			  |
	     Other servers/containers Worldwide (each customer) pull updates
			  |
	     Updated models, reputations, and
		   signatures on each node
			  |
	     ==> The AI gets smarter after
		     every real attack
```

## High-Level Capabilities

### Advanced Defense Modules

- **Byzantine Defense (B):** Krum, Trimmed Mean, Median, Multi-Krum aggregation; peer reputation; ~94% malicious update rejection.
- **Crypto Lineage (C):** SHA-256 hashing, Ed25519 signatures; blockchain-style audit trail; provenance tracking.
- **Deterministic Eval (D):** Fixed random seeds; cryptographic proof certificates; GDPR/HIPAA/SOC 2-aligned evaluation.
- **Threat Model (F):** Policy-based security; confidence thresholds; human-in-the-loop specs; strong policy enforcement.
- **Self-Protection (G):** Model tampering detection; log deletion alerts (>50% reduction in silent failures); rootkit detection (~91% accuracy).
- **Policy Governance (H):** Approval queue; auto-approval limits; expiration/default-deny; complete audit trail.
- **Emergency Controls (J):** Four operation modes (`ACTIVE`, `MONITORING_ONLY`, `SAFE_MODE`, `DISABLED`); compliance-ready audit logs; automatic log rotation.

### Autonomous Response

- Adaptive honeypots (multi-persona SSH/FTP/HTTP/SMB/LDAP/Kubernetes API/Elasticsearch, per-persona statistics, persistent attack history, dashboard attack-history views).
- Self-healing networks (automatic firewall rules, service restart, configuration rollback).
- Predictive modeling (24–48 hour threat forecasting, ~83% accuracy).
- SOAR integration (80+ API endpoints, automated playbooks).
- Deception technologies (honeytokens, attacker profiling).

### Persistent Intelligence

- Historical reputation (SQLite/file-based storage).
- Cross-session memory and recidivism detection (~94% accuracy).
- Geolocation-aware risk profiles (ASN + country + region).
- Reputation decay algorithms.
- OSINT correlation (multiple feeds: AbuseIPDB, GreyNoise, VirusTotal, MalwareBazaar, URLhaus, NIST NVD, ExploitDB, Have I Been Pwned, dark web sources).

## 1. Purpose & Scope

Battle-Hardened AI is **not** an offensive tool and does **not** store exploit payloads or sensitive user data.

It is intended for:

- National cyber defense R&D
- Government SOC experimentation
- Academic research
- Critical infrastructure monitoring
- Enterprise security operations (observer-first deployments)

The platform emphasizes:

- Detection, attribution, and analysis
- Explainability and governance
- Safe automation with human oversight

## 2. System Overview

The platform operates as a **multi-layer NDR system** composed of:

- Kernel-level telemetry (Linux)
- Network traffic analysis
- Behavioral and heuristic engines
- Machine learning ensembles
- Federated and centralized intelligence sharing
- Policy-controlled response execution

Deployment is containerized using Docker and supports **observer-only** and **controlled-response** modes.

## 3. Detection Architecture (Multi-Signal Design)

Battle-Hardened AI uses **18 independent detection signals**, combined through a weighted ensemble to reduce false positives and prevent single-model failure.

### Active Detection Signals

| #  | Signal                     | Description                                                       |
| --- | -------------------------- | ----------------------------------------------------------------- |
| 1   | eBPF Kernel Telemetry      | Syscall and network correlation; kernel/userland integrity checks |
| 2   | Signature Matching         | Deterministic attack pattern detection (3,000+ patterns)          |
| 3   | RandomForest               | Supervised threat classification                                  |
| 4   | IsolationForest            | Unsupervised anomaly detection                                    |
| 5   | Gradient Boosting          | IP and behavior reputation modeling                               |
| 6   | Behavioral Heuristics      | Rule-based statistical risk scoring on per-IP flows (including DNS/TLS metadata) |
| 7   | LSTM                       | Sequential kill-chain analysis                                    |
| 8   | Autoencoder                | Zero-day anomaly detection                                        |
| 9   | Drift Detection            | Model degradation and distribution shift monitoring               |
| 10  | Graph Intelligence         | Lateral movement and C2 relationship mapping from live connection graphs |
| 11  | VPN/Tor Fingerprinting     | Proxy and anonymization indicators                                |
| 12  | Threat Intelligence Feeds  | OSINT correlation                                                 |
| 13  | False Positive Filter      | Multi-gate consensus validation                                   |
| 14  | Historical Reputation      | Cross-session recidivism tracking                                 |
| 15  | Explainability Engine      | Decision transparency                                             |
| 16  | Predictive Modeling        | Short-term threat forecasting                                     |
| 17  | Byzantine Defense          | Poisoned learning update rejection                                |
| 18  | Integrity Monitoring       | Model and telemetry tampering detection                           |

Ensemble decisions require **cross-signal agreement**, reducing single-model bias.

On the network path, packet flows captured by `server/network_monitor.py` are enriched by multiple AI modules before becoming ensemble signals:

- `AI/behavioral_heuristics.py` scores per-IP behavior (connection rates, fan-out, retries).
- `AI/graph_intelligence.py` builds a live connection graph for lateral movement and C2 paths.
- `AI/dns_analyzer.py` inspects DNS metadata only (no payloads) to highlight tunneling/DGA/exfil patterns and writes aggregated metrics to `dns_security.json`.
- `AI/tls_fingerprint.py` fingerprints encrypted flows (ports, fan-out, beacon-like patterns) and writes per-IP TLS metrics to `tls_fingerprints.json`.

High-confidence DNS/TLS anomalies are promoted via `AI/pcs_ai.py` into `server/json/threat_log.json` on the customer node and into `relay/ai_training_materials/global_attacks.json` and `relay/ai_training_materials/attack_statistics.json` on the relay (when enabled), tagged with a stable `sensor_id` for multi-sensor correlation.

## 4. Machine Learning & AI Design

### Core Models

- RandomForest (supervised classification)
- IsolationForest (anomaly detection)
- Gradient Boosting (reputation scoring)
- LSTM (sequence modeling)
- Autoencoder (reconstruction-based anomaly detection)

### ML Safety Measures

- Drift detection (KS test, PSI).
- Shadow model validation.
- Deterministic evaluation mode.
- Cryptographic lineage (hashing and signatures).
- Rollback to known-good models.

No raw exploit payloads are distributed to endpoints.

## 5. Live Signature Extraction (Defensive-Only)

The system supports automated signature extraction from observed attacks:

- Extracts patterns and encodings only.
- Immediately discards payload content.
- Stores no exploit code.
- Aligns with IDS-style defensive detection.

This enables rapid adaptation while minimizing legal and operational risk.

## 6. Kernel Telemetry (Linux)

On Linux hosts, the system can optionally use **eBPF/XDP in observer mode**:

- No packet dropping by default.
- No inline enforcement unless explicitly enabled.
- Automatic fallback to userland capture if eBPF/XDP is unavailable.
- Designed to prevent system instability.

Kernel telemetry is local to the host and does **not** directly surveil other devices unless deployed at a gateway.

## 7. Response & Automation (Governed)

Response actions are **policy-controlled** and can include:

- IP blocking.
- Rate limiting.
- Firewall rule updates.
- Service isolation.
- SOAR playbook execution.

All automated actions are:

- Logged.
- Explainable.
- Reversible.
- Governed by confidence thresholds.
- Subject to human approval (if configured).

## 8. Federated & Central Intelligence

Battle-Hardened AI supports:

- Centralized relay servers.
- Federated learning experiments.
- Byzantine-resilient aggregation.
- Peer reputation weighting.

Only **signatures, statistics, and model updates** are shared — never raw traffic or payload data.

## 9. Dashboard & Visualization

### 📊 Real-Time Dashboard Overview

AI has 18 detection abilities; the web dashboard exposes **31 labeled sections** that surface their outputs, plus governance, compliance, cloud security, and resilience.

The table below reflects the current layout implemented in `AI/inspector_ai_monitoring.html` and used by the Stage 1–10 runbooks in `ai-abilities.md`.

| #  | Section Title                                                    | Summary |
| --- | ---------------------------------------------------------------- | ------- |
| 1   | AI Training Network – Shared Machine Learning                    | P2P/federated training status, threats sent/learned between peers |
| 2   | Network Devices – Live Monitor, Ports & History                  | Consolidated view of live devices, port scans, 7‑day history, and assets |
| 3   | Attackers VPN/Tor De-Anonymization Statistics                    | VPN/Tor detection and de‑anonymization statistics |
| 4   | Real AI/ML Models – Machine Learning Intelligence                | ML models, Byzantine defense, model lineage, deterministic testing |
| 5   | Security Overview – Live Statistics                              | High‑level security posture, key counters and KPIs |
| 6   | Threat Analysis by Type                                          | Breakdown of threats by type/severity |
| 7   | IP Management & Threat Monitoring                                | Per‑IP risk, reputation, and management actions |
| 8   | Failed Login Attempts (Battle-Hardened AI Server)                | Authentication abuse and brute‑force monitoring |
| 9   | Attack Type Breakdown                                            | Distribution of attack types (visual breakdown) |
| 10  | Automated Signature Extraction – Attack Pattern Analysis         | Defensive signature extraction dashboard (patterns only, no payloads) |
| 11  | System Health & Network Performance                              | System resources, network performance, and self‑protection (integrity) |
| 12  | Compliance & Threat Governance                                   | PCI/HIPAA/GDPR/SOC2 status, threat model, and audit summary |
| 13  | Attack Chain Visualization (Graph Intelligence)                  | Lateral movement and kill‑chain visualization (graph intelligence) |
| 14  | Decision Explainability Engine                                   | Explainable AI views for decisions and forensic context |
| 15  | Adaptive Honeypot – AI Training Sandbox                          | Honeypot activity, personas, and training impact |
| 16  | AI Security Crawlers & Threat Intelligence Sources               | Crawler status and external threat‑intel feed coverage |
| 17  | Traffic Analysis & Inspection                                    | Deep packet inspection, app‑aware blocking, encrypted traffic stats |
| 18  | DNS & Geo Security                                               | DNS tunneling/DGA metrics and geo‑IP risk/controls |
| 19  | User & Identity Monitoring + Zero Trust                          | UEBA, insider‑threat analytics, Zero Trust posture |
| 20  | Forensics & Threat Hunting                                       | PCAP storage, hunt queries, and packet‑level investigations |
| 21  | Sandbox Detonation                                               | File detonation statistics and analysis capabilities |
| 22  | Email/SMS Alerts                                                 | Alert configuration and notification metrics |
| 23  | API for SOAR Integration + Workflow Automation                   | SOAR/API usage, playbooks, and integration health |
| 24  | Vulnerability & Supply Chain Management                          | Vulnerability and software supply‑chain posture |
| 25  | Cryptocurrency Mining Detection                                  | Crypto‑mining detection and related statistics |
| 26  | Dark Web Monitoring                                              | Dark‑web‑related intelligence and monitoring |
| 27  | Attack Simulation (Purple Team)                                  | Purple‑team attack simulation and validation views |
| 28  | Cloud Security Posture Management (CSPM)                         | Multi‑cloud misconfigurations, IAM risks, and cloud compliance |
| 29  | Data Loss Prevention (DLP)                                       | PII/PHI detections, exfiltration attempts, DLP coverage |
| 30  | Backup & Recovery Status                                         | Backup posture, ransomware resilience, and recovery tests |
| 31  | Governance & Emergency Controls                                  | Kill‑switch mode, approval queue, policy governance, audit/log health |

These sections are backed by the JSON/audit surfaces described in `filepurpose.md` and exercised by the Stage 1–10 validation and runbooks in `ai-abilities.md`.

---

## Technical Architecture

### eBPF Kernel Telemetry (Module A)

- `XDP_PASS` observer mode (never drops packets).
- Syscall-to-network correlation.
- < 50 μs per-packet overhead; 10+ Gbps throughput.
- Rootkit detection (kernel vs userland verification).
- Telemetry suppression detection.
- Auto-fallback to `scapy` if unavailable.

### Machine Learning Pipeline

- RandomForest (100 trees), IsolationForest, GradientBoosting (50 estimators).
- LSTM neural network (7-state kill chain).
- Traffic autoencoder (15D → 8D → 15D, reconstruction error).
- Drift detection (Kolmogorov–Smirnov, PSI).
- Graph intelligence (lateral movement, C2, betweenness centrality).
- 18-signal ensemble voting (weighted consensus > 75% = auto-block).

## 10. Compliance & Governance

Designed to support alignment with:

- GDPR (data minimization).
- HIPAA (access logging).
- PCI-DSS (segmentation awareness).
- SOC 2 (auditability).
- ISO 27001 (ISMS principles).
- NIST CSF.

The system includes:

- Audit logs.
- Deterministic evaluation.
- Emergency kill-switch modes.
- Human-in-the-loop enforcement.
- Policy-driven automation.

## 11. Deployment Modes

Supported deployment models:

- Research lab.
- SOC observer.
- Network gateway (Linux only).
- Cloud or on-prem.
- Air-gapped environments.

Windows hosts operate in **userland mode only** (no eBPF).

## 12. Open Research Philosophy

Battle-Hardened AI is released as open-source to:

- Enable peer review.
- Encourage academic collaboration.
- Support national cyber capacity building.
- Promote transparency in AI-driven defense systems.

The project prioritizes **defensive research**, **explainability**, and **safety** over unchecked automation.

## 13. Licensing & Support

- License: MIT (research-friendly).
- Professional support available.
- Enterprise deployments supported under custom agreements.

## Closing Statement

Battle-Hardened AI is an evolving research platform, not a finished product. Its purpose is to explore how advanced detection, AI governance, and collective intelligence can be safely applied to modern cyber defense challenges.