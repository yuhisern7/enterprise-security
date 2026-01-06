## Battle-Hardened AI

**An Open Research Platform for Network Detection & Response (NDR) and National Cyber Defense**

Battle-Hardened AI is an open, research-oriented Network Detection and Response (NDR) platform designed to study, evaluate, and deploy advanced defensive cybersecurity techniques. It integrates multi-signal detection, machine learning, kernel-level telemetry, and policy-governed response mechanisms to support enterprise-scale and national-scale cyber defense research.

The system is designed with defensive-only constraints, privacy preservation, and auditability as first-class principles.

---

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

**AI has 18 detection abilities; the dashboard exposes 30+ monitoring sections.**

#### 🧠 Core AI Intelligence (5 sections)

- **Section 1:** Complete AI feature overview (18 detection abilities).
- **Section 5:** ML Models (4 tabs: Models/Training, Byzantine Defense, Model Lineage, Deterministic Testing).
- **Section 11:** Automated signature extraction.
- **Section 14:** Attack chain visualization (Graph Intelligence).
- **Section 15:** Decision explainability engine.

#### 🌐 Network & Devices (4 sections)

- **Section 3:** Live device monitoring and port scanning.
- **Section 12:** System health (3 tabs: Resources, Network, Integrity).
- **Section 18:** Traffic analysis, deep packet inspection (DPI), and encrypted traffic overview (TLS fingerprinting).
- **Section 19:** DNS and geo security, powered by the DNS analyzer and dns_security.json metrics.

#### 🎯 Threat Detection & Analysis (8 sections)

- **Section 2:** AI training network (P2P federated learning).
- **Section 4:** VPN/Tor de-anonymization.
- **Section 6–8:** Security overview, threat analysis, IP management.
- **Section 10:** Attack-type breakdown.
- **Section 17:** AI crawlers and threat intelligence.
- **Section 26:** Cryptocurrency mining detection.
- **Section 27:** Dark web monitoring.

#### 🛡️ Defense & Response (5 sections)

- **Section 9:** Failed login attempts monitoring.
- **Section 16:** Adaptive honeypot (AI learning sandbox).
- **Section 21:** Forensics and threat hunting.
- **Section 22:** Sandbox detonation.
- **Section 28:** Attack simulation (Purple Team).

#### 🔐 Identity, Compliance & Enterprise (10+ sections)

- **Section 13:** Compliance and governance (3 tabs: PCI/HIPAA/GDPR/SOC2, Threat Model, Audit Summary).
- **Section 20:** User monitoring and Zero Trust.
- **Section 23:** Email/SMS alerts.
- **Section 24:** API and SOAR integration.
- **Section 24:** Vulnerability and supply chain management.
- **Section 25:** Cryptocurrency mining detection.
- **Section 26:** Dark web monitoring.
- **Section 27:** Attack simulation (Purple Team).
- **Section 28:** Cloud security posture (CSPM).
- **Section 29:** Data loss prevention (DLP).
- **Section 30:** Backup and recovery status.
- **Section 31:** Governance and emergency controls (kill switch, policy approvals, audit logs, system logs).

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