# 🛡️ Battle-Hardened AI — Network Defense in One Container

AI-driven network protection with live signature learning, deep inspection, and global threat sharing. Runs anywhere; best on Linux or via Docker.

---

## 📌 Snapshot
- **Active modules:** 31/31 (dashboard cards wired to real backends)
- **APIs:** 80+ production endpoints (threats, devices, compliance, SOAR)
- **Protection:** Real-time ML + rule signals, adaptive honeypot, DPI, UEBA, DLP, cloud/backup posture, dark web watch
- **Update cadence:** Models and intel refresh every 6 hours (with relay enabled)

---

## 🧠 What the AI Does
- **Observe:** Monitor gateway traffic, devices, ports, user logins, cloud posture, backups, dark web signals.
- **Classify:** RandomForest, IsolationForest, LSTM, and heuristics score threats; UEBA flags risky users/devices.
- **Decide:** 5-gate false-positive filter demands multi-signal agreement (AI + behavior + reputation) and ≥75% confidence.
- **Act:** Block IPs, quarantine risky devices, enforce zero-trust scores, alert via email/SMS, trigger SOAR workflows.
- **Learn:** Extract signatures from confirmed attacks (patterns only, no payloads), retrain, and sync through the relay mesh.
- **Explain:** Dashboard cards for traffic, DNS/geo, topology, compliance, vuln/SBOM, crypto-mining, DLP, backups, cloud.

---

## 🎛️ Platform & Deployment
- **Linux (recommended):** Full telemetry (ss/tcpdump/proc/sys) and all 31 modules.
- **Windows/macOS:** Core AI, blocking, dashboard, and APIs work. For full parity, run the Linux container via Docker.
- **Modes:**
  - **Full sync (default):** Share anonymous signatures and receive model/threat updates.
  - **Hybrid (receive-only):** RELAY_SYNC_MODE=read_only
  - **Air-gapped:** RELAY_SYNC_ENABLED=false OFFLINE_MODE=true

---

## 🚀 Quick Start (Docker)
```bash
git clone https://github.com/yuhisern7/battle-hardened-ai.git
cd battle-hardened-ai/server
# optional: edit .env to set RELAY_URL, ports, and sync mode
docker compose up -d
```
Dashboard: https://localhost:60000 (self-signed cert; proceed past browser warning).

---

## 🔎 Detection & Response Pillars
- **Traffic & Content:** Deep packet insights, app-aware blocking, DNS/DGA checks, geo hot spots, TLS/JA3/JA4 fingerprints.
- **Identity & Devices:** UEBA for users, device trust scoring, port scans, history, asset inventory, zero-trust posture.
- **Deception:** Adaptive honeypot personas with live attack capture.
- **Forensics & Hunting:** PCAP stats, hunt API, sandbox detonation, threat hunts across captured flows.
- **Resilience:** Vulnerability/SBOM, patch cues, cloud misconfig/iam checks, DLP, ransomware resilience, backup status.
- **Automation:** Email/SMS alerts, SOAR API keys/workflows, attack simulation with MITRE coverage heatmaps.

---

## 🤝 Data Handling & Privacy
- **Shared (optional, via relay):** Anonymous attack signatures (keywords/encodings/pattern hashes), aggregated model features, and counts.
- **Stays local:** Device lists, history, topology, blocked/whitelist entries, port scans, threat logs, configs, packet payloads, and any exploit content (deleted after pattern extraction).
- **No exploit storage:** Patterns only—defensive signatures akin to AV definitions.

---

## 🔧 Key Endpoints (examples)
- Threats & stats: /api/stats, /api/threat_log
- Devices & history: /api/connected-devices, /api/device-history
- Traffic & DNS: /api/traffic/analysis, /api/dns/stats
- Identity & zero trust: /api/users/tracking, /api/zero-trust/scores
- Honeypot: /api/adaptive_honeypot/status
- Signatures: /api/signatures/extracted
- Compliance & posture: /api/compliance/summary, /api/cloud/posture
- Vulnerabilities & SBOM: /api/vulnerabilities/scan, /api/vulnerabilities/sbom
- DLP & backups: /api/zero-trust/dlp, /api/backup/status
- Alerts & SOAR: /api/alerts/stats, /api/soar/stats, /api/openapi.json

---

## 🧩 How It Learns (Pipeline)
1. Capture multi-signal evidence (AI prediction, network behavior, honeypot, reputation).
2. Pass through 5-gate filter (context, repetition, timing, cross-signal, confidence).
3. Extract signature (keywords/encodings/regex features) and drop payloads.
4. Retrain models (RandomForest, IsolationForest, LSTM) on confirmed patterns.
5. Distribute 280 KB models + signature deltas to all nodes (if relay enabled).

---

## 🏗️ Feature Map (31 Modules)
- **Protect:** Threat stats, IP management, failed-logins, attack breakdown, honeypot, DPI, DNS/geo, user/identity, sandbox, alerts, SOAR.
- **Observe:** Devices/ports/history, topology, system health, compliance, performance, traffic anomalies, API status, cloud posture, backups.
- **Investigate:** Signature extraction, forensics/hunt, PCAP stats, MITRE attack simulation, dark web monitoring, crypto-mining detection.
- **Assure:** Vulnerability & SBOM, DLP, zero-trust scores, asset inventory, ransomware resilience, patch guidance.

---

## 🧭 Deployment Tips
- For full metrics, run on Linux or inside the provided Linux container.
- Set DASHBOARD_PORT and P2P_PORT in .env if you need custom ports.
- Use hybrid or air-gapped mode for classified or compliance-restricted environments.
- Keep server/json/*.json on fast local storage; they hold your private telemetry only.

---

## 💬 Contact / Premium Relay
Premium relay ($25/month) adds global mesh updates, six-hour model refresh, and priority support.
- WhatsApp: +60172791717
- Email: yuhisern@protonmail.com

---

## ✅ Why It’s Different
- Live signature extraction with zero exploit storage
- Multi-signal, low-noise detections (5-gate filter)
- Global mesh learning (opt-in) with tiny model payloads
- Full-stack coverage: network, identity, cloud, DLP, backup, dark web, and SOAR
