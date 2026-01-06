# Dashboard Sections: Functions & Test Scripts

This document walks from the top of the AI dashboard (Sections 1–31) and shows **tiny Python helper scripts** you can run to:

- Hit the same backend APIs each section uses, or
- Call the core AI functions that feed that section.

Assumptions:
- Dashboard is running on `https://localhost:60000`.
- Run these from the repo root (`battle-hardened-ai/`).
- Install `requests` first if needed: `pip install requests`.

```python
# common helper for all HTTPS-based snippets
import requests

BASE_URL = "https://localhost:60000"

def show_json(path: str):
    url = f"{BASE_URL}{path}"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    print(f"GET {url} -> status {resp.status_code}")
    print(resp.json())
```

---

## Section 1 – AI Training Network – Shared Machine Learning

Backed by: `/api/p2p/status`, `/api/relay/status`, `/api/p2p/threats` and `AI/p2p_sync.py`.

```python
# Show AI training / P2P mesh and relay status
from pprint import pprint
from helper import show_json  # or inline show_json from above

show_json("/api/p2p/status")
show_json("/api/relay/status")
show_json("/api/p2p/threats")
```

## Section 2 – Network Devices – Live Monitor, Ports & History

Backed by: `/api/connected-devices`, `/api/scan-devices`, `/api/current-ports`, `/api/device-history`, `/api/assets/inventory`, `/api/visualization/topology` and `server/device_scanner.py`, `AI/asset_inventory.py`, `AI/advanced_visualization.py`.

```python
# List live devices, scan ports, and show 7‑day history
from helper import show_json

show_json("/api/connected-devices")       # live devices
show_json("/api/current-ports")           # current port scan config
show_json("/api/device-history")          # historical device connections
show_json("/api/assets/inventory")        # asset inventory
show_json("/api/visualization/topology")  # topology graph
```

## Section 3 – Attackers VPN/Tor De-Anonymization Statistics

Backed by: `pcs_ai.get_vpn_tor_statistics()` (from `AI/pcs_ai.py`) and VPN/Tor enrichment inside the threat pipeline.

```python
# Show raw VPN/Tor de‑anonymization statistics
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai

stats = pcs_ai.get_vpn_tor_statistics()
print(stats)
```

## Section 4 – Real AI/ML Models – Machine Learning Intelligence

Backed by: `pcs_ai.get_ml_model_stats()` and several AI modules (`AI/drift_detector.py`, `AI/meta_decision_engine.py`, `AI/reputation_tracker.py`, `AI/kernel_telemetry.py`, `AI/byzantine_federated_learning.py`, `AI/cryptographic_lineage.py`, `AI/deterministic_evaluation.py`).

```python
# Reveal ML model stats and ensemble/lineage/Byzantine info
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai

ml_stats = pcs_ai.get_ml_model_stats()
from pprint import pprint
pprint(ml_stats)
```

## Section 5 – Security Overview – Live Statistics

Backed by: `pcs_ai.get_threat_statistics()` and `ml_stats` from above.

```python
# High‑level security counters used in the overview tiles
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai
from pprint import pprint

stats = pcs_ai.get_threat_statistics()
pprint(stats)
```

## Section 6 – Threat Analysis by Type

Backed by: `stats.threats_by_type` from `pcs_ai.get_threat_statistics()`.

```python
# Show per‑type threat breakdown
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai

stats = pcs_ai.get_threat_statistics()
print(stats.get("threats_by_type", {}))
```

## Section 7 – IP Management & Threat Monitoring

Backed by: `/api/threat_log`, `/api/unblock/<ip>`, `/api/whitelist`, `/api/whitelist/add`, `/api/whitelist/remove`, `/api/threat/block-ip` and `pcs_ai._threat_log`, `pcs_ai.get_blocked_ips()`, `pcs_ai.get_whitelisted_ips()`.

```python
# Explore blocked IPs, whitelist, and raw threat log
from helper import show_json

show_json("/api/threat_log")   # same data used by live threats table
show_json("/api/whitelist")    # current whitelist
# blocked IPs are part of /api/stats and pcs_ai.get_blocked_ips()
show_json("/api/stats")        # includes blocked_ips_count etc.
```

## Section 8 – Failed Login Attempts (Battle-Hardened AI Server)

Backed by: `stats.failed_login_attempts` inside `pcs_ai.get_threat_statistics()`.

```python
# Show failed login attempts tracked for this server
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai

stats = pcs_ai.get_threat_statistics()
print(stats.get("failed_login_attempts", {}))
```

## Section 9 – Attack Type Breakdown

Backed by: `stats.attack_summary` from `pcs_ai.get_threat_statistics()`.

```python
# Show aggregate attack‑type counts for the chart
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai

stats = pcs_ai.get_threat_statistics()
print(stats.get("attack_summary", {}))
```

## Section 10 – Automated Signature Extraction – Attack Pattern Analysis

Backed by: `/api/signatures/extracted`, `/api/signatures/types`, `/api/signatures/stats` and `AI/signature_extractor.py`, `AI/signature_distribution.py`.

```python
# Inspect extracted defensive signatures and stats
from helper import show_json

show_json("/api/signatures/extracted")  # extracted patterns
show_json("/api/signatures/types")      # attack types with signatures
show_json("/api/signatures/stats")      # high‑level signature stats
```

## Section 11 – System Health & Network Performance

Backed by: `/api/system-status`, `/api/performance/metrics`, `/api/performance/network-stats`, `/api/performance/anomalies`, `/api/self-protection/stats` and modules like `AI/network_performance.py`, `AI/system_log_collector.py`, `AI/self_protection.py`.

```python
# Show host health and network performance metrics
from helper import show_json

show_json("/api/system-status")             # CPU, RAM, disk, uptime, services
show_json("/api/performance/metrics")       # time‑series perf metrics
show_json("/api/performance/network-stats") # bandwidth/latency
show_json("/api/performance/anomalies")     # detected anomalies
show_json("/api/self-protection/stats")     # integrity/self‑protection stats
```

## Section 12 – Compliance & Threat Governance

Backed by: `/api/compliance/summary`, `/api/compliance/report/<type>`, `/api/threat-model/stats`, `/api/audit-log/stats` and `AI/compliance_reporting.py`, `AI/policy_governance.py`, `AI/formal_threat_model.py`.

```python
# Reveal compliance posture and threat‑model/audit summaries
from helper import show_json

show_json("/api/compliance/summary")       # PCI/HIPAA/GDPR/SOC2 scores
show_json("/api/threat-model/stats")       # formal threat‑model metrics
show_json("/api/audit-log/stats")          # audit log statistics
# For full reports: /api/compliance/report/gdpr (or pci, hipaa, soc2, etc.)
show_json("/api/compliance/report/gdpr")
```

## Section 13 – Attack Chain Visualization (Graph Intelligence)

Backed by: `/api/graph-intelligence/attack-chains` and `AI/graph_intelligence.py`.

```python
# Show current attack chains and lateral movement graph
from helper import show_json

show_json("/api/graph-intelligence/attack-chains")
```

## Section 14 – Decision Explainability Engine

Backed by: `/api/explainability/decisions` and `AI/explainability_engine.py`.

```python
# Fetch explainable‑AI decision records
from helper import show_json

show_json("/api/explainability/decisions")
```

## Section 15 – Adaptive Honeypot – AI Training Sandbox

Backed by: `/api/adaptive_honeypot/status`, `/api/adaptive_honeypot/attacks`, `/api/adaptive_honeypot/attacks/history`, `/api/honeypot/status` and `AI/adaptive_honeypot.py`.

```python
# Inspect adaptive honeypot status and captured attacks
from helper import show_json

show_json("/api/adaptive_honeypot/status")       # personas, mode, ports
show_json("/api/adaptive_honeypot/attacks")      # recent honeypot attacks
show_json("/api/adaptive_honeypot/attacks/history")
show_json("/api/honeypot/status")                # legacy/simple honeypot
```

## Section 16 – AI Security Crawlers & Threat Intelligence Sources

Backed by: `AI/threat_intelligence.py`, `relay/threat_crawler.py`, `relay/exploitdb_scraper.py` and the JSON threat‑intel caches they maintain.

```python
# Show current threat‑intel and crawler‑feed state from pcs_ai
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai
from pprint import pprint

intel = pcs_ai.get_threat_intel_summary()  # helper inside pcs_ai
pprint(intel)
```

## Section 17 – Traffic Analysis & Inspection

Backed by: `/api/traffic/analysis`, `/api/traffic/crypto-mining`, `/api/pcap/stats` plus `AI/traffic_analyzer.py`, `AI/kernel_telemetry.py`, `AI/pcap_capture.py`.

```python
# Reveal live traffic analysis and crypto‑mining detection
from helper import show_json

show_json("/api/traffic/analysis")       # protocol/app breakdown, anomalies
show_json("/api/traffic/crypto-mining")  # crypto‑mining indicators
show_json("/api/pcap/stats")             # PCAP capture statistics
```

## Section 18 – DNS & Geo Security

Backed by: `/api/dns/stats`, `/api/traffic/crypto-mining` (for DNS‑based C2), and geolocation enrichment in the core threat pipeline.

```python
# Show DNS statistics, tunneling/DGA detections, and geo‑risk hints
from helper import show_json

show_json("/api/dns/stats")  # same JSON used for DNS/TLD charts
```

## Section 19 – User & Identity Monitoring + Zero Trust

Backed by: `/api/users/tracking`, `/api/zero-trust/scores`, `/api/zero-trust/policies`, `/api/zero-trust/violations`, `/api/zero-trust/dlp`, `/api/zero-trust/data-classification` and `AI/user_tracker.py`, `AI/zero_trust.py`.

```python
# UEBA + Zero‑Trust signals
from helper import show_json

show_json("/api/users/tracking")                 # user behavior & sessions
show_json("/api/zero-trust/scores")             # zero‑trust posture scores
show_json("/api/zero-trust/policies")           # active policies
show_json("/api/zero-trust/violations")         # policy violations
show_json("/api/zero-trust/dlp")                # DLP events/coverage
show_json("/api/zero-trust/data-classification")# data‑classification views
```

## Section 20 – Forensics & Threat Hunting

Backed by: `/api/pcap/stats`, `/api/pcap/download`, `/api/threat-hunt` and `AI/file_analyzer.py`, `AI/sequence_analyzer.py`, `AI/pcap_capture.py`.

```python
# Forensic and hunt surfaces
from helper import show_json

show_json("/api/pcap/stats")   # stored PCAPs and capture health
# /api/pcap/download?file=name.pcap returns a file download
# POST /api/threat-hunt with JSON query body performs hunt operations
```

## Section 21 – Sandbox Detonation

Backed by: `/api/sandbox/detonate`, `/api/sandbox/stats` and `AI/file_analyzer.py`.

```python
# Sandbox detonation statistics
from helper import show_json

show_json("/api/sandbox/stats")
# To detonate a sample:
# import requests; requests.post(BASE_URL+"/api/sandbox/detonate", files={"file": open("sample.bin","rb")})
```

## Section 22 – Email/SMS Alerts

Backed by: `/api/alerts/email/config`, `/api/alerts/sms/config`, `/api/alerts/stats` and `AI/alert_system.py`.

```python
# Alert configuration and metrics
from helper import show_json

show_json("/api/alerts/stats")  # counts/routes of alerts sent
```

## Section 23 – API for SOAR Integration + Workflow Automation

Backed by: `/api/soar/generate-key`, `/api/soar/keys`, `/api/soar/stats`, `/api/soar/workflows`, `/api/soar/incidents`, `/api/soar/playbooks`, `/api/soar/playbooks/<id>/execute` and `AI/soar_api.py`, `AI/soar_workflows.py`.

```python
# SOAR API surface and workflow stats
from helper import show_json

show_json("/api/soar/keys")       # registered API keys
show_json("/api/soar/workflows")  # available workflows
show_json("/api/soar/stats")      # incident/playbook statistics
show_json("/api/soar/incidents")  # current incidents
```

## Section 24 – Vulnerability & Supply Chain Management

Backed by: `/api/vulnerabilities/scan`, `/api/vulnerabilities/cves`, `/api/vulnerabilities/patches`, `/api/vulnerabilities/sbom`, `/api/vulnerabilities/dependencies` and `AI/vulnerability_manager.py`.

```python
# Vulnerability and software‑supply‑chain posture
from helper import show_json

show_json("/api/vulnerabilities/scan")         # current vuln scan summary
show_json("/api/vulnerabilities/cves")         # CVEs detected
show_json("/api/vulnerabilities/patches")      # missing patches
show_json("/api/vulnerabilities/sbom")         # SBOM view
show_json("/api/vulnerabilities/dependencies") # dependency risks
```

## Section 25 – Cryptocurrency Mining Detection

Backed by: `/api/traffic/crypto-mining` and `AI/crypto_security.py`, `AI/traffic_analyzer.py`.

```python
# Crypto‑mining detection statistics
from helper import show_json

show_json("/api/traffic/crypto-mining")
```

## Section 26 – Dark Web Monitoring

Backed by: `/api/vulnerabilities/darkweb`, `/api/vulnerabilities/credential-leaks` and crawler logic in `relay/threat_crawler.py`, `AI/threat_intelligence.py`.

```python
# Dark‑web and credential‑leak intelligence
from helper import show_json

show_json("/api/vulnerabilities/darkweb")         # dark‑web findings
show_json("/api/vulnerabilities/credential-leaks")# credential leaks
```

## Section 27 – Attack Simulation (Purple Team)

Backed by: `/api/soar/attack-simulation`, `/api/soar/mitre-coverage`, `/api/soar/red-team/schedule` and `AI/soar_workflows.py`.

```python
# Purple‑team simulation coverage and scheduling
from helper import show_json

show_json("/api/soar/attack-simulation")  # available simulations
show_json("/api/soar/mitre-coverage")     # MITRE ATT&CK coverage map
```

## Section 28 – Cloud Security Posture Management (CSPM)

Backed by: `/api/cloud/posture`, `/api/cloud/misconfigurations`, `/api/cloud/iam`, `/api/cloud/compliance` and `AI/cloud_security.py`.

```python
# Cloud security posture and misconfiguration data
from helper import show_json

show_json("/api/cloud/posture")           # overall CSPM posture
show_json("/api/cloud/misconfigurations") # specific cloud issues
show_json("/api/cloud/iam")               # IAM risks
show_json("/api/cloud/compliance")        # cloud compliance checks
```

## Section 29 – Data Loss Prevention (DLP)

Backed by: `/api/zero-trust/dlp`, `/api/zero-trust/data-classification` and `AI/zero_trust.py`.

```python
# DLP and data‑classification surfaces
from helper import show_json

show_json("/api/zero-trust/dlp")                # DLP incidents
show_json("/api/zero-trust/data-classification")# classification map
```

## Section 30 – Backup & Recovery Status

Backed by: `/api/backup/status`, `/api/backup/resilience`, `/api/backup/test-restore` and `AI/backup_recovery.py`.

```python
# Backup health, ransomware resilience, and restore tests
from helper import show_json

show_json("/api/backup/status")      # backup jobs and coverage
show_json("/api/backup/resilience")  # resilience score & tests
# POST /api/backup/test-restore kicks off a test restore operation
```

## Section 31 – Governance & Emergency Controls

Backed by: `/api/governance/stats`, `/api/killswitch/status`, `/api/audit-log/stats`, `/api/ai/abilities`, `/api/central-sync/status`, `/api/system-status` and modules like `AI/policy_governance.py`, `AI/emergency_killswitch.py`, `AI/central_sync.py`.

```python
# Governance, kill‑switch, approval‑queue, and global sync surfaces
from helper import show_json

show_json("/api/governance/stats")      # governance/approval metrics
show_json("/api/killswitch/status")     # emergency kill‑switch state
show_json("/api/audit-log/stats")       # audit‑log health
show_json("/api/ai/abilities")          # 18 AI abilities on/off flags
show_json("/api/central-sync/status")   # central sync controller status
show_json("/api/system-status")         # underlying node health
```
