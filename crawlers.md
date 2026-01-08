# Threat Intelligence Crawlers & Relay Integration

**Pipeline Alignment:** Stage 6 (Global Intelligence Sharing) + Stage 7 (Continuous Learning)

This document explains how the **threat intelligence crawlers** and **ExploitDB scraper** integrate with the **7-stage attack detection pipeline**, where they store data under `relay/ai_training_materials`, and how the customer node discovers the relay endpoint automatically via `server/.env`.

## Pipeline Context

The crawlers and relay infrastructure support two critical pipeline stages:

**Stage 6: Global Intelligence Sharing (Optional Relay)**
- Crawlers collect global threat intelligence (CVEs, malware hashes, URLs, ExploitDB patterns)
- Data stored in `relay/ai_training_materials/` for worldwide distribution
- Customer nodes pull threat intel via `MODEL_SYNC_URL`
- Feeds into Stage 2 Signal #12 (Threat Intel Feeds) on customer nodes

**Stage 7: Continuous Learning Loop**
- ExploitDB scraper generates new signatures weekly
- Crawlers update threat intelligence daily
- ML retraining uses crawler data as training input
- Updated models distributed to all customer nodes

## Deployment Architecture

The high‑level design:

- **Customer node** (this repo's `AI/` + `server/` folders) runs the dashboard and local protection (Stages 1-5)
- **Relay node (VPS)** (this repo's `relay/` folder) runs background crawlers + ExploitDB scraper and stores training data under `relay/ai_training_materials/` (Stages 6-7)
- The customer node connects to the relay over WebSocket/HTTP using URLs configured in `server/.env`
- No hardcoded IPs in code paths are required; everything is driven by environment variables

---

## 1. Files Involved in Crawlers & Storage

### 1.1 Relay side (VPS)

These live under the `relay/` folder and should be deployed to your VPS.

- **`relay/threat_crawler.py`** — **[Stage 6: Threat Intel Collection]**
  - Implements multiple threat‑intel crawlers:
    - `CVECrawler` (trending CVEs from cvetrends)
    - `MalwareBazaarCrawler` (malware samples + hashes via CSV export)
    - `AlienVaultOTXCrawler` (public threat pulses)
    - `URLhausCrawler` (malicious URLs via CSV)
    - `AttackerKBCrawler` (sample assessments)
  - `ThreatCrawlerManager.crawl_all(save_to_file=True)`
    - Runs all crawlers, normalizes them into a flat threat list
    - Persists results via `save_results(...)`
  - `ThreatCrawlerManager.save_results(...)`
    - Default path: `relay/ai_training_materials/threat_intelligence/` (relative to `relay/`)
    - This JSON is a **training artifact** consumed by Stage 7 ML retraining pipeline
    - Also feeds Stage 2 Signal #12 (Threat Intel Feeds) on customer nodes

- **`relay/exploitdb_scraper.py`** — **[Stage 7: Signature Generation]**
  - Crawls a **local ExploitDB checkout** (`relay/ai_training_materials/exploitdb/`)
  - Extracts **safe, pattern‑only signatures** from exploit descriptions and PoCs
  - `ExploitDBScraper.export_learned_signatures(...)`:
    - Writes to: `relay/ai_training_materials/ai_signatures/learned_signatures.json`
    - This is the master signatures file on the relay side
    - Feeds Stage 2 Signal #2 (Signature Matching) on customer nodes
  - `start_exploitdb_scraper(exploitdb_path="exploitdb", continuous=True)`
    - Performs initial scrape + export
    - Optionally keeps scraping on a 24h schedule

- **`relay/training_sync_api.py`** — **[Stage 6: Distribution API]**
  - HTTP API on the relay side that exposes training materials to customers
  - Typical responsibilities:
    - Serve model bundles (`trained_models/`) for Stage 7 continuous learning
    - Serve threat‑intel JSON for Stage 2 Signal #12
    - Serve signatures (`ai_signatures/`) for Stage 2 Signal #2

- **`relay/signature_sync.py`** — **[Stage 6: Sync Layer]**
  - Helper layer for syncing signature files (e.g. `learned_signatures.json`) from `ai_training_materials` to connected customers
  - Handles deduplication and HMAC validation
  - Stores `global_attacks.json` with automatic 1GB rotation (see ML_LOG_ROTATION.md)

- **`relay/start_services.py`** — **[Relay Orchestrator]**
  - Convenience launcher to bring up:
    - `relay_server.py` (WebSocket relay for Stage 6)
    - `training_sync_api.py` (HTTP API for Stage 6)
    - Optionally crawlers / scraper daemons for Stage 7

- **`relay/ai_training_materials/`** — **[Stage 6 & 7 Storage]**
  - Canonical storage on the relay for anything *learned*:
    - `ai_signatures/learned_signatures.json`  ← signatures from ExploitDB scraper (Stage 7 → Stage 2 Signal #2)
    - `threat_intelligence/`                  ← crawlers' normalized intel (Stage 6 → Stage 2 Signal #12)
    - `global_attacks.json` + rotation files  ← aggregated customer attacks for ML training (Stage 6 → Stage 7)
    - `trained_models/`                       ← ML models exported for customers (Stage 7 distribution)
    - `orchestration_data/`, `reputation_data/`, etc. for other stages

> **Important:** The relay stack (`relay/` tree) is **not shipped to customers**. It resides on your VPS and is considered your central intelligence plane for Stages 6-7.


### 1.2 Customer side (this repo: AI + server) - Stage 2 & 6 Integration

These files run on the customer node (Docker container), and learn from / talk to the relay.

- **`server/.env`** — **[Stage 6: Relay Configuration]**
  - Central place for pointing the customer to your VPS relay:
    - `RELAY_ENABLED=true`
    - `RELAY_URL=ws://YOUR_RELAY_IP_OR_HOST:60001`
    - `MODEL_SYNC_URL=http://YOUR_RELAY_IP_OR_HOST:60002`
  - When you build / run the Docker container, these variables are injected into the `server` process and `AI` modules.

- `server/server.py`
  - Flask app for the dashboard and API.
  - Loads `.env` via Docker environment; does **not** hardcode relay IP.
  - The AI engine (`AI/pcs_ai.py` & related modules) inherits these env vars.

- `AI/relay_client.py`
  - WebSocket client that connects to the relay mesh.
  - Reads environment variables **only**, nothing hardcoded:
    - `RELAY_URL` – WebSocket endpoint of relay (from `.env`).
    - `RELAY_ENABLED` – toggles the client on/off.
    - `RELAY_CRYPTO_ENABLED`, `CUSTOMER_ID`, `PEER_NAME`, `RELAY_RECONNECT_DELAY`.
  - When `RELAY_ENABLED=true` and `RELAY_URL` is set:
    - Starts a background thread.
    - Maintains a live connection to `RELAY_URL`.
    - Sends **sanitized threat summaries** to the relay.
    - Receives global threats / intelligence from other peers via the relay.

- `AI/central_sync.py`
  - Uses the relay client to **apply** global threat intelligence to the local node.
  - Integrates incoming signals into local ML training and threat detection.

- `AI/signature_distribution.py`
  - Handles **downloading / applying** signature bundles from central sources.
  - In a premium setup, this is where the relay‑provided `learned_signatures.json` ends up being placed into the local `AI/` directory.

- `AI/signature_extractor.py`
  - Local engine that learns **new attack patterns** from real attacks at the customer edge.
  - Writes to a safe patterns file (no payloads) for retraining.
  - Complementary to the relay’s ExploitDB signatures.

- `AI/learned_signatures.json`
  - Local, **shipped** copy of learned signatures.
  - Typically originates from the relay’s `ai_signatures/learned_signatures.json` at build/packaging time or via the signature distribution sync.


---

## 2. Why you don’t see live crawler writes on the customer

- The **actual crawlers and ExploitDB scraper run only on the relay VPS** under `relay/`.
- Their outputs (signatures, threat intel, models) are written into `relay/ai_training_materials/...`.
- The customer **does not run those heavy crawlers**; it only:
  - Connects to the relay using `RELAY_URL` / `MODEL_SYNC_URL`.
  - Downloads precomputed artifacts (signatures + models).
  - Contributes anonymized threat summaries via `AI/relay_client.py`.

Because of that:

- On a dev machine where **no relay is running** or `RELAY_ENABLED` is `false`, you will only see static JSONs (like `AI/learned_signatures.json`) and local pattern extraction from live attacks.
- Once the relay is up and the customer is pointed to it, the flow becomes:
  1. Relay crawlers + ExploitDB scraper populate `relay/ai_training_materials/*`.
  2. Relay’s `training_sync_api.py` exposes those via HTTP.
  3. Customer’s `AI/signature_distribution.py` and related sync code
     fetch new bundles into `AI/learned_signatures.json` (and model files).


---

## 3. Automatic configuration via `server/.env`

You **do not** need to edit Python files to change relay IPs/URLs. Instead:

1. **On the relay VPS** (using the `relay/` folder):
   - Run `relay/start_services.py` (or equivalent Docker compose) so that:
     - `relay_server.py` listens on `60001` (WebSocket).
     - `training_sync_api.py` listens on `60002` (HTTP for models/signatures).
   - Ensure inbound ports `60001` and `60002` are open in the VPS firewall.

2. **On the customer node**:
   - Edit `server/.env`:
     ```env
     RELAY_ENABLED=true
     RELAY_URL=ws://YOUR_VPS_IP_OR_DOMAIN:60001
     MODEL_SYNC_URL=http://YOUR_VPS_IP_OR_DOMAIN:60002
     RELAY_CRYPTO_ENABLED=true
     CUSTOMER_ID=your-customer-id
     PEER_NAME=your-node-name
     ```
   - Rebuild / restart the Docker container so these variables are in the runtime environment.

3. **Runtime behavior (automatic)**:
   - `AI/relay_client.py` reads `RELAY_URL`, `RELAY_ENABLED`, `CUSTOMER_ID`, etc. automatically via `os.getenv`.
   - No code changes are required when you move to a different VPS; you only change `.env`.
   - Signature and model sync code (e.g. `AI/signature_distribution.py`, `AI/central_sync.py`) can use `MODEL_SYNC_URL` in the same fashion to pull from the relay.


---

## 4. Summary of key env variables (Stage 6 Configuration)

From `server/.env` (inherited by AI modules):

- `RELAY_ENABLED`  – `true` / `false`; turns Stage 6 relay client on/off
- `RELAY_URL`      – WebSocket URL of the relay server (e.g. `ws://165.22.108.8:60001`)
- `MODEL_SYNC_URL` – HTTP base URL for model/signature downloads (e.g. `http://165.22.108.8:60002`)
- `RELAY_CRYPTO_ENABLED` – enables message signing/verification (HMAC)
- `CUSTOMER_ID`    – unique ID used for crypto and multi‑tenant separation
- `PEER_NAME`      – friendly name of this node in the relay mesh

As long as these are set correctly in `server/.env` and the relay services are running, the crawlers and learned signatures flow will work **automatically** without changing file paths inside the code.

## Pipeline Stage Summary

**Stage 1-5 (Customer Node):**
- Data Ingestion → 20 Parallel Detections (18 primary + 2 strategic) → Ensemble Voting → Response Execution → Training Material Extraction
- All handled by `AI/` + `server/` folders
- Uses local signatures from `AI/learned_signatures.json` (Stage 2 Signal #2)

**Stage 6 (Relay VPS):**
- Global Intelligence Sharing
- Relay receives sanitized attack summaries from all customer nodes
- Stores in `global_attacks.json` with 1GB rotation (see ML_LOG_ROTATION.md)
- Distributes signatures and threat intel to all customers

**Stage 7 (Relay VPS):**
- Continuous Learning Loop
- `relay/ai_retraining.py` trains ML models on `global_attacks*.json` + threat intel
- `relay/exploitdb_scraper.py` generates new signatures weekly
- `relay/threat_crawler.py` updates threat intelligence daily
- Updated models/signatures pushed to all customer nodes (Stage 7 → Stage 2)
