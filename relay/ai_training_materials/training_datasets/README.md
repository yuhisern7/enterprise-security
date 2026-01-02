# ML Training Datasets

CSV datasets used for model training on the relay server.

## Current Datasets:

### sample_dataset.csv
- **Size:** Variable (grows with confirmed attacks)
- **Purpose:** Train ML models on confirmed threat patterns
- **Columns:** 
  - IP address (hashed)
  - Attack type
  - Feature vector (protocol, timing, behavior metrics)
  - Label (benign/malicious)
  - Timestamp
- **Source:** Aggregated from subscriber nodes (patterns only, no payloads)

## Future Datasets (Planned):

### behavioral_features.csv
- Connection patterns, retry rates, port entropy
- Extracted from behavioral heuristics engine
- Local network baselines NOT included (privacy)

### sequence_training.csv
- State transition sequences for LSTM training
- Attack progression patterns (scan → exploit → lateral movement)

### graph_features.csv
- Graph-based features (node centrality, edge weights)
- Lateral movement patterns
- Beaconing behavior signatures

## Privacy & Safety:
✅ **Included:** Abstract features, statistical patterns, hashed identifiers
❌ **NOT Included:** Raw payloads, exploit code, IP addresses, device details

## Access:
- **Relay Server:** Uses for model training
- **Subscriber Nodes:** Do NOT download datasets (only trained models)
- **Training Frequency:** Models retrained every 6 hours using this data

## Data Retention:
- Keep last 90 days of training data
- Older data archived/deleted to prevent staleness
- Confirmed attacks only (false positives excluded)
