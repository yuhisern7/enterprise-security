# Training Datasets

**⚠️ RELAY SERVER ONLY - Subscribers do NOT download raw training data**

This folder contains training datasets used to train ML models on the relay server.

## Files

### sample_dataset.csv
- **Size:** Example dataset for supervised learning
- **Format:** CSV with labeled attack samples
- **Columns:** src_ip, attack_type, severity, threat_score, protocol, port, payload_size, country, is_malicious
- **Usage:** Training threat_classifier and ip_reputation models

### learned_attack_patterns.json
- **Purpose:** Attack patterns extracted from real threats
- **Source:** Automatic extraction from blocked attacks
- **Format:** JSON with attack signatures, keywords, encodings
- **Usage:** Signature-based detection and pattern matching

### behavioral_metrics.json - Phase 1A
- **Purpose:** Behavioral heuristics tracking data
- **Metrics:** 15+ per entity (connection rate, port entropy, auth failures, fan-out/in, timing variance, etc.)
- **Windows:** 1min, 5min, 15min rolling averages
- **Usage:** Training behavioral anomaly detection models
- **Privacy:** Aggregated metrics only, no raw traffic

### attack_sequences.json - Phase 1B
- **Purpose:** Attack state transition sequences
- **States:** NORMAL → SCANNING → AUTH_ABUSE → PRIV_ESC → LATERAL_MOVEMENT → EXFILTRATION → COMMAND_CONTROL
- **Format:** Observed event sequences with timestamps
- **Usage:** Training LSTM sequence predictor (sequence_lstm.keras)
- **Detection:** Predict next attack state for early warning

## Privacy & Security

🔒 **These files NEVER leave the relay server**
- Contains aggregated attack data from all subscribers
- Used ONLY for centralized model training
- Individual subscriber data not stored
- Models trained on collective patterns, not individual networks

## Advanced AI Components

### Phase 1A: Behavioral Heuristics
- Tracks connection patterns, authentication behavior, network scanning
- Risk scoring based on multiple behavioral signals
- Data stored in `behavioral_metrics.json`

### Phase 1B: LSTM Sequence Analyzer
- Learns attack progression patterns from observed sequences
- 7-state model for attack lifecycle tracking
- Data stored in `attack_sequences.json`

### Phase 3: Drift Detection
- Monitors distribution changes in model inputs
- Triggers retraining when drift exceeds thresholds
- Baseline data stored in server/json/drift_baseline.json
