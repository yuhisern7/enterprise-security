# Trained ML Models

Pre-trained machine learning and deep learning models distributed to subscriber nodes.

## Current Models:

### Classical ML Models (.pkl)

#### anomaly_detector.pkl (~70 KB)
- **Algorithm:** Isolation Forest
- **Purpose:** Detect anomalous network behavior
- **Training:** Trained on 825 MB+ attack dataset
- **Features:** Connection patterns, timing, protocol usage
- **Updated:** Every 6 hours or when drift detected

#### threat_classifier.pkl (~85 KB)
- **Algorithm:** Random Forest Classifier
- **Purpose:** Classify threat types (SQL injection, XSS, etc.)
- **Training:** Learned from ExploitDB signatures + live attacks
- **Accuracy:** Continuously improving via feedback loop

#### ip_reputation.pkl (~90 KB)
- **Algorithm:** Gradient Boosting Classifier
- **Purpose:** Predict IP reputation (malicious/benign)
- **Features:** Geolocation, ASN, historical behavior, VPN detection

#### feature_scaler.pkl (~35 KB)
- **Algorithm:** StandardScaler
- **Purpose:** Normalize features before ML inference
- **Critical:** Must match training data distribution

### Deep Learning Models (.keras)

#### traffic_autoencoder.keras (~200 KB) - Phase 2
- **Architecture:** Autoencoder (15→32→16→8→16→32→15)
- **Purpose:** Unsupervised anomaly detection via reconstruction error
- **Training:** Trained on normal traffic patterns only
- **Detection:** High reconstruction error = anomaly
- **Updated:** When drift detected or every 6 hours

#### sequence_lstm.keras (~150 KB) - Phase 1B
- **Architecture:** 2-layer LSTM (64→32 units)
- **Purpose:** Predict attack state transitions
- **States:** NORMAL → SCANNING → AUTH_ABUSE → PRIV_ESC → LATERAL_MOVEMENT → EXFILTRATION → COMMAND_CONTROL
- **Training:** Trained on observed attack sequences
- **Detection:** Early warning of attack progression

### Metadata

#### node_fingerprint.json
- **Purpose:** Device/node fingerprinting for cross-IP tracking
- **Content:** Browser fingerprints, device characteristics
- **Privacy:** Hashed identifiers only

## Training Data Sources

Models are trained on:
- ExploitDB database (50,000+ exploits)
- Real-time global attacks from subscribers
- Learned attack signatures
- **Phase 1A:** Behavioral metrics (15+ metrics per entity)
- **Phase 1B:** Attack sequences (state transitions)
- **Phase 2:** Normal traffic for autoencoder baseline
- **Phase 3:** Distribution drift monitoring data
- Threat intelligence feeds

## Update Frequency

- **Scheduled:** Every 6 hours
- **Drift-Triggered:** When Phase 3 detects distribution changes
- **On-demand:** When new exploits added
- **Auto-download:** Subscribers check for updates hourly

## Distribution:
- Subscribers download ONLY these model files (not raw training data)
- Models retrained centrally on relay server every 6 hours
- Integrity: SHA256 checksums verified before loading
- Rollback: Last 3 model versions kept for safety

## Privacy:
✅ **Shared:** Model weights and parameters (abstract math)
❌ **NOT Shared:** Training data, exploit payloads, per-network logs
