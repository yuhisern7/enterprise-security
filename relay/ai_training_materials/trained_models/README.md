# Trained ML Models

Pre-trained machine learning models distributed to subscriber nodes (280 KB total).

## Current Models:

### anomaly_detector.pkl
- **Algorithm:** Isolation Forest
- **Purpose:** Detect anomalous network behavior
- **Training:** Trained on 825 MB+ attack dataset
- **Features:** Connection patterns, timing, protocol usage
- **Updated:** Every 6 hours (with relay sync)

### threat_classifier.pkl
- **Algorithm:** Random Forest Classifier
- **Purpose:** Classify threat types (SQL injection, XSS, etc.)
- **Training:** Learned from ExploitDB signatures + live attacks
- **Accuracy:** Continuously improving via feedback loop

### ip_reputation.pkl
- **Algorithm:** Gradient Boosting Classifier
- **Purpose:** Predict IP reputation (malicious/benign)
- **Features:** Geolocation, ASN, historical behavior, VPN detection

### feature_scaler.pkl
- **Algorithm:** StandardScaler
- **Purpose:** Normalize features before ML inference
- **Critical:** Must match training data distribution

## Distribution:
- Subscribers download ONLY these .pkl files (not raw training data)
- Models retrained centrally on relay server every 6 hours
- Integrity: SHA256 checksums verified before loading
- Rollback: Last 3 model versions kept for safety

## Privacy:
✅ **Shared:** Model weights and parameters (abstract math)
❌ **NOT Shared:** Training data, exploit payloads, per-network logs
