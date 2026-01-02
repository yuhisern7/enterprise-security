# Relay Server AI Training Materials

**⚠️ RELAY SERVER ONLY - This folder contains centralized training data for Premium mode**

This folder contains curated datasets for training ML security models on the relay server.  
**Subscribers do NOT download this (825 MB) - they download ONLY trained models (280 KB)**

---

## 📂 Folder Structure (Organized)

```
ai_training_materials/
├── ai_signatures/           # Attack signature patterns (910 KB)
│   ├── learned_signatures.json
│   └── README.md
├── trained_models/          # Pre-trained ML models (distributed)
│   ├── anomaly_detector.pkl
│   ├── threat_classifier.pkl
│   ├── ip_reputation.pkl
│   ├── feature_scaler.pkl
│   ├── node_fingerprint.json
│   ├── traffic_autoencoder.keras  # Phase 2: Deep learning autoencoder
│   ├── sequence_lstm.keras        # Phase 1B: Attack sequence predictor
│   └── README.md
├── threat_intelligence/     # Crawled threat intel data
│   ├── threat_intelligence_crawled.json
│   ├── crawled_YYYYMMDD.json
│   └── README.md
├── training_datasets/       # CSV training data + behavioral metrics
│   ├── sample_dataset.csv
│   ├── learned_attack_patterns.json
│   ├── behavioral_metrics.json     # Phase 1A: Behavioral heuristics
│   ├── attack_sequences.json       # Phase 1B: Attack state sequences
│   └── README.md
├── exploitdb/               # ExploitDB database (824 MB, relay only)
│   ├── exploits/            # 50,000+ exploit scripts
│   ├── shellcodes/          # Shellcode database
│   ├── files_exploits.csv   # Exploit metadata
│   └── files_shellcodes.csv
└── learned_signatures.json  # Symlink → ai_signatures/learned_signatures.json
```

---

## 🔄 Training Workflow (Relay Server)

### 1. Data Collection
**Sources:**
- **ExploitDB**: 50,000+ exploit signatures (static, updated quarterly)
- **Global Attacks**: Real-time attacks from worldwide subscribers
- **Learned Signatures**: Attack patterns learned from previous training
- **Malware Hashes**: Known malware from threat intelligence feeds

### 2. AI Training (Every 6 Hours)
**Process:**
1. Load all training materials from THIS folder (LOCAL loading, no downloads)
2. Merge ExploitDB + global_attacks + learned_signatures into unified dataset
3. Train 7 ML/DL models:
   - `anomaly_detector.pkl` - IsolationForest for unsupervised anomaly detection
   - `threat_classifier.pkl` - RandomForest for attack type classification
   - `ip_reputation.pkl` - GradientBoosting for IP reputation scoring
   - `feature_scaler.pkl` - StandardScaler for feature normalization
   - `traffic_autoencoder.keras` - Deep learning autoencoder (Phase 2)
   - `sequence_lstm.keras` - LSTM for attack sequence prediction (Phase 1B)
   - Drift baselines updated automatically (Phase 3)
4. Save trained models to `trained_models/` folder

**Advanced AI Components:**
- **Phase 1A**: Behavioral heuristics (15+ metrics, risk scoring)
- **Phase 1B**: LSTM sequence analyzer (7-state attack progression)
- **Phase 2**: Traffic autoencoder (unsupervised deep learning)
- **Phase 3**: Drift detector (K-S test, PSI metrics, auto-retraining)

### 3. Model Distribution (HTTP API)
**Endpoint:** `http://relay-server:60002/models/<model_name>`
**Subscribers download:**
- 7 model files (.pkl + .keras)
- Updated every 6 hours or when drift detected
- NO access to raw training data

---

## 📥 Setup Training Materials

### Option A: ExploitDB (Automated)
```bash
cd AI/
./setup_exploitdb.sh
cp -r exploitdb ../relay/ai_training_materials/
```

### Option B: Custom Dataset (CSV)
**Create:** `custom_attacks.csv`
```csv
src_ip,attack_type,severity,threat_score,protocol,port,payload_size,country,is_malicious
192.168.1.100,SQL Injection,high,0.95,TCP,80,1024,US,1
10.0.0.50,Port Scan,medium,0.75,TCP,22,64,CN,1
172.16.0.10,Normal Traffic,low,0.1,TCP,443,512,US,0
```

### Option C: JSON Format
```json
[
  {
    "src_ip": "192.168.1.100",
    "attack_type": "SQL Injection",
    "severity": "high",
    "threat_score": 0.95,
    "protocol": "TCP",
    "port": 80,
    "is_malicious": 1
  }
]
```

---

## 🔐 Security Model

**Relay Server:**
- Hosts 825 MB training data (ExploitDB + global attacks)
- Trains ML models centrally (heavy compute)
- Serves ONLY trained models (280 KB) via API

**Subscribers:**
- Download ONLY pre-trained models (280 KB)
- Use models for inference (fast detection)
- Send detected attacks back to relay
- NO access to raw exploit databases

**Why this matters:**
- Prevents 824 MB ExploitDB download to subscribers
- No exploit databases on customer systems (security risk)
- Minimal bandwidth (280 KB vs 825 MB)
- Fast updates (models only, not entire dataset)

---

## 📊 Training Data Format

### CSV (Recommended for Custom Datasets)
**Required columns:**
- `src_ip`: Source IP address
- `attack_type`: SQL Injection, XSS, Port Scan, DDoS, etc.
- `severity`: low, medium, high, critical
- `threat_score`: Float 0.0-1.0 (higher = more malicious)
- `protocol`: TCP, UDP, ICMP
- `port`: Port number
- `is_malicious`: 1 for attack, 0 for normal traffic

### global_attacks.json (Auto-generated by relay_server.py)
**Format:**
```json
[
  {
    "timestamp": "2024-12-15T10:30:00Z",
    "ip": "192.168.1.100",
    "attack_type": "SQL Injection",
    "threat_score": 0.95,
    "blocked": true,
    "subscriber_id": "node-12345"
  }
]
```

---

## 🚀 Performance

**Training Time:**
- **CPU (scikit-learn):** ~2-5 minutes (50,000 exploits)
- **GPU (TensorFlow/PyTorch):** ~30-60 seconds

**Model Sizes:**
- Total: 280 KB (4 models combined)
- Per subscriber download: 280 KB
- vs. Raw data: 825 MB (2,946x reduction!)

**Update Frequency:**
- Relay trains models every 6 hours
- Subscribers download updated models automatically
- Global attacks logged in real-time

---

## 📝 Logs

**global_attacks.json** - Real attacks from worldwide subscribers
**learned_signatures.json** - Patterns learned from previous training
**malware_hashes.json** - Known malware signatures

These files are automatically updated by:
- `relay_server.py` - Logs attacks to global_attacks.json
- `ai_retraining.py` - Extracts patterns to learned_signatures.json

---

## 🔍 Troubleshooting

**"No training data found"**
- Run `setup_exploitdb.sh` to download ExploitDB
- Or create custom CSV dataset

**"Models not updating"**
- Check `docker logs security-relay-server`
- Verify ai_retraining.py is running every 6 hours

**"Subscribers can't download models"**
- Verify training_sync_api.py is running on port 60002
- Check firewall allows port 60002 TCP

---

**Path:** `/app/relay/ai_training_materials/` (Docker container)  
**Host Path:** `./relay/ai_training_materials/` (Mounted volume)

The system will automatically:
1. Scan this folder for all supported files
2. Load CSV, JSON, and NPY datasets
3. Combine them into training data
4. Train both scikit-learn AND TensorFlow models
5. Use GPU if available, fallback to CPU

## Example Dataset Files

Upload your datasets here:
- `attack_dataset_2024.csv` - Real attack logs from 2024
- `malware_signatures.json` - Known malware patterns
- `ddos_patterns.npy` - DDoS traffic features
- `botnet_traffic.csv` - Botnet communication patterns

## GPU Training

When "Train Using GPU" is clicked:
1. System detects CUDA/ROCm
2. Loads all NPY files (fastest for GPU)
3. Converts CSV/JSON to NPY automatically
4. Trains TensorFlow model on GPU
5. Also trains scikit-learn model on CPU (for comparison)
6. Uses best performing model

## Notes

- Minimum 1000 samples recommended
- Balance malicious (1) and benign (0) samples
- More diverse data = better detection
- GPU training is 10-100x faster than CPU
