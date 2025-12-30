# AI Training Materials Folder

This folder contains curated datasets for training the AI/ML security models.

## Supported Formats

### 1. CSV Format (Recommended)
**File naming:** `attack_dataset_*.csv`

**Required columns:**
```csv
src_ip,attack_type,severity,threat_score,protocol,port,payload_size,country,is_malicious
192.168.1.100,SQL Injection,high,0.95,TCP,80,1024,US,1
10.0.0.50,Port Scan,medium,0.75,TCP,22,64,CN,1
172.16.0.10,Normal Traffic,low,0.1,TCP,443,512,US,0
```

**Column descriptions:**
- `src_ip`: Source IP address
- `attack_type`: Type of attack (SQL Injection, XSS, Port Scan, DDoS, etc.)
- `severity`: low, medium, high, critical
- `threat_score`: Float 0.0-1.0 (higher = more malicious)
- `protocol`: TCP, UDP, ICMP
- `port`: Port number
- `payload_size`: Size in bytes
- `country`: Country code (US, CN, RU, etc.)
- `is_malicious`: 1 for attack, 0 for normal traffic

### 2. JSON Format
**File naming:** `attack_dataset_*.json`

```json
[
  {
    "src_ip": "192.168.1.100",
    "attack_type": "SQL Injection",
    "severity": "high",
    "threat_score": 0.95,
    "protocol": "TCP",
    "port": 80,
    "payload_size": 1024,
    "country": "US",
    "is_malicious": 1
  },
  {
    "src_ip": "10.0.0.50",
    "attack_type": "Normal Traffic",
    "severity": "low",
    "threat_score": 0.1,
    "protocol": "TCP",
    "port": 443,
    "payload_size": 512,
    "country": "US",
    "is_malicious": 0
  }
]
```

### 3. NPY Format (NumPy Arrays for GPU Training)
**File naming:** `attack_features_*.npy` and `attack_labels_*.npy`

For TensorFlow/PyTorch GPU training, we use NumPy arrays:
- `attack_features_*.npy`: Feature matrix (N samples × M features)
- `attack_labels_*.npy`: Labels (N samples)

**Example generation:**
```python
import numpy as np

# Features: [threat_score, port, payload_size, is_tcp, is_udp, ...]
features = np.array([
    [0.95, 80, 1024, 1, 0],
    [0.75, 22, 64, 1, 0],
    [0.1, 443, 512, 1, 0]
])

# Labels: 1=malicious, 0=benign
labels = np.array([1, 1, 0])

np.save('attack_features_001.npy', features)
np.save('attack_labels_001.npy', labels)
```

## Training Process

### scikit-learn (CPU/Small datasets)
- Uses: CSV/JSON files
- Model: RandomForest, SVM, LogisticRegression
- Best for: Quick training, small datasets (<100K samples)

### TensorFlow/PyTorch (GPU/Large datasets)
- Uses: NPY files (for speed) or CSV (for flexibility)
- Model: Neural Networks, Deep Learning
- Best for: Large datasets (>100K samples), complex patterns
- Requires: GPU (CUDA/ROCm) for speed

## Folder Location

**Path:** `AI/exploitdb/ai_training_materials/`

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
