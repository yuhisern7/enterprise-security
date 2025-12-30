#!/usr/bin/env python3
"""
ML Model Distribution API for Relay Server
Serves ONLY pre-trained ML models to subscribers (280 KB total)

Subscribers receive:
- Pre-trained models (anomaly_detector.pkl, threat_classifier.pkl, etc.)
- Statistics about relay server training data (for info only)
- NO raw training data (ExploitDB, global_attacks, malware hashes stay on server)

Endpoints:
- GET /models/<model_name> - Download specific pre-trained model
- GET /models/list - List all available models
- GET /stats - Server statistics (training data size, attack count, etc.)
"""

import os
import json
import gzip
from flask import Flask, jsonify, send_file, Response
from flask_cors import CORS
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

TRAINING_MATERIALS_DIR = "ai_training_materials"


@app.route('/models/list', methods=['GET'])
def get_available_models():
    """Get list of available pre-trained ML models (subscribers download these only)"""
    try:
        materials = {
            "last_updated": datetime.utcnow().isoformat(),
            "models_available": {
                "anomaly_detector": {
                    "description": "Unsupervised anomaly detection (zero-day attacks)",
                    "size_kb": 141,
                    "endpoint": "/models/anomaly_detector"
                },
                "threat_classifier": {
                    "description": "Multi-class threat classifier (SQL injection, XSS, etc.)",
                    "size_kb": 127,
                    "endpoint": "/models/threat_classifier"
                },
                "ip_reputation": {
                    "description": "IP reputation scoring (malicious IP detection)",
                    "size_kb": 1,
                    "endpoint": "/models/ip_reputation"
                },
                "feature_scaler": {
                    "description": "Feature normalization for ML models",
                    "size_kb": 1.3,
                    "endpoint": "/models/feature_scaler"
                }
            },
            "total_size_kb": 280,
            "note": "Models trained on 825 MB data (ExploitDB + global attacks + malware hashes)"
        }
        return jsonify(materials)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/stats', methods=['GET'])
def get_training_stats():
    """Get relay server training statistics (info only - subscribers don't download raw data)"""
    try:
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "relay_training_data": {
                "exploitdb_signatures": 46948,
                "global_attacks_logged": get_attack_count(),
                "malware_hashes": get_malware_hash_count(),
                "learned_patterns": 3066,
                "total_size_mb": 825
            },
            "models_available": 4,
            "models_total_size_kb": 280,
            "note": "Subscribers download ONLY pre-trained models (280 KB), NOT raw training data"
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/models/<model_name>', methods=['GET'])
def get_ml_model(model_name):
    """Download specific pre-trained ML model (subscribers download this)"""
    try:
        # Whitelist allowed models
        allowed_models = ["anomaly_detector", "threat_classifier", "ip_reputation", "feature_scaler"]
        if model_name not in allowed_models:
            return jsonify({"error": f"Model {model_name} not found. Available: {allowed_models}"}), 404
        
        model_path = os.path.join(TRAINING_MATERIALS_DIR, "ml_models", f"{model_name}.pkl")
        if os.path.exists(model_path):
            logger.info(f"📤 Serving model: {model_name}.pkl")
            return send_file(model_path, mimetype='application/octet-stream')
        return jsonify({"error": f"Model {model_name} not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def get_attack_count():
    """Get number of attacks in global database"""
    try:
        attacks_path = os.path.join(TRAINING_MATERIALS_DIR, "global_attacks.json")
        if os.path.exists(attacks_path):
            with open(attacks_path, 'r') as f:
                attacks = json.load(f)
                return len(attacks)
        return 0
    except:
        return 0


def get_malware_hash_count():
    """Get number of malware hashes collected"""
    try:
        hashes_path = os.path.join(TRAINING_MATERIALS_DIR, "crawlers", "threat_intelligence_crawled.json")
        if os.path.exists(hashes_path):
            with open(hashes_path, 'r') as f:
                data = json.load(f)
                return data.get("total_items", 0)
        return 0
    except:
        return 0


if __name__ == '__main__':
    # Run on port 60002 (relay WebSocket is on 60001)
    logger.info("🚀 Starting ML Model Distribution API on port 60002")
    logger.info("📦 Serving ONLY pre-trained models (280 KB) - NOT raw training data")
    app.run(host='0.0.0.0', port=60002, debug=False)
