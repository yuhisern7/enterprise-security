#!/usr/bin/env python3
"""
Training Materials Sync API for Relay Server
Allows subscribers to download AI training materials without local storage

Endpoints:
- GET /training/exploitdb - Download ExploitDB signatures
- GET /training/ml_models - Download pre-trained models
- GET /training/learned_signatures - Download attack patterns
- GET /training/global_attacks - Download worldwide attack database
- GET /training/sync - Get list of all available materials
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


@app.route('/training/sync', methods=['GET'])
def get_available_materials():
    """Get list of all available training materials"""
    try:
        materials = {
            "last_updated": datetime.utcnow().isoformat(),
            "available": {
                "exploitdb": {
                    "exploits_count": 46948,
                    "size_mb": 824,
                    "endpoint": "/training/exploitdb"
                },
                "learned_signatures": {
                    "patterns_count": 3066,
                    "size_kb": 910,
                    "endpoint": "/training/learned_signatures"
                },
                "ml_models": {
                    "models": ["anomaly_detector", "threat_classifier", "ip_reputation", "feature_scaler"],
                    "size_kb": 280,
                    "endpoint": "/training/ml_models"
                },
                "global_attacks": {
                    "attacks_logged": get_attack_count(),
                    "endpoint": "/training/global_attacks"
                },
                "malware_hashes": {
                    "hashes_count": get_malware_hash_count(),
                    "endpoint": "/training/malware_hashes"
                }
            }
        }
        return jsonify(materials)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/training/learned_signatures', methods=['GET'])
def get_learned_signatures():
    """Download learned exploit signatures"""
    try:
        sig_path = os.path.join(TRAINING_MATERIALS_DIR, "learned_signatures.json")
        if os.path.exists(sig_path):
            return send_file(sig_path, mimetype='application/json')
        return jsonify({"error": "Signatures not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/training/global_attacks', methods=['GET'])
def get_global_attacks():
    """Download global attack database"""
    try:
        attacks_path = os.path.join(TRAINING_MATERIALS_DIR, "global_attacks.json")
        if os.path.exists(attacks_path):
            return send_file(attacks_path, mimetype='application/json')
        return jsonify({"attacks": [], "total": 0})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/training/ml_models/<model_name>', methods=['GET'])
def get_ml_model(model_name):
    """Download specific ML model"""
    try:
        model_path = os.path.join(TRAINING_MATERIALS_DIR, "ml_models", f"{model_name}.pkl")
        if os.path.exists(model_path):
            return send_file(model_path, mimetype='application/octet-stream')
        return jsonify({"error": f"Model {model_name} not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/training/malware_hashes', methods=['GET'])
def get_malware_hashes():
    """Download malware hash database from crawlers"""
    try:
        hashes_path = os.path.join(TRAINING_MATERIALS_DIR, "crawlers", "threat_intelligence_crawled.json")
        if os.path.exists(hashes_path):
            return send_file(hashes_path, mimetype='application/json')
        return jsonify({"error": "Malware hashes not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/training/exploitdb/summary', methods=['GET'])
def get_exploitdb_summary():
    """Get ExploitDB statistics without downloading full database"""
    try:
        csv_path = os.path.join(TRAINING_MATERIALS_DIR, "exploitdb", "files_exploits.csv")
        if not os.path.exists(csv_path):
            return jsonify({"error": "ExploitDB not found"}), 404
        
        # Count lines in CSV
        with open(csv_path, 'r') as f:
            exploit_count = sum(1 for _ in f) - 1  # Subtract header
        
        return jsonify({
            "exploits_available": exploit_count,
            "source": "local_database",
            "last_updated": datetime.fromtimestamp(os.path.getmtime(csv_path)).isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/training/stats', methods=['GET'])
def get_training_stats():
    """Get comprehensive training materials statistics"""
    try:
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "exploitdb_signatures": 46948,
            "learned_patterns": 3066,
            "global_attacks_logged": get_attack_count(),
            "malware_hashes": get_malware_hash_count(),
            "ml_models_available": 4,
            "total_size_mb": 825
        }
        return jsonify(stats)
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
    app.run(host='0.0.0.0', port=60002, debug=False)
