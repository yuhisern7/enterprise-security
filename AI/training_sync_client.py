#!/usr/bin/env python3
"""
Training Materials Sync Client
Downloads AI training materials from relay server for local AI training

Subscribers get access to:
- 46,948 ExploitDB signatures (824 MB)
- 3,066 learned attack patterns (910 KB)
- Global attacks from all subscribers worldwide
- Pre-trained ML models (280 KB)
- Malware hashes from crawlers (100+ hashes daily)
"""

import os
import json
import logging
import requests
import pickle
from datetime import datetime
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TrainingSyncClient:
    """Downloads and syncs AI training materials from relay server"""
    
    def __init__(self, relay_url: str = None):
        """
        Args:
            relay_url: Relay server URL (e.g., http://vps-ip:60002)
        """
        self.relay_url = relay_url or os.getenv('RELAY_URL', 'http://localhost:60002')
        self.local_ml_dir = "AI/ml_models"
        self.local_training_dir = "AI/training_data"
        
        # Create local directories
        os.makedirs(self.local_ml_dir, exist_ok=True)
        os.makedirs(self.local_training_dir, exist_ok=True)
    
    
    def sync_all_materials(self):
        """Download all available training materials"""
        logger.info(f"🔄 Syncing training materials from {self.relay_url}")
        
        # 1. Download learned signatures
        self.download_learned_signatures()
        
        # 2. Download global attacks
        self.download_global_attacks()
        
        # 3. Download malware hashes
        self.download_malware_hashes()
        
        # 4. Download ML models
        self.download_ml_models()
        
        logger.info("✅ Training materials sync complete")
    
    
    def download_learned_signatures(self):
        """Download learned exploit signatures"""
        try:
            response = requests.get(f"{self.relay_url}/training/learned_signatures", timeout=30)
            response.raise_for_status()
            
            signatures = response.json()
            filepath = os.path.join(self.local_training_dir, "learned_signatures.json")
            
            with open(filepath, 'w') as f:
                json.dump(signatures, f, indent=2)
            
            logger.info(f"✅ Downloaded {len(signatures)} learned signatures")
        except Exception as e:
            logger.error(f"❌ Failed to download learned signatures: {e}")
    
    
    def download_global_attacks(self) -> Optional[List[Dict]]:
        """Download global attack database from all subscribers"""
        try:
            response = requests.get(f"{self.relay_url}/training/global_attacks", timeout=30)
            response.raise_for_status()
            
            attacks = response.json()
            if isinstance(attacks, dict):
                attacks = attacks.get("attacks", [])
            
            filepath = os.path.join(self.local_training_dir, "global_attacks.json")
            
            with open(filepath, 'w') as f:
                json.dump(attacks, f, indent=2)
            
            logger.info(f"✅ Downloaded {len(attacks)} global attacks from worldwide subscribers")
            return attacks
        except Exception as e:
            logger.error(f"❌ Failed to download global attacks: {e}")
            return None
    
    
    def download_malware_hashes(self):
        """Download malware hash database from crawlers"""
        try:
            response = requests.get(f"{self.relay_url}/training/malware_hashes", timeout=30)
            response.raise_for_status()
            
            hashes = response.json()
            filepath = os.path.join(self.local_training_dir, "malware_hashes.json")
            
            with open(filepath, 'w') as f:
                json.dump(hashes, f, indent=2)
            
            total_hashes = hashes.get("total_items", 0)
            logger.info(f"✅ Downloaded {total_hashes} malware hashes from crawlers")
        except Exception as e:
            logger.error(f"❌ Failed to download malware hashes: {e}")
    
    
    def download_ml_models(self):
        """Download pre-trained ML models"""
        models = ["anomaly_detector", "threat_classifier", "ip_reputation", "feature_scaler"]
        
        for model_name in models:
            try:
                response = requests.get(
                    f"{self.relay_url}/training/ml_models/{model_name}",
                    timeout=30
                )
                response.raise_for_status()
                
                filepath = os.path.join(self.local_ml_dir, f"{model_name}.pkl")
                
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                
                logger.info(f"✅ Downloaded {model_name}.pkl ({len(response.content)} bytes)")
            except Exception as e:
                logger.warning(f"⚠️ Failed to download {model_name}: {e}")
    
    
    def get_training_stats(self) -> Optional[Dict]:
        """Get statistics about available training materials"""
        try:
            response = requests.get(f"{self.relay_url}/training/stats", timeout=10)
            response.raise_for_status()
            
            stats = response.json()
            logger.info(f"📊 Training materials available:")
            logger.info(f"   • {stats.get('exploitdb_signatures', 0):,} ExploitDB signatures")
            logger.info(f"   • {stats.get('learned_patterns', 0):,} learned attack patterns")
            logger.info(f"   • {stats.get('global_attacks_logged', 0):,} worldwide attacks")
            logger.info(f"   • {stats.get('malware_hashes', 0):,} malware hashes")
            logger.info(f"   • {stats.get('ml_models_available', 0)} ML models")
            
            return stats
        except Exception as e:
            logger.error(f"❌ Failed to get training stats: {e}")
            return None
    
    
    def load_local_training_data(self) -> Dict:
        """Load all downloaded training materials for AI training"""
        training_data = {
            "learned_signatures": [],
            "global_attacks": [],
            "malware_hashes": [],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Load learned signatures
        sig_path = os.path.join(self.local_training_dir, "learned_signatures.json")
        if os.path.exists(sig_path):
            with open(sig_path, 'r') as f:
                training_data["learned_signatures"] = json.load(f)
        
        # Load global attacks
        attacks_path = os.path.join(self.local_training_dir, "global_attacks.json")
        if os.path.exists(attacks_path):
            with open(attacks_path, 'r') as f:
                training_data["global_attacks"] = json.load(f)
        
        # Load malware hashes
        hashes_path = os.path.join(self.local_training_dir, "malware_hashes.json")
        if os.path.exists(hashes_path):
            with open(hashes_path, 'r') as f:
                training_data["malware_hashes"] = json.load(f)
        
        total_items = (
            len(training_data["learned_signatures"]) +
            len(training_data["global_attacks"]) +
            training_data["malware_hashes"].get("total_items", 0)
        )
        
        logger.info(f"📚 Loaded {total_items:,} training items from local storage")
        return training_data


def main():
    """Test training sync"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Sync AI training materials from relay server')
    parser.add_argument('--relay-url', help='Relay server URL (e.g., http://vps-ip:60002)')
    parser.add_argument('--stats-only', action='store_true', help='Only show statistics')
    
    args = parser.parse_args()
    
    client = TrainingSyncClient(relay_url=args.relay_url)
    
    if args.stats_only:
        client.get_training_stats()
    else:
        # Full sync
        client.get_training_stats()
        client.sync_all_materials()
        
        # Load and display
        data = client.load_local_training_data()
        logger.info(f"\n📈 Training data ready:")
        logger.info(f"   • {len(data['learned_signatures']):,} signatures")
        logger.info(f"   • {len(data['global_attacks']):,} global attacks")
        logger.info(f"   • {data['malware_hashes'].get('total_items', 0):,} malware hashes")


if __name__ == '__main__':
    main()
