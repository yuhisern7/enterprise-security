#!/usr/bin/env python3
"""
Relay Server AI Retraining Module
Trains ML models centrally on relay server using local training materials

Features:
- Loads training data from LOCAL ai_training_materials/ folder (no downloading)
- Retrains models with ExploitDB + global attacks + malware hashes
- Runs periodically (every 6 hours)
- Saves trained models to ai_training_materials/ml_models/
- Subscribers download ONLY these trained models (280 KB)
"""

import os
import json
import logging
import time
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import threading

# Import main AI module for training
try:
    # In relay server context, we need to import pcs_ai from correct path
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from AI import pcs_ai
    from AI.pcs_ai import _train_ml_models_from_history, _save_ml_models
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    logging.warning("pcs_ai module not available - retraining disabled")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class RelayAITrainer:
    """Manages AI training on relay server using LOCAL training materials"""
    
    def __init__(self):
        self.last_retrain_time = None
        self.retrain_interval = timedelta(hours=6)  # Retrain every 6 hours
        self.training_materials_dir = "ai_training_materials"
        self.last_attack_count = 0
        self.running = False
        self.retrain_thread = None
    
    
    def start_auto_retrain(self):
        """Start background thread for automatic retraining"""
        if self.running:
            logger.warning("Auto-retrain already running")
            return
        
        self.running = True
        self.retrain_thread = threading.Thread(target=self._retrain_loop, daemon=True)
        self.retrain_thread.start()
        logger.info("🤖 AI auto-retrain started (runs every 6 hours)")
    
    
    def stop_auto_retrain(self):
        """Stop automatic retraining"""
        self.running = False
        if self.retrain_thread:
            self.retrain_thread.join(timeout=5)
        logger.info("🛑 AI auto-retrain stopped")
    
    
    def _retrain_loop(self):
        """Background loop for automatic retraining"""
        while self.running:
            try:
                # Check if it's time to retrain
                if self._should_retrain():
                    logger.info("⏰ Scheduled retrain time reached")
                    self.retrain_with_global_attacks()
                
                # Sleep for 30 minutes, wake up to check again
                time.sleep(1800)
            except Exception as e:
                logger.error(f"❌ Error in retrain loop: {e}")
                time.sleep(300)  # Sleep 5 minutes on error
    
    
    def _should_retrain(self) -> bool:
        """Check if model should be retrained"""
        if not self.last_retrain_time:
            return True
        
        time_since_last = datetime.utcnow() - self.last_retrain_time
        return time_since_last >= self.retrain_interval
    
    
    def retrain_with_local_data(self, force: bool = False) -> bool:
        """
        Retrain AI models with LOCAL training materials on relay server
        
        Args:
            force: Force retraining even if not scheduled
        
        Returns:
            True if retraining was successful
        """
        if not AI_AVAILABLE:
            logger.error("❌ AI module not available - cannot retrain")
            return False
        
        if not force and not self._should_retrain():
            logger.info("⏭️ Skipping retrain (not scheduled yet)")
            return False
        
        try:
            logger.info("🔄 Starting relay server AI retrain with local training materials...")
            
            # Step 1: Load training data from LOCAL ai_training_materials/ folder
            logger.info("📥 Loading training materials from local storage...")
            training_data = self._load_local_training_materials()
            
            global_attacks = training_data.get("global_attacks", [])
            learned_signatures = training_data.get("learned_signatures", [])
            exploitdb_count = training_data.get("exploitdb_count", 0)
            
            if not global_attacks:
                logger.warning("⚠️ No global attacks logged yet")
            
            logger.info(f"📚 Loaded training data:")
            logger.info(f"   • {exploitdb_count:,} ExploitDB exploit signatures")
            logger.info(f"   • {len(global_attacks):,} global attacks from worldwide subscribers")
            logger.info(f"   • {len(learned_signatures):,} learned attack patterns")
            
            # Step 2: Merge global attacks into pcs_ai threat log
            new_attacks_added = self._merge_attacks_into_threat_log(global_attacks)
            
            if new_attacks_added == 0 and not force:
                logger.info("✅ No new attacks to train on (already trained)")
                return False
            
            logger.info(f"➕ Added {new_attacks_added} new attacks to training dataset")
            
            # Step 3: Retrain ML models
            logger.info("🧠 Retraining ML models with combined training data...")
            
            # Call pcs_ai's training function
            _train_ml_models_from_history()
            _save_ml_models()
            
            # Step 4: Copy trained models to ai_training_materials/ml_models/ for distribution
            self._copy_models_to_distribution()
            
            # Update tracking
            self.last_retrain_time = datetime.utcnow()
            self.last_attack_count = len(pcs_ai._threat_log)
            
            logger.info(f"✅ Relay AI retrain complete! Models trained on {self.last_attack_count:,} attacks")
            logger.info(f"⏰ Next scheduled retrain: {(self.last_retrain_time + self.retrain_interval).strftime('%Y-%m-%d %H:%M')} UTC")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Relay AI retrain failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    
    def _load_local_training_materials(self) -> Dict:
        """Load training materials from LOCAL ai_training_materials/ folder (no downloading)"""
        training_data = {
            "global_attacks": [],
            "learned_signatures": [],
            "exploitdb_count": 0
        }
        
        # Load global attacks
        attacks_path = os.path.join(self.training_materials_dir, "global_attacks.json")
        if os.path.exists(attacks_path):
            with open(attacks_path, 'r') as f:
                training_data["global_attacks"] = json.load(f)
        
        # Load learned signatures
        sig_path = os.path.join(self.training_materials_dir, "ai_signatures", "learned_signatures.json")
        if os.path.exists(sig_path):
            with open(sig_path, 'r') as f:
                training_data["learned_signatures"] = json.load(f)
        
        # Count ExploitDB exploits
        exploitdb_csv = os.path.join(self.training_materials_dir, "exploitdb", "files_exploits.csv")
        if os.path.exists(exploitdb_csv):
            with open(exploitdb_csv, 'r') as f:
                training_data["exploitdb_count"] = sum(1 for _ in f) - 1  # Subtract header
        
        return training_data
    
    
    def _copy_models_to_distribution(self):
        """Copy trained ML models to ai_training_materials/ml_models/ for distribution to subscribers"""
        source_dir = "ml_models"  # Where pcs_ai saves models
        dest_dir = os.path.join(self.training_materials_dir, "ml_models")
        
        os.makedirs(dest_dir, exist_ok=True)
        
        models = [
            "anomaly_detector.pkl",
            "threat_classifier.pkl", 
            "ip_reputation.pkl",
            "feature_scaler.pkl"
        ]
        
        for model_file in models:
            src_path = os.path.join(source_dir, model_file)
            dest_path = os.path.join(dest_dir, model_file)
            
            if os.path.exists(src_path):
                shutil.copy2(src_path, dest_path)
                logger.info(f"📦 Copied {model_file} to distribution folder")
            else:
                logger.warning(f"⚠️ Model not found: {src_path}")
    
    
    def _merge_attacks_into_threat_log(self, global_attacks: List[Dict]) -> int:
        """
        Merge global attacks into pcs_ai threat log (avoiding duplicates)
        
        Returns:
            Number of new attacks added
        """
        if not global_attacks:
            return 0
        
        # Get existing threat log
        existing_log = pcs_ai._threat_log
        
        # Create set of existing attack fingerprints to avoid duplicates
        existing_fingerprints = set()
        for threat in existing_log:
            # Create unique fingerprint: IP + timestamp + attack_type
            fingerprint = f"{threat.get('ip', '')}_{threat.get('timestamp', '')}_{threat.get('threat_type', '')}"
            existing_fingerprints.add(fingerprint)
        
        # Add new attacks
        new_attacks = 0
        for attack in global_attacks:
            # Create fingerprint for this global attack
            fingerprint = f"{attack.get('ip', '')}_{attack.get('timestamp', '')}_{attack.get('attack_type', '')}"
            
            if fingerprint not in existing_fingerprints:
                # Convert global attack format to threat log format
                threat_entry = {
                    "ip": attack.get("ip", "unknown"),
                    "timestamp": attack.get("timestamp", datetime.utcnow().isoformat()),
                    "threat_type": attack.get("attack_type", "unknown"),
                    "level": attack.get("level", "medium"),
                    "endpoint": attack.get("endpoint", "/"),
                    "user_agent": attack.get("user_agent", "unknown"),
                    "geolocation": attack.get("geolocation", {}),
                    "source": "global_relay",  # Mark as global attack
                    "relay_server": attack.get("relay_server", "central-relay")
                }
                
                pcs_ai._threat_log.append(threat_entry)
                existing_fingerprints.add(fingerprint)
                new_attacks += 1
        
        # Save updated threat log
        if new_attacks > 0:
            pcs_ai._save_threat_log()
            logger.info(f"💾 Saved {new_attacks} new global attacks to local threat log")
        
        return new_attacks
    
    
    def get_retrain_status(self) -> Dict:
        """Get current retraining status"""
        return {
            "auto_retrain_running": self.running,
            "last_retrain_time": self.last_retrain_time.isoformat() if self.last_retrain_time else None,
            "next_retrain_time": (self.last_retrain_time + self.retrain_interval).isoformat() 
                if self.last_retrain_time else "Not scheduled yet",
            "total_attacks_in_model": self.last_attack_count,
            "retrain_interval_hours": self.retrain_interval.total_seconds() / 3600
        }


# Global instance
_retrain_manager = None


def get_retrain_manager(relay_url: str = None) -> AIRetrainingManager:
    """Get singleton retrain manager instance"""
    global _retrain_manager
    if _retrain_manager is None:
        _retrain_manager = AIRetrainingManager(relay_url=relay_url)
    return _retrain_manager


def start_auto_retrain(relay_url: str = None):
    """Start automatic AI retraining"""
    manager = get_retrain_manager(relay_url=relay_url)
    manager.start_auto_retrain()


def force_retrain_now(relay_url: str = None) -> bool:
    """Force immediate retrain with global attacks"""
    manager = get_retrain_manager(relay_url=relay_url)
    return manager.retrain_with_global_attacks(force=True)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='AI Retraining Manager')
    parser.add_argument('--relay-url', help='Relay server URL (e.g., http://vps-ip:60002)')
    parser.add_argument('--once', action='store_true', help='Run retrain once and exit')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon (auto-retrain every 6 hours)')
    
    args = parser.parse_args()
    
    if args.once:
        # One-time retrain
        success = force_retrain_now(relay_url=args.relay_url)
        exit(0 if success else 1)
    elif args.daemon:
        # Run as daemon
        start_auto_retrain(relay_url=args.relay_url)
        logger.info("🤖 AI retrain daemon started. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("⏹️ Stopping...")
    else:
        # Show status
        manager = get_retrain_manager(relay_url=args.relay_url)
        status = manager.get_retrain_status()
        print("\n📊 AI Retraining Status:")
        print(f"   • Auto-retrain running: {status['auto_retrain_running']}")
        print(f"   • Last retrain: {status['last_retrain_time'] or 'Never'}")
        print(f"   • Next retrain: {status['next_retrain_time']}")
        print(f"   • Total attacks in model: {status['total_attacks_in_model']:,}")
        print(f"   • Retrain interval: Every {status['retrain_interval_hours']} hours")
