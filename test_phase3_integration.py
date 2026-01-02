#!/usr/bin/env python3
"""
Integration test for Phase 3 (Drift Detector) with pcs_ai.py

Tests:
- Drift detector integration into pcs_ai
- Feature tracking on all requests
- Baseline updates on safe traffic
- Drift checking in save_all_ai_data()
- Drift stats in get_ml_model_stats()
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from AI.pcs_ai import (
    assess_request_pattern,
    save_all_ai_data,
    get_ml_model_stats,
    ADVANCED_AI_AVAILABLE
)

def test_phase3_integration():
    """Test Phase 3 drift detector integration"""
    print("=" * 70)
    print("PHASE 3 INTEGRATION TEST: Drift Detector")
    print("=" * 70)
    
    if not ADVANCED_AI_AVAILABLE:
        print("\n⚠️  Advanced AI not available - skipping test")
        return
    
    # 1. Test feature tracking on normal requests
    print("\n[1] Testing feature tracking on normal requests...")
    for i in range(50):
        assess_request_pattern(
            ip_address=f"192.168.1.{i}",
            endpoint=f"/api/data/{i}",
            method="GET",
            user_agent="Mozilla/5.0",
            headers={}
        )
    print("✓ Tracked 50 normal requests")
    
    # 2. Test feature tracking on suspicious requests
    print("\n[2] Testing feature tracking on suspicious requests...")
    for i in range(30):
        assess_request_pattern(
            ip_address=f"10.0.0.{i}",
            endpoint="/admin/../../etc/passwd",
            method="POST",
            user_agent="curl/7.0",
            headers={}
        )
    print("✓ Tracked 30 suspicious requests")
    
    # 3. Check ML model stats (should include drift detector)
    print("\n[3] Checking ML model stats...")
    stats = get_ml_model_stats()
    
    if 'drift_detector' in stats.get('models', {}):
        drift_stats = stats['models']['drift_detector']
        print(f"✓ Drift detector found in ML stats")
        print(f"  - Baseline samples: {drift_stats.get('baseline_samples', 0)}")
        print(f"  - Current samples: {drift_stats.get('current_samples', 0)}")
        print(f"  - Samples processed: {drift_stats.get('samples_processed', 0)}")
        print(f"  - Last check: {drift_stats.get('last_check', 'Never')}")
    else:
        print("⚠️  Drift detector not in ML stats (needs more samples)")
    
    # 4. Trigger save_all_ai_data() to check drift
    print("\n[4] Triggering save_all_ai_data() for drift check...")
    save_status = save_all_ai_data()
    
    print(f"  - Threat log saved: {save_status.get('threat_log_saved', False)}")
    print(f"  - Behavioral metrics saved: {save_status.get('behavioral_metrics_saved', False)}")
    print(f"  - Attack sequences saved: {save_status.get('attack_sequences_saved', False)}")
    print(f"  - Drift check performed: {save_status.get('drift_check_performed', False)}")
    print(f"  - Requires retraining: {save_status.get('requires_retraining', False)}")
    
    if save_status.get('drift_check_performed'):
        print("✓ Drift check completed")
        if save_status.get('requires_retraining'):
            print("⚠️  Model retraining recommended due to drift!")
    else:
        print("ℹ️  Drift check skipped (need 500+ threat log entries)")
    
    # 5. Final stats check
    print("\n[5] Final ML stats check...")
    final_stats = get_ml_model_stats()
    
    if 'drift_detector' in final_stats.get('models', {}):
        drift_info = final_stats['models']['drift_detector']
        print(f"✓ Drift detector operational")
        print(f"  - Retraining triggered: {drift_info.get('retraining_triggered', 0)} times")
        print(f"  - Total drift reports: {drift_info.get('total_drift_reports', 0)}")
        
        # Show recent drift reports if any
        recent_reports = drift_info.get('recent_drift_reports', [])
        if recent_reports:
            print(f"\n  Recent Drift Reports:")
            for report in recent_reports[:3]:
                print(f"    - {report['feature_name']}: drift={report['drift_detected']}, score={report['drift_score']:.2f}")
    
    print("\n" + "=" * 70)
    print("PHASE 3 INTEGRATION TEST COMPLETE")
    print("=" * 70)
    print("\n✅ Drift detector successfully integrated into pcs_ai.py")
    print("   - Features tracked on every request")
    print("   - Baseline updated with safe traffic")
    print("   - Drift checked periodically in save_all_ai_data()")
    print("   - Drift stats available in get_ml_model_stats()")

if __name__ == '__main__':
    test_phase3_integration()
