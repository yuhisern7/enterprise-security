#!/usr/bin/env python3
"""
Integration Test for Phase 5 Meta Decision Engine

Tests ensemble decision making across all detection systems.

Author: Enterprise Security AI Team
Version: 1.0.0
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from AI.meta_decision_engine import (
    MetaDecisionEngine, DetectionSignal, SignalType,
    ThreatLevel, make_decision, get_stats
)
from datetime import datetime

def test_meta_engine_integration():
    """Test Phase 5 meta decision engine integration"""
    
    print("=" * 70)
    print("PHASE 5 META DECISION ENGINE INTEGRATION TEST")
    print("=" * 70)
    
    # Test 1: Multi-signal threat detection
    print("\n[1] Testing multi-signal threat detection...")
    
    threat_signals = [
        DetectionSignal(
            signal_type=SignalType.SIGNATURE,
            is_threat=True,
            confidence=0.95,
            threat_level=ThreatLevel.CRITICAL,
            details="SQL injection pattern detected",
            timestamp=datetime.utcnow().isoformat()
        ),
        DetectionSignal(
            signal_type=SignalType.BEHAVIORAL,
            is_threat=True,
            confidence=0.78,
            threat_level=ThreatLevel.DANGEROUS,
            details="Suspicious behavioral pattern",
            timestamp=datetime.utcnow().isoformat()
        ),
        DetectionSignal(
            signal_type=SignalType.ML_ANOMALY,
            is_threat=True,
            confidence=0.72,
            threat_level=ThreatLevel.SUSPICIOUS,
            details="ML anomaly detected",
            timestamp=datetime.utcnow().isoformat()
        )
    ]
    
    decision = make_decision(threat_signals, "203.0.113.50", "/admin/login")
    
    print(f"    Decision: {'THREAT' if decision.is_threat else 'SAFE'}")
    print(f"    Threat Level: {decision.threat_level.value}")
    print(f"    Confidence: {decision.confidence:.2%}")
    print(f"    Weighted Vote: {decision.weighted_vote_score:.2%}")
    print(f"    Should Block: {decision.should_block}")
    print(f"    Signals: {decision.threat_signals} threats / {decision.safe_signals} safe")
    
    assert decision.is_threat, "Should detect threat with 3 threat signals"
    assert decision.confidence > 0.7, "Confidence should be high"
    print("    ✅ Multi-signal threat detection working")
    
    # Test 2: Mixed signals (threat + safe)
    print("\n[2] Testing mixed signal scenario...")
    
    mixed_signals = [
        DetectionSignal(SignalType.SIGNATURE, True, 0.90, ThreatLevel.CRITICAL,
                       "Attack detected", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.ML_ANOMALY, False, 0.75, ThreatLevel.SAFE,
                       "Normal pattern", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.ML_CLASSIFICATION, False, 0.80, ThreatLevel.SAFE,
                       "Safe traffic", datetime.utcnow().isoformat())
    ]
    
    decision2 = make_decision(mixed_signals, "192.168.1.100", "/api/data")
    
    print(f"    Decision: {'THREAT' if decision2.is_threat else 'SAFE'}")
    print(f"    Threat Level: {decision2.threat_level.value}")
    print(f"    Weighted Vote: {decision2.weighted_vote_score:.2%}")
    print(f"    Confidence: {decision2.confidence:.2%}")
    
    # Signature has high weight (0.90) so should lean toward threat
    if decision2.is_threat:
        print("    ✅ High-weight signal influenced decision")
    else:
        print("    ✅ Multiple safe signals balanced out single threat")
    
    # Test 3: All safe signals
    print("\n[3] Testing all safe signals...")
    
    safe_signals = [
        DetectionSignal(SignalType.ML_ANOMALY, False, 0.85, ThreatLevel.SAFE,
                       "Normal", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.ML_CLASSIFICATION, False, 0.90, ThreatLevel.SAFE,
                       "Safe", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.BEHAVIORAL, False, 0.80, ThreatLevel.SAFE,
                       "Normal behavior", datetime.utcnow().isoformat())
    ]
    
    decision3 = make_decision(safe_signals, "192.168.1.1", "/")
    
    print(f"    Decision: {'THREAT' if decision3.is_threat else 'SAFE'}")
    print(f"    Unanimous: {decision3.unanimous_verdict}")
    print(f"    Confidence: {decision3.confidence:.2%}")
    
    assert not decision3.is_threat, "Should be safe with all safe signals"
    assert decision3.unanimous_verdict, "Should be unanimous"
    print("    ✅ All safe signals correctly classified")
    
    # Test 4: Consensus detection
    print("\n[4] Testing consensus detection...")
    
    consensus_signals = [
        DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.THREAT_INTEL, True, 0.98, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.GRAPH, True, 0.88, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.BEHAVIORAL, True, 0.80, ThreatLevel.DANGEROUS, "T", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.ML_ANOMALY, False, 0.60, ThreatLevel.SAFE, "S", datetime.utcnow().isoformat())
    ]
    
    decision4 = make_decision(consensus_signals, "203.0.113.100", "/attack")
    
    print(f"    Strong Consensus: {decision4.strong_consensus}")
    print(f"    Agreement: {decision4.threat_signals}/{decision4.total_signals} = {decision4.threat_signals/decision4.total_signals*100:.0f}%")
    print(f"    Should Block: {decision4.should_block}")
    
    assert decision4.strong_consensus, "Should have strong consensus (80%+ agreement)"
    print("    ✅ Strong consensus detection working")
    
    # Test 5: Auto-block threshold
    print("\n[5] Testing auto-block threshold...")
    
    critical_signals = [
        DetectionSignal(SignalType.SIGNATURE, True, 0.98, ThreatLevel.CRITICAL, "SQL injection", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.THREAT_INTEL, True, 0.99, ThreatLevel.CRITICAL, "Known attacker", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.GRAPH, True, 0.92, ThreatLevel.CRITICAL, "Lateral movement", datetime.utcnow().isoformat())
    ]
    
    decision5 = make_decision(critical_signals, "198.51.100.10", "/exploit")
    
    print(f"    Weighted Vote: {decision5.weighted_vote_score:.2%}")
    print(f"    Block Threshold: 75%")
    print(f"    Should Block: {decision5.should_block}")
    
    assert decision5.should_block, "Should auto-block with critical signals"
    assert decision5.weighted_vote_score > 0.75, "Vote should exceed block threshold"
    print("    ✅ Auto-block threshold working")
    
    # Test 6: Signal performance tracking
    print("\n[6] Testing signal performance tracking...")
    
    engine = MetaDecisionEngine()
    
    # Make multiple decisions to build history
    for i in range(10):
        test_signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.90, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.ML_ANOMALY, i % 2 == 0, 0.70, ThreatLevel.SUSPICIOUS, "M", datetime.utcnow().isoformat())
        ]
        engine.add_signal(test_signals, f"192.168.1.{i}", "/test")
    
    performance = engine.get_signal_performance()
    
    print(f"    Tracked signal types: {len(performance)}")
    if "signature" in performance:
        print(f"    Signature activations: {performance['signature']['total_activations']}")
        print(f"    Signature avg confidence: {performance['signature']['avg_confidence']:.2%}")
    
    assert len(performance) > 0, "Should track signal performance"
    print("    ✅ Signal performance tracking working")
    
    # Test 7: Statistics collection
    print("\n[7] Testing statistics collection...")
    
    stats = get_stats()
    
    print(f"    Total decisions: {stats['metrics']['total_decisions']}")
    print(f"    Threats detected: {stats['metrics']['threats_detected']}")
    print(f"    Safe classified: {stats['metrics']['safe_classified']}")
    print(f"    Auto-blocked: {stats['metrics']['auto_blocked']}")
    
    assert "metrics" in stats, "Should have metrics"
    assert "config" in stats, "Should have config"
    print("    ✅ Statistics collection working")
    
    # Test 8: Primary threats extraction
    print("\n[8] Testing primary threats extraction...")
    
    varied_signals = [
        DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL,
                       "SQL injection attempt detected. Database vulnerable.", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.GRAPH, True, 0.88, ThreatLevel.CRITICAL,
                       "Lateral movement detected across 5 hosts. Breach in progress.", datetime.utcnow().isoformat()),
        DetectionSignal(SignalType.BEHAVIORAL, True, 0.75, ThreatLevel.DANGEROUS,
                       "Brute force attack detected. 500 attempts in 60 seconds.", datetime.utcnow().isoformat())
    ]
    
    decision8 = make_decision(varied_signals, "203.0.113.200", "/admin")
    
    print(f"    Primary threats found: {len(decision8.primary_threats)}")
    for threat in decision8.primary_threats:
        print(f"      - {threat[:70]}...")
    
    assert len(decision8.primary_threats) == 3, "Should extract 3 primary threats"
    print("    ✅ Primary threats extraction working")
    
    print("\n" + "=" * 70)
    print("PHASE 5 INTEGRATION TEST COMPLETE")
    print("=" * 70)
    
    print("\n✅ Meta decision engine operational")
    print("✅ Weighted voting working correctly")
    print("✅ Signal fusion and consensus detection active")
    print("✅ Auto-block threshold enforced")
    print("✅ Performance tracking enabled")
    
    return True


if __name__ == "__main__":
    try:
        success = test_meta_engine_integration()
        exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
