#!/usr/bin/env python3
"""
Demo: Layers 19-20 Integration

Shows how Causal Inference Engine (Layer 19) and Trust Degradation Graph (Layer 20)
integrate with the existing detection pipeline and meta decision engine.

Usage:
    python demo_layers_19_20.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timezone
from AI.causal_inference import CausalInferenceEngine, CausalLabel
from AI.trust_graph import TrustDegradationGraph, EntityType, TrustAction
from AI.meta_decision_engine import MetaDecisionEngine, DetectionSignal, SignalType, ThreatLevel

print("=" * 80)
print("Battle-Hardened AI - Layers 19-20 Integration Demo")
print("=" * 80)
print()

# Initialize engines
print("[1] Initializing engines...")
causal_engine = CausalInferenceEngine(json_dir="server/json")
trust_graph = TrustDegradationGraph(json_dir="server/json")
meta_engine = MetaDecisionEngine()
print("✅ All engines initialized")
print()

# Scenario 1: Legitimate deployment causing anomaly
print("-" * 80)
print("SCENARIO 1: Legitimate Deployment Causing Anomaly")
print("-" * 80)

# Simulate deployment event
deployment = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "service": "payment-api",
    "automated": True
}

# Simulate primary detection signals (1-18) detecting anomaly
event = {
    "src_ip": "10.0.1.50",
    "dst_ip": "10.0.2.100",
    "protocol": "TCP",
    "timestamp": datetime.now(timezone.utc).isoformat()
}

primary_signals = [
    DetectionSignal(
        signal_type=SignalType.BEHAVIORAL,
        is_threat=True,
        confidence=0.72,
        threat_level=ThreatLevel.SUSPICIOUS,
        details="Unusual connection pattern detected",
        timestamp=datetime.now(timezone.utc).isoformat()
    ),
    DetectionSignal(
        signal_type=SignalType.ML_ANOMALY,
        is_threat=True,
        confidence=0.68,
        threat_level=ThreatLevel.SUSPICIOUS,
        details="Traffic pattern anomaly",
        timestamp=datetime.now(timezone.utc).isoformat()
    )
]

# Layer 19: Causal inference analysis
print("\n[Layer 19] Running causal inference...")
causal_result = causal_engine.analyze_root_cause(
    signals=primary_signals,
    event=event,
    deployments=[deployment]
)

print(f"  Causal Label: {causal_result.causal_label.value}")
print(f"  Confidence: {causal_result.confidence:.2f}")
print(f"  Reasoning: {causal_result.reasoning}")
print(f"  Primary Causes: {', '.join(causal_result.primary_causes)}")

# Add causal signal to ensemble
causal_signal = DetectionSignal(
    signal_type=SignalType.CAUSAL_INFERENCE,
    is_threat=False,  # Not malicious
    confidence=causal_result.confidence,
    threat_level=ThreatLevel.INFO,
    details=causal_result.reasoning,
    timestamp=causal_result.timestamp,
    metadata={
        "causal_label": causal_result.causal_label.value,
        "primary_causes": causal_result.primary_causes
    }
)

# Layer 20: Trust state check
print("\n[Layer 20] Checking trust state...")
trust_score = trust_graph.get_entity_trust(
    entity_id=event["src_ip"],
    entity_type=EntityType.IP_ADDRESS,
    is_internal=True
)
print(f"  Trust Score: {trust_score:.1f}/100")

trust_signal = DetectionSignal(
    signal_type=SignalType.TRUST_DEGRADATION,
    is_threat=False,
    confidence=0.90,
    threat_level=ThreatLevel.SAFE,
    details=f"High trust entity ({trust_score:.1f}/100)",
    timestamp=datetime.now(timezone.utc).isoformat(),
    metadata={
        "trust_score": trust_score,
        "recommended_action": "allow"
    }
)

# Ensemble decision with all signals
all_signals = primary_signals + [causal_signal, trust_signal]
print("\n[Meta Engine] Making ensemble decision...")
decision = meta_engine.add_signal(all_signals, ip_address=event["src_ip"])

print(f"\n  Final Decision:")
print(f"    Threat: {decision.is_threat}")
print(f"    Should Block: {decision.should_block}")
print(f"    Weighted Score: {decision.weighted_vote_score:.2f}")
print(f"    Confidence: {decision.confidence:.2f}")
print(f"    Result: ✅ ALLOWED (legitimate deployment)")

print()

# Scenario 2: External attack with low trust
print("-" * 80)
print("SCENARIO 2: External Attack from Low-Trust Entity")
print("-" * 80)

# Simulate attack from known bad actor
attacker_ip = "203.0.113.66"
attack_event = {
    "src_ip": attacker_ip,
    "dst_ip": "192.168.1.10",
    "protocol": "TCP",
    "timestamp": datetime.now(timezone.utc).isoformat()
}

# Simulate primary signals detecting attack
attack_signals = [
    DetectionSignal(
        signal_type=SignalType.SIGNATURE,
        is_threat=True,
        confidence=0.95,
        threat_level=ThreatLevel.CRITICAL,
        details="SQL injection pattern detected",
        timestamp=datetime.now(timezone.utc).isoformat()
    ),
    DetectionSignal(
        signal_type=SignalType.THREAT_INTEL,
        is_threat=True,
        confidence=0.92,
        threat_level=ThreatLevel.DANGEROUS,
        details="IP in threat intelligence feeds",
        timestamp=datetime.now(timezone.utc).isoformat()
    ),
    DetectionSignal(
        signal_type=SignalType.BEHAVIORAL,
        is_threat=True,
        confidence=0.85,
        threat_level=ThreatLevel.DANGEROUS,
        details="High-frequency attack pattern",
        timestamp=datetime.now(timezone.utc).isoformat()
    )
]

# Layer 19: Causal inference (no legitimate cause)
print("\n[Layer 19] Running causal inference...")
attack_causal_result = causal_engine.analyze_root_cause(
    signals=attack_signals,
    event=attack_event,
    config_changes=None,
    deployments=None
)

print(f"  Causal Label: {attack_causal_result.causal_label.value}")
print(f"  Confidence: {attack_causal_result.confidence:.2f}")
print(f"  Reasoning: {attack_causal_result.reasoning}")

attack_causal_signal = DetectionSignal(
    signal_type=SignalType.CAUSAL_INFERENCE,
    is_threat=True,
    confidence=attack_causal_result.confidence,
    threat_level=ThreatLevel.CRITICAL,
    details=attack_causal_result.reasoning,
    timestamp=attack_causal_result.timestamp,
    metadata={
        "causal_label": attack_causal_result.causal_label.value,
        "primary_causes": attack_causal_result.primary_causes
    }
)

# Layer 20: Degrade trust for confirmed attack
print("\n[Layer 20] Updating trust state...")
trust_update = trust_graph.update_trust(
    entity_id=attacker_ip,
    entity_type=EntityType.IP_ADDRESS,
    event_type="confirmed_attack",
    event_details={"attack_type": "SQL injection"},
    is_internal=False
)

print(f"  Previous Trust: {trust_update.previous_trust:.1f}/100")
print(f"  Current Trust: {trust_update.current_trust:.1f}/100")
print(f"  Recommended Action: {trust_update.recommended_action.value}")
print(f"  Reasons: {', '.join(trust_update.reasons)}")

attack_trust_signal = DetectionSignal(
    signal_type=SignalType.TRUST_DEGRADATION,
    is_threat=True,
    confidence=0.95,
    threat_level=ThreatLevel.CRITICAL,
    details=f"Low trust entity ({trust_update.current_trust:.1f}/100) - {trust_update.recommended_action.value}",
    timestamp=trust_update.timestamp,
    metadata={
        "trust_score": trust_update.current_trust,
        "recommended_action": trust_update.recommended_action.value
    }
)

# Ensemble decision
attack_all_signals = attack_signals + [attack_causal_signal, attack_trust_signal]
print("\n[Meta Engine] Making ensemble decision...")
attack_decision = meta_engine.add_signal(attack_all_signals, ip_address=attacker_ip)

print(f"\n  Final Decision:")
print(f"    Threat: {attack_decision.is_threat}")
print(f"    Should Block: {attack_decision.should_block}")
print(f"    Weighted Score: {attack_decision.weighted_vote_score:.2f}")
print(f"    Confidence: {attack_decision.confidence:.2f}")
print(f"    Result: 🔒 BLOCKED (confirmed attack + low trust)")

print()

# Show trust statistics
print("-" * 80)
print("TRUST GRAPH STATISTICS")
print("-" * 80)
stats = trust_graph.get_trust_statistics()
print(f"  Total Entities Tracked: {stats['total_entities']}")
print(f"  Average Trust: {stats['avg_trust']:.1f}/100")
print(f"  Low Trust Count: {stats['low_trust_count']}")
print(f"  Quarantine Count: {stats['quarantine_count']}")
print("\n  Trust Distribution:")
for category, count in stats['trust_distribution'].items():
    print(f"    {category}: {count}")

print()
print("=" * 80)
print("✅ Demo Complete - Layers 19-20 Successfully Integrated!")
print("=" * 80)
