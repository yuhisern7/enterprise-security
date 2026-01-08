# Layers 19-20 Implementation Guide

This guide explains how to use the newly implemented **Signal #19 (Causal Inference Engine)** and **Signal #20 (Trust Degradation Graph)**.

## Overview

**Layer 19: Causal Inference Engine**
- Determines WHY events happen, not just that they happened
- Distinguishes legitimate operational changes from disguised attacks
- Uses causal graphs and counterfactual testing
- Prevents false positives from deployments, config changes, and automation

**Layer 20: Trust Degradation Graph**
- Persistent entity trust tracking across sessions
- Non-linear trust degradation (attacks permanently reduce trust)
- Zero-trust enforcement (trust never fully recovers)
- Defeats "try again later" evasion strategies

## Files Created

```
AI/
├── causal_inference.py       # Layer 19 implementation
├── trust_graph.py            # Layer 20 implementation
└── meta_decision_engine.py   # Updated with Layer 19/20 integration

server/json/
├── causal_analysis.json      # Causal inference logs (auto-created)
└── trust_graph.json          # Persistent trust state (auto-created)
```

## Quick Start

### 1. Run the Demo

```bash
cd /path/to/battle-hardened-ai
python demo_layers_19_20.py
```

This demonstrates:
- ✅ Legitimate deployment causing anomaly (Layer 19 prevents false positive)
- 🔒 External attack from low-trust entity (Layer 20 enforces stricter blocking)

### 2. Basic Usage

```python
from AI.causal_inference import CausalInferenceEngine
from AI.trust_graph import TrustDegradationGraph, EntityType
from AI.meta_decision_engine import MetaDecisionEngine, DetectionSignal, SignalType

# Initialize engines
causal_engine = CausalInferenceEngine()
trust_graph = TrustDegradationGraph()
meta_engine = MetaDecisionEngine()

# Your existing detection signals (1-18)
primary_signals = [
    DetectionSignal(...),  # Signature matching
    DetectionSignal(...),  # Behavioral heuristics
    # ... other signals
]

# Layer 19: Causal inference
causal_result = causal_engine.analyze_root_cause(
    signals=primary_signals,
    event=event_dict,
    deployments=recent_deployments,  # Optional
    config_changes=recent_config_changes,  # Optional
    identity_events=recent_identity_events  # Optional
)

# Create causal signal
causal_signal = DetectionSignal(
    signal_type=SignalType.CAUSAL_INFERENCE,
    is_threat=(causal_result.causal_label == CausalLabel.EXTERNAL_ATTACK),
    confidence=causal_result.confidence,
    threat_level=...,
    details=causal_result.reasoning,
    timestamp=causal_result.timestamp,
    metadata={
        "causal_label": causal_result.causal_label.value,
        "primary_causes": causal_result.primary_causes
    }
)

# Layer 20: Trust state
trust_score = trust_graph.get_entity_trust(
    entity_id=event["src_ip"],
    entity_type=EntityType.IP_ADDRESS,
    is_internal=is_internal_ip(event["src_ip"])
)

trust_signal = DetectionSignal(
    signal_type=SignalType.TRUST_DEGRADATION,
    is_threat=(trust_score < 40),
    confidence=0.90,
    threat_level=...,
    details=f"Trust: {trust_score:.1f}/100",
    timestamp=...,
    metadata={
        "trust_score": trust_score,
        "recommended_action": "allow" if trust_score >= 80 else "quarantine"
    }
)

# Ensemble decision (auto-applies Layer 19/20 modulation)
all_signals = primary_signals + [causal_signal, trust_signal]
decision = meta_engine.add_signal(all_signals, ip_address=event["src_ip"])

# Update trust after decision
if decision.is_threat:
    trust_update = trust_graph.update_trust(
        entity_id=event["src_ip"],
        entity_type=EntityType.IP_ADDRESS,
        event_type="confirmed_attack",  # or "suspicious_behavior", "lateral_movement", etc.
        event_details={"attack_type": "..."}
    )
```

## Causal Inference Engine (Layer 19)

### Causal Labels

```python
from AI.causal_inference import CausalLabel

# Possible classifications:
CausalLabel.LEGITIMATE_CAUSE        # Normal operational change (deployment, patch)
CausalLabel.MISCONFIGURATION        # Human error, not malicious
CausalLabel.AUTOMATION_SIDE_EFFECT  # CI/CD pipeline, orchestration tool
CausalLabel.EXTERNAL_ATTACK         # Malicious external actor
CausalLabel.INSIDER_MISUSE          # Internal actor abusing access
CausalLabel.UNKNOWN_CAUSE           # Insufficient context
```

### Providing Context

The causal engine works best when provided with recent operational events:

```python
# Example: Recent deployments
deployments = [
    {
        "timestamp": "2026-01-09T10:30:00Z",
        "service": "payment-api",
        "automated": True
    }
]

# Example: Config changes
config_changes = [
    {
        "timestamp": "2026-01-09T10:25:00Z",
        "change_type": "firewall_rule_update",
        "automated": False
    }
]

# Example: Identity events
identity_events = [
    {
        "timestamp": "2026-01-09T10:20:00Z",
        "event_type": "privilege_escalation",
        "user": "admin@example.com",
        "privileged": True
    }
]

causal_result = causal_engine.analyze_root_cause(
    signals=primary_signals,
    event=event,
    deployments=deployments,
    config_changes=config_changes,
    identity_events=identity_events
)
```

### Modulation Effects

Layer 19 modulates the ensemble weighted score:

| Causal Label | Confidence | Score Adjustment | Effect |
|--------------|-----------|------------------|--------|
| `LEGITIMATE_CAUSE` | ≥0.85 | -20% | Prevents false positive |
| `AUTOMATION_SIDE_EFFECT` | ≥0.80 | -15% | Allows automation |
| `EXTERNAL_ATTACK` | ≥0.80 | +15% | Boosts confidence |
| `INSIDER_MISUSE` | ≥0.75 | +10% | Escalates threat |
| `MISCONFIGURATION` | Any | 0% | Routes to governance |
| `UNKNOWN_CAUSE` | Any | 0% | Requires human review |

## Trust Degradation Graph (Layer 20)

### Entity Types

```python
from AI.trust_graph import EntityType

EntityType.IP_ADDRESS    # External/internal IP addresses
EntityType.DEVICE        # Physical/virtual devices
EntityType.USER_ACCOUNT  # User accounts
EntityType.SERVICE       # Microservices, APIs
EntityType.API           # API clients
EntityType.CLOUD_ROLE    # Cloud IAM roles
EntityType.CONTAINER     # Docker containers, pods
```

### Trust Scoring

**Initial Trust:**
- Internal entities: 100/100
- External entities: 60/100

**Event Penalties:**
```python
penalties = {
    "minor_anomaly": -5,
    "failed_auth": -10,
    "suspicious_behavior": -15,
    "confirmed_attack": -25,
    "lateral_movement": -30,
    "data_exfiltration": -35,
    "integrity_breach": -40,
    "repeated_attack": -50  # Recidivism (3+ attacks in 7 days)
}
```

**Recovery:**
- +1 trust per 24 hours of clean behavior
- Capped at 80% of baseline (trust never fully recovers)

### Trust Thresholds

| Trust Score | Action | Behavior |
|-------------|--------|----------|
| ≥80 | `ALLOW` | Normal operation |
| 60-79 | `MONITOR` | Increased logging |
| 40-59 | `RATE_LIMIT` | Connection throttling |
| 20-39 | `ISOLATE` | Deny-by-default |
| <20 | `QUARANTINE` | Auto-block + SOC alert |

### Updating Trust

```python
# After detecting an attack
trust_update = trust_graph.update_trust(
    entity_id="203.0.113.42",
    entity_type=EntityType.IP_ADDRESS,
    event_type="confirmed_attack",  # Maps to penalty
    event_details={"attack_type": "SQL injection"},
    is_internal=False
)

print(f"Trust: {trust_update.previous_trust} → {trust_update.current_trust}")
print(f"Action: {trust_update.recommended_action.value}")
```

### Recidivism Detection

Trust graph automatically detects repeat offenders:
- Tracks event history per entity
- Flags entities with 3+ attacks in 7 days
- Applies exponential penalty (-50 instead of normal)

### Querying Trust State

```python
# Get trust score
trust_score = trust_graph.get_entity_trust(
    entity_id="10.0.1.50",
    entity_type=EntityType.IP_ADDRESS,
    is_internal=True
)

# Get low-trust entities
low_trust = trust_graph.get_low_trust_entities(threshold=40.0, limit=100)
for entity in low_trust:
    print(f"{entity['entity_id']}: {entity['trust_score']:.1f}/100")

# Get statistics
stats = trust_graph.get_trust_statistics()
print(f"Total entities: {stats['total_entities']}")
print(f"Average trust: {stats['avg_trust']:.1f}/100")
print(f"Quarantine count: {stats['quarantine_count']}")
```

## Meta Decision Engine Integration

The `MetaDecisionEngine` automatically applies Layer 19 and Layer 20 modulation when you include their signals:

### Automatic Modulation Flow

```
1. Calculate weighted vote from primary signals (1-18)
2. Apply authoritative signal boosting (honeypot, threat intel)
3. Apply Layer 19 causal modulation (±20% based on root cause)
4. Apply Layer 20 trust modulation (±15% based on entity trust)
5. Make final block/log/allow decision
6. Override based on trust action (quarantine forces block)
```

### Signal Weights

```python
{
    SignalType.CAUSAL_INFERENCE: 0.88,    # Context-aware, reduces false positives
    SignalType.TRUST_DEGRADATION: 0.90    # Persistent memory, recidivism tracking
}
```

## Privacy Guarantees

**Layer 19:**
- ✅ No raw payloads or credentials processed
- ✅ Uses only metadata: timestamps, change types, entity IDs
- ✅ No PII retention

**Layer 20:**
- ✅ Entity IDs are SHA-256 hashed
- ✅ No PII or credentials stored
- ✅ Trust scores are statistical only
- ✅ Persistent across sessions but privacy-preserving

## Configuration

### JSON Persistence

Both layers automatically persist state to `server/json/`:

```bash
server/json/
├── causal_analysis.json   # Last 10,000 causal analyses
└── trust_graph.json       # All entity trust states (persistent)
```

### Tuning Parameters

**Causal Inference Engine:**
```python
causal_engine.deployment_window = 3600      # 1 hour correlation window
causal_engine.config_change_window = 1800   # 30 minutes
causal_engine.identity_event_window = 900   # 15 minutes
```

**Trust Degradation Graph:**
```python
trust_graph.initial_trust_internal = 100.0  # Internal baseline
trust_graph.initial_trust_external = 60.0   # External baseline
trust_graph.recovery_rate_per_day = 1.0     # +1/day recovery
trust_graph.recovery_cap_multiplier = 0.8   # Max 80% recovery
```

## Testing

Run the demo script to verify integration:

```bash
python demo_layers_19_20.py
```

Expected output:
- ✅ Scenario 1: Legitimate deployment → ALLOWED (causal analysis prevents false positive)
- 🔒 Scenario 2: External attack → BLOCKED (low trust enforces stricter threshold)

## Integration Checklist

- [x] `AI/causal_inference.py` created
- [x] `AI/trust_graph.py` created
- [x] `AI/meta_decision_engine.py` updated with new signal types
- [x] Signal weights added (0.88 and 0.90)
- [x] Causal modulation logic implemented
- [x] Trust modulation logic implemented
- [x] Demo script created
- [ ] Integrate with existing `pcs_ai.py` workflow (next step)
- [ ] Add dashboard API endpoints for Layer 19/20 stats
- [ ] Update relay to sync causal analysis and trust state

## Next Steps

### 1. Integrate with pcs_ai.py

Add to main threat assessment flow:

```python
# In AI/pcs_ai.py assess_threat() method:
from AI.causal_inference import CausalInferenceEngine
from AI.trust_graph import TrustDegradationGraph

# Initialize once at module level
_causal_engine = CausalInferenceEngine()
_trust_graph = TrustDegradationGraph()

# In assess_threat():
# ... existing primary signals (1-18) ...

# Layer 19
causal_result = _causal_engine.analyze_root_cause(
    signals=primary_signals,
    event=event,
    deployments=get_recent_deployments(),
    config_changes=get_recent_config_changes()
)

# Layer 20
trust_score = _trust_graph.get_entity_trust(
    entity_id=event["src_ip"],
    entity_type=EntityType.IP_ADDRESS,
    is_internal=is_internal_ip(event["src_ip"])
)

# Add to ensemble
all_signals = primary_signals + [causal_signal, trust_signal]
decision = meta_engine.add_signal(all_signals, ip_address=event["src_ip"])

# Update trust after decision
if decision.is_threat:
    _trust_graph.update_trust(...)
```

### 2. Dashboard Integration

Add API endpoints to `server/server.py`:

```python
@app.route('/api/causal-analysis/recent')
def get_recent_causal_analyses():
    return jsonify(causal_engine.get_recent_analyses(limit=100))

@app.route('/api/trust/low-trust-entities')
def get_low_trust_entities():
    return jsonify(trust_graph.get_low_trust_entities(threshold=40.0))

@app.route('/api/trust/statistics')
def get_trust_statistics():
    return jsonify(trust_graph.get_trust_statistics())
```

### 3. Relay Sync

Update relay to aggregate causal analysis and trust state:

```python
# In relay/signature_sync.py or relay/training_sync_api.py

# Share anonymized causal patterns
# Share trust degradation statistics (hashed entity IDs only)
```

## Support

For questions or issues:
- Email: yuhisern@protonmail.com
- Review: `ai-instructions.md` for architecture details
- Review: `README.md` for system overview
