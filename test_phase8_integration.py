"""
Integration tests for Phase 8: Advanced Orchestration.
Tests complete workflows with predictive modeling and automated response.
"""

import unittest
import os
import json
import time
import shutil
from datetime import datetime, timedelta
from AI.advanced_orchestration import (
    AdvancedOrchestration, ThreatForecast, ResponseAction
)


class TestPhase8Integration(unittest.TestCase):
    """Integration tests for Phase 8."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_export_dir = "test_phase8_integration_data"
        self.orch = AdvancedOrchestration(export_dir=self.test_export_dir)
    
    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.test_export_dir):
            shutil.rmtree(self.test_export_dir)
        
        test_dirs = ["server/json/predictions", "server/json/responses", "server/json"]
        for d in test_dirs:
            if os.path.exists(d):
                for f in os.listdir(d):
                    if any(f.startswith(p) for p in ["RESP-", "PRED-", "network_topology"]):
                        try:
                            os.remove(os.path.join(d, f))
                        except:
                            pass
    
    def test_predict_and_respond_workflow(self):
        """Test complete predict-then-respond workflow."""
        print("\n=== Test: Predict and Respond Workflow ===")
        
        # Step 1: Build attack history
        current_time = time.time()
        historical_data = []
        
        # Known repeat offender
        attacker_ip = "203.0.113.50"
        for i in range(5):
            historical_data.append({
                "entity": attacker_ip,
                "attack_type": "SQL Injection",
                "timestamp": current_time - (3600 * (5-i)),
                "severity": 0.85
            })
        
        # Add to orchestrator's history
        for event in historical_data:
            self.orch.attack_history.append(event)
        
        # Step 2: Generate predictions
        predictions = self.orch.predict_threats(
            ThreatForecast.SHORT_TERM,
            historical_data
        )
        
        print(f"Generated {len(predictions)} predictions")
        self.assertGreater(len(predictions), 0)
        
        # Should predict this attacker will strike again
        attacker_predictions = [p for p in predictions if p.entity == attacker_ip]
        if attacker_predictions:
            pred = attacker_predictions[0]
            print(f"Predicted: {pred.entity} will perform {pred.attack_type} "
                  f"with {pred.confidence:.2%} confidence")
            self.assertGreater(pred.confidence, 0.5)
        
        # Step 3: Create preemptive alert rule based on prediction
        rule = self.orch.create_alert_rule(
            name="Preemptive Block - Predicted Threat",
            description=f"Auto-block {attacker_ip} based on prediction",
            conditions=[
                {"field": "entity", "operator": "==", "value": attacker_ip},
                {"field": "reputation_score", "operator": ">", "value": 0.7}
            ],
            actions=[ResponseAction.BLOCK_IP, ResponseAction.HONEYPOT_REDIRECT],
            priority=10,
            action_params={"honeypot_ip": "10.0.0.100"}
        )
        
        print(f"Created preemptive rule: {rule.name}")
        
        # Step 4: Simulate threat detection matching prediction
        threat_context = {
            "entity": attacker_ip,
            "reputation_score": 0.9,
            "attack_type": "SQL Injection"
        }
        
        # Evaluate rules
        results = self.orch.evaluate_alert_rules(threat_context)
        triggered_rules = [r for r, t in results if t]
        
        print(f"Triggered {len(triggered_rules)} rules")
        self.assertEqual(len(triggered_rules), 1)
        
        # Step 5: Execute automated response
        response = self.orch.execute_automated_response(
            incident_id="INC-PREDICTED-001",
            entity=attacker_ip,
            threat_type="SQL Injection",
            severity="HIGH",
            actions=triggered_rules[0].actions,
            action_params=triggered_rules[0].action_params
        )
        
        print(f"Response executed: {response.success_count} actions succeeded")
        print(f"Response time: {response.response_time_ms:.2f}ms")
        
        self.assertEqual(response.success_count, 2)
        self.assertTrue(response.threat_mitigated)
        
        # Verify exports
        self.assertTrue(os.path.exists(f"{self.test_export_dir}/predictions_latest.json"))
        print("\n✓ Prediction → Alert Rule → Response workflow complete")
    
    def test_network_topology_with_honeypot_deployment(self):
        """Test network topology visualization with adaptive honeypot."""
        print("\n=== Test: Network Topology + Honeypot Deployment ===")
        
        # Step 1: Build network topology
        nodes = []
        edges = []
        
        # Add legitimate nodes
        for i in range(5):
            nodes.append({
                "node_id": f"server-{i}",
                "ip_address": f"10.0.1.{i+1}",
                "node_type": "server",
                "threat_level": "CLEAN",
                "reputation_score": 0.1,
                "attack_count": 0,
                "connection_count": 50 + i
            })
        
        # Add malicious node
        malicious_ip = "192.0.2.100"
        nodes.append({
            "node_id": "attacker-1",
            "ip_address": malicious_ip,
            "node_type": "device",
            "threat_level": "MALICIOUS",
            "reputation_score": 0.95,
            "attack_count": 15,
            "is_blocked": True,
            "connection_count": 100
        })
        
        # Add connections (including suspicious ones)
        for i in range(5):
            edges.append({
                "source": "attacker-1",
                "target": f"server-{i}",
                "type": "tcp",
                "traffic_volume": 10240,
                "is_suspicious": True,
                "threat_score": 0.9
            })
        
        self.orch.update_network_topology(nodes, edges)
        
        print(f"Topology: {len(self.orch.topology_nodes)} nodes, "
              f"{len(self.orch.topology_edges)} edges")
        
        self.assertEqual(len(self.orch.topology_nodes), 6)
        self.assertEqual(len(self.orch.topology_edges), 5)
        
        # Step 2: Deploy adaptive honeypot for common attack type
        honeypot = self.orch.configure_honeypot(
            honeypot_type="web",
            listen_ip="10.0.0.50",
            listen_port=8080,
            adaptive=True
        )
        
        print(f"Deployed honeypot: {honeypot.honeypot_id} on {honeypot.listen_ip}:{honeypot.listen_port}")
        self.assertTrue(honeypot.enabled)
        self.assertTrue(honeypot.adaptive)
        
        # Step 3: Create rule to redirect high-risk traffic to honeypot
        rule = self.orch.create_alert_rule(
            name="Honeypot Redirect",
            description="Redirect suspicious traffic to honeypot",
            conditions=[
                {"field": "threat_score", "operator": ">", "value": 0.8}
            ],
            actions=[ResponseAction.HONEYPOT_REDIRECT],
            priority=7,
            action_params={"honeypot_ip": honeypot.listen_ip}
        )
        
        # Step 4: Trigger redirect for malicious traffic
        context = {
            "entity": malicious_ip,
            "threat_score": 0.95
        }
        
        results = self.orch.evaluate_alert_rules(context)
        triggered = [r for r, t in results if t]
        
        self.assertEqual(len(triggered), 1)
        
        # Execute redirect
        response = self.orch.execute_automated_response(
            incident_id="INC-HONEYPOT-001",
            entity=malicious_ip,
            threat_type="Scan",
            severity="MEDIUM",
            actions=[ResponseAction.HONEYPOT_REDIRECT],
            action_params={"honeypot_ip": honeypot.listen_ip}
        )
        
        print(f"Redirected {malicious_ip} to honeypot {honeypot.listen_ip}")
        self.assertTrue(response.threat_mitigated)
        
        # Verify topology export
        self.assertTrue(os.path.exists("server/json/network_topology.json"))
        print("\n✓ Network topology + honeypot deployment complete")
    
    def test_multi_tier_response_escalation(self):
        """Test escalating responses based on threat severity."""
        print("\n=== Test: Multi-Tier Response Escalation ===")
        
        # Create tiered alert rules
        rules = []
        
        # Tier 1: Low severity - alert only
        rules.append(self.orch.create_alert_rule(
            name="Tier 1: Low Severity",
            description="Low risk - monitor",
            conditions=[
                {"field": "severity", "operator": "==", "value": "LOW"}
            ],
            actions=[ResponseAction.ALERT_ONLY],
            priority=3
        ))
        
        # Tier 2: Medium severity - rate limit
        rules.append(self.orch.create_alert_rule(
            name="Tier 2: Medium Severity",
            description="Medium risk - throttle",
            conditions=[
                {"field": "severity", "operator": "==", "value": "MEDIUM"}
            ],
            actions=[ResponseAction.RATE_LIMIT, ResponseAction.ALERT_ONLY],
            priority=6,
            action_params={"rate_limit": "50/min"}
        ))
        
        # Tier 3: High severity - block + quarantine
        rules.append(self.orch.create_alert_rule(
            name="Tier 3: High Severity",
            description="High risk - isolate",
            conditions=[
                {"field": "severity", "operator": "==", "value": "HIGH"}
            ],
            actions=[ResponseAction.BLOCK_IP, ResponseAction.QUARANTINE, ResponseAction.ALERT_ONLY],
            priority=9
        ))
        
        # Tier 4: Critical - full isolation
        rules.append(self.orch.create_alert_rule(
            name="Tier 4: Critical",
            description="Critical risk - full isolation",
            conditions=[
                {"field": "severity", "operator": "==", "value": "CRITICAL"}
            ],
            actions=[
                ResponseAction.BLOCK_IP,
                ResponseAction.KILL_CONNECTION,
                ResponseAction.ISOLATE_SEGMENT,
                ResponseAction.ALERT_ONLY
            ],
            priority=10
        ))
        
        print(f"Created {len(rules)} tiered response rules")
        
        # Test each tier
        test_scenarios = [
            ("LOW", 1, "192.168.1.10"),
            ("MEDIUM", 2, "192.168.1.20"),
            ("HIGH", 3, "192.168.1.30"),
            ("CRITICAL", 4, "192.168.1.40")
        ]
        
        for severity, expected_actions, entity in test_scenarios:
            context = {"severity": severity}
            results = self.orch.evaluate_alert_rules(context)
            triggered = [r for r, t in results if t]
            
            self.assertEqual(len(triggered), 1)
            rule = triggered[0]
            
            # Execute response
            response = self.orch.execute_automated_response(
                incident_id=f"INC-{severity}-001",
                entity=entity,
                threat_type="Test",
                severity=severity,
                actions=rule.actions
            )
            
            print(f"  {severity}: {response.success_count} actions executed")
            self.assertEqual(response.success_count, expected_actions)
            self.assertTrue(response.threat_mitigated)
        
        print("\n✓ Multi-tier escalation complete")
    
    def test_temporal_prediction_accuracy(self):
        """Test temporal pattern prediction accuracy."""
        print("\n=== Test: Temporal Prediction Accuracy ===")
        
        # Generate realistic attack pattern: high activity during business hours
        historical_data = []
        current_time = time.time()
        
        # Business hours (9-17): 20 attacks/day
        # Off hours: 2 attacks/day
        for day in range(7):
            base_date = datetime.now() - timedelta(days=day)
            
            # Business hours attacks
            for hour in range(9, 17):
                for i in range(20):
                    attack_time = base_date.replace(hour=hour, minute=i*3, second=0)
                    historical_data.append({
                        "entity": f"192.168.{day}.{i}",
                        "attack_type": "Brute Force",
                        "timestamp": attack_time.timestamp(),
                        "severity": 0.6
                    })
            
            # Off-hours attacks (fewer)
            for hour in [2, 22]:
                for i in range(2):
                    attack_time = base_date.replace(hour=hour, minute=i*30, second=0)
                    historical_data.append({
                        "entity": f"192.168.{day}.{100+i}",
                        "attack_type": "Scan",
                        "timestamp": attack_time.timestamp(),
                        "severity": 0.3
                    })
        
        print(f"Generated {len(historical_data)} historical attacks")
        
        # Predict future threats
        predictions = self.orch.predict_threats(
            ThreatForecast.MEDIUM_TERM,
            historical_data
        )
        
        print(f"Generated {len(predictions)} predictions")
        self.assertGreater(len(predictions), 0)
        
        # Should identify business hours pattern
        temporal_preds = [p for p in predictions if "temporal pattern" in p.historical_pattern.lower()]
        
        if temporal_preds:
            print(f"Found {len(temporal_preds)} temporal pattern predictions")
            for pred in temporal_preds[:3]:
                print(f"  - {pred.historical_pattern} (confidence: {pred.confidence:.2%})")
                self.assertGreater(pred.confidence, 0.3)
        
        print("\n✓ Temporal prediction analysis complete")
    
    def test_automated_forensics_workflow(self):
        """Test automated forensic data collection and response."""
        print("\n=== Test: Automated Forensics Workflow ===")
        
        # Simulate sophisticated attack sequence
        attack_sequence = []
        base_time = time.time()
        attacker = "198.51.100.75"
        
        # 1. Reconnaissance
        for i in range(5):
            attack_sequence.append({
                "entity": attacker,
                "attack_type": "Port Scan",
                "timestamp": base_time - 300 + i,
                "severity": 0.3
            })
        
        # 2. Exploitation attempt
        for i in range(3):
            attack_sequence.append({
                "entity": attacker,
                "attack_type": "SQL Injection",
                "timestamp": base_time - 200 + i * 10,
                "severity": 0.8
            })
        
        # 3. Persistence attempt
        attack_sequence.append({
            "entity": attacker,
            "attack_type": "Backdoor Install",
            "timestamp": base_time - 100,
            "severity": 0.95
        })
        
        print(f"Simulated {len(attack_sequence)} attack events")
        
        # Add to history
        for event in attack_sequence:
            self.orch.attack_history.append(event)
        
        # Create forensic collection rule
        rule = self.orch.create_alert_rule(
            name="Forensic Collection + Response",
            description="Capture forensics and respond to multi-stage attacks",
            conditions=[
                {"field": "attack_count", "operator": ">=", "value": 5}
            ],
            actions=[
                ResponseAction.KILL_CONNECTION,
                ResponseAction.BLOCK_IP,
                ResponseAction.ALERT_ONLY
            ],
            priority=10
        )
        
        # Trigger forensic response
        context = {
            "entity": attacker,
            "attack_count": len([a for a in attack_sequence if a["entity"] == attacker]),
            "max_severity": 0.95
        }
        
        results = self.orch.evaluate_alert_rules(context)
        triggered = [r for r, t in results if t]
        
        self.assertEqual(len(triggered), 1)
        
        # Execute response with forensic collection
        response = self.orch.execute_automated_response(
            incident_id="INC-FORENSIC-001",
            entity=attacker,
            threat_type="Multi-Stage Attack",
            severity="CRITICAL",
            actions=triggered[0].actions
        )
        
        print(f"Forensic response executed:")
        print(f"  - Actions: {response.success_count}/{len(response.actions_executed)}")
        print(f"  - Response time: {response.response_time_ms:.2f}ms")
        print(f"  - Threat mitigated: {response.threat_mitigated}")
        
        self.assertTrue(response.threat_mitigated)
        
        # Verify forensic data export
        response_files = [f for f in os.listdir(self.test_export_dir) 
                         if f.startswith("response_")]
        self.assertGreater(len(response_files), 0)
        
        # Load and verify response data
        latest_response = sorted(response_files)[-1]
        with open(f"{self.test_export_dir}/{latest_response}", 'r') as f:
            forensic_data = json.load(f)
        
        self.assertEqual(forensic_data["entity"], attacker)
        self.assertEqual(forensic_data["severity"], "CRITICAL")
        self.assertIn("execution_log", forensic_data)
        
        print("\n✓ Automated forensics workflow complete")
    
    def test_statistics_tracking(self):
        """Test comprehensive statistics tracking."""
        print("\n=== Test: Statistics Tracking ===")
        
        # Perform various operations
        
        # 1. Create rules
        for i in range(3):
            self.orch.create_alert_rule(
                name=f"Rule {i}",
                description="Test",
                conditions=[],
                actions=[ResponseAction.ALERT_ONLY],
                priority=5
            )
        
        # 2. Make predictions
        for _ in range(2):
            self.orch.predict_threats(ThreatForecast.SHORT_TERM, [])
        
        # 3. Execute responses
        for i in range(5):
            self.orch.execute_automated_response(
                incident_id=f"INC-STATS-{i}",
                entity=f"192.168.1.{i}",
                threat_type="Test",
                severity="MEDIUM",
                actions=[ResponseAction.ALERT_ONLY]
            )
        
        # 4. Deploy honeypots
        for i in range(2):
            self.orch.configure_honeypot(
                honeypot_type="web",
                listen_ip="10.0.0.100",
                listen_port=8000 + i
            )
        
        # 5. Update topology
        self.orch.update_network_topology(
            [{"node_id": "test", "ip_address": "1.2.3.4"}],
            []
        )
        
        # Get statistics
        stats = self.orch.get_statistics()
        
        print(f"Statistics:")
        print(f"  - Total rules: {stats['total_rules']}")
        print(f"  - Active rules: {stats['active_rules']}")
        print(f"  - Predictions made: {stats['predictions_made']}")
        print(f"  - Responses executed: {stats['responses_executed']}")
        print(f"  - Responses successful: {stats['responses_successful']}")
        print(f"  - Response success rate: {stats['response_success_rate']:.1f}%")
        print(f"  - Honeypots deployed: {stats['honeypots_deployed']}")
        print(f"  - Topology nodes: {stats['topology_nodes']}")
        
        self.assertEqual(stats["total_rules"], 3)
        self.assertEqual(stats["predictions_made"], 2)
        self.assertEqual(stats["responses_executed"], 5)
        self.assertEqual(stats["honeypots_deployed"], 2)
        self.assertEqual(stats["topology_nodes"], 1)
        
        print("\n✓ Statistics tracking verified")


if __name__ == "__main__":
    unittest.main(verbosity=2)
