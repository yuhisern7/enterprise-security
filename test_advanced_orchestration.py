"""
Unit tests for Phase 8: Advanced Orchestration.
Tests predictive modeling, automated response, and alert rules.
"""

import unittest
import os
import json
import time
import shutil
from datetime import datetime, timedelta
from AI.advanced_orchestration import (
    AdvancedOrchestration, ThreatForecast, ResponseAction,
    RuleConditionOperator, ThreatPrediction, AlertRule,
    IncidentResponse, HoneypotConfig
)


class TestAdvancedOrchestration(unittest.TestCase):
    """Test suite for advanced orchestration."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_export_dir = "test_orchestration_data"
        self.orch = AdvancedOrchestration(export_dir=self.test_export_dir)
    
    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.test_export_dir):
            shutil.rmtree(self.test_export_dir)
        
        # Clean up server paths
        test_dirs = ["server/json/predictions", "server/json/responses"]
        for d in test_dirs:
            if os.path.exists(d):
                for f in os.listdir(d):
                    if f.startswith("RESP-") or f.startswith("PRED-"):
                        os.remove(os.path.join(d, f))
    
    def test_initialization(self):
        """Test orchestration initialization."""
        self.assertIsNotNone(self.orch)
        self.assertEqual(len(self.orch.alert_rules), 0)
        self.assertEqual(len(self.orch.predictions), 0)
        self.assertEqual(len(self.orch.responses), 0)
        self.assertTrue(os.path.exists(self.test_export_dir))
    
    def test_predict_threats_empty_data(self):
        """Test threat prediction with no data."""
        predictions = self.orch.predict_threats(ThreatForecast.MEDIUM_TERM, [])
        self.assertEqual(len(predictions), 0)
    
    def test_predict_threats_repeat_offenders(self):
        """Test prediction of repeat offenders."""
        # Create historical data with repeat attacker
        current_time = time.time()
        historical_data = []
        
        # Attacker with 3 attacks at regular intervals
        for i in range(3):
            historical_data.append({
                "entity": "192.168.1.100",
                "ip": "192.168.1.100",
                "attack_type": "SQL Injection",
                "timestamp": current_time - (3600 * (3-i)),  # 1 hour apart
                "severity": 0.8
            })
        
        predictions = self.orch.predict_threats(
            ThreatForecast.SHORT_TERM,
            historical_data
        )
        
        self.assertGreater(len(predictions), 0)
        self.assertEqual(self.orch.stats["predictions_made"], 1)
        
        # Check if prediction for repeat offender exists
        repeat_pred = [p for p in predictions if p.entity == "192.168.1.100"]
        if repeat_pred:
            self.assertGreater(repeat_pred[0].confidence, 0.5)
    
    def test_predict_temporal_patterns(self):
        """Test temporal pattern prediction."""
        current_time = time.time()
        historical_data = []
        
        # Create attacks with varying hours (10 at hour 14, 2 at hour 15, 1 at hour 16)
        base_time = datetime.now().replace(hour=14, minute=0, second=0)
        for i in range(10):
            attack_time = base_time - timedelta(days=i)
            historical_data.append({
                "entity": f"192.168.1.{i}",
                "attack_type": "Port Scan",
                "timestamp": attack_time.timestamp(),
                "severity": 0.6
            })
        
        # Add attacks at different hours
        for i in range(2):
            attack_time = base_time.replace(hour=15) - timedelta(days=i)
            historical_data.append({
                "entity": f"192.168.2.{i}",
                "attack_type": "Port Scan",
                "timestamp": attack_time.timestamp(),
                "severity": 0.5
            })
        
        attack_time = base_time.replace(hour=16)
        historical_data.append({
            "entity": "192.168.3.1",
            "attack_type": "Port Scan",
            "timestamp": attack_time.timestamp(),
            "severity": 0.4
        })
        
        predictions = self.orch.predict_threats(
            ThreatForecast.MEDIUM_TERM,
            historical_data
        )
        
        # Should predict based on temporal pattern (hour 14 has most attacks)
        self.assertGreater(len(predictions), 0)
    
    def test_create_alert_rule(self):
        """Test creating alert rule."""
        rule = self.orch.create_alert_rule(
            name="High Reputation Alert",
            description="Alert on high reputation score",
            conditions=[
                {"field": "reputation_score", "operator": ">", "value": 0.8}
            ],
            actions=[ResponseAction.ALERT_ONLY],
            priority=8
        )
        
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "High Reputation Alert")
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.priority, 8)
        self.assertEqual(len(rule.conditions), 1)
        self.assertEqual(len(self.orch.alert_rules), 1)
    
    def test_evaluate_alert_rules_trigger(self):
        """Test alert rule evaluation - should trigger."""
        # Create rule
        self.orch.create_alert_rule(
            name="Test Rule",
            description="Test",
            conditions=[
                {"field": "reputation_score", "operator": ">", "value": 0.7}
            ],
            actions=[ResponseAction.ALERT_ONLY],
            priority=5
        )
        
        # Context that should trigger
        context = {"reputation_score": 0.85}
        results = self.orch.evaluate_alert_rules(context)
        
        self.assertEqual(len(results), 1)
        rule, triggered = results[0]
        self.assertTrue(triggered)
        self.assertEqual(self.orch.stats["rules_triggered"], 1)
    
    def test_evaluate_alert_rules_no_trigger(self):
        """Test alert rule evaluation - should not trigger."""
        self.orch.create_alert_rule(
            name="Test Rule",
            description="Test",
            conditions=[
                {"field": "reputation_score", "operator": ">", "value": 0.9}
            ],
            actions=[ResponseAction.ALERT_ONLY],
            priority=5
        )
        
        # Context that should NOT trigger
        context = {"reputation_score": 0.5}
        results = self.orch.evaluate_alert_rules(context)
        
        self.assertEqual(len(results), 1)
        rule, triggered = results[0]
        self.assertFalse(triggered)
    
    def test_evaluate_multiple_conditions(self):
        """Test rule with multiple conditions (all must be true)."""
        self.orch.create_alert_rule(
            name="Multi-Condition Rule",
            description="Test",
            conditions=[
                {"field": "reputation_score", "operator": ">", "value": 0.7},
                {"field": "attack_count", "operator": ">=", "value": 3}
            ],
            actions=[ResponseAction.BLOCK_IP],
            priority=8
        )
        
        # All conditions met
        context = {"reputation_score": 0.8, "attack_count": 5}
        results = self.orch.evaluate_alert_rules(context)
        rule, triggered = results[0]
        self.assertTrue(triggered)
        
        # Only one condition met
        context = {"reputation_score": 0.8, "attack_count": 1}
        results = self.orch.evaluate_alert_rules(context)
        rule, triggered = results[0]
        self.assertFalse(triggered)
    
    def test_condition_operators(self):
        """Test different condition operators."""
        test_cases = [
            ({"value": 10}, ">", 5, True),
            ({"value": 3}, ">", 5, False),
            ({"value": 5}, ">=", 5, True),
            ({"value": 10}, "<", 15, True),
            ({"value": "test"}, "==", "test", True),
            ({"value": "test"}, "!=", "other", True),
            ({"value": "hello world"}, "contains", "world", True),
            ({"value": "test"}, "in", ["test", "other"], True),
        ]
        
        for context, op, val, expected in test_cases:
            self.orch.alert_rules.clear()
            self.orch.create_alert_rule(
                name="Test",
                description="Test",
                conditions=[{"field": "value", "operator": op, "value": val}],
                actions=[ResponseAction.ALERT_ONLY],
                priority=5
            )
            
            results = self.orch.evaluate_alert_rules(context)
            rule, triggered = results[0]
            self.assertEqual(triggered, expected, 
                           f"Failed for {context['value']} {op} {val}")
    
    def test_execute_automated_response(self):
        """Test executing automated response."""
        response = self.orch.execute_automated_response(
            incident_id="INC-001",
            entity="192.168.1.100",
            threat_type="SQL Injection",
            severity="HIGH",
            actions=[ResponseAction.BLOCK_IP, ResponseAction.ALERT_ONLY]
        )
        
        self.assertIsNotNone(response)
        self.assertEqual(response.entity, "192.168.1.100")
        self.assertEqual(response.severity, "HIGH")
        self.assertEqual(response.success_count, 2)
        self.assertEqual(response.failure_count, 0)
        self.assertTrue(response.threat_mitigated)
        self.assertGreater(response.response_time_ms, 0)
        self.assertEqual(len(self.orch.responses), 1)
    
    def test_execute_multiple_actions(self):
        """Test executing multiple response actions."""
        actions = [
            ResponseAction.BLOCK_IP,
            ResponseAction.RATE_LIMIT,
            ResponseAction.HONEYPOT_REDIRECT
        ]
        
        response = self.orch.execute_automated_response(
            incident_id="INC-002",
            entity="10.0.0.50",
            threat_type="Brute Force",
            severity="MEDIUM",
            actions=actions,
            action_params={"rate_limit": "50/min", "honeypot_ip": "10.0.0.100"}
        )
        
        self.assertEqual(response.success_count, 3)
        self.assertEqual(len(response.actions_executed), 3)
        self.assertEqual(len(response.execution_log), 3)
    
    def test_network_topology_update(self):
        """Test updating network topology."""
        nodes = [
            {
                "node_id": "node1",
                "ip_address": "192.168.1.1",
                "node_type": "server",
                "threat_level": "CLEAN",
                "reputation_score": 0.1,
                "attack_count": 0,
                "connection_count": 10
            },
            {
                "node_id": "node2",
                "ip_address": "192.168.1.2",
                "node_type": "device",
                "threat_level": "MALICIOUS",
                "reputation_score": 0.9,
                "attack_count": 5,
                "is_blocked": True
            }
        ]
        
        edges = [
            {
                "source": "node1",
                "target": "node2",
                "type": "tcp",
                "traffic_volume": 1024,
                "is_suspicious": True,
                "threat_score": 0.8
            }
        ]
        
        self.orch.update_network_topology(nodes, edges)
        
        self.assertEqual(len(self.orch.topology_nodes), 2)
        self.assertEqual(len(self.orch.topology_edges), 1)
        
        # Check node details
        node1 = self.orch.topology_nodes["node1"]
        self.assertEqual(node1.threat_level, "CLEAN")
        self.assertEqual(node1.color, "#00FF00")
        
        node2 = self.orch.topology_nodes["node2"]
        self.assertEqual(node2.threat_level, "MALICIOUS")
        self.assertEqual(node2.color, "#FFA500")
        self.assertTrue(node2.is_blocked)
        
        # Check edge details
        edge = self.orch.topology_edges[0]
        self.assertTrue(edge.is_suspicious)
        self.assertEqual(edge.color, "#FF0000")
    
    def test_configure_honeypot(self):
        """Test honeypot configuration."""
        config = self.orch.configure_honeypot(
            honeypot_type="ssh",
            listen_ip="10.0.0.100",
            listen_port=22,
            adaptive=True
        )
        
        self.assertIsNotNone(config)
        self.assertEqual(config.honeypot_type, "ssh")
        self.assertEqual(config.listen_port, 22)
        self.assertTrue(config.enabled)
        self.assertTrue(config.adaptive)
        self.assertIn("OpenSSH_7.4", config.fake_services)
        self.assertEqual(self.orch.stats["honeypots_deployed"], 1)
    
    def test_configure_multiple_honeypots(self):
        """Test configuring multiple honeypots."""
        types = ["web", "ssh", "ftp", "database"]
        
        for i, hp_type in enumerate(types):
            config = self.orch.configure_honeypot(
                honeypot_type=hp_type,
                listen_ip="10.0.0.100",
                listen_port=8000 + i
            )
            self.assertEqual(config.honeypot_type, hp_type)
        
        self.assertEqual(len(self.orch.honeypots), 4)
    
    def test_prediction_export(self):
        """Test prediction data export."""
        # Generate prediction
        historical_data = [
            {
                "entity": "192.168.1.100",
                "attack_type": "XSS",
                "timestamp": time.time() - 3600,
                "severity": 0.7
            } for _ in range(5)
        ]
        
        predictions = self.orch.predict_threats(
            ThreatForecast.MEDIUM_TERM,
            historical_data
        )
        
        # Check export file exists
        latest_file = f"{self.test_export_dir}/predictions_latest.json"
        self.assertTrue(os.path.exists(latest_file))
        
        # Verify content
        with open(latest_file, 'r') as f:
            data = json.load(f)
        
        self.assertIn("predictions", data)
        self.assertEqual(data["forecast_horizon"], "24h")
    
    def test_response_export(self):
        """Test response data export."""
        response = self.orch.execute_automated_response(
            incident_id="INC-TEST",
            entity="192.168.1.100",
            threat_type="Test",
            severity="LOW",
            actions=[ResponseAction.ALERT_ONLY]
        )
        
        # Check server export
        server_file = f"server/json/responses/{response.response_id}.json"
        self.assertTrue(os.path.exists(server_file))
        
        # Check training export (should have at least one file)
        training_files = [f for f in os.listdir(self.test_export_dir) 
                         if f.startswith("response_")]
        self.assertGreater(len(training_files), 0)
    
    def test_topology_export(self):
        """Test network topology export."""
        nodes = [{"node_id": "test", "ip_address": "1.2.3.4"}]
        edges = []
        
        self.orch.update_network_topology(nodes, edges)
        
        # Check exports
        self.assertTrue(os.path.exists("server/json/network_topology.json"))
        self.assertTrue(os.path.exists(f"{self.test_export_dir}/topology_latest.json"))
    
    def test_get_statistics(self):
        """Test statistics retrieval."""
        # Perform some operations
        self.orch.create_alert_rule(
            name="Test",
            description="Test",
            conditions=[],
            actions=[ResponseAction.ALERT_ONLY],
            priority=5
        )
        
        self.orch.predict_threats(ThreatForecast.SHORT_TERM, [])
        
        self.orch.execute_automated_response(
            incident_id="INC-STAT",
            entity="1.2.3.4",
            threat_type="Test",
            severity="LOW",
            actions=[ResponseAction.ALERT_ONLY]
        )
        
        stats = self.orch.get_statistics()
        
        self.assertEqual(stats["total_rules"], 1)
        self.assertEqual(stats["active_rules"], 1)
        self.assertEqual(stats["predictions_made"], 1)
        self.assertEqual(stats["responses_executed"], 1)
        self.assertIn("response_success_rate", stats)
        self.assertIn("prediction_accuracy", stats)
    
    def test_rule_priority_ordering(self):
        """Test that rules are evaluated by priority."""
        # Create rules with different priorities
        self.orch.create_alert_rule(
            name="Low Priority",
            description="Test",
            conditions=[{"field": "test", "operator": "==", "value": 1}],
            actions=[ResponseAction.ALERT_ONLY],
            priority=3
        )
        
        self.orch.create_alert_rule(
            name="High Priority",
            description="Test",
            conditions=[{"field": "test", "operator": "==", "value": 1}],
            actions=[ResponseAction.BLOCK_IP],
            priority=9
        )
        
        context = {"test": 1}
        results = self.orch.evaluate_alert_rules(context)
        
        # Should have 2 results
        self.assertEqual(len(results), 2)
        
        # First result should be high priority
        self.assertEqual(results[0][0].name, "High Priority")
        self.assertEqual(results[1][0].name, "Low Priority")
    
    def test_disabled_rule_not_evaluated(self):
        """Test that disabled rules are not evaluated."""
        rule = self.orch.create_alert_rule(
            name="Disabled Rule",
            description="Test",
            conditions=[{"field": "test", "operator": "==", "value": 1}],
            actions=[ResponseAction.ALERT_ONLY],
            priority=5
        )
        
        # Disable rule
        rule.enabled = False
        
        context = {"test": 1}
        results = self.orch.evaluate_alert_rules(context)
        
        # Should return empty results since rule is disabled
        self.assertEqual(len(results), 0)
    
    def test_attack_history_tracking(self):
        """Test attack history sliding window."""
        # Add events to history
        for i in range(100):
            self.orch.attack_history.append({
                "entity": f"192.168.1.{i % 10}",
                "timestamp": time.time() - i,
                "attack_type": "test"
            })
        
        self.assertEqual(len(self.orch.attack_history), 100)
        
        # Add more to test maxlen
        for i in range(50):
            self.orch.attack_history.append({
                "entity": "test",
                "timestamp": time.time(),
                "attack_type": "test"
            })
        
        self.assertEqual(len(self.orch.attack_history), 150)


if __name__ == "__main__":
    unittest.main()
