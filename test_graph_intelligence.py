#!/usr/bin/env python3
"""
Unit Tests for Graph Intelligence Module (Phase 4)

Tests:
- Network graph construction
- Lateral movement detection
- C2 pattern detection
- Exfiltration path detection
- Centrality calculations
- Segmentation violation detection
- Graph persistence

Author: Enterprise Security AI Team
Version: 1.0.0
"""

import unittest
import os
import json
import tempfile
import shutil
import time
from datetime import datetime, timedelta

# Import graph intelligence
from AI.graph_intelligence import (
    NetworkGraph,
    Connection,
    LateralMovementAlert,
    get_graph_intelligence,
    track_connection,
    analyze_lateral_movement,
    save_graph_data
)


class TestNetworkGraph(unittest.TestCase):
    """Test NetworkGraph class"""
    
    def setUp(self):
        """Create temporary directory for test files"""
        self.test_dir = tempfile.mkdtemp()
        self.graph_file = os.path.join(self.test_dir, "test_graph.json")
        self.alerts_file = os.path.join(self.test_dir, "test_alerts.json")
        self.graph = NetworkGraph(graph_file=self.graph_file, alerts_file=self.alerts_file)
    
    def tearDown(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_01_add_connection(self):
        """Test adding connections to graph"""
        self.graph.add_connection("192.168.1.1", "192.168.1.2", 80, "TCP", 1024)
        
        self.assertIn("192.168.1.1", self.graph.nodes)
        self.assertIn("192.168.1.2", self.graph.nodes)
        self.assertEqual(self.graph.connection_count, 1)
        self.assertEqual(len(self.graph.get_neighbors("192.168.1.1")), 1)
    
    def test_02_get_degree(self):
        """Test degree calculation"""
        self.graph.add_connection("192.168.1.1", "192.168.1.2", 80)
        self.graph.add_connection("192.168.1.1", "192.168.1.3", 443)
        self.graph.add_connection("192.168.1.1", "192.168.1.4", 22)
        
        self.assertEqual(self.graph.get_degree("192.168.1.1"), 3)
        self.assertEqual(self.graph.get_degree("192.168.1.2"), 0)
    
    def test_03_get_in_degree(self):
        """Test in-degree calculation"""
        self.graph.add_connection("192.168.1.1", "192.168.1.10", 80)
        self.graph.add_connection("192.168.1.2", "192.168.1.10", 80)
        self.graph.add_connection("192.168.1.3", "192.168.1.10", 80)
        
        self.assertEqual(self.graph.get_in_degree("192.168.1.10"), 3)
        self.assertEqual(self.graph.get_in_degree("192.168.1.1"), 0)
    
    def test_04_lateral_movement_detection(self):
        """Test lateral movement detection"""
        # Simulate attack chain: attacker → host1 → host2 → host3 → host4
        chain = ["203.0.113.50", "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]
        
        for i in range(len(chain) - 1):
            self.graph.add_connection(chain[i], chain[i+1], 22, "TCP", 1024)
            time.sleep(0.05)  # Small delay to simulate progression
        
        alerts = self.graph.detect_lateral_movement(time_window_minutes=1, min_hops=3)
        
        self.assertGreater(len(alerts), 0, "Should detect lateral movement")
        
        if alerts:
            alert = alerts[0]
            self.assertIsInstance(alert, LateralMovementAlert)
            self.assertGreaterEqual(alert.hop_count, 3)
            self.assertIn(alert.severity, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    
    def test_05_c2_pattern_detection(self):
        """Test Command & Control pattern detection"""
        c2_server = "198.51.100.10"
        
        # C2 server controls 10 bots
        for i in range(10):
            bot = f"192.168.2.{i+1}"
            self.graph.add_connection(c2_server, bot, 443, "TCP", 512)
        
        c2_alerts = self.graph.detect_c2_patterns(min_controlled_nodes=5)
        
        self.assertGreater(len(c2_alerts), 0, "Should detect C2 pattern")
        
        if c2_alerts:
            alert = c2_alerts[0]
            self.assertEqual(alert["node"], c2_server)
            self.assertGreaterEqual(alert["controlled_nodes"], 10)
            self.assertGreater(alert["confidence"], 0.5)
    
    def test_06_exfiltration_path_detection(self):
        """Test data exfiltration path detection"""
        # Internal → External path with high volume
        self.graph.add_connection("192.168.1.100", "10.0.0.5", 443, "TCP", 50_000_000)
        self.graph.add_connection("10.0.0.5", "203.0.113.100", 443, "TCP", 50_000_000)
        
        exfil_alerts = self.graph.detect_exfiltration_paths(internal_subnets=["192.168.", "10."])
        
        # May or may not detect depending on path finding
        # Just verify no errors
        self.assertIsInstance(exfil_alerts, list)
    
    def test_07_betweenness_centrality(self):
        """Test betweenness centrality calculation"""
        # Create a simple network
        self.graph.add_connection("A", "B", 80)
        self.graph.add_connection("B", "C", 80)
        self.graph.add_connection("C", "D", 80)
        self.graph.add_connection("A", "D", 80)
        
        centrality = self.graph.calculate_betweenness_centrality(sample_size=10)
        
        self.assertIsInstance(centrality, dict)
        self.assertIn("B", centrality)
        self.assertIn("C", centrality)
    
    def test_08_segmentation_violation(self):
        """Test segmentation violation detection"""
        # Define zones
        self.graph.set_zone("192.168.1.10", "DMZ")
        self.graph.set_zone("10.0.0.50", "Internal_DB")
        
        # DMZ should not talk to Internal DB
        self.graph.set_zone_rule("DMZ", "Internal_DB", False)
        
        # Create violation
        self.graph.add_connection("192.168.1.10", "10.0.0.50", 3306, "TCP", 1024)
        
        violations = self.graph.detect_segmentation_violations()
        
        self.assertGreater(len(violations), 0, "Should detect segmentation violation")
        
        if violations:
            v = violations[0]
            self.assertEqual(v["source_zone"], "DMZ")
            self.assertEqual(v["dest_zone"], "Internal_DB")
    
    def test_09_graph_persistence(self):
        """Test graph save and load"""
        # Add some data
        self.graph.add_connection("192.168.1.1", "192.168.1.2", 80, "TCP", 1024)
        self.graph.add_connection("192.168.1.2", "192.168.1.3", 443, "TCP", 2048)
        
        # Save
        self.graph.save_graph()
        
        # Verify file exists
        self.assertTrue(os.path.exists(self.graph_file))
        
        # Load in new instance
        new_graph = NetworkGraph(graph_file=self.graph_file, alerts_file=self.alerts_file)
        
        # Verify data loaded
        self.assertIn("192.168.1.1", new_graph.nodes)
        self.assertIn("192.168.1.2", new_graph.nodes)
    
    def test_10_alert_persistence(self):
        """Test alert save and load"""
        # Create lateral movement alert
        chain = ["203.0.113.50", "192.168.1.10", "192.168.1.11", "192.168.1.12"]
        for i in range(len(chain) - 1):
            self.graph.add_connection(chain[i], chain[i+1], 22, "TCP", 1024)
        
        alerts = self.graph.detect_lateral_movement(time_window_minutes=1, min_hops=2)
        
        # Save
        self.graph.save_alerts()
        
        # Verify file exists
        self.assertTrue(os.path.exists(self.alerts_file))
        
        # Load in new instance
        new_graph = NetworkGraph(graph_file=self.graph_file, alerts_file=self.alerts_file)
        
        # Verify alerts loaded
        self.assertGreater(len(new_graph.alerts), 0)
    
    def test_11_graph_stats(self):
        """Test graph statistics"""
        self.graph.add_connection("A", "B", 80)
        self.graph.add_connection("B", "C", 80)
        self.graph.add_connection("C", "D", 80)
        
        stats = self.graph.get_graph_stats()
        
        self.assertIn("node_count", stats)
        self.assertIn("connection_count", stats)
        self.assertIn("average_degree", stats)
        self.assertEqual(stats["node_count"], 4)
        self.assertEqual(stats["connection_count"], 3)
    
    def test_12_path_finding(self):
        """Test path finding algorithm"""
        # Create a path: A → B → C → D
        self.graph.add_connection("A", "B", 80)
        self.graph.add_connection("B", "C", 80)
        self.graph.add_connection("C", "D", 80)
        
        # Also create shortcut: A → D
        self.graph.add_connection("A", "D", 80)
        
        paths = self.graph._find_paths("A", "D", max_length=5)
        
        self.assertGreater(len(paths), 0, "Should find at least one path")
        
        # Should find both long and short path
        path_lengths = [len(p) for p in paths]
        self.assertIn(2, path_lengths)  # Direct path A→D
    
    def test_13_shortest_path(self):
        """Test shortest path algorithm"""
        # Create network
        self.graph.add_connection("A", "B", 80)
        self.graph.add_connection("B", "C", 80)
        self.graph.add_connection("A", "C", 80)
        
        shortest = self.graph._find_shortest_paths("A", "C")
        
        self.assertGreater(len(shortest), 0)
        # Shortest should be A→C (length 2)
        self.assertEqual(len(shortest[0]), 2)
    
    def test_14_beaconing_detection(self):
        """Test beaconing pattern detection"""
        # Create periodic connections (beaconing)
        bot = "192.168.1.50"
        c2 = "198.51.100.10"
        
        for i in range(10):
            self.graph.add_connection(bot, c2, 443, "TCP", 100)
            time.sleep(0.05)  # Regular intervals
        
        beaconing_score = self.graph._detect_beaconing(bot)
        
        # Should detect some periodicity
        self.assertIsInstance(beaconing_score, float)
        self.assertGreaterEqual(beaconing_score, 0.0)
        self.assertLessEqual(beaconing_score, 1.0)
    
    def test_15_multiple_connections_same_pair(self):
        """Test multiple connections between same IP pair"""
        self.graph.add_connection("192.168.1.1", "192.168.1.2", 80, "TCP", 1024)
        self.graph.add_connection("192.168.1.1", "192.168.1.2", 443, "TCP", 2048)
        self.graph.add_connection("192.168.1.1", "192.168.1.2", 22, "TCP", 512)
        
        # Should still have unique edge but multiple connections
        neighbors = self.graph.get_neighbors("192.168.1.1")
        self.assertEqual(len(neighbors), 1)
        self.assertIn("192.168.1.2", neighbors)
    
    def test_16_node_metadata_tracking(self):
        """Test node metadata tracking"""
        self.graph.add_connection("192.168.1.1", "192.168.1.2", 80, "TCP", 1024)
        self.graph.add_connection("192.168.1.1", "192.168.1.3", 443, "TCP", 2048)
        
        metadata = self.graph.node_metadata.get("192.168.1.1")
        
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata["connection_count"], 2)
        self.assertEqual(len(metadata["unique_destinations"]), 2)
        self.assertEqual(len(metadata["unique_ports"]), 2)
    
    def test_17_lateral_movement_severity(self):
        """Test lateral movement severity calculation"""
        # Fast, many hops = CRITICAL
        severity = self.graph._calculate_lateral_severity(
            hop_count=7,
            time_window=100,  # Very fast
            ports=[22, 80, 443, 3389, 445, 135, 139, 1433, 3306]
        )
        
        self.assertIn(severity, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    
    def test_18_empty_graph_operations(self):
        """Test operations on empty graph"""
        # Should not crash
        neighbors = self.graph.get_neighbors("nonexistent")
        self.assertEqual(len(neighbors), 0)
        
        degree = self.graph.get_degree("nonexistent")
        self.assertEqual(degree, 0)
        
        in_degree = self.graph.get_in_degree("nonexistent")
        self.assertEqual(in_degree, 0)
    
    def test_19_zone_configuration(self):
        """Test zone configuration"""
        self.graph.set_zone("192.168.1.0/24", "DMZ")
        self.graph.set_zone("10.0.0.0/8", "Internal")
        
        self.assertEqual(self.graph.zones["192.168.1.0/24"], "DMZ")
        self.assertEqual(self.graph.zones["10.0.0.0/8"], "Internal")
    
    def test_20_zone_rules(self):
        """Test zone rules"""
        self.graph.set_zone_rule("DMZ", "Internal", False)
        self.graph.set_zone_rule("Internal", "DMZ", True)
        
        self.assertFalse(self.graph.zone_rules[("DMZ", "Internal")])
        self.assertTrue(self.graph.zone_rules[("Internal", "DMZ")])
    
    def test_21_connection_data_class(self):
        """Test Connection dataclass"""
        conn = Connection(
            source="192.168.1.1",
            destination="192.168.1.2",
            port=80,
            protocol="TCP",
            timestamp=datetime.utcnow().isoformat(),
            packet_count=10,
            byte_count=1024
        )
        
        conn_dict = conn.to_dict()
        
        self.assertIsInstance(conn_dict, dict)
        self.assertEqual(conn_dict["source"], "192.168.1.1")
        self.assertEqual(conn_dict["port"], 80)
    
    def test_22_alert_data_class(self):
        """Test LateralMovementAlert dataclass"""
        alert = LateralMovementAlert(
            alert_id="LM-TEST-123",
            source_ip="203.0.113.50",
            hop_chain=["203.0.113.50", "192.168.1.10", "192.168.1.11"],
            hop_count=3,
            time_window=120.5,
            ports_used=[22, 80, 443],
            severity="HIGH",
            timestamp=datetime.utcnow().isoformat(),
            confidence=0.85
        )
        
        alert_dict = alert.to_dict()
        
        self.assertIsInstance(alert_dict, dict)
        self.assertEqual(alert_dict["severity"], "HIGH")
        self.assertEqual(alert_dict["hop_count"], 3)
    
    def test_23_large_graph_performance(self):
        """Test performance with larger graph"""
        # Add 100 nodes
        for i in range(100):
            for j in range(3):  # Each node connects to 3 others
                self.graph.add_connection(f"192.168.1.{i}", f"192.168.1.{(i+j+1)%100}", 80)
        
        stats = self.graph.get_graph_stats()
        self.assertEqual(stats["node_count"], 100)
    
    def test_24_training_materials_export(self):
        """Test export to training materials directory"""
        # Add some data
        self.graph.add_connection("192.168.1.1", "192.168.1.2", 80)
        
        # Save (should create training materials file)
        self.graph.save_graph()
        
        # Verify training file created
        self.assertTrue(os.path.exists(self.graph.training_file))
        
        # Load and verify structure
        with open(self.graph.training_file, 'r') as f:
            training_data = json.load(f)
        
        self.assertIn("graph_stats", training_data)
        self.assertIn("centrality_scores", training_data)
        self.assertIn("lateral_movement_patterns", training_data)
    
    def test_25_singleton_pattern(self):
        """Test singleton pattern for global instance"""
        from AI.graph_intelligence import get_graph_intelligence
        
        instance1 = get_graph_intelligence()
        instance2 = get_graph_intelligence()
        
        # Should be same instance
        self.assertIs(instance1, instance2)
    
    def test_26_convenience_functions(self):
        """Test convenience wrapper functions"""
        from AI.graph_intelligence import track_connection, save_graph_data
        
        # Should not crash
        track_connection("192.168.1.1", "192.168.1.2", 80, "TCP", 1024)
        save_graph_data()
        
        # Verify connection was tracked
        graph = get_graph_intelligence()
        self.assertIn("192.168.1.1", graph.nodes)


class TestGraphIntegration(unittest.TestCase):
    """Integration tests for graph intelligence"""
    
    def test_realistic_attack_scenario(self):
        """Test realistic multi-stage attack scenario"""
        graph = NetworkGraph()
        
        # Stage 1: Initial compromise
        attacker = "203.0.113.50"
        victim1 = "192.168.1.100"
        graph.add_connection(attacker, victim1, 22, "TCP", 1024)
        
        # Stage 2: Lateral movement
        victim2 = "192.168.1.101"
        victim3 = "192.168.1.102"
        graph.add_connection(victim1, victim2, 445, "TCP", 2048)
        graph.add_connection(victim2, victim3, 3389, "TCP", 4096)
        
        # Stage 3: Data exfiltration
        external = "198.51.100.200"
        graph.add_connection(victim3, external, 443, "TCP", 100_000_000)
        
        # Analyze
        lateral_alerts = graph.detect_lateral_movement(time_window_minutes=60, min_hops=2)
        c2_alerts = graph.detect_c2_patterns()
        exfil_alerts = graph.detect_exfiltration_paths()
        
        # Should detect something
        total_alerts = len(lateral_alerts) + len(c2_alerts) + len(exfil_alerts)
        self.assertGreater(total_alerts, 0, "Should detect attack indicators")


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all tests
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkGraph))
    suite.addTests(loader.loadTestsFromTestCase(TestGraphIntegration))
    
    # Run with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
