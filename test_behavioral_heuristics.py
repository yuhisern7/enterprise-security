#!/usr/bin/env python3
"""
Unit Tests for Behavioral Heuristics Engine
Tests each metric calculation and risk scoring logic.
"""

import unittest
import time
from AI.behavioral_heuristics import (
    BehavioralHeuristics,
    BehaviorMetrics,
    get_behavioral_heuristics
)


class TestBehavioralHeuristics(unittest.TestCase):
    """Test behavioral heuristics engine"""
    
    def setUp(self):
        """Create fresh instance for each test"""
        import os
        os.makedirs('/tmp/test_behavioral', exist_ok=True)
        self.bh = BehavioralHeuristics(storage_dir='/tmp/test_behavioral')
        self.test_ip = "192.168.1.100"
    
    def tearDown(self):
        """Cleanup"""
        import os
        if os.path.exists('/tmp/test_behavioral/behavioral_metrics.json'):
            os.remove('/tmp/test_behavioral/behavioral_metrics.json')
    
    def test_basic_connection_tracking(self):
        """Test basic connection event tracking"""
        self.bh.track_connection(self.test_ip, dest_port=80, protocol='tcp')
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        self.assertIsNotNone(metrics)
        self.assertEqual(metrics.entity_id, self.test_ip)
        self.assertEqual(metrics.tcp_count, 1)
        self.assertEqual(metrics.connection_count_1min, 1)
    
    def test_connection_rate_detection(self):
        """Test high connection rate detection"""
        # Simulate 70 connections in 1 minute
        for _ in range(70):
            self.bh.track_connection(self.test_ip, dest_port=80)
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        self.assertGreater(metrics.connection_count_1min, 60)
        self.assertGreater(metrics.heuristic_score, 0.1)
        self.assertTrue(any('High conn rate' in rf for rf in metrics.risk_factors))
    
    def test_port_scanning_detection(self):
        """Test port scanning behavior (high port entropy)"""
        # Access many different ports
        for port in range(1, 100):
            self.bh.track_connection(self.test_ip, dest_port=port)
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        self.assertGreater(metrics.port_entropy, 4.0)
        self.assertGreater(metrics.heuristic_score, 0.0)
        self.assertTrue(any('Port scanning' in rf for rf in metrics.risk_factors))
    
    def test_auth_failure_tracking(self):
        """Test authentication failure ratio calculation"""
        # 6 failures out of 10 attempts = 60% (>50% threshold)
        for _ in range(4):
            self.bh.track_auth_attempt(self.test_ip, success=True)
        for _ in range(6):
            self.bh.track_auth_attempt(self.test_ip, success=False)
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        self.assertEqual(metrics.auth_attempts, 10)
        self.assertEqual(metrics.auth_failures, 6)
        self.assertAlmostEqual(metrics.auth_failure_ratio, 0.6, places=2)
        self.assertGreater(metrics.heuristic_score, 0.0)
    
    def test_retry_frequency_tracking(self):
        """Test retry frequency calculation"""
        self.bh.track_connection(self.test_ip)
        
        # Simulate 15 retries
        for _ in range(15):
            self.bh.track_retry(self.test_ip)
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        self.assertEqual(metrics.retry_count, 15)
        self.assertGreater(metrics.retry_frequency, 0.0)
    
    def test_fan_out_detection(self):
        """Test fan-out (lateral movement) detection"""
        # Contact 60 different IPs
        for i in range(60):
            self.bh.track_connection(
                self.test_ip,
                dest_ip=f"10.0.0.{i}",
                dest_port=80
            )
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        self.assertEqual(metrics.fan_out, 60)
        self.assertGreater(metrics.heuristic_score, 0.0)
        self.assertTrue(any('fan-out' in rf for rf in metrics.risk_factors))
    
    def test_fan_in_detection(self):
        """Test fan-in (port hopping) detection"""
        # Use 25 different source ports
        for port in range(10000, 10025):
            self.bh.track_connection(
                self.test_ip,
                src_port=port,
                dest_port=80
            )
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        self.assertEqual(metrics.fan_in, 25)
        self.assertGreater(metrics.heuristic_score, 0.0)
        self.assertTrue(any('Port hopping' in rf for rf in metrics.risk_factors))
    
    def test_protocol_tracking(self):
        """Test protocol distribution tracking"""
        self.bh.track_connection(self.test_ip, protocol='tcp')
        self.bh.track_connection(self.test_ip, protocol='tcp')
        self.bh.track_connection(self.test_ip, protocol='udp')
        self.bh.track_connection(self.test_ip, protocol='icmp')
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        self.assertEqual(metrics.tcp_count, 2)
        self.assertEqual(metrics.udp_count, 1)
        self.assertEqual(metrics.icmp_count, 1)
    
    def test_timing_variance_calculation(self):
        """Test timing variance detection"""
        # Irregular timing pattern
        intervals = [0.1, 0.5, 0.05, 1.0, 0.2]
        base_time = time.time()
        
        for i, interval in enumerate(intervals):
            # Manually inject timing events
            self.bh.track_connection(self.test_ip)
            if i > 0:
                time.sleep(0.01)  # Small delay to create variance
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        # Timing variance should be calculated
        self.assertGreaterEqual(metrics.timing_variance, 0.0)
    
    def test_payload_size_tracking(self):
        """Test payload size statistics"""
        sizes = [100, 200, 150, 180, 120]
        for size in sizes:
            self.bh.track_connection(self.test_ip, payload_size=size)
        
        metrics = self.bh.get_entity_metrics(self.test_ip)
        expected_avg = sum(sizes) / len(sizes)
        self.assertAlmostEqual(metrics.avg_payload_size, expected_avg, places=1)
    
    def test_risk_score_multi_signal(self):
        """Test that high risk requires multiple signals"""
        # Single suspicious behavior should have moderate score
        for _ in range(70):
            self.bh.track_connection(self.test_ip, dest_port=80)
        
        single_signal_score = self.bh.get_entity_metrics(self.test_ip).heuristic_score
        
        # Add more suspicious behaviors
        for _ in range(10):
            self.bh.track_retry(self.test_ip)
        
        for _ in range(8):
            self.bh.track_auth_attempt(self.test_ip, success=False)
        
        multi_signal_score = self.bh.get_entity_metrics(self.test_ip).heuristic_score
        
        # Multi-signal should have higher score
        self.assertGreater(multi_signal_score, single_signal_score)
    
    def test_get_high_risk_entities(self):
        """Test filtering high-risk entities"""
        # Create benign entity
        self.bh.track_connection("10.0.0.1", dest_port=80)
        
        # Create high-risk entity with multiple suspicious behaviors
        # High connection rate + port scanning + retries
        for port in range(1, 150):  # Port scanning (high entropy)
            self.bh.track_connection("10.0.0.2", dest_port=port)
        
        for _ in range(20):  # High retries
            self.bh.track_retry("10.0.0.2")
        
        for _ in range(50):  # High fan-out
            self.bh.track_connection("10.0.0.2", dest_ip=f"192.168.1.{_}")
        
        high_risk = self.bh.get_high_risk_entities(threshold=0.2)
        self.assertGreater(len(high_risk), 0)
        self.assertTrue(any(e.entity_id == "10.0.0.2" for e in high_risk))
    
    def test_entity_cleanup(self):
        """Test old entity cleanup"""
        # Track connection
        self.bh.track_connection(self.test_ip)
        self.assertEqual(len(self.bh.entities), 1)
        
        # Manually set last_seen to old time
        self.bh.entities[self.test_ip].last_seen = time.time() - 7200  # 2 hours ago
        
        # Cleanup (entities older than 1 hour)
        removed = self.bh.cleanup_old_entities(max_age_seconds=3600)
        self.assertEqual(removed, 1)
        self.assertEqual(len(self.bh.entities), 0)
    
    def test_persistence(self):
        """Test save/load metrics"""
        # Track some activity
        for _ in range(10):
            self.bh.track_connection(self.test_ip, dest_port=80)
        
        # Save
        self.assertTrue(self.bh.save_metrics())
        
        # Create new instance and load
        bh2 = BehavioralHeuristics(storage_dir='/tmp/test_behavioral')
        self.assertIn(self.test_ip, bh2.entities)
        self.assertEqual(bh2.entities[self.test_ip].tcp_count, 10)
    
    def test_stats_generation(self):
        """Test overall statistics"""
        # Track multiple entities
        for i in range(5):
            self.bh.track_connection(f"10.0.0.{i}", dest_port=80)
        
        stats = self.bh.get_stats()
        self.assertEqual(stats['total_entities'], 5)
        self.assertGreaterEqual(stats['avg_risk_score'], 0.0)
        self.assertLessEqual(stats['avg_risk_score'], 1.0)


class TestConvenienceFunctions(unittest.TestCase):
    """Test module-level convenience functions"""
    
    def test_global_instance(self):
        """Test global instance creation"""
        bh1 = get_behavioral_heuristics()
        bh2 = get_behavioral_heuristics()
        self.assertIs(bh1, bh2)  # Should be same instance
    
    def test_convenience_track_connection(self):
        """Test convenience function for tracking connections"""
        from AI.behavioral_heuristics import track_connection, get_entity_risk_score
        
        track_connection("192.168.1.50", dest_port=443, protocol='tcp')
        score = get_entity_risk_score("192.168.1.50")
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


if __name__ == '__main__':
    unittest.main()
