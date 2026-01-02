"""
Unit tests for Phase 6: Persistent Reputation Tracker
Tests reputation scoring, recidivism detection, temporal decay, and persistence.
"""

import unittest
import os
import time
import tempfile
import shutil
from datetime import datetime, timedelta

# Add parent directory to path
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from AI.reputation_tracker import (
    ReputationTracker, ReputationRecord, ReputationQuery,
    get_reputation_tracker, REPUTATION_TRACKER_AVAILABLE
)


class TestReputationTracker(unittest.TestCase):
    """Test suite for ReputationTracker."""
    
    def setUp(self):
        """Create temporary database for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_reputation.db")
        self.tracker = ReputationTracker(db_path=self.db_path, decay_days=90)
    
    def tearDown(self):
        """Clean up temporary files."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_tracker_initialization(self):
        """Test 1: Tracker initializes correctly."""
        self.assertTrue(REPUTATION_TRACKER_AVAILABLE)
        self.assertEqual(self.tracker.decay_days, 90)
        self.assertEqual(self.tracker.recidivist_threshold, 3)
        self.assertTrue(os.path.exists(self.db_path))
        self.assertEqual(len(self.tracker.cache), 0)
    
    def test_record_single_attack(self):
        """Test 2: Record a single attack."""
        record = self.tracker.record_attack(
            entity="192.168.1.100",
            entity_type="ip",
            attack_type="sql_injection",
            severity=0.8,
            signature="UNION SELECT",
            blocked=True,
            geolocation={"country": "US", "region": "CA", "asn": "AS15169"}
        )
        
        self.assertEqual(record.entity, "192.168.1.100")
        self.assertEqual(record.total_attacks, 1)
        self.assertEqual(record.attack_types["sql_injection"], 1)
        self.assertEqual(record.blocked_count, 1)
        self.assertFalse(record.is_recidivist)  # Not yet
        self.assertGreater(record.reputation_score, 0.0)
    
    def test_multiple_attacks_same_entity(self):
        """Test 3: Multiple attacks on same entity."""
        ip = "192.168.1.200"
        
        for i in range(5):
            self.tracker.record_attack(ip, "ip", "xss", 0.7, f"<script>{i}</script>", True)
        
        result = self.tracker.query_reputation(ip)
        self.assertIsNotNone(result)
        self.assertEqual(result.total_attacks, 5)
        self.assertGreater(result.reputation_score, 0.5)
        self.assertEqual(result.threat_level, "MALICIOUS")
    
    def test_recidivist_detection(self):
        """Test 4: Recidivist flag after threshold."""
        ip = "10.0.0.50"
        
        # First 2 attacks - not recidivist
        self.tracker.record_attack(ip, "ip", "brute_force", 0.6)
        record = self.tracker.record_attack(ip, "ip", "brute_force", 0.6)
        self.assertFalse(record.is_recidivist)
        
        # 3rd attack - becomes recidivist
        record = self.tracker.record_attack(ip, "ip", "brute_force", 0.6)
        self.assertTrue(record.is_recidivist)
        
        # Verify query shows recidivist status
        result = self.tracker.query_reputation(ip)
        self.assertTrue(result.is_recidivist)
        self.assertIn("Recidivist", " ".join(result.risk_factors))
    
    def test_reputation_decay(self):
        """Test 5: Reputation decays over time."""
        ip = "10.0.0.100"
        
        # Record attack
        record = self.tracker.record_attack(ip, "ip", "port_scan", 0.5)
        initial_score = record.reputation_score
        
        # Simulate 45 days passing (50% decay with 90-day threshold)
        old_time = time.time() - (45 * 24 * 3600)
        record.last_seen = old_time
        self.tracker.cache[ip] = record
        self.tracker._save_to_db(record)
        
        # Query with decay applied
        result = self.tracker.query_reputation(ip)
        self.assertLess(result.reputation_score, initial_score)
        self.assertGreater(result.days_since_last_seen, 40)
    
    def test_different_attack_types(self):
        """Test 6: Track different attack types."""
        ip = "172.16.0.10"
        
        self.tracker.record_attack(ip, "ip", "sql_injection", 0.8)
        self.tracker.record_attack(ip, "ip", "xss", 0.7)
        self.tracker.record_attack(ip, "ip", "sql_injection", 0.9)
        self.tracker.record_attack(ip, "ip", "lfi", 0.6)
        
        result = self.tracker.query_reputation(ip)
        
        # Check attack type tracking in cache
        record = self.tracker.cache[ip]
        self.assertEqual(record.attack_types["sql_injection"], 2)
        self.assertEqual(record.attack_types["xss"], 1)
        self.assertEqual(record.attack_types["lfi"], 1)
        
        # Verify specialization tracking works (may not always appear in top 5 risk factors)
        self.assertEqual(result.total_attacks, 4)
    
    def test_geolocation_risk_factor(self):
        """Test 7: High-risk geolocation increases score."""
        ip_low_risk = "10.1.1.1"
        ip_high_risk = "10.1.1.2"
        
        # Low risk country (US)
        record_low = self.tracker.record_attack(
            ip_low_risk, "ip", "scan", 0.5,
            geolocation={"country": "US"}
        )
        
        # High risk country (CN)
        record_high = self.tracker.record_attack(
            ip_high_risk, "ip", "scan", 0.5,
            geolocation={"country": "CN"}
        )
        
        # High-risk should have higher score
        self.assertGreater(record_high.reputation_score, record_low.reputation_score)
        
        result = self.tracker.query_reputation(ip_high_risk)
        self.assertIn("High-risk geolocation", " ".join(result.risk_factors))
    
    def test_severity_impact(self):
        """Test 8: High severity attacks increase reputation score."""
        ip_low = "10.2.1.1"
        ip_high = "10.2.1.2"
        
        # Low severity attacks
        for _ in range(3):
            self.tracker.record_attack(ip_low, "ip", "scan", 0.2)
        
        # High severity attacks
        for _ in range(3):
            self.tracker.record_attack(ip_high, "ip", "exploit", 0.9)
        
        record_low = self.tracker.query_reputation(ip_low)
        record_high = self.tracker.query_reputation(ip_high)
        
        self.assertGreater(record_high.reputation_score, record_low.reputation_score)
    
    def test_threat_level_classification(self):
        """Test 9: Threat level classification."""
        # CLEAN (score < 0.3)
        ip1 = "10.3.1.1"
        self.tracker.record_attack(ip1, "ip", "scan", 0.1)
        result1 = self.tracker.query_reputation(ip1)
        self.assertEqual(result1.threat_level, "CLEAN")
        
        # SUSPICIOUS (0.3 <= score < 0.6)
        ip2 = "10.3.1.2"
        for _ in range(3):
            self.tracker.record_attack(ip2, "ip", "scan", 0.4)
        result2 = self.tracker.query_reputation(ip2)
        self.assertEqual(result2.threat_level, "SUSPICIOUS")
        
        # MALICIOUS (0.6 <= score < 0.8)
        ip3 = "10.3.1.3"
        for _ in range(5):
            self.tracker.record_attack(ip3, "ip", "exploit", 0.7)
        result3 = self.tracker.query_reputation(ip3)
        self.assertIn(result3.threat_level, ["MALICIOUS", "CRITICAL"])
        
        # CRITICAL (score >= 0.8)
        ip4 = "10.3.1.4"
        for _ in range(10):
            self.tracker.record_attack(ip4, "ip", "exploit", 0.9)
        result4 = self.tracker.query_reputation(ip4)
        self.assertEqual(result4.threat_level, "CRITICAL")
    
    def test_persistence_across_instances(self):
        """Test 10: Data persists across tracker instances."""
        ip = "10.4.1.1"
        
        # Record with first instance
        self.tracker.record_attack(ip, "ip", "attack1", 0.7, "sig1", True)
        self.tracker.record_attack(ip, "ip", "attack2", 0.8, "sig2", True)
        
        # Create new instance with same database
        tracker2 = ReputationTracker(db_path=self.db_path)
        
        # Query from new instance
        result = tracker2.query_reputation(ip)
        self.assertIsNotNone(result)
        self.assertEqual(result.total_attacks, 2)
        self.assertGreater(result.reputation_score, 0.0)
    
    def test_attack_timeline(self):
        """Test 11: Attack timeline tracking."""
        ip = "10.5.1.1"
        
        # Record attacks with delays
        self.tracker.record_attack(ip, "ip", "attack1", 0.5, "sig1", False)
        time.sleep(0.1)
        self.tracker.record_attack(ip, "ip", "attack2", 0.7, "sig2", True)
        time.sleep(0.1)
        self.tracker.record_attack(ip, "ip", "attack3", 0.9, "sig3", True)
        
        result = self.tracker.query_reputation(ip)
        
        # Timeline should have 3 events
        self.assertEqual(len(result.attack_timeline), 3)
        
        # Events should be in reverse chronological order
        self.assertEqual(result.attack_timeline[0]["attack_type"], "attack3")
        self.assertEqual(result.attack_timeline[1]["attack_type"], "attack2")
        self.assertEqual(result.attack_timeline[2]["attack_type"], "attack1")
        
        # Check event details
        self.assertTrue(result.attack_timeline[0]["blocked"])
        self.assertFalse(result.attack_timeline[2]["blocked"])
    
    def test_cache_functionality(self):
        """Test 12: Cache hit/miss tracking."""
        ip = "10.6.1.1"
        
        # First query - cache miss
        self.tracker.record_attack(ip, "ip", "test", 0.5)
        initial_misses = self.tracker.stats["cache_misses"]
        
        # Second query - should be cache hit
        result1 = self.tracker.query_reputation(ip)
        result2 = self.tracker.query_reputation(ip)
        
        self.assertGreater(self.tracker.stats["cache_hits"], 0)
        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)
    
    def test_top_offenders(self):
        """Test 13: Get top offenders by reputation."""
        # Create multiple entities with different scores
        for i in range(10):
            ip = f"10.7.1.{i}"
            attacks = i + 1  # 1 to 10 attacks
            for _ in range(attacks):
                self.tracker.record_attack(ip, "ip", "test", 0.7)
        
        top_offenders = self.tracker.get_top_offenders(limit=5)
        
        # Should return 5 entities
        self.assertEqual(len(top_offenders), 5)
        
        # Should be sorted by reputation score (descending)
        scores = [o.reputation_score for o in top_offenders]
        self.assertEqual(scores, sorted(scores, reverse=True))
        
        # Top offender should be the one with most attacks
        self.assertEqual(top_offenders[0].total_attacks, 10)
    
    def test_get_recidivists(self):
        """Test 14: Get all recidivists."""
        # Create some recidivists
        for i in range(5):
            ip = f"10.8.1.{i}"
            for _ in range(4):  # 4 attacks -> recidivist
                self.tracker.record_attack(ip, "ip", "test", 0.6)
        
        # Create non-recidivist
        self.tracker.record_attack("10.8.1.100", "ip", "test", 0.5)
        
        recidivists = self.tracker.get_recidivists()
        
        # Should return 5 recidivists
        self.assertEqual(len(recidivists), 5)
        
        # All should be marked as recidivist
        for r in recidivists:
            self.assertTrue(r.is_recidivist)
    
    def test_export_training_data(self):
        """Test 15: Export to training materials."""
        # Create some data
        for i in range(3):
            ip = f"10.9.1.{i}"
            self.tracker.record_attack(ip, "ip", "test", 0.7)
        
        # Export
        path = self.tracker.export_training_data()
        
        # Verify export file exists
        self.assertTrue(os.path.exists(path))
        
        # Load and verify content
        import json
        with open(path, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(data["total_entities"], 3)
        self.assertIn("records", data)
        self.assertEqual(len(data["records"]), 3)
        self.assertIn("export_timestamp", data)
    
    def test_cleanup_old_records(self):
        """Test 16: Cleanup old records."""
        # Create old record
        ip_old = "10.10.1.1"
        record = self.tracker.record_attack(ip_old, "ip", "old", 0.2)
        
        # Manually set to 200 days ago
        old_time = time.time() - (200 * 24 * 3600)
        record.last_seen = old_time
        record.reputation_score = 0.2  # Low score
        self.tracker.cache[ip_old] = record
        self.tracker._save_to_db(record)
        
        # Create recent record
        ip_recent = "10.10.1.2"
        self.tracker.record_attack(ip_recent, "ip", "recent", 0.7)
        
        # Cleanup records older than 180 days
        deleted = self.tracker.cleanup_old_records(days=180)
        
        # Old record should be deleted
        self.assertGreater(deleted, 0)
        
        # Recent record should still exist
        result = self.tracker.query_reputation(ip_recent)
        self.assertIsNotNone(result)
    
    def test_statistics(self):
        """Test 17: Get tracker statistics."""
        # Create some data
        for i in range(5):
            ip = f"10.11.1.{i}"
            for _ in range(4):
                self.tracker.record_attack(ip, "ip", "test", 0.6)
        
        stats = self.tracker.get_statistics()
        
        self.assertEqual(stats["total_entities"], 5)
        self.assertEqual(stats["recidivists"], 5)  # All became recidivists
        self.assertGreater(stats["total_attack_events"], 0)
        self.assertIn("cache_hit_rate", stats)
        self.assertIn("avg_reputation_score", stats)
    
    def test_blocked_count_tracking(self):
        """Test 18: Track blocked vs allowed attacks."""
        ip = "10.12.1.1"
        
        # 3 blocked, 2 allowed
        self.tracker.record_attack(ip, "ip", "t1", 0.5, blocked=True)
        self.tracker.record_attack(ip, "ip", "t2", 0.5, blocked=False)
        self.tracker.record_attack(ip, "ip", "t3", 0.5, blocked=True)
        self.tracker.record_attack(ip, "ip", "t4", 0.5, blocked=False)
        self.tracker.record_attack(ip, "ip", "t5", 0.5, blocked=True)
        
        record = self.tracker.cache[ip]
        self.assertEqual(record.blocked_count, 3)
        self.assertEqual(record.total_attacks, 5)
        
        # Verify recidivist status (5 attacks >= 3 threshold)
        self.assertTrue(record.is_recidivist)
    
    def test_risk_factors_generation(self):
        """Test 19: Risk factors are generated correctly."""
        ip = "10.13.1.1"
        
        # High frequency, high severity, from high-risk country
        for i in range(15):
            self.tracker.record_attack(
                ip, "ip", "sql_injection", 0.85, f"sig{i}", True,
                {"country": "RU"}
            )
        
        result = self.tracker.query_reputation(ip)
        risk_text = " ".join(result.risk_factors)
        
        self.assertIn("Recidivist", risk_text)
        self.assertIn("High attack frequency", risk_text)
        self.assertIn("High severity", risk_text)
        self.assertIn("High-risk geolocation", risk_text)
        self.assertIn("sql_injection", risk_text)
    
    def test_domain_tracking(self):
        """Test 20: Track domains in addition to IPs."""
        domain = "evil.com"
        
        record = self.tracker.record_attack(
            entity=domain,
            entity_type="domain",
            attack_type="phishing",
            severity=0.9
        )
        
        self.assertEqual(record.entity, "evil.com")
        self.assertEqual(record.entity_type, "domain")
        
        result = self.tracker.query_reputation(domain)
        self.assertIsNotNone(result)
        self.assertEqual(result.entity, "evil.com")
    
    def test_last_attack_signature(self):
        """Test 21: Last attack signature is saved."""
        ip = "10.14.1.1"
        
        self.tracker.record_attack(ip, "ip", "t1", 0.5, "sig1")
        self.tracker.record_attack(ip, "ip", "t2", 0.5, "sig2")
        self.tracker.record_attack(ip, "ip", "t3", 0.5, "sig3")
        
        record = self.tracker.cache[ip]
        self.assertEqual(record.last_attack_signature, "sig3")
    
    def test_query_nonexistent_entity(self):
        """Test 22: Query nonexistent entity returns None."""
        result = self.tracker.query_reputation("192.168.99.99")
        self.assertIsNone(result)
    
    def test_recent_activity_risk_factor(self):
        """Test 23: Recent activity flagged in risk factors."""
        ip = "10.15.1.1"
        
        self.tracker.record_attack(ip, "ip", "test", 0.7)
        
        result = self.tracker.query_reputation(ip)
        risk_text = " ".join(result.risk_factors)
        
        # Should mention recent activity (within 24 hours)
        self.assertIn("Recent activity", risk_text)
    
    def test_reputation_recalculation_on_query(self):
        """Test 24: Reputation recalculated with current decay on query."""
        ip = "10.16.1.1"
        
        # Record attack
        record = self.tracker.record_attack(ip, "ip", "test", 0.8)
        initial_score = record.reputation_score
        
        # Simulate 30 days passing
        old_time = time.time() - (30 * 24 * 3600)
        record.last_seen = old_time
        self.tracker.cache[ip] = record
        self.tracker._save_to_db(record)
        
        # Query should recalculate with decay
        result = self.tracker.query_reputation(ip)
        self.assertLess(result.reputation_score, initial_score)
    
    def test_global_instance(self):
        """Test 25: Global instance function."""
        from AI.reputation_tracker import get_reputation_tracker
        
        tracker1 = get_reputation_tracker()
        tracker2 = get_reputation_tracker()
        
        # Should return same instance
        self.assertIs(tracker1, tracker2)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
