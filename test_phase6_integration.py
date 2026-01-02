"""
Phase 6 Integration Test: Persistent Reputation Tracker
Tests real-world scenarios with persistent memory and cross-session intelligence.
"""

import unittest
import os
import sys
import tempfile
import shutil
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from AI.reputation_tracker import ReputationTracker


class TestPhase6Integration(unittest.TestCase):
    """Integration tests for Phase 6: Persistent Reputation Tracker."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "integration_test.db")
        self.tracker = ReputationTracker(db_path=self.db_path, decay_days=30)
    
    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_scenario_1_recidivist_detection(self):
        """
        Scenario 1: Recidivist Detection
        Attacker launches multiple attacks over time, becomes flagged as repeat offender.
        """
        print("\n=== Scenario 1: Recidivist Detection ===")
        attacker = "203.0.113.50"
        
        # Day 1: Initial reconnaissance
        print("Day 1: Port scanning detected")
        self.tracker.record_attack(attacker, "ip", "port_scan", 0.4, "", False)
        result = self.tracker.query_reputation(attacker)
        print(f"  Reputation: {result.reputation_score:.4f}, Level: {result.threat_level}")
        print(f"  Recidivist: {result.is_recidivist}")
        self.assertFalse(result.is_recidivist)
        # Clean or Suspicious depending on exact score
        self.assertIn(result.threat_level, ["CLEAN", "SUSPICIOUS"])
        
        # Day 2: SQL injection attempt
        print("\nDay 2: SQL injection attempt")
        time.sleep(0.1)
        self.tracker.record_attack(attacker, "ip", "sql_injection", 0.8, "UNION SELECT", True)
        result = self.tracker.query_reputation(attacker)
        print(f"  Reputation: {result.reputation_score:.4f}, Level: {result.threat_level}")
        print(f"  Recidivist: {result.is_recidivist}")
        self.assertFalse(result.is_recidivist)  # Still not recidivist (2 attacks)
        
        # Day 3: XSS attack - becomes recidivist
        print("\nDay 3: XSS attack (becomes recidivist)")
        time.sleep(0.1)
        self.tracker.record_attack(attacker, "ip", "xss", 0.7, "<script>alert(1)</script>", True)
        result = self.tracker.query_reputation(attacker)
        print(f"  Reputation: {result.reputation_score:.4f}, Level: {result.threat_level}")
        print(f"  Recidivist: {result.is_recidivist} ✓")
        print(f"  Total attacks: {result.total_attacks}")
        self.assertTrue(result.is_recidivist)
        self.assertIn("MALICIOUS", result.threat_level)
        
        # Verify risk factors
        print(f"\n  Risk Factors:")
        for factor in result.risk_factors:
            print(f"    - {factor}")
        self.assertIn("Recidivist", " ".join(result.risk_factors))
        
        print("\n✓ Recidivist detection working correctly")
    
    def test_scenario_2_reputation_decay(self):
        """
        Scenario 2: Reputation Decay
        Old threats decay over time if no new activity.
        """
        print("\n=== Scenario 2: Reputation Decay ===")
        ip = "198.51.100.25"
        
        # Initial high-severity attack
        print("Initial attack: High severity (0.9)")
        record = self.tracker.record_attack(ip, "ip", "exploit", 0.9, "CVE-2023-12345", True)
        initial_score = record.reputation_score
        print(f"  Initial reputation: {initial_score:.4f}")
        
        # Simulate 15 days passing (50% of 30-day decay threshold)
        print("\nSimulating 15 days passing...")
        old_time = time.time() - (15 * 24 * 3600)
        record.last_seen = old_time
        self.tracker.cache[ip] = record
        self.tracker._save_to_db(record)
        
        # Query with decay applied
        result = self.tracker.query_reputation(ip)
        decayed_score = result.reputation_score
        print(f"  After 15 days: {decayed_score:.4f}")
        print(f"  Decay factor: {(1 - decayed_score/initial_score)*100:.1f}%")
        
        self.assertLess(decayed_score, initial_score)
        self.assertGreater(result.days_since_last_seen, 14)
        
        print("\n✓ Reputation decay working correctly")
    
    def test_scenario_3_geolocation_risk_scoring(self):
        """
        Scenario 3: Geolocation Risk Scoring
        Attacks from high-risk countries receive higher threat scores.
        """
        print("\n=== Scenario 3: Geolocation Risk Scoring ===")
        
        # Attack from low-risk country
        ip_us = "192.0.2.10"
        print("Attack from US (low-risk)")
        record_us = self.tracker.record_attack(
            ip_us, "ip", "scan", 0.5, "",
            geolocation={"country": "US", "region": "California", "asn": "AS15169"}
        )
        print(f"  Reputation: {record_us.reputation_score:.4f}")
        
        # Identical attack from high-risk country
        ip_cn = "192.0.2.20"
        print("\nIdentical attack from CN (high-risk)")
        record_cn = self.tracker.record_attack(
            ip_cn, "ip", "scan", 0.5, "",
            geolocation={"country": "CN", "region": "Beijing", "asn": "AS4134"}
        )
        print(f"  Reputation: {record_cn.reputation_score:.4f}")
        
        # High-risk should have higher score
        print(f"\nRisk delta: +{(record_cn.reputation_score - record_us.reputation_score):.4f}")
        self.assertGreater(record_cn.reputation_score, record_us.reputation_score)
        
        result_cn = self.tracker.query_reputation(ip_cn)
        self.assertIn("High-risk geolocation", " ".join(result_cn.risk_factors))
        
        print("✓ Geolocation risk scoring working correctly")
    
    def test_scenario_4_cross_session_persistence(self):
        """
        Scenario 4: Cross-Session Persistence
        Data persists across tracker restarts (simulating system reboots).
        """
        print("\n=== Scenario 4: Cross-Session Persistence ===")
        attacker = "203.0.113.100"
        
        # Session 1: Record attacks
        print("Session 1: Recording 5 attacks")
        for i in range(5):
            self.tracker.record_attack(attacker, "ip", f"attack_{i}", 0.7 + i*0.05, f"sig_{i}", True)
        
        result1 = self.tracker.query_reputation(attacker)
        score1 = result1.reputation_score
        attacks1 = result1.total_attacks
        print(f"  Attacks recorded: {attacks1}")
        print(f"  Reputation: {score1:.4f}")
        print(f"  Threat level: {result1.threat_level}")
        
        # Simulate system restart (new tracker instance)
        print("\nSimulating system restart...")
        tracker2 = ReputationTracker(db_path=self.db_path, decay_days=30)
        
        # Session 2: Query from new instance
        print("Session 2: Querying from new instance")
        result2 = tracker2.query_reputation(attacker)
        score2 = result2.reputation_score
        attacks2 = result2.total_attacks
        print(f"  Attacks found: {attacks2}")
        print(f"  Reputation: {score2:.4f}")
        print(f"  Threat level: {result2.threat_level}")
        
        # Data should persist
        self.assertEqual(attacks1, attacks2)
        self.assertAlmostEqual(score1, score2, places=3)
        
        # Session 2: Add more attacks
        print("\nSession 2: Recording 3 more attacks")
        for i in range(3):
            tracker2.record_attack(attacker, "ip", f"attack_new_{i}", 0.8, f"new_sig_{i}", True)
        
        result3 = tracker2.query_reputation(attacker)
        print(f"  Total attacks now: {result3.total_attacks}")
        print(f"  New reputation: {result3.reputation_score:.4f}")
        
        self.assertEqual(result3.total_attacks, 8)
        
        print("\n✓ Cross-session persistence working correctly")
    
    def test_scenario_5_attack_timeline_reconstruction(self):
        """
        Scenario 5: Attack Timeline Reconstruction
        Detailed timeline shows attack progression over time.
        """
        print("\n=== Scenario 5: Attack Timeline Reconstruction ===")
        attacker = "198.51.100.75"
        
        # Simulate multi-stage attack
        stages = [
            ("reconnaissance", "port_scan", 0.3, False),
            ("exploitation", "sql_injection", 0.8, True),
            ("privilege_escalation", "lfi", 0.7, True),
            ("lateral_movement", "smb_exploit", 0.9, True),
            ("data_exfiltration", "ftp_upload", 0.9, True)
        ]
        
        print("Simulating multi-stage attack:")
        for stage_name, attack_type, severity, blocked in stages:
            time.sleep(0.05)  # Small delay to ensure chronological order
            self.tracker.record_attack(attacker, "ip", attack_type, severity, stage_name, blocked)
            print(f"  {stage_name}: {attack_type} (severity: {severity}, blocked: {blocked})")
        
        # Get timeline
        result = self.tracker.query_reputation(attacker)
        timeline = result.attack_timeline
        
        print(f"\nAttack Timeline ({len(timeline)} events):")
        for i, event in enumerate(reversed(timeline), 1):  # Chronological order
            timestamp = event['datetime']
            attack = event['attack_type']
            blocked_str = "BLOCKED" if event['blocked'] else "ALLOWED"
            print(f"  {i}. {timestamp}: {attack} [{blocked_str}]")
        
        # Verify timeline
        self.assertEqual(len(timeline), 5)
        self.assertEqual(timeline[0]['attack_type'], 'ftp_upload')  # Most recent
        self.assertEqual(timeline[-1]['attack_type'], 'port_scan')  # Oldest
        
        # Verify final threat level
        print(f"\nFinal Threat Assessment:")
        print(f"  Reputation: {result.reputation_score:.4f}")
        print(f"  Threat Level: {result.threat_level}")
        print(f"  Is Recidivist: {result.is_recidivist}")
        
        self.assertEqual(result.threat_level, "CRITICAL")
        self.assertTrue(result.is_recidivist)
        
        print("\n✓ Attack timeline reconstruction working correctly")
    
    def test_scenario_6_top_offenders_identification(self):
        """
        Scenario 6: Top Offenders Identification
        System identifies most malicious entities across all tracked IPs.
        """
        print("\n=== Scenario 6: Top Offenders Identification ===")
        
        # Create varying threat levels
        threats = [
            ("192.0.2.1", 2, 0.3),   # Low threat
            ("192.0.2.2", 5, 0.6),   # Medium threat
            ("192.0.2.3", 10, 0.8),  # High threat
            ("192.0.2.4", 15, 0.9),  # Critical threat
            ("192.0.2.5", 8, 0.7),   # High threat
            ("192.0.2.6", 3, 0.4),   # Low-medium threat
        ]
        
        print("Creating threats with varying severity:")
        for ip, attack_count, severity in threats:
            for i in range(attack_count):
                self.tracker.record_attack(ip, "ip", "attack", severity, f"sig_{i}", True)
            result = self.tracker.query_reputation(ip)
            print(f"  {ip}: {attack_count} attacks, severity {severity} → {result.threat_level}")
        
        # Get top 3 offenders
        print("\nTop 3 Offenders:")
        top_offenders = self.tracker.get_top_offenders(limit=3)
        
        for i, offender in enumerate(top_offenders, 1):
            print(f"  {i}. {offender.entity}")
            print(f"     Reputation: {offender.reputation_score:.4f}")
            print(f"     Attacks: {offender.total_attacks}")
            print(f"     Threat Level: {offender.threat_level}")
        
        # Verify top offender
        self.assertEqual(top_offenders[0].entity, "192.0.2.4")  # Most attacks
        self.assertEqual(top_offenders[0].total_attacks, 15)
        
        print("\n✓ Top offenders identification working correctly")
    
    def test_scenario_7_training_data_export(self):
        """
        Scenario 7: AI Training Data Export
        Reputation data exported to training materials for model improvement.
        """
        print("\n=== Scenario 7: AI Training Data Export ===")
        
        # Create diverse reputation data
        print("Creating diverse threat dataset:")
        test_data = [
            ("malicious1.com", "domain", 10, 0.9, True),
            ("192.0.2.50", "ip", 5, 0.7, True),
            ("192.0.2.51", "ip", 15, 0.95, True),
            ("benign.com", "domain", 1, 0.1, False),
        ]
        
        for entity, entity_type, attacks, severity, recidivist in test_data:
            for i in range(attacks):
                self.tracker.record_attack(entity, entity_type, "test", severity)
            result = self.tracker.query_reputation(entity)
            print(f"  {entity} ({entity_type}): {attacks} attacks, recidivist: {recidivist}")
        
        # Export training data
        print("\nExporting to training materials...")
        export_path = self.tracker.export_training_data()
        print(f"  Export path: {export_path}")
        
        # Verify export
        self.assertTrue(os.path.exists(export_path))
        
        import json
        with open(export_path, 'r') as f:
            export_data = json.load(f)
        
        print(f"\nExport Statistics:")
        print(f"  Total entities: {export_data['total_entities']}")
        print(f"  Recidivists: {export_data['recidivists']}")
        print(f"  Avg reputation: {export_data['avg_reputation_score']:.4f}")
        
        self.assertEqual(export_data['total_entities'], 4)
        self.assertEqual(export_data['recidivists'], 3)  # 3 entities with >=3 attacks
        
        # Verify records structure
        print(f"\nSample Record:")
        sample = export_data['records'][0]
        print(f"  Entity: {sample['entity']}")
        print(f"  Attacks: {sample['total_attacks']}")
        print(f"  Reputation: {sample['reputation_score']:.4f}")
        print(f"  Recidivist: {sample['is_recidivist']}")
        
        self.assertIn('entity', sample)
        self.assertIn('reputation_score', sample)
        self.assertIn('attack_types', sample)
        
        print("\n✓ Training data export working correctly")
    
    def test_scenario_8_old_record_cleanup(self):
        """
        Scenario 8: Old Record Cleanup
        System automatically purges stale records to maintain performance.
        """
        print("\n=== Scenario 8: Old Record Cleanup ===")
        
        # Create old and recent records
        print("Creating test records:")
        
        # Recent records (should be kept)
        recent_ips = ["10.0.1.1", "10.0.1.2", "10.0.1.3"]
        for ip in recent_ips:
            self.tracker.record_attack(ip, "ip", "recent", 0.7)
        print(f"  Created {len(recent_ips)} recent records (high threat)")
        
        # Old, low-threat records (should be deleted)
        old_ips = ["10.0.2.1", "10.0.2.2"]
        for ip in old_ips:
            record = self.tracker.record_attack(ip, "ip", "old", 0.2)
            # Set to 200 days ago
            old_time = time.time() - (200 * 24 * 3600)
            record.last_seen = old_time
            record.reputation_score = 0.2
            self.tracker.cache[ip] = record
            self.tracker._save_to_db(record)
        print(f"  Created {len(old_ips)} old records (200 days, low threat)")
        
        # Check initial count
        stats_before = self.tracker.get_statistics()
        print(f"\nBefore cleanup:")
        print(f"  Total entities: {stats_before['total_entities']}")
        
        # Cleanup records older than 180 days with low score
        print("\nCleaning up records older than 180 days...")
        deleted = self.tracker.cleanup_old_records(days=180)
        print(f"  Deleted: {deleted} records")
        
        # Check after cleanup
        stats_after = self.tracker.get_statistics()
        print(f"\nAfter cleanup:")
        print(f"  Total entities: {stats_after['total_entities']}")
        
        # Verify old records deleted
        self.assertEqual(deleted, 2)
        self.assertEqual(stats_after['total_entities'], 3)
        
        # Verify recent records still exist
        for ip in recent_ips:
            result = self.tracker.query_reputation(ip)
            self.assertIsNotNone(result)
            print(f"  {ip} still exists ✓")
        
        print("\n✓ Old record cleanup working correctly")


if __name__ == "__main__":
    print("=" * 70)
    print("Phase 6 Integration Test: Persistent Reputation Tracker")
    print("=" * 70)
    
    # Run tests
    unittest.main(verbosity=2)
