#!/usr/bin/env python3
"""
Unit Tests for Meta Decision Engine (Phase 5)

Tests:
- Weighted voting calculations
- Signal aggregation
- Consensus detection
- Threat level determination
- Configuration management
- Performance metrics

Author: Enterprise Security AI Team
Version: 1.0.0
"""

import unittest
import os
import json
import tempfile
import shutil
from datetime import datetime

from AI.meta_decision_engine import (
    MetaDecisionEngine,
    DetectionSignal,
    EnsembleDecision,
    ThreatLevel,
    SignalType,
    get_meta_engine,
    make_decision,
    get_stats
)


class TestDetectionSignal(unittest.TestCase):
    """Test DetectionSignal dataclass"""
    
    def test_01_signal_creation(self):
        """Test creating detection signal"""
        signal = DetectionSignal(
            signal_type=SignalType.SIGNATURE,
            is_threat=True,
            confidence=0.95,
            threat_level=ThreatLevel.CRITICAL,
            details="SQL injection detected",
            timestamp=datetime.utcnow().isoformat()
        )
        
        self.assertEqual(signal.signal_type, SignalType.SIGNATURE)
        self.assertTrue(signal.is_threat)
        self.assertEqual(signal.confidence, 0.95)
        self.assertEqual(signal.threat_level, ThreatLevel.CRITICAL)
    
    def test_02_signal_to_dict(self):
        """Test signal serialization"""
        signal = DetectionSignal(
            signal_type=SignalType.BEHAVIORAL,
            is_threat=False,
            confidence=0.60,
            threat_level=ThreatLevel.SAFE,
            details="Normal behavior",
            timestamp=datetime.utcnow().isoformat()
        )
        
        signal_dict = signal.to_dict()
        
        self.assertIsInstance(signal_dict, dict)
        self.assertEqual(signal_dict["signal_type"], "behavioral")
        self.assertFalse(signal_dict["is_threat"])
        self.assertEqual(signal_dict["confidence"], 0.60)


class TestMetaDecisionEngine(unittest.TestCase):
    """Test MetaDecisionEngine class"""
    
    def setUp(self):
        """Create temporary directory for test files"""
        self.test_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.test_dir, "test_config.json")
        self.engine = MetaDecisionEngine(config_file=self.config_file)
    
    def tearDown(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_03_engine_initialization(self):
        """Test engine initialization"""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.threat_threshold, 0.50)
        self.assertEqual(self.engine.block_threshold, 0.75)
        self.assertIn(SignalType.SIGNATURE, self.engine.signal_weights)
    
    def test_04_empty_signals(self):
        """Test decision with no signals"""
        decision = self.engine.add_signal([], "192.168.1.1", "/test")
        
        self.assertFalse(decision.is_threat)
        self.assertEqual(decision.threat_level, ThreatLevel.SAFE)
        self.assertEqual(decision.total_signals, 0)
        self.assertFalse(decision.should_block)
    
    def test_05_single_threat_signal(self):
        """Test decision with single threat signal"""
        signals = [
            DetectionSignal(
                signal_type=SignalType.SIGNATURE,
                is_threat=True,
                confidence=0.95,
                threat_level=ThreatLevel.CRITICAL,
                details="SQL injection",
                timestamp=datetime.utcnow().isoformat()
            )
        ]
        
        decision = self.engine.add_signal(signals, "203.0.113.50", "/admin")
        
        self.assertTrue(decision.is_threat)
        self.assertEqual(decision.total_signals, 1)
        self.assertEqual(decision.threat_signals, 1)
        self.assertEqual(decision.safe_signals, 0)
        self.assertTrue(decision.unanimous_verdict)
    
    def test_06_single_safe_signal(self):
        """Test decision with single safe signal"""
        signals = [
            DetectionSignal(
                signal_type=SignalType.ML_ANOMALY,
                is_threat=False,
                confidence=0.80,
                threat_level=ThreatLevel.SAFE,
                details="Normal traffic",
                timestamp=datetime.utcnow().isoformat()
            )
        ]
        
        decision = self.engine.add_signal(signals, "192.168.1.1", "/api/status")
        
        self.assertFalse(decision.is_threat)
        self.assertEqual(decision.safe_signals, 1)
        self.assertTrue(decision.unanimous_verdict)
    
    def test_07_mixed_signals_threat_majority(self):
        """Test decision with mixed signals, threat majority"""
        signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, 
                          "SQL injection", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.BEHAVIORAL, True, 0.75, ThreatLevel.DANGEROUS,
                          "Suspicious behavior", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.ML_ANOMALY, False, 0.60, ThreatLevel.SAFE,
                          "Normal pattern", datetime.utcnow().isoformat())
        ]
        
        decision = self.engine.add_signal(signals, "203.0.113.50", "/admin")
        
        self.assertTrue(decision.is_threat)
        self.assertEqual(decision.threat_signals, 2)
        self.assertEqual(decision.safe_signals, 1)
        self.assertFalse(decision.unanimous_verdict)
    
    def test_08_mixed_signals_safe_majority(self):
        """Test decision with mixed signals, safe majority"""
        signals = [
            DetectionSignal(SignalType.ML_ANOMALY, False, 0.80, ThreatLevel.SAFE,
                          "Normal", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.ML_CLASSIFICATION, False, 0.85, ThreatLevel.SAFE,
                          "Safe traffic", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.VPN_TOR, True, 0.50, ThreatLevel.SUSPICIOUS,
                          "VPN detected", datetime.utcnow().isoformat())
        ]
        
        decision = self.engine.add_signal(signals, "192.168.1.1", "/api/data")
        
        self.assertFalse(decision.is_threat)
        self.assertEqual(decision.safe_signals, 2)
        self.assertEqual(decision.threat_signals, 1)
    
    def test_09_weighted_vote_calculation(self):
        """Test weighted voting calculation"""
        signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.90, ThreatLevel.CRITICAL,
                          "Attack detected", datetime.utcnow().isoformat()),
        ]
        
        score = self.engine._calculate_weighted_vote(signals)
        
        # Should be close to: 0.90 (weight) * 0.90 (confidence) / 0.90 (total weight)
        self.assertGreater(score, 0.8)
        self.assertLessEqual(score, 1.0)
    
    def test_10_threat_level_determination(self):
        """Test threat level determination"""
        level_low = self.engine._determine_threat_level(0.2, [])
        level_medium = self.engine._determine_threat_level(0.55, [])
        level_high = self.engine._determine_threat_level(0.75, [])
        level_critical = self.engine._determine_threat_level(0.95, [])
        
        self.assertEqual(level_low, ThreatLevel.SAFE)
        self.assertIn(level_medium, [ThreatLevel.SUSPICIOUS, ThreatLevel.DANGEROUS])
        self.assertIn(level_high, [ThreatLevel.DANGEROUS, ThreatLevel.CRITICAL])
        self.assertEqual(level_critical, ThreatLevel.CRITICAL)
    
    def test_11_strong_consensus_detection(self):
        """Test strong consensus detection"""
        # 3 threats, 1 safe = 75% agreement (not strong)
        signals_weak = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.9, ThreatLevel.CRITICAL, "T1", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.BEHAVIORAL, True, 0.8, ThreatLevel.DANGEROUS, "T2", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.SEQUENCE, True, 0.85, ThreatLevel.DANGEROUS, "T3", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.ML_ANOMALY, False, 0.6, ThreatLevel.SAFE, "S1", datetime.utcnow().isoformat())
        ]
        
        has_consensus = self.engine._check_strong_consensus(signals_weak, is_threat=True)
        self.assertFalse(has_consensus)
        
        # 4 threats, 1 safe = 80% agreement (strong)
        signals_strong = signals_weak + [
            DetectionSignal(SignalType.GRAPH, True, 0.88, ThreatLevel.CRITICAL, "T4", datetime.utcnow().isoformat())
        ]
        
        has_strong = self.engine._check_strong_consensus(signals_strong, is_threat=True)
        self.assertTrue(has_strong)
    
    def test_12_unanimous_verdict(self):
        """Test unanimous verdict detection"""
        # All threat signals
        all_threats = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.BEHAVIORAL, True, 0.80, ThreatLevel.DANGEROUS, "T", datetime.utcnow().isoformat())
        ]
        
        decision_threat = self.engine.add_signal(all_threats, "203.0.113.50", "/attack")
        self.assertTrue(decision_threat.unanimous_verdict)
        
        # All safe signals
        all_safe = [
            DetectionSignal(SignalType.ML_ANOMALY, False, 0.85, ThreatLevel.SAFE, "S", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.ML_CLASSIFICATION, False, 0.90, ThreatLevel.SAFE, "S", datetime.utcnow().isoformat())
        ]
        
        decision_safe = self.engine.add_signal(all_safe, "192.168.1.1", "/normal")
        self.assertTrue(decision_safe.unanimous_verdict)
    
    def test_13_primary_threats_extraction(self):
        """Test extraction of primary threats"""
        signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL,
                          "SQL injection detected. Blocking IP.", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.BEHAVIORAL, True, 0.80, ThreatLevel.DANGEROUS,
                          "Brute force attempt detected. Rate limiting.", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.GRAPH, True, 0.88, ThreatLevel.CRITICAL,
                          "Lateral movement detected. 4 hop chain.", datetime.utcnow().isoformat())
        ]
        
        decision = self.engine.add_signal(signals, "203.0.113.50", "/admin")
        
        self.assertEqual(len(decision.primary_threats), 3)
        self.assertTrue(any("SQL injection" in t for t in decision.primary_threats))
        self.assertTrue(any("SIGNATURE" in t for t in decision.primary_threats))
    
    def test_14_auto_block_threshold(self):
        """Test auto-block threshold"""
        # High confidence threat signals
        high_threat_signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.98, ThreatLevel.CRITICAL, "T1", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.THREAT_INTEL, True, 0.95, ThreatLevel.CRITICAL, "T2", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.GRAPH, True, 0.92, ThreatLevel.CRITICAL, "T3", datetime.utcnow().isoformat())
        ]
        
        decision = self.engine.add_signal(high_threat_signals, "203.0.113.50", "/attack")
        
        # Should auto-block with high threat score
        self.assertTrue(decision.should_block)
        self.assertGreater(decision.weighted_vote_score, 0.75)
    
    def test_15_metrics_tracking(self):
        """Test metrics tracking"""
        initial_decisions = self.engine.metrics["total_decisions"]
        
        # Make a few decisions
        signals_threat = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat())
        ]
        signals_safe = [
            DetectionSignal(SignalType.ML_ANOMALY, False, 0.80, ThreatLevel.SAFE, "S", datetime.utcnow().isoformat())
        ]
        
        self.engine.add_signal(signals_threat, "203.0.113.50", "/attack")
        self.engine.add_signal(signals_safe, "192.168.1.1", "/normal")
        
        self.assertEqual(self.engine.metrics["total_decisions"], initial_decisions + 2)
        self.assertGreater(self.engine.metrics["threats_detected"], 0)
        self.assertGreater(self.engine.metrics["safe_classified"], 0)
    
    def test_16_config_save_load(self):
        """Test configuration save and load"""
        # Modify config
        self.engine.threat_threshold = 0.60
        self.engine.block_threshold = 0.80
        self.engine.save_config()
        
        # Load in new instance
        new_engine = MetaDecisionEngine(config_file=self.config_file)
        
        self.assertEqual(new_engine.threat_threshold, 0.60)
        self.assertEqual(new_engine.block_threshold, 0.80)
    
    def test_17_signal_weight_adjustment(self):
        """Test adjusting signal weights"""
        old_weight = self.engine.signal_weights[SignalType.SIGNATURE]
        new_weight = 0.85
        
        self.engine.adjust_signal_weight(SignalType.SIGNATURE, new_weight)
        
        self.assertEqual(self.engine.signal_weights[SignalType.SIGNATURE], new_weight)
        self.assertNotEqual(self.engine.signal_weights[SignalType.SIGNATURE], old_weight)
    
    def test_18_invalid_weight_adjustment(self):
        """Test invalid weight adjustment"""
        old_weight = self.engine.signal_weights[SignalType.BEHAVIORAL]
        
        # Try invalid weight
        self.engine.adjust_signal_weight(SignalType.BEHAVIORAL, 1.5)
        
        # Should remain unchanged
        self.assertEqual(self.engine.signal_weights[SignalType.BEHAVIORAL], old_weight)
    
    def test_19_decision_history(self):
        """Test decision history tracking"""
        initial_history = len(self.engine.decision_history)
        
        signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat())
        ]
        
        self.engine.add_signal(signals, "203.0.113.50", "/test")
        
        self.assertEqual(len(self.engine.decision_history), initial_history + 1)
    
    def test_20_get_stats(self):
        """Test statistics retrieval"""
        stats = self.engine.get_stats()
        
        self.assertIn("metrics", stats)
        self.assertIn("config", stats)
        self.assertIn("history_size", stats)
        self.assertIn("total_decisions", stats["metrics"])
    
    def test_21_signal_performance_tracking(self):
        """Test signal performance analysis"""
        # Make some decisions
        for i in range(5):
            signals = [
                DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat()),
                DetectionSignal(SignalType.ML_ANOMALY, False, 0.70, ThreatLevel.SAFE, "S", datetime.utcnow().isoformat())
            ]
            self.engine.add_signal(signals, f"192.168.1.{i}", "/test")
        
        performance = self.engine.get_signal_performance()
        
        self.assertIn("signature", performance)
        self.assertEqual(performance["signature"]["total_activations"], 5)
        self.assertEqual(performance["signature"]["threat_activations"], 5)
    
    def test_22_decision_serialization(self):
        """Test decision serialization"""
        signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat())
        ]
        
        decision = self.engine.add_signal(signals, "203.0.113.50", "/test")
        decision_dict = decision.to_dict()
        
        self.assertIsInstance(decision_dict, dict)
        self.assertEqual(decision_dict["ip_address"], "203.0.113.50")
        self.assertTrue(decision_dict["is_threat"])
        self.assertIn("signals", decision_dict)
    
    def test_23_aggregate_confidence_calculation(self):
        """Test aggregate confidence calculation"""
        # High confidence aligned signals
        high_conf_signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.THREAT_INTEL, True, 0.98, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat())
        ]
        
        decision_high = self.engine.add_signal(high_conf_signals, "203.0.113.50", "/test")
        self.assertGreater(decision_high.confidence, 0.85)
        
        # Low confidence signals
        low_conf_signals = [
            DetectionSignal(SignalType.VPN_TOR, True, 0.55, ThreatLevel.SUSPICIOUS, "T", datetime.utcnow().isoformat())
        ]
        
        decision_low = self.engine.add_signal(low_conf_signals, "192.168.1.1", "/test")
        self.assertLess(decision_low.confidence, 0.70)
    
    def test_24_history_save(self):
        """Test decision history save"""
        # Make some decisions
        signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat())
        ]
        
        self.engine.add_signal(signals, "203.0.113.50", "/test")
        
        # Save history
        history_file = os.path.join(self.test_dir, "history.json")
        self.engine.save_decision_history(history_file)
        
        # Verify file exists and has content
        self.assertTrue(os.path.exists(history_file))
        
        with open(history_file, 'r') as f:
            data = json.load(f)
        
        self.assertIn("decisions", data)
        self.assertIn("metrics", data)
    
    def test_25_high_weight_signal_dominance(self):
        """Test that high-weight signals have strong influence"""
        signals = [
            # High weight, high confidence threat
            DetectionSignal(SignalType.THREAT_INTEL, True, 0.98, ThreatLevel.CRITICAL,
                          "Known malicious IP", datetime.utcnow().isoformat()),
            # Another high-weight threat signal
            DetectionSignal(SignalType.SIGNATURE, True, 0.92, ThreatLevel.CRITICAL,
                          "Attack pattern", datetime.utcnow().isoformat()),
            # One safe signal
            DetectionSignal(SignalType.VPN_TOR, False, 0.60, ThreatLevel.SAFE, "S", datetime.utcnow().isoformat())
        ]
        
        decision = self.engine.add_signal(signals, "203.0.113.50", "/test")
        
        # Two high weight threat signals should dominate
        self.assertTrue(decision.is_threat)
        self.assertGreater(decision.weighted_vote_score, 0.65)
    
    def test_26_all_signal_types_representation(self):
        """Test that all signal types have weights configured"""
        for signal_type in SignalType:
            self.assertIn(signal_type, self.engine.signal_weights)
            self.assertGreater(self.engine.signal_weights[signal_type], 0.0)
            self.assertLessEqual(self.engine.signal_weights[signal_type], 1.0)
    
    def test_27_consistency_across_decisions(self):
        """Test decision consistency with same signals"""
        signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.90, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat()),
            DetectionSignal(SignalType.BEHAVIORAL, True, 0.75, ThreatLevel.DANGEROUS, "T", datetime.utcnow().isoformat())
        ]
        
        decision1 = self.engine.add_signal(signals, "203.0.113.50", "/test1")
        decision2 = self.engine.add_signal(signals, "203.0.113.50", "/test2")
        
        # Should produce same verdict and similar scores
        self.assertEqual(decision1.is_threat, decision2.is_threat)
        self.assertAlmostEqual(decision1.weighted_vote_score, decision2.weighted_vote_score, places=2)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience wrapper functions"""
    
    def test_28_make_decision_function(self):
        """Test make_decision convenience function"""
        signals = [
            DetectionSignal(SignalType.SIGNATURE, True, 0.95, ThreatLevel.CRITICAL, "T", datetime.utcnow().isoformat())
        ]
        
        decision = make_decision(signals, "203.0.113.50", "/test")
        
        self.assertIsInstance(decision, EnsembleDecision)
        self.assertTrue(decision.is_threat)
    
    def test_29_get_stats_function(self):
        """Test get_stats convenience function"""
        stats = get_stats()
        
        self.assertIsInstance(stats, dict)
        self.assertIn("metrics", stats)
    
    def test_30_singleton_pattern(self):
        """Test singleton pattern for global instance"""
        engine1 = get_meta_engine()
        engine2 = get_meta_engine()
        
        self.assertIs(engine1, engine2)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestDetectionSignal))
    suite.addTests(loader.loadTestsFromTestCase(TestMetaDecisionEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestConvenienceFunctions))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
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
