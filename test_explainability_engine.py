"""
Unit tests for Phase 7: Explainability Engine
Tests decision breakdown, timeline reconstruction, what-if analysis, and forensic reporting.
"""

import unittest
import os
import sys
import time
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from AI.explainability_engine import (
    ExplainabilityEngine, DecisionBreakdown, AttackTimeline,
    WhatIfScenario, ForensicReport, SignalContribution,
    ExplanationLevel, get_explainability_engine,
    EXPLAINABILITY_ENGINE_AVAILABLE
)


class TestExplainabilityEngine(unittest.TestCase):
    """Test suite for ExplainabilityEngine."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.engine = ExplainabilityEngine(export_dir=os.path.join(self.test_dir, "export"))
    
    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_engine_initialization(self):
        """Test 1: Engine initializes correctly."""
        self.assertTrue(EXPLAINABILITY_ENGINE_AVAILABLE)
        self.assertEqual(self.engine.max_history, 1000)
        self.assertTrue(os.path.exists(self.engine.export_dir))
        self.assertEqual(len(self.engine.decision_history), 0)
    
    def test_explain_simple_threat(self):
        """Test 2: Explain simple threat decision."""
        ensemble_decision = {
            "entity": "192.168.1.100",
            "verdict": "THREAT",
            "confidence": 0.85,
            "threat_score": 85.0
        }
        
        signals = [
            {"signal_type": "signature", "weight": 0.90, "confidence": 0.95, 
             "is_threat": True, "evidence": "SQL injection pattern"},
            {"signal_type": "behavioral", "weight": 0.75, "confidence": 0.80, 
             "is_threat": True, "evidence": "Abnormal request frequency"},
        ]
        
        breakdown = self.engine.explain_decision(ensemble_decision, signals)
        
        self.assertEqual(breakdown.entity, "192.168.1.100")
        self.assertEqual(breakdown.final_verdict, "THREAT")
        self.assertEqual(breakdown.confidence, 0.85)
        self.assertEqual(breakdown.total_signals, 2)
        self.assertEqual(breakdown.threat_signals, 2)
        self.assertEqual(breakdown.safe_signals, 0)
        self.assertGreater(len(breakdown.decision_reason), 0)
    
    def test_signal_contribution_analysis(self):
        """Test 3: Signal contribution analysis."""
        signals = [
            {"signal_type": "signature", "weight": 0.90, "confidence": 0.95, 
             "is_threat": True, "evidence": "Attack pattern"},
            {"signal_type": "behavioral", "weight": 0.75, "confidence": 0.50, 
             "is_threat": False, "evidence": "Normal behavior"},
        ]
        
        contributions = self.engine._analyze_signal_contributions(signals)
        
        self.assertEqual(len(contributions), 2)
        
        # First should be highest weighted
        self.assertEqual(contributions[0].signal_name, "signature")
        self.assertEqual(contributions[0].weight, 0.90)
        self.assertEqual(contributions[0].confidence, 0.95)
        self.assertAlmostEqual(contributions[0].weighted_vote, 0.855, places=3)
        self.assertEqual(contributions[0].verdict, "THREAT")
        self.assertEqual(contributions[0].certainty, "HIGH")
    
    def test_primary_threat_identification(self):
        """Test 4: Primary threat type identification."""
        signals = [
            {"signal_type": "signature", "weight": 0.90, "confidence": 0.95, 
             "is_threat": True, "evidence": "Known pattern"},
            {"signal_type": "autoencoder", "weight": 0.80, "confidence": 0.70, 
             "is_threat": True, "evidence": "Anomaly"},
        ]
        
        contributions = self.engine._analyze_signal_contributions(signals)
        primary = self.engine._identify_primary_threat(contributions)
        
        self.assertEqual(primary, "Known Attack Pattern")
    
    def test_attack_stage_determination(self):
        """Test 5: Attack stage determination."""
        # Multi-stage attack
        signals1 = [
            {"signal_type": "sequence", "weight": 0.85, "confidence": 0.90, "is_threat": True},
        ]
        contrib1 = self.engine._analyze_signal_contributions(signals1)
        stage1 = self.engine._determine_attack_stage(contrib1)
        self.assertEqual(stage1, "Multi-Stage Attack")
        
        # Graph-based attack
        signals2 = [
            {"signal_type": "graph", "weight": 0.88, "confidence": 0.85, "is_threat": True},
        ]
        contrib2 = self.engine._analyze_signal_contributions(signals2)
        stage2 = self.engine._determine_attack_stage(contrib2)
        self.assertEqual(stage2, "Lateral Movement / C2")
    
    def test_severity_calculation(self):
        """Test 6: Severity level calculation."""
        self.assertEqual(self.engine._calculate_severity(0.95, 12), "CRITICAL")
        self.assertEqual(self.engine._calculate_severity(0.80, 8), "HIGH")
        self.assertEqual(self.engine._calculate_severity(0.60, 5), "MEDIUM")
        self.assertEqual(self.engine._calculate_severity(0.30, 2), "LOW")
    
    def test_consensus_detection(self):
        """Test 7: Strong consensus detection."""
        # Strong threat consensus
        signals1 = [
            {"signal_type": "sig1", "weight": 0.90, "confidence": 0.95, "is_threat": True},
            {"signal_type": "sig2", "weight": 0.85, "confidence": 0.90, "is_threat": True},
            {"signal_type": "sig3", "weight": 0.80, "confidence": 0.85, "is_threat": True},
        ]
        contrib1 = self.engine._analyze_signal_contributions(signals1)
        strong1, pct1 = self.engine._check_consensus(contrib1)
        self.assertTrue(strong1)
        self.assertGreater(pct1, 80.0)
        
        # Weak consensus (mixed signals)
        signals2 = [
            {"signal_type": "sig1", "weight": 0.90, "confidence": 0.95, "is_threat": True},
            {"signal_type": "sig2", "weight": 0.85, "confidence": 0.90, "is_threat": False},
        ]
        contrib2 = self.engine._analyze_signal_contributions(signals2)
        strong2, pct2 = self.engine._check_consensus(contrib2)
        self.assertLess(pct2, 80.0)
    
    def test_decision_reason_generation(self):
        """Test 8: Human-readable decision reason."""
        reason = self.engine._generate_decision_reason(
            "THREAT", 85.0, "SQL Injection", 5, 2, True
        )
        
        self.assertIn("Threat detected", reason)
        self.assertIn("85.0%", reason)
        self.assertIn("SQL Injection", reason)
        self.assertIn("Strong consensus", reason)
    
    def test_action_recommendation(self):
        """Test 9: Action recommendation."""
        self.assertEqual(
            self.engine._recommend_action("BLOCK", 95.0, "CRITICAL"),
            "BLOCK - Immediate blocking required"
        )
        
        self.assertEqual(
            self.engine._recommend_action("THREAT", 85.0, "HIGH"),
            "BLOCK - High-severity threat"
        )
        
        self.assertEqual(
            self.engine._recommend_action("SAFE", 20.0, "LOW"),
            "ALLOW - Continue monitoring"
        )
    
    def test_mitigation_steps_generation(self):
        """Test 10: Mitigation steps generation."""
        steps = self.engine._generate_mitigation_steps("Known Attack Pattern", "CRITICAL")
        
        self.assertGreater(len(steps), 0)
        self.assertIn("Block IP address immediately", steps)
        self.assertIn("Update signature database", steps)
    
    def test_decision_history_tracking(self):
        """Test 11: Decision history tracking."""
        # Generate multiple decisions
        for i in range(5):
            ensemble = {
                "entity": f"192.168.1.{i}",
                "verdict": "THREAT",
                "confidence": 0.8,
                "threat_score": 80.0
            }
            signals = [
                {"signal_type": "test", "weight": 0.9, "confidence": 0.85, "is_threat": True}
            ]
            self.engine.explain_decision(ensemble, signals)
        
        self.assertEqual(len(self.engine.decision_history), 5)
        self.assertEqual(self.engine.stats["explanations_generated"], 5)
    
    def test_timeline_reconstruction_empty(self):
        """Test 12: Timeline reconstruction with no events."""
        timeline = self.engine.reconstruct_attack_timeline("192.168.1.1", [])
        
        self.assertEqual(timeline.entity, "192.168.1.1")
        self.assertEqual(timeline.total_events, 0)
        self.assertEqual(len(timeline.stages), 0)
        self.assertEqual(timeline.attack_pattern, "None")
    
    def test_timeline_reconstruction_single_event(self):
        """Test 13: Timeline reconstruction with single event."""
        events = [
            {"timestamp": time.time(), "attack_type": "port_scan", "severity": 0.3}
        ]
        
        timeline = self.engine.reconstruct_attack_timeline("10.0.0.1", events)
        
        self.assertEqual(timeline.total_events, 1)
        self.assertEqual(timeline.attack_pattern, "Single Event")
    
    def test_timeline_reconstruction_multi_stage(self):
        """Test 14: Timeline reconstruction with multi-stage attack."""
        base_time = time.time()
        events = [
            {"timestamp": base_time, "attack_type": "port_scan", "severity": 0.3},
            {"timestamp": base_time + 10, "attack_type": "sql_injection", "severity": 0.8},
            {"timestamp": base_time + 20, "attack_type": "privilege_escalation", "severity": 0.9},
            {"timestamp": base_time + 30, "attack_type": "ftp", "severity": 0.7},
        ]
        
        timeline = self.engine.reconstruct_attack_timeline("10.0.0.2", events)
        
        self.assertEqual(timeline.total_events, 4)
        self.assertGreater(len(timeline.stages), 1)
        self.assertIn("Stage", timeline.attack_pattern)
    
    def test_escalation_detection(self):
        """Test 15: Escalation point detection."""
        events = [
            {"timestamp": time.time(), "attack_type": "scan", "severity": 0.2},
            {"timestamp": time.time() + 10, "attack_type": "exploit", "severity": 0.9},  # Escalation
        ]
        
        escalations = self.engine._identify_escalations(events)
        
        self.assertGreater(len(escalations), 0)
        self.assertGreaterEqual(escalations[0]["severity_jump"], 0.3)
    
    def test_attack_pattern_identification(self):
        """Test 16: Attack pattern identification."""
        # Brute force pattern
        events1 = [{"timestamp": time.time(), "attack_type": "login"} for _ in range(15)]
        stages1 = []
        pattern1 = self.engine._identify_attack_pattern(events1, stages1)
        self.assertEqual(pattern1, "Brute Force / Repeated Attempts")
        
        # Multi-stage pattern
        events2 = []
        stages2 = [{"stage": "Recon"}, {"stage": "Exploit"}, {"stage": "Exfil"}]
        pattern2 = self.engine._identify_attack_pattern(events2, stages2)
        self.assertEqual(pattern2, "Multi-Stage Attack (APT-like)")
    
    def test_what_if_disable_signal(self):
        """Test 17: What-if analysis - disable signal."""
        # Create original decision
        ensemble = {
            "entity": "192.168.1.100",
            "verdict": "THREAT",
            "confidence": 0.85,
            "threat_score": 85.0
        }
        signals = [
            {"signal_type": "signature", "weight": 0.90, "confidence": 0.95, "is_threat": True},
            {"signal_type": "behavioral", "weight": 0.75, "confidence": 0.80, "is_threat": True},
            {"signal_type": "ml_class", "weight": 0.78, "confidence": 0.60, "is_threat": False},
        ]
        
        breakdown = self.engine.explain_decision(ensemble, signals)
        
        # What-if: Disable signature signal
        modifications = {
            "disable_signals": ["signature"]
        }
        
        scenario = self.engine.what_if_analysis(breakdown, "Disable Signature", modifications)
        
        self.assertEqual(scenario.scenario_name, "Disable Signature")
        self.assertIn("Disabled signature signal", scenario.changes_made)
        self.assertLess(scenario.modified_confidence, scenario.original_confidence)
    
    def test_what_if_adjust_weight(self):
        """Test 18: What-if analysis - adjust weight."""
        ensemble = {
            "entity": "10.0.0.1",
            "verdict": "THREAT",
            "confidence": 0.75,
            "threat_score": 75.0
        }
        signals = [
            {"signal_type": "signature", "weight": 0.90, "confidence": 0.80, "is_threat": True},
            {"signal_type": "behavioral", "weight": 0.75, "confidence": 0.60, "is_threat": False},
        ]
        
        breakdown = self.engine.explain_decision(ensemble, signals)
        
        # What-if: Reduce signature weight (should decrease threat score)
        modifications = {
            "adjust_weights": {"signature": 0.30}
        }
        
        scenario = self.engine.what_if_analysis(breakdown, "Reduce Signature Weight", modifications)
        
        self.assertIn("weight", scenario.changes_made[0].lower())
        # With reduced threat signal weight, confidence should decrease
        self.assertNotEqual(scenario.modified_confidence, scenario.original_confidence)
    
    def test_what_if_verdict_change(self):
        """Test 19: What-if analysis - verdict change."""
        # Borderline decision
        ensemble = {
            "entity": "10.0.0.2",
            "verdict": "THREAT",
            "confidence": 0.55,
            "threat_score": 55.0
        }
        signals = [
            {"signal_type": "sig1", "weight": 0.80, "confidence": 0.70, "is_threat": True},
            {"signal_type": "sig2", "weight": 0.75, "confidence": 0.60, "is_threat": False},
        ]
        
        breakdown = self.engine.explain_decision(ensemble, signals)
        
        # What-if: Disable threat signal
        modifications = {
            "disable_signals": ["sig1"]
        }
        
        scenario = self.engine.what_if_analysis(breakdown, "Disable Main Threat", modifications)
        
        self.assertTrue(scenario.verdict_changed)
        self.assertEqual(scenario.modified_verdict, "SAFE")
    
    def test_forensic_report_generation(self):
        """Test 20: Forensic report generation."""
        ensemble = {
            "entity": "192.168.1.100",
            "verdict": "THREAT",
            "confidence": 0.90,
            "threat_score": 90.0
        }
        signals = [
            {"signal_type": "signature", "weight": 0.90, "confidence": 0.95, 
             "is_threat": True, "evidence": "SQL injection"},
        ]
        
        breakdown = self.engine.explain_decision(ensemble, signals)
        report = self.engine.generate_forensic_report(breakdown)
        
        self.assertIsNotNone(report.report_id)
        self.assertEqual(report.entity, "192.168.1.100")
        self.assertGreater(len(report.incident_summary), 0)
        self.assertEqual(report.decision_breakdown, breakdown)
        self.assertGreater(len(report.immediate_actions), 0)
        self.assertGreater(len(report.investigation_steps), 0)
    
    def test_forensic_report_with_timeline(self):
        """Test 21: Forensic report with attack timeline."""
        ensemble = {
            "entity": "10.0.0.3",
            "verdict": "THREAT",
            "confidence": 0.85,
            "threat_score": 85.0
        }
        signals = [
            {"signal_type": "sequence", "weight": 0.85, "confidence": 0.90, "is_threat": True},
        ]
        
        breakdown = self.engine.explain_decision(ensemble, signals)
        
        # Create timeline
        events = [
            {"timestamp": time.time(), "attack_type": "port_scan", "severity": 0.3},
            {"timestamp": time.time() + 10, "attack_type": "sql_injection", "severity": 0.8},
        ]
        timeline = self.engine.reconstruct_attack_timeline("10.0.0.3", events)
        
        report = self.engine.generate_forensic_report(breakdown, attack_timeline=timeline)
        
        self.assertIsNotNone(report.attack_timeline)
        self.assertEqual(report.attack_timeline.total_events, 2)
    
    def test_signal_evidence_collection(self):
        """Test 22: Signal evidence collection."""
        contributions = [
            SignalContribution("sig1", 0.9, 0.95, 0.855, "THREAT", "Evidence 1", "HIGH"),
            SignalContribution("sig2", 0.8, 0.85, 0.680, "THREAT", "Evidence 2", "HIGH"),
            SignalContribution("sig3", 0.7, 0.60, 0.420, "SAFE", "Evidence 3", "MEDIUM"),
        ]
        
        evidence = self.engine._collect_signal_evidence(contributions)
        
        # Only threat signals collected
        self.assertIn("sig1", evidence)
        self.assertIn("sig2", evidence)
        self.assertNotIn("sig3", evidence)
        
        self.assertIn("Evidence 1", evidence["sig1"][0])
    
    def test_threat_indicators_identification(self):
        """Test 23: Threat indicators identification."""
        breakdown = DecisionBreakdown(
            decision_id="TEST",
            timestamp=time.time(),
            entity="10.0.0.1",
            final_verdict="THREAT",
            confidence=0.95,
            threat_score=95.0,
            total_signals=15,
            threat_signals=12,
            safe_signals=3,
            signal_contributions=[],
            primary_threat_type="SQL Injection",
            attack_stage="Exploitation",
            severity_level="CRITICAL",
            strong_consensus=True,
            consensus_percentage=92.5,
            decision_reason="Test",
            recommended_action="BLOCK",
            mitigation_steps=[]
        )
        
        indicators = self.engine._identify_threat_indicators(breakdown)
        
        self.assertGreater(len(indicators), 0)
        self.assertTrue(any("high threat score" in i.lower() for i in indicators))
        self.assertTrue(any("consensus" in i.lower() for i in indicators))
    
    def test_fp_indicators_identification(self):
        """Test 24: False positive indicators identification."""
        breakdown = DecisionBreakdown(
            decision_id="TEST",
            timestamp=time.time(),
            entity="10.0.0.2",
            final_verdict="THREAT",
            confidence=0.45,  # Low confidence
            threat_score=45.0,
            total_signals=10,
            threat_signals=4,
            safe_signals=6,  # More safe than threat
            signal_contributions=[],
            primary_threat_type=None,
            attack_stage=None,
            severity_level="LOW",
            strong_consensus=False,  # Weak consensus
            consensus_percentage=55.0,
            decision_reason="Test",
            recommended_action="ALERT",
            mitigation_steps=[]
        )
        
        fp_indicators = self.engine._identify_fp_indicators(breakdown)
        
        self.assertGreater(len(fp_indicators), 0)
        self.assertTrue(any("safe signals" in i.lower() for i in fp_indicators))
        self.assertTrue(any("low confidence" in i.lower() for i in fp_indicators))
        self.assertTrue(any("weak consensus" in i.lower() for i in fp_indicators))
    
    def test_forensic_report_export(self):
        """Test 25: Forensic report file export."""
        ensemble = {
            "entity": "10.0.0.4",
            "verdict": "THREAT",
            "confidence": 0.80,
            "threat_score": 80.0
        }
        signals = [
            {"signal_type": "test", "weight": 0.85, "confidence": 0.85, "is_threat": True},
        ]
        
        breakdown = self.engine.explain_decision(ensemble, signals)
        report = self.engine.generate_forensic_report(breakdown, export_format="json")
        
        # Check if files were created
        latest_path = os.path.join(self.engine.export_dir, "forensic_latest.json")
        self.assertTrue(os.path.exists(latest_path))
        
        # Verify content
        import json
        with open(latest_path, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(data["entity"], "10.0.0.4")
        self.assertEqual(data["report_id"], report.report_id)
    
    def test_statistics_tracking(self):
        """Test 26: Statistics tracking."""
        # Generate various operations
        ensemble = {
            "entity": "10.0.0.5",
            "verdict": "THREAT",
            "confidence": 0.75,
            "threat_score": 75.0
        }
        signals = [
            {"signal_type": "test", "weight": 0.80, "confidence": 0.80, "is_threat": True},
        ]
        
        breakdown = self.engine.explain_decision(ensemble, signals)
        self.engine.generate_forensic_report(breakdown)
        
        events = [{"timestamp": time.time(), "attack_type": "test", "severity": 0.5}]
        self.engine.reconstruct_attack_timeline("10.0.0.5", events)
        
        mods = {"disable_signals": ["test"]}
        self.engine.what_if_analysis(breakdown, "Test", mods)
        
        stats = self.engine.get_statistics()
        
        self.assertEqual(stats["explanations_generated"], 1)
        self.assertEqual(stats["forensic_reports_created"], 1)
        self.assertEqual(stats["timelines_reconstructed"], 1)
        self.assertEqual(stats["what_if_scenarios_run"], 1)
        self.assertEqual(stats["decision_history_size"], 1)
    
    def test_global_instance(self):
        """Test 27: Global instance function."""
        from AI.explainability_engine import get_explainability_engine
        
        engine1 = get_explainability_engine()
        engine2 = get_explainability_engine()
        
        # Should return same instance
        self.assertIs(engine1, engine2)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
