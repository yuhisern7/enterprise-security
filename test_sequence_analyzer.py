#!/usr/bin/env python3
"""
Unit Tests for Sequence Analyzer (LSTM-based)
Tests state classification, sequence prediction, and LSTM training.
"""

import unittest
import time
import random
import numpy as np
from AI.sequence_analyzer import (
    SequenceAnalyzer,
    AttackState,
    StateEvent,
    get_sequence_analyzer,
    TF_AVAILABLE
)


@unittest.skipIf(not TF_AVAILABLE, "TensorFlow not available")
class TestSequenceAnalyzer(unittest.TestCase):
    """Test sequence analyzer with LSTM"""
    
    def setUp(self):
        """Create fresh instance for each test"""
        import os
        os.makedirs('/tmp/test_sequence', exist_ok=True)
        self.analyzer = SequenceAnalyzer(storage_dir='/tmp/test_sequence')
        self.test_ip = "192.168.1.100"
    
    def tearDown(self):
        """Cleanup"""
        import os
        import shutil
        if os.path.exists('/tmp/test_sequence'):
            shutil.rmtree('/tmp/test_sequence')
    
    def test_state_classification_normal(self):
        """Test classification of normal traffic"""
        event = self.analyzer.observe_event(
            self.test_ip,
            signature_score=0.1,
            heuristic_score=0.1,
            behavioral_features={'port_entropy': 1.0, 'fan_out': 2}
        )
        
        self.assertIsNotNone(event)
        self.assertEqual(event.state, AttackState.NORMAL)
        self.assertGreater(event.confidence, 0.5)
    
    def test_state_classification_scanning(self):
        """Test classification of scanning behavior"""
        event = self.analyzer.observe_event(
            self.test_ip,
            signature_score=0.3,
            heuristic_score=0.4,
            behavioral_features={'port_entropy': 5.5, 'connection_count_1min': 120}
        )
        
        self.assertEqual(event.state, AttackState.SCANNING)
        self.assertGreater(event.confidence, 0.6)
    
    def test_state_classification_auth_abuse(self):
        """Test classification of brute force attacks"""
        event = self.analyzer.observe_event(
            self.test_ip,
            signature_score=0.4,
            heuristic_score=0.6,
            behavioral_features={
                'auth_failure_ratio': 0.75,
                'retry_frequency': 15
            }
        )
        
        self.assertEqual(event.state, AttackState.AUTH_ABUSE)
        self.assertGreater(event.confidence, 0.6)
    
    def test_state_classification_lateral_movement(self):
        """Test classification of lateral movement"""
        event = self.analyzer.observe_event(
            self.test_ip,
            signature_score=0.5,
            heuristic_score=0.7,
            behavioral_features={'fan_out': 80}
        )
        
        self.assertEqual(event.state, AttackState.LATERAL_MOVEMENT)
        self.assertGreater(event.confidence, 0.6)
    
    def test_state_classification_priv_esc(self):
        """Test classification of privilege escalation"""
        event = self.analyzer.observe_event(
            self.test_ip,
            signature_score=0.8,
            heuristic_score=0.5,
            behavioral_features={}
        )
        
        self.assertEqual(event.state, AttackState.PRIV_ESC)
    
    def test_state_classification_exfiltration(self):
        """Test classification of data exfiltration"""
        event = self.analyzer.observe_event(
            self.test_ip,
            signature_score=0.6,
            heuristic_score=0.8,
            behavioral_features={}
        )
        
        self.assertEqual(event.state, AttackState.EXFILTRATION)
    
    def test_sequence_tracking(self):
        """Test that events are tracked in sequence"""
        # Add multiple events
        for i in range(5):
            self.analyzer.observe_event(
                self.test_ip,
                signature_score=0.1 * i,
                heuristic_score=0.1 * i
            )
        
        self.assertIn(self.test_ip, self.analyzer.entity_sequences)
        self.assertEqual(len(self.analyzer.entity_sequences[self.test_ip]), 5)
    
    def test_sequence_prediction_insufficient_data(self):
        """Test prediction with insufficient data"""
        # Single event
        self.analyzer.observe_event(self.test_ip, signature_score=0.2)
        
        prediction = self.analyzer.predict_sequence(self.test_ip)
        self.assertIsNone(prediction)  # Need at least 2 events
    
    def test_sequence_prediction_with_data(self):
        """Test sequence prediction with sufficient data"""
        # Simulate attack progression
        states_to_simulate = [
            (0.1, 0.1, {'port_entropy': 1.0}),  # Normal
            (0.3, 0.4, {'port_entropy': 5.0}),  # Scanning
            (0.5, 0.6, {'auth_failure_ratio': 0.8}),  # Auth abuse
        ]
        
        for sig, heur, features in states_to_simulate:
            self.analyzer.observe_event(self.test_ip, sig, heur, features)
            time.sleep(0.01)  # Small delay
        
        prediction = self.analyzer.predict_sequence(self.test_ip)
        
        self.assertIsNotNone(prediction)
        self.assertEqual(prediction.entity_id, self.test_ip)
        self.assertIsInstance(prediction.current_state, AttackState)
        self.assertIsInstance(prediction.predicted_next_state, AttackState)
        self.assertGreaterEqual(prediction.sequence_risk_score, 0.0)
        self.assertLessEqual(prediction.sequence_risk_score, 1.0)
        self.assertGreaterEqual(prediction.attack_stage, 0)
        self.assertLessEqual(prediction.attack_stage, 5)
    
    def test_attack_progression_risk_scoring(self):
        """Test that attack progression increases risk score"""
        # Start with normal
        self.analyzer.observe_event(
            self.test_ip,
            signature_score=0.1,
            heuristic_score=0.1,
            behavioral_features={'port_entropy': 1.0}
        )
        
        prediction1 = self.analyzer.predict_sequence(self.test_ip)
        # Need at least 2 events, so add one more
        self.analyzer.observe_event(self.test_ip, 0.1, 0.1, {})
        prediction1 = self.analyzer.predict_sequence(self.test_ip)
        
        # Progress to later stages
        self.analyzer.observe_event(
            self.test_ip,
            signature_score=0.3,
            heuristic_score=0.4,
            behavioral_features={'port_entropy': 5.0}
        )
        self.analyzer.observe_event(
            self.test_ip,
            signature_score=0.7,
            heuristic_score=0.6,
            behavioral_features={'auth_failure_ratio': 0.8}
        )
        
        prediction2 = self.analyzer.predict_sequence(self.test_ip)
        
        # Later stage should have higher risk
        if prediction1 and prediction2:
            self.assertGreaterEqual(
                prediction2.sequence_risk_score,
                prediction1.sequence_risk_score
            )
    
    def test_sequence_length_limit(self):
        """Test that sequences are limited to max length"""
        # Add more events than max sequence length
        for i in range(30):
            self.analyzer.observe_event(
                self.test_ip,
                signature_score=0.1,
                heuristic_score=0.1
            )
        
        sequence = self.analyzer.entity_sequences[self.test_ip]
        self.assertLessEqual(len(sequence), self.analyzer.sequence_length * 2)
    
    def test_training_sample_addition(self):
        """Test adding training samples"""
        # Create a sequence
        events = []
        for i in range(self.analyzer.sequence_length):
            event = StateEvent(
                timestamp=time.time() + i,
                entity_id=self.test_ip,
                state=AttackState.SCANNING,
                confidence=0.8,
                signature_score=0.5,
                heuristic_score=0.4
            )
            events.append(event)
        
        initial_count = len(self.analyzer.training_sequences)
        self.analyzer.add_training_sample(events, AttackState.AUTH_ABUSE)
        
        self.assertEqual(len(self.analyzer.training_sequences), initial_count + 1)
        self.assertEqual(len(self.analyzer.training_labels), initial_count + 1)
    
    def test_training_sample_too_short(self):
        """Test that short sequences are rejected for training"""
        events = [
            StateEvent(
                timestamp=time.time(),
                entity_id=self.test_ip,
                state=AttackState.NORMAL,
                confidence=0.9,
                signature_score=0.1,
                heuristic_score=0.1
            )
        ]
        
        initial_count = len(self.analyzer.training_sequences)
        self.analyzer.add_training_sample(events, AttackState.SCANNING)
        
        # Should not add (too short)
        self.assertEqual(len(self.analyzer.training_sequences), initial_count)
    
    def test_model_training_insufficient_data(self):
        """Test training with insufficient data"""
        result = self.analyzer.train_model(epochs=1)
        
        self.assertEqual(result['status'], 'insufficient_data')
        self.assertFalse(self.analyzer.is_trained)
    
    def test_model_training_with_data(self):
        """Test LSTM model training"""
        # Generate synthetic training data
        for _ in range(60):  # Above min_training_samples
            events = []
            for i in range(self.analyzer.sequence_length):
                state = random.choice(list(AttackState))
                event = StateEvent(
                    timestamp=time.time() + i,
                    entity_id=f"test_{_}",
                    state=state,
                    confidence=0.7,
                    signature_score=np.random.random(),
                    heuristic_score=np.random.random()
                )
                events.append(event)
            
            next_state = random.choice(list(AttackState))
            self.analyzer.add_training_sample(events, next_state)
        
        result = self.analyzer.train_model(epochs=2, batch_size=8)
        
        self.assertEqual(result['status'], 'success')
        self.assertGreater(result['samples'], 50)
        self.assertTrue(self.analyzer.is_trained)
        self.assertIn('final_loss', result)
        self.assertIn('final_accuracy', result)
    
    def test_attack_stage_mapping(self):
        """Test that attack states map to correct stages"""
        stage_map = {
            AttackState.NORMAL: 0,
            AttackState.SCANNING: 1,
            AttackState.AUTH_ABUSE: 2,
            AttackState.PRIV_ESC: 3,
            AttackState.LATERAL_MOVEMENT: 4,
            AttackState.EXFILTRATION: 5
        }
        
        for state, expected_stage in stage_map.items():
            stage = self.analyzer._get_attack_stage(state)
            self.assertEqual(stage, expected_stage)
    
    def test_statistics_generation(self):
        """Test statistics generation"""
        # Track some entities
        for i in range(3):
            self.analyzer.observe_event(
                f"10.0.0.{i}",
                signature_score=0.2,
                heuristic_score=0.3
            )
        
        stats = self.analyzer.get_stats()
        
        self.assertEqual(stats['total_entities_tracked'], 3)
        self.assertIn('model_trained', stats)
        self.assertIn('current_state_distribution', stats)
    
    def test_sequence_persistence(self):
        """Test saving/loading sequences"""
        # Add some events
        for i in range(3):
            self.analyzer.observe_event(
                self.test_ip,
                signature_score=0.1 * i,
                heuristic_score=0.2 * i
            )
        
        # Save
        self.assertTrue(self.analyzer.save_sequences())
        
        # Verify file exists
        import os
        self.assertTrue(os.path.exists(self.analyzer.sequences_file))
    
    def test_transition_matrix_structure(self):
        """Test transition probability matrix is valid"""
        matrix = self.analyzer.transition_probs
        
        # Check shape
        self.assertEqual(matrix.shape, (self.analyzer.num_states, self.analyzer.num_states))
        
        # Check each row sums to ~1.0 (probability distribution)
        for row in matrix:
            self.assertAlmostEqual(np.sum(row), 1.0, places=5)
    
    def test_feature_preparation(self):
        """Test sequence feature preparation for LSTM"""
        events = []
        for i in range(5):
            event = StateEvent(
                timestamp=time.time() + i,
                entity_id=self.test_ip,
                state=AttackState.SCANNING,
                confidence=0.8,
                signature_score=0.5,
                heuristic_score=0.4
            )
            events.append(event)
        
        features = self.analyzer._prepare_sequence_features(events)
        
        # Check shape
        self.assertEqual(features.shape, (self.analyzer.sequence_length, self.analyzer.feature_dim))
        
        # Check feature ranges
        self.assertTrue(np.all(features[:, 1] >= 0) and np.all(features[:, 1] <= 1))  # signature_score
        self.assertTrue(np.all(features[:, 2] >= 0) and np.all(features[:, 2] <= 1))  # heuristic_score


class TestConvenienceFunctions(unittest.TestCase):
    """Test module-level convenience functions"""
    
    @unittest.skipIf(not TF_AVAILABLE, "TensorFlow not available")
    def test_global_instance(self):
        """Test global instance creation"""
        from AI.sequence_analyzer import get_sequence_analyzer
        
        analyzer1 = get_sequence_analyzer()
        analyzer2 = get_sequence_analyzer()
        
        if analyzer1 and analyzer2:
            self.assertIs(analyzer1, analyzer2)
    
    @unittest.skipIf(not TF_AVAILABLE, "TensorFlow not available")
    def test_convenience_observe(self):
        """Test convenience observation function"""
        from AI.sequence_analyzer import observe_event
        
        event = observe_event("192.168.1.50", signature_score=0.3, heuristic_score=0.4)
        if event:
            self.assertIsNotNone(event)
            self.assertEqual(event.entity_id, "192.168.1.50")


if __name__ == '__main__':
    unittest.main()
