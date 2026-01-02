#!/usr/bin/env python3
"""
Unit Tests for Traffic Autoencoder (Phase 2)
Tests unsupervised anomaly detection using deep learning.
"""

import unittest
import os
import shutil
import numpy as np
from AI.pcs_ai import (
    TrafficAutoencoder,
    get_traffic_autoencoder,
    TENSORFLOW_AVAILABLE,
    ML_AVAILABLE
)


@unittest.skipIf(not TENSORFLOW_AVAILABLE, "TensorFlow not available")
@unittest.skipIf(not ML_AVAILABLE, "scikit-learn not available")
class TestTrafficAutoencoder(unittest.TestCase):
    """Test autoencoder for unsupervised anomaly detection"""
    
    def setUp(self):
        """Create fresh instance for each test"""
        self.test_dir = '/tmp/test_autoencoder'
        os.makedirs(self.test_dir, exist_ok=True)
        self.autoencoder = TrafficAutoencoder(storage_dir=self.test_dir)
    
    def tearDown(self):
        """Cleanup"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_initialization(self):
        """Test autoencoder initialization"""
        self.assertIsNotNone(self.autoencoder)
        self.assertEqual(self.autoencoder.input_dim, 15)
        self.assertEqual(self.autoencoder.encoding_dim, 8)
        # May be trained if model file exists from previous runs
        self.assertIsInstance(self.autoencoder.is_trained, bool)
    
    def test_model_building(self):
        """Test model architecture creation"""
        autoencoder, encoder = self.autoencoder._build_model()
        
        self.assertIsNotNone(autoencoder)
        self.assertIsNotNone(encoder)
        
        # Check input/output shapes
        self.assertEqual(autoencoder.input_shape, (None, 15))
        self.assertEqual(autoencoder.output_shape, (None, 15))
        self.assertEqual(encoder.output_shape, (None, 8))
    
    def test_training_insufficient_data(self):
        """Test training with insufficient data"""
        # Generate small dataset
        normal_traffic = np.random.rand(50, 15)
        
        result = self.autoencoder.train(normal_traffic)
        
        self.assertEqual(result['status'], 'insufficient_data')
        self.assertEqual(result['required'], 100)
        self.assertEqual(result['available'], 50)
    
    def test_training_with_data(self):
        """Test successful training"""
        # Generate normal traffic (Gaussian distribution around 0.3)
        np.random.seed(42)
        normal_traffic = np.random.normal(0.3, 0.1, (150, 15))
        normal_traffic = np.clip(normal_traffic, 0, 1)  # Clip to [0, 1]
        
        result = self.autoencoder.train(normal_traffic, epochs=5, batch_size=16)
        
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['samples'], 150)
        self.assertEqual(result['epochs'], 5)
        self.assertIn('final_loss', result)
        self.assertIn('val_loss', result)
        self.assertIn('threshold', result)
        self.assertGreater(result['threshold'], 0)
        
        # Check model state
        self.assertTrue(self.autoencoder.is_trained)
        self.assertIsNotNone(self.autoencoder.last_trained)
    
    def test_anomaly_detection_untrained(self):
        """Test detection returns defaults when untrained"""
        test_features = np.random.rand(15)
        
        is_anomaly, recon_error, anomaly_score = self.autoencoder.detect_anomaly(test_features)
        
        self.assertFalse(is_anomaly)
        self.assertEqual(recon_error, 0.0)
        self.assertEqual(anomaly_score, 0.0)
    
    def test_anomaly_detection_normal_traffic(self):
        """Test detection of normal traffic after training"""
        # Train on normal traffic
        np.random.seed(42)
        normal_traffic = np.random.normal(0.3, 0.1, (150, 15))
        normal_traffic = np.clip(normal_traffic, 0, 1)
        
        self.autoencoder.train(normal_traffic, epochs=10, batch_size=16)
        
        # Test with similar normal traffic
        test_normal = np.random.normal(0.3, 0.1, 15)
        test_normal = np.clip(test_normal, 0, 1)
        
        is_anomaly, recon_error, anomaly_score = self.autoencoder.detect_anomaly(test_normal)
        
        # Should NOT be anomaly
        self.assertFalse(is_anomaly)
        self.assertLess(anomaly_score, 0.5)  # Low anomaly score
    
    def test_anomaly_detection_anomalous_traffic(self):
        """Test detection of anomalous traffic"""
        # Train on normal traffic (low values)
        np.random.seed(42)
        normal_traffic = np.random.normal(0.2, 0.05, (150, 15))
        normal_traffic = np.clip(normal_traffic, 0, 1)
        
        self.autoencoder.train(normal_traffic, epochs=15, batch_size=16)
        
        # Test with very different anomalous traffic (high values)
        test_anomaly = np.random.normal(0.8, 0.1, 15)
        test_anomaly = np.clip(test_anomaly, 0, 1)
        
        is_anomaly, recon_error, anomaly_score = self.autoencoder.detect_anomaly(test_anomaly)
        
        # Should detect as anomaly
        self.assertTrue(is_anomaly)
        self.assertGreater(recon_error, self.autoencoder.reconstruction_threshold)
        self.assertGreater(anomaly_score, 0.3)  # Significant anomaly score
    
    def test_feature_extraction(self):
        """Test compressed feature extraction from bottleneck"""
        # Train first
        np.random.seed(42)
        normal_traffic = np.random.normal(0.3, 0.1, (150, 15))
        normal_traffic = np.clip(normal_traffic, 0, 1)
        
        self.autoencoder.train(normal_traffic, epochs=5, batch_size=16)
        
        # Extract features
        test_features = np.random.rand(15)
        encoded = self.autoencoder.get_encoded_features(test_features)
        
        self.assertIsNotNone(encoded)
        self.assertEqual(len(encoded), 8)  # Bottleneck dimension
        self.assertIsInstance(encoded, np.ndarray)
    
    def test_model_persistence(self):
        """Test saving and loading model"""
        # Train model
        np.random.seed(42)
        normal_traffic = np.random.normal(0.3, 0.1, (150, 15))
        normal_traffic = np.clip(normal_traffic, 0, 1)
        
        self.autoencoder.train(normal_traffic, epochs=5, batch_size=16)
        threshold_before = self.autoencoder.reconstruction_threshold
        
        # Create new instance (should load saved model)
        autoencoder2 = TrafficAutoencoder(storage_dir=self.test_dir)
        
        self.assertTrue(autoencoder2.is_trained)
        self.assertAlmostEqual(autoencoder2.reconstruction_threshold, threshold_before, places=4)
        self.assertIsNotNone(autoencoder2.autoencoder)
        self.assertIsNotNone(autoencoder2.encoder)
    
    def test_threshold_persistence(self):
        """Test threshold configuration persistence"""
        # Train and save
        np.random.seed(42)
        normal_traffic = np.random.normal(0.3, 0.1, (150, 15))
        normal_traffic = np.clip(normal_traffic, 0, 1)
        
        result = self.autoencoder.train(normal_traffic, epochs=5, batch_size=16)
        threshold = result['threshold']
        
        # Load in new instance
        autoencoder2 = TrafficAutoencoder(storage_dir=self.test_dir)
        
        self.assertAlmostEqual(autoencoder2.reconstruction_threshold, threshold, places=4)
        self.assertEqual(autoencoder2.training_samples, 150)
    
    def test_statistics_generation(self):
        """Test statistics output"""
        stats = self.autoencoder.get_stats()
        
        self.assertIn('tensorflow_available', stats)
        self.assertIn('is_trained', stats)
        self.assertIn('reconstruction_threshold', stats)
        self.assertIn('total_predictions', stats)
        self.assertIn('anomalies_detected', stats)
        self.assertIn('anomaly_rate', stats)
        self.assertTrue(stats['tensorflow_available'])
    
    def test_statistics_with_predictions(self):
        """Test statistics tracking predictions"""
        # Train
        np.random.seed(42)
        normal_traffic = np.random.normal(0.3, 0.1, (150, 15))
        normal_traffic = np.clip(normal_traffic, 0, 1)
        self.autoencoder.train(normal_traffic, epochs=5, batch_size=16)
        
        # Make several predictions
        for _ in range(10):
            test_features = np.random.rand(15)
            self.autoencoder.detect_anomaly(test_features)
        
        stats = self.autoencoder.get_stats()
        
        self.assertEqual(stats['total_predictions'], 10)
        self.assertGreaterEqual(stats['anomalies_detected'], 0)
        self.assertGreaterEqual(stats['anomaly_rate'], 0.0)
        self.assertLessEqual(stats['anomaly_rate'], 1.0)
    
    def test_reconstruction_threshold_calculation(self):
        """Test that threshold is 95th percentile of training errors"""
        # Train with controlled data
        np.random.seed(42)
        normal_traffic = np.random.normal(0.3, 0.1, (150, 15))
        normal_traffic = np.clip(normal_traffic, 0, 1)
        
        self.autoencoder.train(normal_traffic, epochs=10, batch_size=16)
        
        # Threshold should be positive and reasonable
        self.assertGreater(self.autoencoder.reconstruction_threshold, 0.0)
        self.assertLess(self.autoencoder.reconstruction_threshold, 1.0)
    
    def test_feature_scaling(self):
        """Test that feature scaling is applied"""
        # Train
        np.random.seed(42)
        normal_traffic = np.random.normal(0.3, 0.1, (150, 15))
        normal_traffic = np.clip(normal_traffic, 0, 1)
        self.autoencoder.train(normal_traffic, epochs=5, batch_size=16)
        
        # Check scaler was fitted
        self.assertTrue(hasattr(self.autoencoder.scaler, 'mean_'))
        self.assertEqual(len(self.autoencoder.scaler.mean_), 15)


class TestGlobalAutoencoder(unittest.TestCase):
    """Test global instance functionality"""
    
    @unittest.skipIf(not TENSORFLOW_AVAILABLE, "TensorFlow not available")
    def test_global_instance(self):
        """Test global instance creation"""
        ae1 = get_traffic_autoencoder()
        ae2 = get_traffic_autoencoder()
        
        if ae1 and ae2:  # May be None if TensorFlow not available
            self.assertIs(ae1, ae2)


if __name__ == '__main__':
    unittest.main()
