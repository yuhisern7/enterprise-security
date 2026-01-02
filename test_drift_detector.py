#!/usr/bin/env python3
"""
Unit Tests for Drift Detector (Phase 3)

Tests statistical drift detection across:
- Baseline distribution management
- K-S test drift detection
- PSI (Population Stability Index) calculation
- Drift reporting and persistence
- Retraining recommendations
"""

import unittest
import os
import json
import numpy as np
import tempfile
import shutil
from datetime import datetime

# Import the module
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'AI'))
from drift_detector import (
    DriftDetector, DriftReport, DriftStatistics,
    get_drift_detector, update_baseline, check_drift, track_features,
    SCIPY_AVAILABLE
)


@unittest.skipUnless(SCIPY_AVAILABLE, "scipy not available")
class TestDriftDetector(unittest.TestCase):
    """Test drift detector functionality"""
    
    def setUp(self):
        """Create temporary storage for each test"""
        self.temp_dir = tempfile.mkdtemp()
        self.detector = DriftDetector(storage_dir=self.temp_dir, window_size=500)
    
    def tearDown(self):
        """Clean up temporary storage"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _generate_normal_data(self, n_samples: int = 100) -> np.ndarray:
        """Generate synthetic normal traffic features"""
        np.random.seed(42)
        
        # 15 features matching the system
        features = np.random.randn(n_samples, 15)
        
        # Make features realistic (positive values)
        features = np.abs(features)
        
        return features
    
    def _generate_drifted_data(self, n_samples: int = 100, drift_amount: float = 2.0) -> np.ndarray:
        """Generate synthetic drifted data (mean shifted)"""
        np.random.seed(123)
        
        # Same distribution but shifted mean
        features = np.random.randn(n_samples, 15) + drift_amount
        features = np.abs(features)
        
        return features
    
    def test_01_initialization(self):
        """Test detector initialization"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.window_size, 500)
        self.assertEqual(len(self.detector.baseline_features), 0)
        self.assertEqual(len(self.detector.current_features), 0)
        self.assertEqual(self.detector.samples_processed, 0)
    
    def test_02_update_baseline(self):
        """Test adding samples to baseline"""
        # Add 100 normal samples
        normal_data = self._generate_normal_data(100)
        
        for features in normal_data:
            self.detector.update_baseline(features)
        
        self.assertEqual(len(self.detector.baseline_features), 100)
        self.assertEqual(self.detector.samples_processed, 100)
        
        # Check statistics calculated
        self.assertGreater(len(self.detector.baseline_statistics), 0)
    
    def test_03_baseline_statistics(self):
        """Test baseline statistics calculation"""
        # Add 150 samples
        normal_data = self._generate_normal_data(150)
        
        for features in normal_data:
            self.detector.update_baseline(features)
        
        # Should have stats for all 15 features
        self.assertEqual(len(self.detector.baseline_statistics), 15)
        
        # Check first feature stats
        stats_0 = self.detector.baseline_statistics[0]
        self.assertIn('mean', stats_0)
        self.assertIn('std', stats_0)
        self.assertIn('min', stats_0)
        self.assertIn('max', stats_0)
        self.assertIn('median', stats_0)
        
        # Mean should be positive (we used abs())
        self.assertGreater(stats_0['mean'], 0)
    
    def test_04_add_current_samples(self):
        """Test adding samples to current window"""
        normal_data = self._generate_normal_data(50)
        
        for features in normal_data:
            self.detector.add_current_sample(features)
        
        self.assertEqual(len(self.detector.current_features), 50)
    
    def test_05_no_drift_detection(self):
        """Test no drift when distributions are similar"""
        # Build baseline with normal data
        baseline_data = self._generate_normal_data(200)
        for features in baseline_data:
            self.detector.update_baseline(features)
        
        # Add more normal data to current window
        current_data = self._generate_normal_data(100)
        for features in current_data:
            self.detector.add_current_sample(features)
        
        # Check drift
        stats = self.detector.check_drift()
        
        self.assertIsNotNone(stats)
        self.assertEqual(stats.total_features, 15)
        
        # Should detect minimal or no drift
        self.assertLess(stats.avg_drift_score, 0.5)
        self.assertFalse(stats.requires_retraining)
    
    def test_06_drift_detection(self):
        """Test drift detection when distribution shifts"""
        # Build baseline with normal data
        baseline_data = self._generate_normal_data(200)
        for features in baseline_data:
            self.detector.update_baseline(features)
        
        # Add drifted data to current window
        drifted_data = self._generate_drifted_data(100, drift_amount=3.0)
        for features in drifted_data:
            self.detector.add_current_sample(features)
        
        # Check drift
        stats = self.detector.check_drift()
        
        self.assertIsNotNone(stats)
        
        # Should detect significant drift
        self.assertGreater(stats.features_drifted, 0)
        self.assertGreater(stats.avg_drift_score, 0.3)
        self.assertGreater(stats.max_drift_score, 0.5)
        
        # Should recommend retraining
        self.assertTrue(stats.requires_retraining)
    
    def test_07_psi_calculation(self):
        """Test Population Stability Index calculation"""
        baseline = np.random.randn(1000)
        
        # Similar distribution - low PSI
        current_similar = np.random.randn(500)
        psi_low = self.detector._calculate_psi(baseline, current_similar)
        self.assertLess(psi_low, 0.2)  # Should be low
        
        # Shifted distribution - high PSI
        current_shifted = np.random.randn(500) + 2.0
        psi_high = self.detector._calculate_psi(baseline, current_shifted)
        self.assertGreater(psi_high, 0.2)  # Should be high
    
    def test_08_drift_score_calculation(self):
        """Test combined drift score calculation"""
        # Low drift scenario
        score_low = self.detector._calculate_drift_score(
            ks_stat=0.1,
            p_value=0.8,
            psi=0.05
        )
        self.assertLess(score_low, 0.3)
        
        # High drift scenario
        score_high = self.detector._calculate_drift_score(
            ks_stat=0.8,
            p_value=0.01,
            psi=0.5
        )
        self.assertGreater(score_high, 0.7)
    
    def test_09_drift_reports(self):
        """Test drift report generation"""
        # Setup baseline and current
        baseline_data = self._generate_normal_data(150)
        for features in baseline_data:
            self.detector.update_baseline(features)
        
        drifted_data = self._generate_drifted_data(80, drift_amount=2.5)
        for features in drifted_data:
            self.detector.add_current_sample(features)
        
        # Check drift
        stats = self.detector.check_drift()
        
        # Should have reports
        self.assertGreater(len(self.detector.drift_reports), 0)
        
        # Get recent reports
        recent = self.detector.get_recent_reports(limit=5)
        self.assertGreater(len(recent), 0)
        
        # Check report structure
        report = recent[0]
        self.assertIn('timestamp', report)
        self.assertIn('feature_index', report)
        self.assertIn('feature_name', report)
        self.assertIn('drift_detected', report)
        self.assertIn('drift_score', report)
        self.assertIn('recommendation', report)
    
    def test_10_baseline_persistence(self):
        """Test baseline save/load"""
        # Add baseline data
        baseline_data = self._generate_normal_data(120)
        for features in baseline_data:
            self.detector.update_baseline(features)
        
        # Save
        self.detector._save_baseline()
        
        # Check file exists
        self.assertTrue(os.path.exists(self.detector.baseline_file))
        
        # Create new detector and load
        detector2 = DriftDetector(storage_dir=self.temp_dir)
        
        # Should have loaded baseline
        self.assertEqual(len(detector2.baseline_features), 120)
        self.assertEqual(detector2.samples_processed, 120)
        self.assertEqual(len(detector2.baseline_statistics), 15)
    
    def test_11_reports_persistence(self):
        """Test drift reports save/load"""
        # Generate some drift
        baseline_data = self._generate_normal_data(150)
        for features in baseline_data:
            self.detector.update_baseline(features)
        
        drifted_data = self._generate_drifted_data(75)
        for features in drifted_data:
            self.detector.add_current_sample(features)
        
        stats = self.detector.check_drift()
        
        # Save reports
        self.detector._save_reports()
        
        # Check file exists
        self.assertTrue(os.path.exists(self.detector.reports_file))
        
        # Load and verify
        with open(self.detector.reports_file, 'r') as f:
            reports_data = json.load(f)
        
        self.assertGreater(len(reports_data), 0)
        self.assertIn('feature_name', reports_data[0])
    
    def test_12_window_management(self):
        """Test window size limits"""
        # Add more than window_size samples
        large_data = self._generate_normal_data(600)
        
        for features in large_data:
            self.detector.update_baseline(features)
        
        # Should be capped at window_size
        self.assertEqual(len(self.detector.baseline_features), 500)
        
        # Add to current window (half size)
        for features in large_data[:300]:
            self.detector.add_current_sample(features)
        
        self.assertEqual(len(self.detector.current_features), 250)  # window_size // 2
    
    def test_13_reset_current_window(self):
        """Test resetting current window"""
        # Add samples
        data = self._generate_normal_data(50)
        for features in data:
            self.detector.add_current_sample(features)
        
        self.assertEqual(len(self.detector.current_features), 50)
        
        # Reset
        self.detector.reset_current_window()
        
        self.assertEqual(len(self.detector.current_features), 0)
    
    def test_14_update_baseline_from_current(self):
        """Test updating baseline with current window"""
        # Build initial baseline
        baseline_data = self._generate_normal_data(100)
        for features in baseline_data:
            self.detector.update_baseline(features)
        
        initial_size = len(self.detector.baseline_features)
        
        # Add different data to current
        new_data = self._generate_drifted_data(60)
        for features in new_data:
            self.detector.add_current_sample(features)
        
        self.assertEqual(len(self.detector.current_features), 60)
        
        # Update baseline from current
        success = self.detector.update_baseline_from_current()
        
        self.assertTrue(success)
        self.assertEqual(len(self.detector.baseline_features), initial_size + 60)
        self.assertEqual(len(self.detector.current_features), 0)  # Reset after update
    
    def test_15_insufficient_samples(self):
        """Test behavior with insufficient samples"""
        # Baseline with only 50 samples (need 100)
        small_baseline = self._generate_normal_data(50)
        for features in small_baseline:
            self.detector.update_baseline(features)
        
        # Current with only 20 samples (need 50)
        small_current = self._generate_normal_data(20)
        for features in small_current:
            self.detector.add_current_sample(features)
        
        # Should return empty statistics
        stats = self.detector.check_drift()
        
        self.assertEqual(stats.total_features, 0)
        self.assertFalse(stats.requires_retraining)
    
    def test_16_get_stats(self):
        """Test statistics retrieval"""
        # Add some data
        data = self._generate_normal_data(80)
        for features in data:
            self.detector.update_baseline(features)
        
        stats = self.detector.get_stats()
        
        self.assertIn('baseline_samples', stats)
        self.assertIn('current_samples', stats)
        self.assertIn('samples_processed', stats)
        self.assertIn('scipy_available', stats)
        
        self.assertEqual(stats['baseline_samples'], 80)
        self.assertTrue(stats['scipy_available'])
    
    def test_17_retraining_trigger_count(self):
        """Test retraining trigger counting"""
        initial_count = self.detector.retraining_triggered
        
        # Build baseline
        baseline_data = self._generate_normal_data(200)
        for features in baseline_data:
            self.detector.update_baseline(features)
        
        # Add severely drifted data
        drifted_data = self._generate_drifted_data(100, drift_amount=5.0)
        for features in drifted_data:
            self.detector.add_current_sample(features)
        
        # Check drift
        stats = self.detector.check_drift()
        
        if stats.requires_retraining:
            self.assertEqual(self.detector.retraining_triggered, initial_count + 1)
    
    def test_18_global_instance(self):
        """Test global detector instance"""
        detector1 = get_drift_detector()
        detector2 = get_drift_detector()
        
        # Should be same instance
        self.assertIs(detector1, detector2)
    
    def test_19_convenience_functions(self):
        """Test convenience wrapper functions"""
        # These use the global instance
        data = self._generate_normal_data(50)
        
        # Update baseline
        for features in data:
            update_baseline(features)
        
        # Track features
        for features in data:
            track_features(features)
        
        # Check drift (may not have enough samples)
        result = check_drift()
        
        # Should return None or DriftStatistics
        self.assertTrue(result is None or isinstance(result, DriftStatistics))
    
    def test_20_edge_cases(self):
        """Test edge cases"""
        # Constant feature (no variation)
        constant_baseline = np.ones((100, 15))
        constant_current = np.ones((50, 15))
        
        for features in constant_baseline:
            self.detector.update_baseline(features)
        
        for features in constant_current:
            self.detector.add_current_sample(features)
        
        # Should handle gracefully (no drift since identical)
        stats = self.detector.check_drift()
        self.assertIsNotNone(stats)


if __name__ == '__main__':
    # Run tests
    print("=" * 70)
    print("DRIFT DETECTOR UNIT TESTS (Phase 3)")
    print("=" * 70)
    
    if not SCIPY_AVAILABLE:
        print("\n⚠️  WARNING: scipy not available - drift tests will be skipped")
    
    unittest.main(verbosity=2)
