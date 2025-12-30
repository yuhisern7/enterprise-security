#!/usr/bin/env python3
"""
GPU-Accelerated AI Training Module
Supports TensorFlow/PyTorch for large-scale threat detection
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class GPUTrainer:
    """GPU-accelerated ML training for threat detection"""
    
    def __init__(self):
        self.gpu_available = False
        self.gpu_type = None  # 'cuda', 'rocm', or None
        self.gpu_name = None
        self.framework = None  # 'tensorflow' or 'pytorch'
        self.model = None
        self.training_data_path = "/app/relay/ai_training_materials"
        
        # Detect GPU
        self._detect_gpu()
    
    def _detect_gpu(self) -> Dict[str, any]:
        """Detect available GPU and framework"""
        gpu_info = {
            'available': False,
            'type': None,
            'name': 'CPU Only',
            'framework': None,
            'memory_gb': 0
        }
        
        # Try CUDA (NVIDIA)
        try:
            import torch
            if torch.cuda.is_available():
                gpu_info['available'] = True
                gpu_info['type'] = 'cuda'
                gpu_info['name'] = torch.cuda.get_device_name(0)
                gpu_info['framework'] = 'pytorch'
                gpu_info['memory_gb'] = torch.cuda.get_device_properties(0).total_memory / 1e9
                self.gpu_available = True
                self.gpu_type = 'cuda'
                self.gpu_name = gpu_info['name']
                self.framework = 'pytorch'
                logger.info(f"🚀 GPU Detected: {gpu_info['name']} ({gpu_info['memory_gb']:.1f}GB)")
                return gpu_info
        except ImportError:
            pass
        
        # Try TensorFlow
        try:
            import tensorflow as tf
            gpus = tf.config.list_physical_devices('GPU')
            if gpus:
                gpu_info['available'] = True
                gpu_info['type'] = 'cuda' if 'CUDA' in str(gpus[0]) else 'gpu'
                gpu_info['name'] = str(gpus[0])
                gpu_info['framework'] = 'tensorflow'
                self.gpu_available = True
                self.gpu_type = 'cuda'
                self.gpu_name = gpu_info['name']
                self.framework = 'tensorflow'
                logger.info(f"🚀 GPU Detected (TensorFlow): {len(gpus)} GPU(s)")
                return gpu_info
        except ImportError:
            pass
        
        # Fallback to CPU
        logger.info("💻 No GPU detected - using CPU")
        return gpu_info
    
    def get_gpu_info(self) -> Dict[str, any]:
        """Get GPU information for dashboard"""
        return {
            'available': self.gpu_available,
            'type': self.gpu_type,
            'name': self.gpu_name,
            'framework': self.framework
        }
    
    def load_training_materials(self) -> Tuple[np.ndarray, np.ndarray, int]:
        """Load all training materials from ai_training_materials folder"""
        all_features = []
        all_labels = []
        files_loaded = 0
        
        if not os.path.exists(self.training_data_path):
            logger.warning(f"Training materials folder not found: {self.training_data_path}")
            return np.array([]), np.array([]), 0
        
        # Load CSV files
        for filename in os.listdir(self.training_data_path):
            filepath = os.path.join(self.training_data_path, filename)
            
            if filename.endswith('.csv'):
                try:
                    df = pd.read_csv(filepath)
                    features, labels = self._process_csv(df)
                    all_features.append(features)
                    all_labels.append(labels)
                    files_loaded += 1
                    logger.info(f"📁 Loaded CSV: {filename} ({len(labels)} samples)")
                except Exception as e:
                    logger.error(f"Failed to load {filename}: {e}")
            
            elif filename.endswith('.json'):
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    df = pd.DataFrame(data)
                    features, labels = self._process_csv(df)
                    all_features.append(features)
                    all_labels.append(labels)
                    files_loaded += 1
                    logger.info(f"📁 Loaded JSON: {filename} ({len(labels)} samples)")
                except Exception as e:
                    logger.error(f"Failed to load {filename}: {e}")
            
            elif filename.endswith('_features.npy'):
                try:
                    features = np.load(filepath)
                    label_file = filepath.replace('_features.npy', '_labels.npy')
                    if os.path.exists(label_file):
                        labels = np.load(label_file)
                        all_features.append(features)
                        all_labels.append(labels)
                        files_loaded += 1
                        logger.info(f"📁 Loaded NPY: {filename} ({len(labels)} samples)")
                except Exception as e:
                    logger.error(f"Failed to load {filename}: {e}")
        
        if not all_features:
            logger.warning("No training materials found!")
            return np.array([]), np.array([]), 0
        
        # Combine all datasets
        X = np.vstack(all_features)
        y = np.concatenate(all_labels)
        
        logger.info(f"✅ Loaded {files_loaded} files, {len(y)} total samples")
        return X, y, files_loaded
    
    def _process_csv(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Convert CSV data to features and labels"""
        # Extract features
        features = []
        labels = df['is_malicious'].values
        
        for _, row in df.iterrows():
            feature_vector = [
                row.get('threat_score', 0.5),
                row.get('port', 80),
                row.get('payload_size', 512),
                1 if row.get('protocol') == 'TCP' else 0,
                1 if row.get('protocol') == 'UDP' else 0,
                1 if row.get('severity') == 'critical' else 0,
                1 if row.get('severity') == 'high' else 0,
                1 if row.get('severity') == 'medium' else 0,
            ]
            features.append(feature_vector)
        
        return np.array(features), labels
    
    def train_gpu_model(self, X: np.ndarray, y: np.ndarray) -> Dict[str, any]:
        """Train model using GPU acceleration"""
        if not self.gpu_available:
            return {
                'success': False,
                'message': 'No GPU available',
                'accuracy': 0,
                'training_time': 0
            }
        
        import time
        start_time = time.time()
        
        if self.framework == 'tensorflow':
            result = self._train_tensorflow(X, y)
        elif self.framework == 'pytorch':
            result = self._train_pytorch(X, y)
        else:
            return {'success': False, 'message': 'No framework available'}
        
        training_time = time.time() - start_time
        result['training_time'] = training_time
        
        logger.info(f"🎓 GPU Training completed in {training_time:.2f}s - Accuracy: {result.get('accuracy', 0):.2%}")
        return result
    
    def _train_tensorflow(self, X: np.ndarray, y: np.ndarray) -> Dict[str, any]:
        """Train using TensorFlow on GPU"""
        try:
            import tensorflow as tf
            from sklearn.model_selection import train_test_split
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Build neural network
            model = tf.keras.Sequential([
                tf.keras.layers.Dense(128, activation='relu', input_shape=(X.shape[1],)),
                tf.keras.layers.Dropout(0.3),
                tf.keras.layers.Dense(64, activation='relu'),
                tf.keras.layers.Dropout(0.2),
                tf.keras.layers.Dense(32, activation='relu'),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            # Train on GPU
            with tf.device('/GPU:0'):
                history = model.fit(
                    X_train, y_train,
                    epochs=10,
                    batch_size=32,
                    validation_split=0.2,
                    verbose=0
                )
            
            # Evaluate
            _, accuracy = model.evaluate(X_test, y_test, verbose=0)
            
            self.model = model
            
            return {
                'success': True,
                'framework': 'tensorflow',
                'accuracy': accuracy,
                'samples': len(y),
                'message': f'Trained on {len(y)} samples'
            }
        
        except Exception as e:
            logger.error(f"TensorFlow training failed: {e}")
            return {'success': False, 'message': str(e)}
    
    def _train_pytorch(self, X: np.ndarray, y: np.ndarray) -> Dict[str, any]:
        """Train using PyTorch on GPU"""
        try:
            import torch
            import torch.nn as nn
            import torch.optim as optim
            from sklearn.model_selection import train_test_split
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Convert to tensors
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            X_train_t = torch.FloatTensor(X_train).to(device)
            y_train_t = torch.FloatTensor(y_train).unsqueeze(1).to(device)
            X_test_t = torch.FloatTensor(X_test).to(device)
            y_test_t = torch.FloatTensor(y_test).unsqueeze(1).to(device)
            
            # Build neural network
            class ThreatNet(nn.Module):
                def __init__(self, input_size):
                    super(ThreatNet, self).__init__()
                    self.fc1 = nn.Linear(input_size, 128)
                    self.dropout1 = nn.Dropout(0.3)
                    self.fc2 = nn.Linear(128, 64)
                    self.dropout2 = nn.Dropout(0.2)
                    self.fc3 = nn.Linear(64, 32)
                    self.fc4 = nn.Linear(32, 1)
                    self.sigmoid = nn.Sigmoid()
                
                def forward(self, x):
                    x = torch.relu(self.fc1(x))
                    x = self.dropout1(x)
                    x = torch.relu(self.fc2(x))
                    x = self.dropout2(x)
                    x = torch.relu(self.fc3(x))
                    x = self.sigmoid(self.fc4(x))
                    return x
            
            model = ThreatNet(X.shape[1]).to(device)
            criterion = nn.BCELoss()
            optimizer = optim.Adam(model.parameters())
            
            # Train
            model.train()
            for epoch in range(10):
                optimizer.zero_grad()
                outputs = model(X_train_t)
                loss = criterion(outputs, y_train_t)
                loss.backward()
                optimizer.step()
            
            # Evaluate
            model.eval()
            with torch.no_grad():
                predictions = model(X_test_t)
                predictions = (predictions > 0.5).float()
                accuracy = (predictions == y_test_t).float().mean().item()
            
            self.model = model
            
            return {
                'success': True,
                'framework': 'pytorch',
                'accuracy': accuracy,
                'samples': len(y),
                'message': f'Trained on {len(y)} samples'
            }
        
        except Exception as e:
            logger.error(f"PyTorch training failed: {e}")
            return {'success': False, 'message': str(e)}


# Global trainer instance
_gpu_trainer = None

def get_gpu_trainer() -> GPUTrainer:
    """Get global GPU trainer instance"""
    global _gpu_trainer
    if _gpu_trainer is None:
        _gpu_trainer = GPUTrainer()
    return _gpu_trainer


def get_gpu_info() -> Dict[str, any]:
    """Get GPU information for dashboard"""
    trainer = get_gpu_trainer()
    return trainer.get_gpu_info()


def train_with_gpu() -> Dict[str, any]:
    """Train model using GPU with materials from folder"""
    trainer = get_gpu_trainer()
    
    # Load training materials
    X, y, files_loaded = trainer.load_training_materials()
    
    if len(y) == 0:
        return {
            'success': False,
            'message': 'No training data found in ai_training_materials folder'
        }
    
    # Train
    result = trainer.train_gpu_model(X, y)
    result['files_loaded'] = files_loaded
    
    return result
