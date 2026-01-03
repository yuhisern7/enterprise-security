"""
MODULE B: Byzantine-Resilient Federated Learning

Ensures adversarial nodes cannot poison the global ML model through malicious
updates. Uses Byzantine fault-tolerant aggregation to filter out outlier model
updates from compromised peers.

Pure Python implementation using mathematical outlier detection - no kernel access.

Risk Level: LOW (Pure defensive, math-based validation)
"""

import numpy as np
import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class ModelUpdate:
    """Represents a model update from a peer node."""
    peer_id: str
    weights: np.ndarray
    timestamp: datetime
    signature: str
    metadata: Dict


class ByzantineDefender:
    """
    Byzantine-resilient federated learning aggregator.
    
    Protects against:
    - Malicious model updates from compromised peers
    - Data poisoning attacks
    - Model inversion attempts
    - Gradient manipulation
    
    Methods:
    - Krum: Select most representative update
    - Trimmed Mean: Remove outliers before averaging
    - Median: Byzantine-robust central tendency
    - Multi-Krum: Average of K most central updates
    """
    
    def __init__(self, byzantine_tolerance: float = 0.3):
        """
        Initialize Byzantine defender.
        
        Args:
            byzantine_tolerance: Maximum fraction of Byzantine nodes (default 30%)
        """
        self.byzantine_tolerance = byzantine_tolerance
        self.update_history = []
        self.rejected_updates = []
        self.aggregation_stats = {
            "total_updates": 0,
            "rejected_byzantine": 0,
            "accepted_updates": 0,
            "method_used": []
        }
        
        logger.info(f"[BYZANTINE] Initialized with {byzantine_tolerance*100}% tolerance")
    
    def aggregate_updates(
        self, 
        updates: List[ModelUpdate], 
        method: str = "trimmed_mean"
    ) -> Tuple[np.ndarray, Dict]:
        """
        Aggregate model updates with Byzantine fault tolerance.
        
        Args:
            updates: List of model updates from peers
            method: Aggregation method ('krum', 'trimmed_mean', 'median', 'multi_krum')
        
        Returns:
            Tuple of (aggregated_weights, statistics)
        """
        if len(updates) == 0:
            raise ValueError("No updates to aggregate")
        
        self.aggregation_stats["total_updates"] += len(updates)
        self.aggregation_stats["method_used"].append(method)
        
        # Extract weight matrices
        weight_matrices = [u.weights for u in updates]
        
        # Apply Byzantine-resilient aggregation
        if method == "krum":
            result, stats = self._krum(weight_matrices, updates)
        elif method == "trimmed_mean":
            result, stats = self._trimmed_mean(weight_matrices, updates)
        elif method == "median":
            result, stats = self._median(weight_matrices, updates)
        elif method == "multi_krum":
            result, stats = self._multi_krum(weight_matrices, updates)
        else:
            raise ValueError(f"Unknown method: {method}")
        
        self.aggregation_stats["rejected_byzantine"] += stats["rejected_count"]
        self.aggregation_stats["accepted_updates"] += stats["accepted_count"]
        
        logger.info(f"[BYZANTINE] Aggregated {len(updates)} updates using {method}")
        logger.info(f"[BYZANTINE] Rejected {stats['rejected_count']} suspicious updates")
        
        return result, stats
    
    def _krum(
        self, 
        weight_matrices: List[np.ndarray], 
        updates: List[ModelUpdate]
    ) -> Tuple[np.ndarray, Dict]:
        """
        Krum aggregation: Select most representative update.
        
        Computes pairwise distances and selects the update with smallest
        sum of distances to its K nearest neighbors.
        """
        n = len(weight_matrices)
        f = int(n * self.byzantine_tolerance)  # Max Byzantine nodes
        k = n - f - 2  # Number of neighbors to consider
        
        if k <= 0:
            logger.warning("[KRUM] Too few updates for Byzantine tolerance")
            return weight_matrices[0], {"rejected_count": 0, "accepted_count": 1}
        
        # Compute pairwise distances
        distances = np.zeros((n, n))
        for i in range(n):
            for j in range(i + 1, n):
                dist = np.linalg.norm(weight_matrices[i] - weight_matrices[j])
                distances[i, j] = dist
                distances[j, i] = dist
        
        # For each update, sum distances to K nearest neighbors
        scores = []
        for i in range(n):
            sorted_distances = np.sort(distances[i])
            score = np.sum(sorted_distances[1:k+2])  # Exclude self (distance 0)
            scores.append(score)
        
        # Select update with minimum score
        selected_idx = np.argmin(scores)
        selected_update = weight_matrices[selected_idx]
        
        # Mark rejected updates
        rejected = [i for i in range(n) if i != selected_idx]
        for idx in rejected:
            self.rejected_updates.append({
                "peer_id": updates[idx].peer_id,
                "reason": "Not selected by Krum",
                "timestamp": datetime.now().isoformat()
            })
        
        stats = {
            "rejected_count": len(rejected),
            "accepted_count": 1,
            "selected_peer": updates[selected_idx].peer_id,
            "krum_score": scores[selected_idx]
        }
        
        return selected_update, stats
    
    def _trimmed_mean(
        self, 
        weight_matrices: List[np.ndarray], 
        updates: List[ModelUpdate]
    ) -> Tuple[np.ndarray, Dict]:
        """
        Trimmed mean: Remove outliers then average.
        
        Removes top and bottom percentile of values for each weight,
        then computes mean of remaining values.
        """
        n = len(weight_matrices)
        f = int(n * self.byzantine_tolerance)  # Number to trim from each end
        
        if n - 2*f < 1:
            logger.warning("[TRIMMED_MEAN] Too few updates for trimming")
            return np.mean(weight_matrices, axis=0), {
                "rejected_count": 0, 
                "accepted_count": n
            }
        
        # Stack all weight matrices
        stacked = np.stack(weight_matrices)
        
        # For each weight position, sort across all updates and trim
        shape = weight_matrices[0].shape
        result = np.zeros(shape)
        
        for idx in np.ndindex(shape):
            values = stacked[:, idx[0]] if len(shape) == 1 else stacked[:, idx[0], idx[1]]
            sorted_values = np.sort(values)
            trimmed = sorted_values[f:n-f]  # Remove f from each end
            result[idx] = np.mean(trimmed)
        
        stats = {
            "rejected_count": 2 * f,  # Trimmed from both ends
            "accepted_count": n - 2*f,
            "trim_fraction": self.byzantine_tolerance
        }
        
        return result, stats
    
    def _median(
        self, 
        weight_matrices: List[np.ndarray], 
        updates: List[ModelUpdate]
    ) -> Tuple[np.ndarray, Dict]:
        """
        Coordinate-wise median aggregation.
        
        Byzantine-robust as median is resistant to outliers.
        """
        stacked = np.stack(weight_matrices)
        result = np.median(stacked, axis=0)
        
        stats = {
            "rejected_count": 0,  # Median doesn't explicitly reject
            "accepted_count": len(weight_matrices),
            "method": "median"
        }
        
        return result, stats
    
    def _multi_krum(
        self, 
        weight_matrices: List[np.ndarray], 
        updates: List[ModelUpdate]
    ) -> Tuple[np.ndarray, Dict]:
        """
        Multi-Krum: Average of K most representative updates.
        
        More robust than single Krum by averaging multiple good updates.
        """
        n = len(weight_matrices)
        f = int(n * self.byzantine_tolerance)
        k_select = n - f  # Number of updates to average
        
        if k_select <= 0:
            logger.warning("[MULTI-KRUM] Too few updates")
            return weight_matrices[0], {"rejected_count": 0, "accepted_count": 1}
        
        # Compute pairwise distances (same as Krum)
        distances = np.zeros((n, n))
        for i in range(n):
            for j in range(i + 1, n):
                dist = np.linalg.norm(weight_matrices[i] - weight_matrices[j])
                distances[i, j] = dist
                distances[j, i] = dist
        
        # Compute scores for each update
        k_neighbors = max(1, n - f - 2)
        scores = []
        for i in range(n):
            sorted_distances = np.sort(distances[i])
            score = np.sum(sorted_distances[1:k_neighbors+2])
            scores.append(score)
        
        # Select K updates with lowest scores
        selected_indices = np.argsort(scores)[:k_select]
        selected_weights = [weight_matrices[i] for i in selected_indices]
        
        # Average selected updates
        result = np.mean(selected_weights, axis=0)
        
        # Mark rejected updates
        rejected_indices = set(range(n)) - set(selected_indices)
        for idx in rejected_indices:
            self.rejected_updates.append({
                "peer_id": updates[idx].peer_id,
                "reason": "Multi-Krum rejection (high score)",
                "timestamp": datetime.now().isoformat()
            })
        
        stats = {
            "rejected_count": len(rejected_indices),
            "accepted_count": k_select,
            "selected_peers": [updates[i].peer_id for i in selected_indices],
            "avg_score": np.mean([scores[i] for i in selected_indices])
        }
        
        return result, stats
    
    def detect_poisoning_attempt(self, update: ModelUpdate, baseline: np.ndarray) -> Dict:
        """
        Detect if an update is likely a poisoning attempt.
        
        Checks:
        - L2 distance from baseline (magnitude check)
        - Cosine similarity (direction check)
        - Weight distribution analysis
        """
        weights = update.weights
        
        # L2 distance
        l2_dist = np.linalg.norm(weights - baseline)
        
        # Cosine similarity
        cosine_sim = np.dot(weights.flatten(), baseline.flatten()) / (
            np.linalg.norm(weights) * np.linalg.norm(baseline) + 1e-8
        )
        
        # Weight statistics
        weight_mean = np.mean(weights)
        weight_std = np.std(weights)
        weight_max = np.max(np.abs(weights))
        
        # Heuristic thresholds (can be tuned)
        is_suspicious = (
            l2_dist > 10.0 or  # Very different from baseline
            cosine_sim < -0.5 or  # Opposite direction
            weight_max > 100.0 or  # Extreme weights
            weight_std > 50.0  # High variance
        )
        
        return {
            "is_suspicious": is_suspicious,
            "l2_distance": float(l2_dist),
            "cosine_similarity": float(cosine_sim),
            "weight_mean": float(weight_mean),
            "weight_std": float(weight_std),
            "weight_max": float(weight_max)
        }
    
    def get_stats(self) -> Dict:
        """Get Byzantine defense statistics."""
        return {
            "total_updates_processed": self.aggregation_stats["total_updates"],
            "rejected_byzantine": self.aggregation_stats["rejected_byzantine"],
            "accepted_updates": self.aggregation_stats["accepted_updates"],
            "rejection_rate": self.aggregation_stats["rejected_byzantine"] / 
                            max(1, self.aggregation_stats["total_updates"]),
            "byzantine_tolerance": self.byzantine_tolerance,
            "methods_used": list(set(self.aggregation_stats["method_used"]))
        }


# Singleton instance
_byzantine_defender: Optional[ByzantineDefender] = None


def get_byzantine_defender() -> ByzantineDefender:
    """Get singleton Byzantine defender instance."""
    global _byzantine_defender
    if _byzantine_defender is None:
        _byzantine_defender = ByzantineDefender()
    return _byzantine_defender
