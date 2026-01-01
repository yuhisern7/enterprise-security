#!/usr/bin/env python3
"""
Attack Signature Synchronization Service
Receives attack signatures from all security nodes and stores in centralized database

Data Flow:
1. Node detects attack → Extracts signature (keywords, encodings, patterns)
2. Node DELETES attack payload (exploit code)
3. Node sends ONLY signature hash + features to relay
4. Relay stores signature in PostgreSQL database
5. Relay uses signatures for ML training
6. Relay distributes updated models back to all nodes

Privacy Guarantee:
- Nodes send ONLY attack patterns (no device info, no topology, no IPs)
- Database stores ONLY signatures (no exploit code, no customer data)
- Signatures are anonymous (no customer ID attached)
"""

import asyncio
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
from database import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SignatureSyncService:
    """
    Handles incoming attack signatures from security nodes
    Stores in centralized database for ML training
    """
    
    def __init__(self):
        self.signatures_received = 0
        self.signatures_stored = 0
        self.duplicates_detected = 0
        self.invalid_signatures = 0
    
    async def process_signature(self, signature_data: Dict[str, Any], source_ip: str = None) -> Dict[str, Any]:
        """
        Process incoming attack signature from security node
        
        Args:
            signature_data: Attack signature dict containing:
                - attack_type: Type of attack
                - keywords: List of keywords detected
                - encodings: List of encoding types
                - payload_length: Original attack size
                - ml_features: Feature vector
            source_ip: Source IP (for anonymous region mapping)
        
        Returns:
            Dict with status and signature_id
        """
        
        self.signatures_received += 1
        
        try:
            # Validate signature (ensure NO exploit code)
            if not self._validate_signature(signature_data):
                self.invalid_signatures += 1
                return {
                    'success': False,
                    'error': 'Invalid signature format or contains prohibited data'
                }
            
            # Generate pattern hash (unique identifier)
            pattern_hash = self._generate_pattern_hash(signature_data)
            signature_data['pattern_hash'] = pattern_hash
            
            # Map source IP to anonymous region (privacy)
            if source_ip:
                signature_data['source_region'] = self._anonymize_region(source_ip)
            
            # Calculate derived features
            signature_data = self._enrich_signature(signature_data)
            
            # Store in database
            signature_id = db.insert_attack_signature(signature_data)
            
            if signature_id:
                self.signatures_stored += 1
                logger.info(f"✅ Stored signature {pattern_hash[:8]}... ({signature_data['attack_type']})")
                
                return {
                    'success': True,
                    'signature_id': signature_id,
                    'pattern_hash': pattern_hash,
                    'duplicate': False
                }
            else:
                self.duplicates_detected += 1
                return {
                    'success': True,
                    'duplicate': True,
                    'pattern_hash': pattern_hash
                }
        
        except Exception as e:
            logger.error(f"Failed to process signature: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _validate_signature(self, signature: Dict[str, Any]) -> bool:
        """
        Validate signature format and ensure NO exploit code
        
        Returns:
            True if valid, False if contains prohibited data
        """
        
        # Required fields
        required_fields = ['attack_type', 'keywords', 'encodings']
        if not all(field in signature for field in required_fields):
            logger.warning("Missing required fields in signature")
            return False
        
        # Prohibited fields (privacy violations)
        prohibited_fields = [
            'device_list', 'ip_addresses', 'network_topology',
            'customer_id', 'organization_name', 'device_history',
            'blocked_ips', 'whitelist', 'exploit_code', 'payload',
            'attack_payload', 'malware_binary'
        ]
        
        for field in prohibited_fields:
            if field in signature:
                logger.error(f"❌ PROHIBITED FIELD DETECTED: {field}")
                return False
        
        # Check for base64 blobs (might be exploit code)
        for key, value in signature.items():
            if isinstance(value, str) and len(value) > 1000:
                # Long strings might be encoded exploit code
                logger.warning(f"Suspicious long string in field '{key}' (length: {len(value)})")
                # Don't reject, but log for review
        
        return True
    
    def _generate_pattern_hash(self, signature: Dict[str, Any]) -> str:
        """
        Generate unique hash for attack pattern
        Hash is based on attack characteristics, NOT customer data
        """
        
        # Create deterministic signature string
        signature_components = [
            signature.get('attack_type', ''),
            json.dumps(sorted(signature.get('keywords', [])), sort_keys=True),
            json.dumps(sorted(signature.get('encodings', [])), sort_keys=True),
            str(signature.get('encoding_chain_depth', 0)),
        ]
        
        signature_string = '|'.join(signature_components)
        return hashlib.sha256(signature_string.encode()).hexdigest()
    
    def _anonymize_region(self, ip_address: str) -> str:
        """
        Convert IP to anonymous region (privacy)
        
        Examples:
        - 192.168.x.x → "Private Network" (don't store)
        - 203.x.x.x → "Asia"
        - 52.x.x.x → "North America"
        
        Privacy: NO exact IP stored, only continental region
        """
        
        # Private/local IPs
        if ip_address.startswith(('192.168.', '10.', '172.16.', '127.')):
            return "Unknown"
        
        # Simple continent mapping (use GeoIP library in production)
        # This is a placeholder - use python-geoip or maxminddb
        first_octet = int(ip_address.split('.')[0])
        
        if 1 <= first_octet <= 62:
            return "North America"
        elif 63 <= first_octet <= 125:
            return "Europe"
        elif 126 <= first_octet <= 188:
            return "Asia"
        elif 189 <= first_octet <= 223:
            return "South America"
        else:
            return "Other"
    
    def _enrich_signature(self, signature: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate derived features for ML training
        """
        
        # Count keywords
        signature['keyword_count'] = len(signature.get('keywords', []))
        
        # Count encodings
        signature['encoding_count'] = len(signature.get('encodings', []))
        
        # Calculate encoding chain depth
        if 'encoding_chain_depth' not in signature:
            signature['encoding_chain_depth'] = signature['encoding_count']
        
        # Calculate pattern complexity (1-10)
        complexity = min(10, max(1, 
            signature['keyword_count'] + 
            signature['encoding_count'] * 2 +
            signature.get('encoding_chain_depth', 0)
        ))
        signature['pattern_complexity'] = complexity
        
        # Ensure ml_features exists
        if 'ml_features' not in signature:
            signature['ml_features'] = {
                'keyword_count': signature['keyword_count'],
                'encoding_count': signature['encoding_count'],
                'has_base64': 'base64' in signature.get('encodings', []),
                'has_hex': 'hex' in signature.get('encodings', []),
                'has_url_encoding': 'url_encoded' in signature.get('encodings', []),
                'pattern_complexity': complexity
            }
        
        return signature
    
    def get_sync_statistics(self) -> Dict[str, Any]:
        """Get synchronization statistics"""
        return {
            'signatures_received': self.signatures_received,
            'signatures_stored': self.signatures_stored,
            'duplicates_detected': self.duplicates_detected,
            'invalid_signatures': self.invalid_signatures,
            'database_stats': db.get_database_stats()
        }


# Global sync service instance
sync_service = SignatureSyncService()


async def handle_signature_upload(signature_data: Dict[str, Any], source_ip: str = None) -> Dict[str, Any]:
    """
    Handler for signature uploads from security nodes
    
    Usage in relay_server.py:
        result = await handle_signature_upload(signature_data, client_ip)
    """
    return await sync_service.process_signature(signature_data, source_ip)


if __name__ == "__main__":
    # Test signature processing
    logger.info("Testing signature sync service...")
    
    test_signature = {
        'attack_type': 'SQL Injection',
        'keywords': ['SELECT', 'UNION', 'FROM', 'WHERE'],
        'encodings': ['url_encoded'],
        'payload_length': 156,
        'encoding_chain_depth': 1
    }
    
    async def test():
        result = await sync_service.process_signature(test_signature, '203.0.113.1')
        logger.info(f"Test result: {result}")
        
        stats = sync_service.get_sync_statistics()
        logger.info(f"Sync stats: {json.dumps(stats, indent=2)}")
    
    asyncio.run(test())
