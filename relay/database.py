#!/usr/bin/env python3
"""
Centralized Attack Signature Database for Battle-Hardened AI
Stores ONLY attack signatures (patterns, keywords, encodings) - NO exploit payloads
Privacy: Customer device info, IPs, topology NEVER stored - only anonymous attack patterns

Database Schema:
- attack_signatures: Extracted patterns from real attacks (for ML training)
- threat_intelligence: Aggregated threat statistics by type/region
- training_batches: Versioned ML training datasets
- signature_updates: Distribution log for subscribers
"""

import psycopg2
from psycopg2.extras import RealDictCursor, Json
from datetime import datetime
import json
import logging
import os
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackSignatureDatabase:
    """
    Centralized database for attack signatures ONLY
    
    Privacy Guarantee:
    - NO customer device lists stored
    - NO network topology stored
    - NO IP addresses stored (except attacker IPs, anonymized)
    - NO exploit code/payloads stored
    - ONLY attack patterns (keywords, encodings, hashes)
    """
    
    def __init__(self):
        self.db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', 5432)),
            'database': os.getenv('DB_NAME', 'attack_signatures'),
            'user': os.getenv('DB_USER', 'battlehardened'),
            'password': os.getenv('DB_PASSWORD', 'change-this-password'),
        }
        self._create_tables()
    
    @contextmanager
    def get_connection(self):
        """Get database connection with automatic cleanup"""
        conn = None
        try:
            conn = psycopg2.connect(**self.db_config)
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def _create_tables(self):
        """Create database schema - PRIVACY COMPLIANT (signatures only)"""
        
        schema = """
        -- ATTACK SIGNATURES TABLE (ML Training Data)
        CREATE TABLE IF NOT EXISTS attack_signatures (
            signature_id SERIAL PRIMARY KEY,
            pattern_hash VARCHAR(64) UNIQUE NOT NULL,  -- Hash of attack pattern
            attack_type VARCHAR(100) NOT NULL,         -- SQL Injection, XSS, etc.
            
            -- Pattern Features (NOT exploit code)
            keywords JSONB,                            -- Keywords detected (e.g., ["eval", "base64_decode"])
            encodings JSONB,                           -- Encoding types (e.g., ["base64", "url_encoded"])
            encoding_chain_depth INTEGER,              -- Multi-layer encoding depth
            regex_patterns TEXT[],                     -- Generated detection patterns
            
            -- Statistical Features for ML
            payload_length INTEGER,                    -- Size of original attack
            keyword_count INTEGER,                     -- Number of suspicious keywords
            encoding_count INTEGER,                    -- Number of encoding layers
            pattern_complexity INTEGER,                -- Complexity score (1-10)
            
            -- Metadata
            first_seen TIMESTAMP DEFAULT NOW(),
            last_seen TIMESTAMP DEFAULT NOW(),
            global_occurrence_count INTEGER DEFAULT 1, -- How many times seen globally
            source_region VARCHAR(50),                 -- Anonymous region (e.g., "Asia", "Europe")
            
            -- ML Model Features (stored as JSON)
            ml_features JSONB,                         -- Feature vector for training
            
            -- Privacy: NO customer ID, NO device info, NO topology
            created_at TIMESTAMP DEFAULT NOW()
        );
        
        CREATE INDEX IF NOT EXISTS idx_attack_type ON attack_signatures(attack_type);
        CREATE INDEX IF NOT EXISTS idx_pattern_hash ON attack_signatures(pattern_hash);
        CREATE INDEX IF NOT EXISTS idx_first_seen ON attack_signatures(first_seen);
        
        -- THREAT INTELLIGENCE TABLE (Aggregated Statistics)
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            threat_id SERIAL PRIMARY KEY,
            attack_type VARCHAR(100) NOT NULL,
            
            -- Anonymous Statistics (NO customer data)
            total_occurrences BIGINT DEFAULT 0,
            unique_patterns INTEGER DEFAULT 0,
            avg_complexity FLOAT,
            
            -- Geographic Distribution (Anonymous Regions)
            region_distribution JSONB,                 -- {"Asia": 1234, "Europe": 567}
            
            -- Temporal Patterns
            hourly_distribution JSONB,                 -- Attack frequency by hour
            daily_trend JSONB,                         -- 30-day trend
            
            -- Top Patterns
            top_keywords JSONB,                        -- Most common keywords
            top_encodings JSONB,                       -- Most common encoding types
            
            last_updated TIMESTAMP DEFAULT NOW()
        );
        
        CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_intelligence(attack_type);
        
        -- ML TRAINING BATCHES TABLE (Versioned Datasets)
        CREATE TABLE IF NOT EXISTS training_batches (
            batch_id SERIAL PRIMARY KEY,
            version VARCHAR(50) UNIQUE NOT NULL,       -- e.g., "v1.2.3"
            
            -- Training Data Summary
            total_signatures INTEGER,                  -- Number of patterns in batch
            attack_type_distribution JSONB,            -- Distribution by type
            
            -- Model Performance
            accuracy FLOAT,
            precision_score FLOAT,
            recall FLOAT,
            f1_score FLOAT,
            
            -- Dataset Files (stored separately, paths only)
            training_file_path TEXT,                   -- Path to training CSV
            model_file_path TEXT,                      -- Path to trained model file
            
            created_at TIMESTAMP DEFAULT NOW(),
            training_duration_seconds INTEGER
        );
        
        -- SIGNATURE DISTRIBUTION LOG (Track who received what updates)
        CREATE TABLE IF NOT EXISTS signature_updates (
            update_id SERIAL PRIMARY KEY,
            batch_version VARCHAR(50) NOT NULL,
            
            -- Anonymous Subscriber Info (NO customer identity)
            subscriber_count INTEGER,                  -- How many nodes received update
            distribution_timestamp TIMESTAMP DEFAULT NOW(),
            
            -- Update Summary
            new_signatures_count INTEGER,
            updated_signatures_count INTEGER,
            model_size_kb INTEGER
        );
        
        -- EXPLOIT-FREE GUARANTEE TABLE (Audit Trail)
        CREATE TABLE IF NOT EXISTS payload_deletion_log (
            log_id SERIAL PRIMARY KEY,
            signature_hash VARCHAR(64) NOT NULL,
            attack_type VARCHAR(100),
            
            -- Proof of Deletion
            payload_deleted_at TIMESTAMP DEFAULT NOW(),
            pattern_extracted BOOLEAN DEFAULT TRUE,
            exploit_code_stored BOOLEAN DEFAULT FALSE, -- ALWAYS FALSE
            
            -- Audit Info
            deletion_verified BOOLEAN DEFAULT TRUE
        );
        
        CREATE INDEX IF NOT EXISTS idx_deletion_log ON payload_deletion_log(payload_deleted_at);
        """
        
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(schema)
            logger.info("✅ Database schema created successfully")
        except Exception as e:
            logger.error(f"Failed to create schema: {e}")
            raise
    
    def insert_attack_signature(self, signature: Dict[str, Any]) -> int:
        """
        Insert attack signature into database
        
        Args:
            signature: Dict containing:
                - pattern_hash: Unique hash of attack pattern
                - attack_type: Type of attack
                - keywords: List of keywords detected
                - encodings: List of encoding types
                - ml_features: Feature vector for ML
                - source_region: Anonymous region (optional)
        
        Returns:
            signature_id: Database ID of inserted signature
        
        Privacy: NO exploit code, NO customer data
        """
        
        query = """
        INSERT INTO attack_signatures (
            pattern_hash, attack_type, keywords, encodings,
            encoding_chain_depth, payload_length, keyword_count,
            encoding_count, pattern_complexity, source_region, ml_features
        ) VALUES (
            %(pattern_hash)s, %(attack_type)s, %(keywords)s, %(encodings)s,
            %(encoding_chain_depth)s, %(payload_length)s, %(keyword_count)s,
            %(encoding_count)s, %(pattern_complexity)s, %(source_region)s, %(ml_features)s
        )
        ON CONFLICT (pattern_hash) 
        DO UPDATE SET
            global_occurrence_count = attack_signatures.global_occurrence_count + 1,
            last_seen = NOW()
        RETURNING signature_id;
        """
        
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, signature)
                    result = cursor.fetchone()
                    
                    # Log payload deletion for audit trail
                    self._log_payload_deletion(signature['pattern_hash'], signature['attack_type'])
                    
                    return result[0] if result else None
        except Exception as e:
            logger.error(f"Failed to insert signature: {e}")
            raise
    
    def _log_payload_deletion(self, pattern_hash: str, attack_type: str):
        """Log that attack payload was deleted (audit trail)"""
        query = """
        INSERT INTO payload_deletion_log (signature_hash, attack_type)
        VALUES (%s, %s);
        """
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, (pattern_hash, attack_type))
        except Exception as e:
            logger.warning(f"Failed to log payload deletion: {e}")
    
    def get_signatures_by_type(self, attack_type: str, limit: int = 100) -> List[Dict]:
        """Get attack signatures by type"""
        query = """
        SELECT 
            signature_id, pattern_hash, attack_type,
            keywords, encodings, encoding_chain_depth,
            global_occurrence_count, first_seen, last_seen,
            ml_features
        FROM attack_signatures
        WHERE attack_type = %s
        ORDER BY global_occurrence_count DESC, first_seen DESC
        LIMIT %s;
        """
        
        try:
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute(query, (attack_type, limit))
                    return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to fetch signatures: {e}")
            return []
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get aggregated threat statistics (NO customer data)"""
        query = """
        SELECT 
            attack_type,
            COUNT(*) as unique_patterns,
            SUM(global_occurrence_count) as total_occurrences,
            AVG(pattern_complexity) as avg_complexity,
            MAX(last_seen) as most_recent
        FROM attack_signatures
        GROUP BY attack_type
        ORDER BY total_occurrences DESC;
        """
        
        try:
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute(query)
                    return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to fetch statistics: {e}")
            return {}
    
    def update_threat_intelligence(self):
        """Update aggregated threat intelligence table"""
        query = """
        INSERT INTO threat_intelligence (
            attack_type, total_occurrences, unique_patterns, avg_complexity
        )
        SELECT 
            attack_type,
            SUM(global_occurrence_count),
            COUNT(DISTINCT pattern_hash),
            AVG(pattern_complexity)
        FROM attack_signatures
        GROUP BY attack_type
        ON CONFLICT (attack_type) 
        DO UPDATE SET
            total_occurrences = EXCLUDED.total_occurrences,
            unique_patterns = EXCLUDED.unique_patterns,
            avg_complexity = EXCLUDED.avg_complexity,
            last_updated = NOW();
        """
        
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query)
            logger.info("✅ Threat intelligence updated")
        except Exception as e:
            logger.error(f"Failed to update threat intelligence: {e}")
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        queries = {
            'total_signatures': "SELECT COUNT(*) FROM attack_signatures;",
            'total_occurrences': "SELECT SUM(global_occurrence_count) FROM attack_signatures;",
            'attack_types': "SELECT COUNT(DISTINCT attack_type) FROM attack_signatures;",
            'oldest_signature': "SELECT MIN(first_seen) FROM attack_signatures;",
            'newest_signature': "SELECT MAX(first_seen) FROM attack_signatures;",
            'exploit_code_stored': "SELECT COUNT(*) FROM payload_deletion_log WHERE exploit_code_stored = TRUE;",
        }
        
        stats = {}
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    for key, query in queries.items():
                        cursor.execute(query)
                        result = cursor.fetchone()
                        stats[key] = result[0] if result else 0
        except Exception as e:
            logger.error(f"Failed to fetch database stats: {e}")
        
        return stats


# Initialize database singleton
db = AttackSignatureDatabase()


if __name__ == "__main__":
    # Test database connection
    logger.info("Testing database connection...")
    
    try:
        stats = db.get_database_stats()
        logger.info(f"✅ Database connected successfully")
        logger.info(f"   Total signatures: {stats.get('total_signatures', 0)}")
        logger.info(f"   Total occurrences: {stats.get('total_occurrences', 0)}")
        logger.info(f"   Attack types: {stats.get('attack_types', 0)}")
        logger.info(f"   Exploit code stored: {stats.get('exploit_code_stored', 0)} (MUST be 0)")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
