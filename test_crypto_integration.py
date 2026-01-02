#!/usr/bin/env python3
"""
Test Cryptographic Integration in Relay Mesh
Verifies that:
1. Relay server rejects unsigned messages
2. Relay server accepts signed messages
3. Replay attacks are blocked
"""

import asyncio
import json
import sys
import os
from datetime import datetime

# Add paths
sys.path.insert(0, os.path.dirname(__file__))

from AI.crypto_security import MessageSecurity

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

def test_message_signing():
    """Test that messages can be signed and verified"""
    print("\n" + "="*60)
    print("TEST 1: Message Signing and Verification")
    print("="*60)
    
    try:
        # Initialize crypto
        security = MessageSecurity(key_dir="test_crypto_keys")
        
        # Create test message
        message = {
            "type": "threat",
            "attack_type": "sql_injection",
            "ip": "192.168.1.100",
            "severity": "high",
            "peer_id": "test-peer-1"
        }
        
        # Sign message
        signed = security.sign_message(message)
        print(f"✅ Message signed successfully")
        print(f"   - Contains signature: {'signature' in signed}")
        print(f"   - Contains HMAC: {'hmac' in signed}")
        print(f"   - Contains nonce: {'nonce' in signed}")
        print(f"   - Contains timestamp: {'timestamp' in signed}")
        
        # Verify message
        is_valid, reason = security.verify_message(signed)
        
        if is_valid:
            print(f"{GREEN}✅ PASS: Message verification succeeded{RESET}")
            return True
        else:
            print(f"{RED}❌ FAIL: Message verification failed: {reason}{RESET}")
            return False
            
    except Exception as e:
        print(f"{RED}❌ FAIL: Exception during test: {e}{RESET}")
        return False


def test_unsigned_message_rejection():
    """Test that unsigned messages are rejected"""
    print("\n" + "="*60)
    print("TEST 2: Unsigned Message Rejection")
    print("="*60)
    
    try:
        security = MessageSecurity(key_dir="test_crypto_keys")
        
        # Create unsigned message (no signature/hmac/nonce)
        unsigned_message = {
            "type": "threat",
            "attack_type": "xss",
            "ip": "10.0.0.50"
        }
        
        # Try to verify
        is_valid, reason = security.verify_message(unsigned_message)
        
        if not is_valid:
            print(f"{GREEN}✅ PASS: Unsigned message correctly rejected{RESET}")
            print(f"   Rejection reason: {reason}")
            return True
        else:
            print(f"{RED}❌ FAIL: Unsigned message was accepted (security vulnerability!){RESET}")
            return False
            
    except Exception as e:
        print(f"{RED}❌ FAIL: Exception during test: {e}{RESET}")
        return False


def test_tampered_message_rejection():
    """Test that tampered messages are rejected"""
    print("\n" + "="*60)
    print("TEST 3: Tampered Message Rejection")
    print("="*60)
    
    try:
        security = MessageSecurity(key_dir="test_crypto_keys")
        
        # Create and sign message
        message = {
            "type": "threat",
            "attack_type": "sql_injection",
            "ip": "192.168.1.100",
            "peer_id": "test-peer-1"
        }
        signed = security.sign_message(message)
        
        # Tamper with the message
        signed["ip"] = "192.168.1.200"  # Change IP (breaks HMAC)
        
        # Try to verify tampered message
        is_valid, reason = security.verify_message(signed)
        
        if not is_valid:
            print(f"{GREEN}✅ PASS: Tampered message correctly rejected{RESET}")
            print(f"   Rejection reason: {reason}")
            return True
        else:
            print(f"{RED}❌ FAIL: Tampered message was accepted (security vulnerability!){RESET}")
            return False
            
    except Exception as e:
        print(f"{RED}❌ FAIL: Exception during test: {e}{RESET}")
        return False


def test_replay_attack_protection():
    """Test that replayed messages are rejected"""
    print("\n" + "="*60)
    print("TEST 4: Replay Attack Protection")
    print("="*60)
    
    try:
        security = MessageSecurity(key_dir="test_crypto_keys")
        
        # Create and sign message
        message = {
            "type": "threat",
            "attack_type": "port_scan",
            "ip": "10.0.0.1",
            "peer_id": "test-peer-1"
        }
        signed = security.sign_message(message)
        
        # Verify first time (should succeed)
        is_valid_1, reason_1 = security.verify_message(signed)
        print(f"   First verification: {'✅ Valid' if is_valid_1 else '❌ Invalid'}")
        
        # Try to verify again (replay - should fail due to nonce)
        is_valid_2, reason_2 = security.verify_message(signed)
        print(f"   Second verification: {'✅ Valid' if is_valid_2 else '❌ Invalid (expected)'}")
        
        if is_valid_1 and not is_valid_2:
            print(f"{GREEN}✅ PASS: Replay attack correctly blocked{RESET}")
            print(f"   Rejection reason: {reason_2}")
            return True
        else:
            print(f"{RED}❌ FAIL: Replay attack not blocked{RESET}")
            return False
            
    except Exception as e:
        print(f"{RED}❌ FAIL: Exception during test: {e}{RESET}")
        return False


def cleanup():
    """Clean up test keys"""
    import shutil
    try:
        if os.path.exists("test_crypto_keys"):
            shutil.rmtree("test_crypto_keys")
            print("\n✅ Cleaned up test keys")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")


if __name__ == "__main__":
    print(f"\n{YELLOW}{'='*60}")
    print("CRYPTOGRAPHIC INTEGRATION TEST SUITE")
    print("Testing relay mesh message security")
    print(f"{'='*60}{RESET}")
    
    results = []
    
    # Run tests
    results.append(("Message Signing", test_message_signing()))
    results.append(("Unsigned Rejection", test_unsigned_message_rejection()))
    results.append(("Tamper Detection", test_tampered_message_rejection()))
    results.append(("Replay Protection", test_replay_attack_protection()))
    
    # Summary
    print(f"\n{YELLOW}{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}{RESET}")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = f"{GREEN}PASS{RESET}" if result else f"{RED}FAIL{RESET}"
        print(f"  {test_name:.<40} {status}")
    
    print(f"\n{YELLOW}Total: {passed}/{total} tests passed{RESET}")
    
    # Cleanup
    cleanup()
    
    # Exit code
    sys.exit(0 if passed == total else 1)
