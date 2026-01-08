#!/usr/bin/env python3
"""
Test script to verify Home WiFi Security System is working
"""

import requests
import time
import sys
import os
import urllib3

# Disable SSL warnings for self-signed certificates in testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = f"https://localhost:{os.getenv('DASHBOARD_PORT', '60000')}"

def test_connection():
    """Test if server is running"""
    print("🔍 Testing server connection...")
    try:
        response = requests.get(BASE_URL, timeout=5, verify=False)
        if response.status_code == 200:
            print("✅ Server is running!")
            return True
        else:
            print(f"❌ Server returned status code: {response.status_code}")
            return False
    except requests.ConnectionError:
        print("❌ Cannot connect to server")
        print("   Make sure the server is running: ./start.sh")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_attack_detection():
    """Test if attack detection is working"""
    print("\n🎯 Testing attack detection...")
    
    attacks = [
        ("SQL Injection", "/test?id=1' OR '1'='1"),
        ("XSS Attack", "/test?name=<script>alert(1)</script>"),
        ("Directory Traversal", "/test?file=../../etc/passwd"),
        ("Command Injection", "/test?cmd=; cat /etc/passwd"),
    ]
    
    detected = 0
    for name, endpoint in attacks:
        try:
            print(f"  Testing {name}...", end=" ")
            response = requests.get(BASE_URL + endpoint, timeout=5, verify=False)
            print("✅ Sent")
            detected += 1
            time.sleep(0.5)
        except Exception as e:
            print(f"❌ {e}")
    
    print(f"\n✅ Sent {detected}/{len(attacks)} test attacks")
    print("   Check dashboard to see if they were detected!")
    return True


def test_api():
    """Test API endpoints"""
    print("\n📡 Testing API endpoints...")
    
    endpoints = [
        "/api/stats",
    ]
    
    for endpoint in endpoints:
        try:
            print(f"  Testing {endpoint}...", end=" ")
            response = requests.get(BASE_URL + endpoint, timeout=5, verify=False)
            if response.status_code == 200:
                print("✅ OK")
            else:
                print(f"❌ Status {response.status_code}")
        except Exception as e:
            print(f"❌ {e}")
    
    return True


def main():
    print("=" * 60)
    print("🛡️  HOME WIFI SECURITY SYSTEM - TEST SUITE")
    print("=" * 60)
    print()
    
    # Test 1: Connection
    if not test_connection():
        print("\n❌ Server is not running!")
        print("   Start it with: ./start.sh")
        sys.exit(1)
    
    # Test 2: Attack Detection
    test_attack_detection()
    
    # Test 3: API
    test_api()
    
    print("\n" + "=" * 60)
    print("✅ TESTS COMPLETE!")
    print("=" * 60)
    print()
    print("📊 View results at: " + BASE_URL)
    print("   The test attacks should appear in the threat log!")
    print()


if __name__ == '__main__':
    main()
