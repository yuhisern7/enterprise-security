#!/usr/bin/env python3
"""Test all API endpoints for sections 18-24"""
import requests
import json
import time
import subprocess
import sys

BASE_URL = "http://localhost:5000"

def test_endpoint(section, name, endpoint):
    """Test a single endpoint"""
    try:
        response = requests.get(f"{BASE_URL}{endpoint}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Section {section} - {name}: Working")
            return True, data
        else:
            print(f"❌ Section {section} - {name}: HTTP {response.status_code}")
            return False, None
    except Exception as e:
        print(f"❌ Section {section} - {name}: {str(e)}")
        return False, None

def main():
    print("🔍 Testing Sections 18-24 API Endpoints\n")
    print("=" * 60)
    
    # Wait for server to be ready
    print("Waiting for server...")
    for i in range(10):
        try:
            requests.get(f"{BASE_URL}/api/system-status", timeout=2)
            print("✅ Server is ready!\n")
            break
        except:
            time.sleep(1)
    else:
        print("❌ Server not responding")
        sys.exit(1)
    
    results = []
    
    # Test each section
    success, data = test_endpoint(18, "Traffic Analysis", "/api/traffic/analysis")
    if success:
        print(f"   └─ {data['total_packets']} packets, {data['encrypted_percent']}% encrypted")
    results.append(success)
    
    success, data = test_endpoint(19, "DNS Stats", "/api/dns/stats")
    if success:
        print(f"   └─ {data['total_queries']} DNS queries")
    results.append(success)
    
    success, data = test_endpoint(20, "User Tracking", "/api/users/tracking")
    if success:
        print(f"   └─ {data['tracked_users']} users, {data['active_sessions']} sessions")
    results.append(success)
    
    success, data = test_endpoint(21, "PCAP Stats", "/api/pcap/stats")
    if success:
        print(f"   └─ PCAP size: {data['pcap_size']}, tcpdump: {data['available']}")
    results.append(success)
    
    success, data = test_endpoint(22, "Sandbox Stats", "/api/sandbox/stats")
    if success:
        print(f"   └─ {data['analyzed']} analyzed, {data['malicious']} malicious")
    results.append(success)
    
    success, data = test_endpoint(23, "Alert Stats", "/api/alerts/stats")
    if success:
        print(f"   └─ {data['email_sent']} sent, {data['subscribers']} subscribers")
    results.append(success)
    
    success, data = test_endpoint(24, "SOAR API Stats", "/api/soar/stats")
    if success:
        print(f"   └─ {data['total_keys']} keys, {data['avg_latency_ms']}ms latency")
    results.append(success)
    
    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"\n📊 Results: {passed}/{total} sections working")
    
    if passed == total:
        print("🎉 All sections 18-24 are fully functional!")
        return 0
    else:
        print(f"⚠️  {total - passed} section(s) have issues")
        return 1

if __name__ == "__main__":
    sys.exit(main())
