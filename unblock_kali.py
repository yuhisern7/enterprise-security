#!/usr/bin/env python3
"""Quick unblock script for testing"""

import sys
sys.path.insert(0, '.')
from AI import pcs_ai

# Your Kali Linux IP (change this to your actual IP)
KALI_IP = "192.168.0.119"  # Kali Linux IP

if len(sys.argv) > 1:
    KALI_IP = sys.argv[1]

print(f"Unblocking {KALI_IP}...")
success = pcs_ai.unblock_ip(KALI_IP)

if success:
    print(f"✅ {KALI_IP} unblocked successfully")
else:
    print(f"⚠️ {KALI_IP} was not blocked")

# Also clear from blocked IPs file
import json
import os

blocked_file = 'server/json/blocked_ips.json'
if os.path.exists(blocked_file):
    try:
        with open(blocked_file, 'r') as f:
            blocked = json.load(f)
        
        blocked = [ip for ip in blocked if ip != KALI_IP]
        
        with open(blocked_file, 'w') as f:
            json.dump(blocked, f, indent=2)
        
        print(f"✅ Removed {KALI_IP} from blocked_ips.json")
    except Exception as e:
        print(f"Warning: {e}")

print("\n✅ Ready for next attack test!")
