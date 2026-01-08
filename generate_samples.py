#!/usr/bin/env python3
"""Generate 1,000+ sample threat events for fresh installations."""

import json
from datetime import datetime, timedelta
import random
import os

attacks = []
start = datetime(2026, 1, 1)

# SQL Injection patterns
sql_patterns = [
    "' OR '1'='1",
    "' UNION SELECT password FROM users--",
    "'; DROP TABLE users--",
    "1' AND 1=1--",
    "admin'--",
    "' OR 'x'='x",
    "1' OR '1' = '1'/*",
    "' WAITFOR DELAY '0:0:5'--"
]

# XSS patterns
xss_patterns = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(1)'>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>"
]

# Generate 300 SQL injection attacks
for i in range(300):
    attacks.append({
        'timestamp': (start + timedelta(hours=i)).isoformat() + 'Z',
        'ip_address': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
        'threat_type': 'SQL Injection',
        'level': 'CRITICAL',
        'details': random.choice(sql_patterns),
        'packet_size': random.randint(256, 1024),
        'flow_duration': round(random.uniform(1.0, 5.0), 2),
        'payload_entropy': round(random.uniform(3.5, 5.0), 2)
    })

# Generate 300 XSS attacks
for i in range(300):
    attacks.append({
        'timestamp': (start + timedelta(hours=300+i)).isoformat() + 'Z',
        'ip_address': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
        'threat_type': 'XSS Attack',
        'level': 'HIGH',
        'details': random.choice(xss_patterns),
        'packet_size': random.randint(128, 512),
        'flow_duration': round(random.uniform(0.5, 3.0), 2),
        'payload_entropy': round(random.uniform(3.0, 4.5), 2)
    })

# Generate 200 brute force attacks
for i in range(200):
    attacks.append({
        'timestamp': (start + timedelta(hours=600+i)).isoformat() + 'Z',
        'ip_address': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
        'threat_type': 'Brute Force',
        'level': 'CRITICAL',
        'details': f'Failed login attempt #{random.randint(1, 100)}',
        'packet_size': random.randint(64, 256),
        'flow_duration': round(random.uniform(0.1, 1.0), 2),
        'payload_entropy': round(random.uniform(1.5, 3.0), 2)
    })

# Generate 200 safe traffic samples
for i in range(200):
    attacks.append({
        'timestamp': (start + timedelta(hours=800+i)).isoformat() + 'Z',
        'ip_address': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
        'threat_type': 'Safe Traffic',
        'level': 'SAFE',
        'details': random.choice(['DNS query', 'HTTP GET', 'HTTPS session', 'API request']),
        'packet_size': random.randint(32, 128),
        'flow_duration': round(random.uniform(0.05, 0.5), 2),
        'payload_entropy': round(random.uniform(1.0, 2.5), 2)
    })

# Shuffle to mix attack types
random.shuffle(attacks)

# Save
output_path = os.path.join('server', 'json', 'sample_threats.json')
os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, 'w') as f:
    json.dump(attacks, f, indent=2)

print(f'✅ Generated {len(attacks)} sample threats → {output_path}')
print(f'   - SQL Injection: 300 samples')
print(f'   - XSS Attack: 300 samples')
print(f'   - Brute Force: 200 samples')
print(f'   - Safe Traffic: 200 samples')
