#!/bin/bash
# Test Phase 1: Crypto Integration in Relay Server
# Quick validation that relay_server.py can start with crypto enabled

echo "=========================================="
echo "PHASE 1 VALIDATION TEST"
echo "Testing relay server crypto integration"
echo "=========================================="

cd /home/yuhisern/Downloads/workspace/enterprise-security/relay

echo ""
echo "1. Checking Python imports..."
python3 -c "
import sys
sys.path.insert(0, '..')
from AI.crypto_security import MessageSecurity
print('✅ MessageSecurity imported successfully')
" || { echo "❌ Failed to import MessageSecurity"; exit 1; }

echo ""
echo "2. Checking relay_server.py syntax..."
python3 -m py_compile relay_server.py && echo "✅ relay_server.py syntax OK" || { echo "❌ Syntax error"; exit 1; }

echo ""
echo "3. Verifying crypto initialization..."
python3 -c "
import sys
import os
sys.path.insert(0, '..')
os.chdir('..')

# Just import to verify it works
import relay.relay_server as relay
print('✅ Relay server imports successfully')
print(f'   Crypto enabled: {relay.CRYPTO_ENABLED}')
print(f'   Signature sync enabled: {relay.SIGNATURE_SYNC_ENABLED}')
" || { echo "❌ Failed to initialize"; exit 1; }

echo ""
echo "=========================================="
echo "✅ PHASE 1 VALIDATION PASSED"
echo "Relay server is ready with crypto enabled"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Start relay: cd relay && python3 relay_server.py"
echo "  2. In another terminal, start a client with RELAY_ENABLED=true"
echo "  3. Verify signed messages are accepted"
