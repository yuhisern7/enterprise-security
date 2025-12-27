#!/bin/bash
# QUICK INSTALLATION GUIDE
# Run this script to install and start the security system

echo "========================================"
echo "🛡️  HOME WIFI SECURITY SYSTEM"
echo "========================================"
echo ""
echo "Step 1: Installing dependencies..."
echo ""

# Run setup
./setup.sh

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "✅ INSTALLATION SUCCESSFUL!"
    echo "========================================"
    echo ""
    echo "🚀 Starting server now..."
    echo ""
    sleep 2
    
    # Start the server
    ./start.sh
else
    echo ""
    echo "❌ Installation failed. Check errors above."
    exit 1
fi
