#!/bin/bash
# Quick start script for Home WiFi Security System

echo "🛡️  Starting Home WiFi Security System..."
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "   Run ./setup.sh first"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "✅ Running with root privileges - Network monitoring ENABLED"
else
    echo "⚠️  Running without root privileges - Network monitoring DISABLED"
    echo "   For full protection, run: sudo ./start.sh"
fi

echo ""
echo "🚀 Starting server..."
echo "📊 Dashboard: http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start the server
python3 server.py
