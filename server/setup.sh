#!/bin/bash
# Home WiFi Security System - Installation Script

echo "========================================"
echo "🛡️  HOME WIFI SECURITY SYSTEM SETUP"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  WARNING: Not running as root"
    echo "   Network monitoring requires root privileges (sudo)"
    echo "   You can still run the server without network monitoring"
    echo ""
fi

# Check Python version
echo "📋 Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo "❌ Python 3 is not installed!"
    echo "   Install Python 3.8+ and try again"
    exit 1
fi
echo "✅ Python 3 found"
echo ""

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "✅ Virtual environment created"
echo ""

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi
echo "✅ Dependencies installed"
echo ""

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p json
echo "✅ Directories created"
echo ""

# Check if AI folder exists
if [ ! -d "../AI" ]; then
    echo "❌ Error: AI folder not found!"
    echo "   Expected structure:"
    echo "   home-security/"
    echo "   ├── AI/           (AI engine and dashboard)"
    echo "   └── server/       (you are here)"
    exit 1
fi

# Check if AI models exist
if [ ! -d "../AI/ml_models" ]; then
    echo "⚠️  Creating ML models directory..."
    mkdir -p ../AI/ml_models
    echo "   Note: AI models will be trained on first use"
fi

# Set permissions
chmod +x server.py
chmod +x network_monitor.py

echo ""
echo "========================================"
echo "✅ INSTALLATION COMPLETE!"
echo "========================================"
echo ""
echo "🚀 To start the security system:"
echo ""
echo "   Option 1 - With network monitoring (requires sudo):"
echo "   $ sudo ./venv/bin/python3 server.py"
echo ""
echo "   Option 2 - Without network monitoring:"
echo "   $ ./venv/bin/python3 server.py"
echo ""
echo "📊 Dashboard will be available at:"
echo "   http://localhost:5000"
echo "   http://YOUR_IP:5000"
echo ""
echo "🔒 Security Features:"
echo "   ✅ AI/ML threat detection"
echo "   ✅ SQL injection blocking"
echo "   ✅ XSS attack prevention"
echo "   ✅ DDoS protection"
echo "   ✅ Port scan detection"
echo "   ✅ Brute force prevention"
echo "   ✅ VPN/Tor de-anonymization"
echo "   ✅ Real-time monitoring"
echo ""
echo "📖 For more information, see README.md"
echo ""
