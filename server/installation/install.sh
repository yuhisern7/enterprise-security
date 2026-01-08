#!/bin/bash
# Quick Start Script - Home WiFi Security System

echo "🛡️  HOME WIFI SECURITY SYSTEM - QUICK START"
echo "==========================================="
echo ""

# Check if we're in the right directory
if [ ! -f "../docker-compose.yml" ]; then
    echo "❌ Error: docker-compose.yml not found"
    echo "   Run this script from: server/installation/"
    echo "   Or run: bash installation/quickstart.sh"
    exit 1
fi

# Change to server directory
cd "$(dirname "$0")/.." || exit 1

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed!"
    echo ""
    echo "📥 Installation instructions:"
    echo ""
    echo "Linux:"
    echo "  curl -fsSL https://get.docker.com -o get-docker.sh"
    echo "  sudo sh get-docker.sh"
    echo "  sudo usermod -aG docker \$USER"
    echo "  # Log out and back in"
    echo ""
    echo "Windows/macOS:"
    echo "  Download Docker Desktop from:"
    echo "  https://www.docker.com/products/docker-desktop"
    echo ""
    exit 1
fi

# Check if Docker Compose is available
if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not available!"
    echo ""
    echo "Please install Docker Compose:"
    echo "  sudo apt install docker-compose-plugin"
    exit 1
fi

echo "✅ Docker is installed"
echo ""

# Check if JSON files exist
if [ ! -f "json/threat_log.json" ]; then
    echo "📁 Creating json directory and files..."
    mkdir -p json
    mkdir -p json/compliance_reports
    mkdir -p json/performance_metrics
    echo "[]" > json/threat_log.json
    echo "[]" > json/blocked_ips.json
    echo "{}" > json/visualization_data.json
    echo "✅ Created json files and enterprise feature directories"
fi

# Check if crypto_keys exist
if [ ! -d "crypto_keys" ]; then
    echo "🔐 Creating crypto_keys directory..."
    mkdir -p crypto_keys
    echo "⚠️  Warning: crypto_keys directory is empty!"
    echo "   The system will generate keys automatically on first run."
fi

# Check if AI folder exists
if [ ! -d "../AI" ]; then
    echo "❌ Error: AI folder not found!"
    echo "   The AI folder should be at ../AI/"
    exit 1
fi

# Check if AI models exist
if [ ! -d "../AI/ml_models" ]; then
    echo "⚠️  Warning: ML models directory not found!"
    echo "   Creating empty ml_models directory..."
    mkdir -p ../AI/ml_models
    echo "   Note: AI models will be trained on first use"
fi

echo ""
echo "🚀 Starting Home WiFi Security System..."
echo ""

# Start Docker Compose
docker compose up -d

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ SUCCESS! System is running"
    echo ""
    echo "📊 Dashboard: https://localhost:60000 (HTTPS - Secure)"
    echo "   ⚠️  Browser will show SSL warning (self-signed cert) - this is NORMAL"
    echo "   Click 'Advanced' → 'Proceed to localhost' to access"
    echo ""
    echo "🌐 Access from other devices:"
    echo "   1. Find your IP address:"
    if [ "$(uname)" == "Darwin" ]; then
        IP=$(ipconfig getifaddr en0)
    else
        IP=$(hostname -I | awk '{print $1}')
    fi
    echo "      Your IP: $IP"
    echo "   2. Open: https://$IP:60000 (Accept SSL warning)"
    echo ""
    echo "📋 Useful commands:"
    echo "   View logs:    docker compose logs -f"
    echo "   Stop system:  docker compose down"
    echo "   Restart:      docker compose restart"
    echo "   Status:       docker compose ps"
    echo ""
else
    echo ""
    echo "❌ Failed to start system"
    echo "   Check logs: docker compose logs"
    exit 1
fi
