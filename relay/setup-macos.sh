#!/bin/bash
# Quick setup script for relay server deployment on macOS

echo "=================================="
echo "🌍 Security Mesh Relay Server"
echo "=================================="
echo ""

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "⚠️  This script is designed for macOS"
    echo "For Linux, use setup.sh instead"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if Docker Desktop is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found!"
    echo ""
    echo "Install Docker using Homebrew:"
    echo "brew install --cask docker"
    echo ""
    echo "Or download Docker Desktop:"
    echo "https://www.docker.com/products/docker-desktop"
    echo ""
    echo "After installation:"
    echo "1. Launch Docker Desktop"
    echo "2. Wait for Docker to start"
    echo "3. Run this script again"
    exit 1
fi

# Check if Docker is running
if ! docker ps &> /dev/null; then
    echo "❌ Docker is not running!"
    echo "Please start Docker Desktop and try again"
    exit 1
fi

# Check Docker Compose
if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not found!"
    echo "Please update Docker Desktop for Mac"
    exit 1
fi

# Get public IP
echo ""
echo "📍 Detecting your public IP..."
PUBLIC_IP=$(curl -s https://ifconfig.me 2>/dev/null || curl -s https://api.ipify.org 2>/dev/null || echo "Unable to detect")

if [ "$PUBLIC_IP" != "Unable to detect" ]; then
    echo "📍 Your Public IP: $PUBLIC_IP"
else
    echo "⚠️  Could not auto-detect public IP"
    echo "Please check manually: https://whatismyip.com"
fi

# macOS doesn't need firewall config (Docker Desktop handles it)
echo ""
echo "✅ macOS detected - Docker Desktop handles networking automatically"

# Build and start relay server
echo ""
echo "🚀 Starting relay server..."
docker compose build
docker compose up -d

echo ""
echo "✅ Relay server started!"
echo ""
echo "=================================="
echo "📋 Next Steps:"
echo "=================================="
echo ""
echo "1. Verify relay is running:"
echo "   docker logs -f security-relay-server"
echo ""
echo "2. On each security container, edit server/.env:"
echo "   RELAY_ENABLED=true"
if [ "$PUBLIC_IP" != "Unable to detect" ]; then
    echo "   RELAY_URL=ws://$PUBLIC_IP:60001"
else
    echo "   RELAY_URL=ws://YOUR-PUBLIC-IP:60001"
fi
echo "   RELAY_CRYPTO_ENABLED=true"
echo ""
echo "3. Rebuild containers (to install cryptography package):"
echo "   cd ../server"
echo "   docker compose down"
echo "   docker compose build"
echo "   docker compose up -d"
echo ""
echo "4. Test connection:"
echo "   curl http://localhost:60000/api/relay/status"
echo "   (Should show: \"connected\": true)"
echo ""
echo "=================================="
if [ "$PUBLIC_IP" != "Unable to detect" ]; then
    echo "🌐 Relay Server: ws://$PUBLIC_IP:60001"
else
    echo "🌐 Relay Server: ws://YOUR-PUBLIC-IP:60001"
fi
echo "=================================="
