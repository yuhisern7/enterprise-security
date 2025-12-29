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
    echo "Please install Docker Desktop for Mac:"
    echo "https://www.docker.com/products/docker-desktop"
    echo ""
    echo "Installation steps:"
    echo "1. Download Docker.dmg"
    echo "2. Drag Docker to Applications"
    echo "3. Launch Docker Desktop"
    echo "4. Wait for Docker to start"
    echo "5. Run this script again"
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
docker-compose build
docker-compose up -d

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
    echo "   RELAY_URL=wss://$PUBLIC_IP:60001"
else
    echo "   RELAY_URL=wss://YOUR-PUBLIC-IP:60001"
fi
echo "   P2P_SYNC_ENABLED=false"
echo ""
echo "3. Restart containers:"
echo "   docker compose down && docker compose up -d"
echo ""
echo "4. Test connection:"
if [ "$PUBLIC_IP" != "Unable to detect" ]; then
    echo "   telnet $PUBLIC_IP 60001"
else
    echo "   telnet YOUR-PUBLIC-IP 60001"
fi
echo ""
echo "=================================="
if [ "$PUBLIC_IP" != "Unable to detect" ]; then
    echo "🌐 Relay Server: ws://$PUBLIC_IP:60001"
else
    echo "🌐 Relay Server: ws://YOUR-PUBLIC-IP:60001"
fi
echo "=================================="
