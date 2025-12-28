#!/bin/bash
# Central Threat Intelligence Server Setup
# Run this ONLY on your central server (NOT on client machines)

set -e

echo "============================================"
echo "🌍 Central Threat Intelligence Server Setup"
echo "============================================"
echo ""
echo "This will deploy the CENTRAL SERVER that aggregates"
echo "threats from all client containers globally."
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed!"
    echo "Please install Docker first:"
    echo "  Ubuntu/Debian: curl -fsSL https://get.docker.com | sh"
    echo "  Other: https://docs.docker.com/engine/install/"
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is not installed!"
    echo "Please install Docker Compose v2"
    exit 1
fi

echo "✅ Docker installed: $(docker --version)"
echo "✅ Docker Compose installed: $(docker compose version)"
echo ""

# Navigate to central_server directory
cd central_server

echo "📦 Building central server image..."
docker compose build

echo ""
echo "🚀 Starting central server..."
docker compose up -d

echo ""
echo "⏳ Waiting for server to start..."
sleep 5

# Get the master API key from logs
echo ""
echo "============================================"
echo "🔑 MASTER API KEY (SAVE THIS!)"
echo "============================================"
docker compose logs | grep -i "master API key" || echo "Master key will be shown on first run"

echo ""
echo "============================================"
echo "✅ Central Server Deployed Successfully!"
echo "============================================"
echo ""
echo "📊 Server Status:"
docker compose ps
echo ""
echo "🌐 Server URL: https://$(hostname -I | awk '{print $1}'):5001"
echo "   (or use your public IP/domain)"
echo ""
echo "📖 View logs:"
echo "   cd central_server && docker compose logs -f"
echo ""
echo "🔐 Security:"
echo "   - SSL/TLS encryption enabled (self-signed cert)"
echo "   - API key authentication required"
echo "   - Data stored in: central_server/data/"
echo ""
echo "👥 Next Steps:"
echo "   1. Save your master API key (shown above)"
echo "   2. Open firewall: sudo ufw allow 5001/tcp"
echo "   3. Share server URL with clients"
echo "   4. Clients register using: ./setup_client.sh"
echo ""
echo "📊 Monitor connected clients:"
echo "   curl -k https://localhost:5001/health"
echo ""
