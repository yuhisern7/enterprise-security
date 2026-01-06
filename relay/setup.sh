#!/bin/bash
# Quick setup script for relay server deployment

echo "=================================="
echo "🌍 Security Mesh Relay Server"
echo "=================================="
echo ""

# Check if running on VPS
if [ ! -f /proc/version ]; then
    echo "⚠️  Warning: Run this on your VPS/cloud server"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install Docker if needed
if ! command -v docker &> /dev/null; then
    echo "📦 Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

# Install Docker Compose if needed
if ! command -v docker-compose &> /dev/null; then
    echo "📦 Installing Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/download/v2.23.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# Configure firewall
echo ""
echo "🔥 Configuring firewall..."
if command -v ufw &> /dev/null; then
    # CRITICAL: Allow SSH first to prevent lockout!
    ufw allow 22/tcp comment 'SSH Access'
    ufw allow 60001/tcp comment 'WebSocket Relay'
    ufw allow 60002/tcp comment 'Model Distribution API'
    
    # Check if UFW is already enabled
    if ufw status | grep -q "Status: active"; then
        echo "✅ UFW already active - Rules added"
    else
        echo "⚠️  UFW is installed but not enabled"
        echo "   To enable firewall manually (ONLY if you have SSH access):"
        echo "   sudo ufw enable"
    fi
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=60001/tcp
    firewall-cmd --permanent --add-port=60002/tcp
    firewall-cmd --reload
    echo "✅ Firewalld configured"
else
    echo "⚠️  No firewall detected - Port 60001 should be accessible"
fi

# Get public IP
PUBLIC_IP=$(curl -s ifconfig.me)
echo ""
echo "📍 Your VPS Public IP: $PUBLIC_IP"

# Create required directories
echo ""
echo "📁 Creating relay server directories..."
mkdir -p ai_training_materials/ml_models
mkdir -p ai_training_materials/exploitdb
mkdir -p json
mkdir -p ml_models

# Initialize training materials (Premium mode requires this)
echo ""
echo "📚 Initializing training materials..."
echo "   ⚠️  NOTE: For Premium mode, you need to upload training data to ai_training_materials/"
echo "   • ExploitDB database → ai_training_materials/exploitdb/"
echo "   • Global attacks → ai_training_materials/global_attacks.json"
echo "   • Malware hashes → ai_training_materials/malware_hashes.json"
echo ""
echo "   📥 To setup ExploitDB on relay server:"
echo "   cd relay && ./setup_exploitdb.sh"
echo "   cp -r exploitdb ai_training_materials/"
echo ""

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
echo "1. Verify relay services are running:"
echo "   docker logs -f security-relay-server"
echo "   (Should see: WebSocket Relay + Model Distribution API)"
echo ""
echo "2. Test Model Distribution API:"
echo "   curl https://localhost:60002/models/list -k"
echo "   curl https://localhost:60002/stats -k"
echo ""
echo "3. On each subscriber container, edit server/.env:"
echo "   RELAY_ENABLED=true"
echo "   RELAY_URL=wss://$PUBLIC_IP:60001"
echo "   RELAY_CRYPTO_ENABLED=true"
echo "   MODEL_SYNC_URL=https://$PUBLIC_IP:60002"
echo ""
echo "4. Rebuild subscriber containers:"
echo "   cd ../server"
echo "   docker compose down"
echo "   docker compose build"
echo "   docker compose up -d"
echo ""
echo "5. Test connection:"
echo "   curl https://localhost:60000/api/relay/status -k"
echo "   (Should show: \"connected\": true)"
echo ""
echo "=================================="
echo "🌐 WebSocket Relay: wss://$PUBLIC_IP:60001"
echo "📦 Model Distribution API: https://$PUBLIC_IP:60002"
echo "🔒 Crypto: RSA-2048 + HMAC-SHA256"
echo "📚 Training Materials: ai_training_materials/ (825 MB)"
echo "🤖 ML Models: Served via API (280 KB total)"
echo "=================================="
