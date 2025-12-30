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
    firewall-cmd --reload
    echo "✅ Firewalld configured"
else
    echo "⚠️  No firewall detected - Port 60001 should be accessible"
fi

# Get public IP
PUBLIC_IP=$(curl -s ifconfig.me)
echo ""
echo "📍 Your VPS Public IP: $PUBLIC_IP"

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
echo "   RELAY_URL=ws://$PUBLIC_IP:60001"
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
echo "🌐 Relay Server: ws://$PUBLIC_IP:60001"
echo "🔒 Crypto: RSA-2048 + HMAC-SHA256"
echo "=================================="
