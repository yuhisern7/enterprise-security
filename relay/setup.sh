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
    ufw allow 60001/tcp comment 'WebSocket Relay'
    ufw --force enable
    echo "✅ UFW configured"
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=60001/tcp
    firewall-cmd --reload
    echo "✅ Firewalld configured"
else
    echo "⚠️  Manual firewall configuration needed: Allow TCP port 60001"
fi

# Get public IP
PUBLIC_IP=$(curl -s ifconfig.me)
echo ""
echo "📍 Your VPS Public IP: $PUBLIC_IP"

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
echo "   RELAY_URL=wss://$PUBLIC_IP:60001"
echo "   P2P_SYNC_ENABLED=false"
echo ""
echo "3. Restart containers:"
echo "   docker compose down && docker compose up -d"
echo ""
echo "4. Test connection:"
echo "   telnet $PUBLIC_IP 60001"
echo ""
echo "=================================="
echo "🌐 Relay Server: ws://$PUBLIC_IP:60001"
echo "=================================="
