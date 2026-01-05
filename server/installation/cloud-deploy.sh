#!/bin/bash
###############################################################################
# Enterprise Security - Universal Cloud Deployment Script
# Works on: DigitalOcean, Linode, Vultr, Hetzner, AWS, GCP, Azure, etc.
# Requirements: Ubuntu 20.04+, Debian 11+, RHEL 8+, or similar
###############################################################################

set -e  # Exit on error

echo "🛡️  Enterprise Security - Cloud Deployment"
echo "=========================================="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo "❌ Cannot detect OS. Please use Ubuntu, Debian, or RHEL-based system."
    exit 1
fi

echo "✅ Detected: $PRETTY_NAME"
echo ""

# Update package lists
echo "📦 Updating package lists..."
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    sudo apt-get update -qq
elif [ "$OS" = "rhel" ] || [ "$OS" = "centos" ] || [ "$OS" = "fedora" ]; then
    sudo yum update -y -q
fi

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo "✅ Docker installed"
else
    echo "✅ Docker already installed ($(docker --version))"
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "📦 Installing Docker Compose..."
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        sudo apt-get install -y -qq docker-compose-plugin
    elif [ "$OS" = "rhel" ] || [ "$OS" = "centos" ] || [ "$OS" = "fedora" ]; then
        sudo yum install -y -q docker-compose-plugin
    fi
    echo "✅ Docker Compose installed"
else
    echo "✅ Docker Compose already installed"
fi

# Install Git if not present
if ! command -v git &> /dev/null; then
    echo "📦 Installing Git..."
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        sudo apt-get install -y -qq git
    elif [ "$OS" = "rhel" ] || [ "$OS" = "centos" ] || [ "$OS" = "fedora" ]; then
        sudo yum install -y -q git
    fi
    echo "✅ Git installed"
else
    echo "✅ Git already installed"
fi

# Get public IP
echo ""
echo "🌐 Detecting public IP address..."
PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "unknown")
if [ "$PUBLIC_IP" = "unknown" ]; then
    echo "⚠️  Could not detect public IP"
else
    echo "✅ Public IP: $PUBLIC_IP"
fi

# Clone repository
echo ""
echo "📥 Cloning battle-hardened-ai repository..."
if [ -d "battle-hardened-ai" ]; then
    echo "⚠️  Directory already exists, updating..."
    cd battle-hardened-ai
    git pull
else
    git clone https://github.com/yuhisern7/battle-hardened-ai.git
    cd battle-hardened-ai
fi

# Configure firewall
echo ""
echo "🔥 Configuring firewall..."
if command -v ufw &> /dev/null; then
    sudo ufw allow 60001/tcp  # P2P port only
    sudo ufw --force enable
    echo "✅ UFW firewall configured (port 60001 opened)"
elif command -v firewall-cmd &> /dev/null; then
    sudo firewall-cmd --permanent --add-port=60001/tcp
    sudo firewall-cmd --reload
    echo "✅ Firewalld configured (port 60001 opened)"
else
    echo "⚠️  No firewall detected. Manually open port 60001 if needed."
fi

# Run setup
echo ""
echo "🚀 Running deployment setup..."
chmod +x setup_peer.sh
./setup_peer.sh

echo ""
echo "=========================================="
echo "✅ DEPLOYMENT COMPLETE!"
echo "=========================================="
echo ""
echo "📊 Dashboard URL: http://$PUBLIC_IP:60000"
echo "🌐 P2P Sync URL: https://$PUBLIC_IP:60001"
echo ""
echo "⚠️  IMPORTANT: Dashboard port 60000 is for internal use only!"
echo "   Only share P2P URL (port 60001) with other containers."
echo ""
echo "📝 View logs: cd battle-hardened-ai/server && docker compose logs -f"
echo "🛑 Stop: cd battle-hardened-ai/server && docker compose down"
echo "🔄 Restart: cd battle-hardened-ai/server && docker compose restart"
echo ""
echo "🎉 Happy securing!"
