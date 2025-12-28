#!/bin/bash

###############################################################################
# Simple P2P Container Setup - Every Container Is Equal
# Each container acts as both server and client, sharing threats with peers
###############################################################################

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🛡️  Enterprise Security P2P Container Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Every container is equal - no central server needed!"
echo "If A gets attacked, B and C learn automatically."
echo "The network gets smarter every hour. Brilliant. 🌐"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Installing Docker..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker $USER
        echo "✅ Docker installed. Please logout and login again for group permissions."
        echo "   Then run this script again."
        exit 0
    else
        echo "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop"
        exit 1
    fi
fi

# Check if ExploitDB exists
if [ ! -d "AI/exploitdb" ]; then
    echo "📥 ExploitDB not found. Downloading..."
    cd AI
    ./setup_exploitdb.sh
    cd ..
fi

# Create .env file if it doesn't exist
if [ ! -f "server/.env" ]; then
    echo "📝 Creating configuration file..."
    cp server/.env.example server/.env
fi

# Configure VirusTotal API
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VirusTotal API Configuration (Optional but Recommended)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
read -p "Do you have a VirusTotal API key? (y/n): " has_vt_key

if [[ "$has_vt_key" == "y" ]]; then
    read -p "Enter your VirusTotal API key: " vt_key
    sed -i "s/VIRUSTOTAL_API_KEY=.*/VIRUSTOTAL_API_KEY=$vt_key/" server/.env
    echo "✅ VirusTotal API key configured"
fi

# Configure P2P mesh
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  P2P Mesh Network Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Connect to other containers to share threats automatically."
echo "Each container learns from all others in real-time."
echo ""
read -p "Do you want to connect to other peer containers? (y/n): " connect_peers

if [[ "$connect_peers" == "y" ]]; then
    echo ""
    echo "Enter peer container URLs (comma-separated)"
    echo "Example: http://192.168.1.100:5000,http://192.168.1.101:5000"
    echo ""
    read -p "Peer URLs: " peer_urls
    
    if [ ! -z "$peer_urls" ]; then
        # Enable P2P sync
        sed -i "s/P2P_SYNC_ENABLED=.*/P2P_SYNC_ENABLED=true/" server/.env
        sed -i "s|PEER_URLS=.*|PEER_URLS=$peer_urls|" server/.env
        
        # Set peer name
        read -p "Enter a name for this container (e.g., office-1, home-main): " peer_name
        if [ ! -z "$peer_name" ]; then
            sed -i "s/PEER_NAME=.*/PEER_NAME=$peer_name/" server/.env
        fi
        
        echo ""
        echo "✅ P2P mesh configured:"
        echo "   - Peers: $peer_urls"
        echo "   - Name: ${peer_name:-auto}"
        echo "   - Sync: Every 3 minutes"
    fi
else
    echo "ℹ️  Running in standalone mode (no peer sharing)"
    echo "   You can configure peers later in server/.env"
fi

# Build and start container
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Building and Starting Container"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd server
docker compose build
docker compose up -d

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Container Started Successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 Dashboard: http://localhost:5000"
echo ""
echo "🔍 View logs:"
echo "   docker compose logs -f"
echo ""
echo "🛑 Stop container:"
echo "   docker compose down"
echo ""

if [[ "$connect_peers" == "y" ]]; then
    echo "🌐 P2P Mesh Network:"
    echo "   - Your container is sharing threats with peers"
    echo "   - When you detect attacks, peers learn automatically"
    echo "   - When peers detect attacks, you learn automatically"
    echo "   - The network gets smarter every hour! 🚀"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Open browser
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:5000
elif command -v open &> /dev/null; then
    open http://localhost:5000
fi
