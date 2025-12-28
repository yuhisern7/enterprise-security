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

# Configure ports
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Port Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Default ports (high ports to avoid conflicts):"
echo "  Dashboard: 60000 (HTTP - local access)"
echo "  P2P Sync:  60001 (HTTPS - worldwide connections)"
echo ""
read -p "Use default ports? (y/n): " use_default_ports

if [[ "$use_default_ports" != "y" ]]; then
    read -p "Enter Dashboard port (default 60000): " dashboard_port
    dashboard_port=${dashboard_port:-60000}
    
    read -p "Enter P2P port (default 60001): " p2p_port
    p2p_port=${p2p_port:-60001}
    
    # Update .env with custom ports
    if grep -q "DASHBOARD_PORT=" server/.env; then
        sed -i "s/DASHBOARD_PORT=.*/DASHBOARD_PORT=$dashboard_port/" server/.env
    else
        echo "DASHBOARD_PORT=$dashboard_port" >> server/.env
    fi
    
    if grep -q "P2P_PORT=" server/.env; then
        sed -i "s/P2P_PORT=.*/P2P_PORT=$p2p_port/" server/.env
    else
        echo "P2P_PORT=$p2p_port" >> server/.env
    fi
    
    echo "✅ Ports configured: Dashboard=$dashboard_port, P2P=$p2p_port"
else
    echo "✅ Using default ports: Dashboard=60000, P2P=60001"
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
echo "🔐 All connections are HTTPS encrypted - hackers cannot sniff."
echo ""
read -p "Do you want to connect to other peer containers? (y/n): " connect_peers

if [[ "$connect_peers" == "y" ]]; then
    echo ""
    echo "Enter peer container IPs or domains (comma-separated)"
    echo "Example: 192.168.1.100,192.168.1.101,office.example.com"
    echo "Note: Use the P2P port each peer is using (ask them or default is 60001)"
    echo ""
    read -p "Peer IPs/Domains: " peer_hosts
    
    if [ ! -z "$peer_hosts" ]; then
        # Convert to HTTPS URLs automatically (encrypted by default)
        peer_urls=""
        IFS=',' read -ra HOSTS <<< "$peer_hosts"
        for host in "${HOSTS[@]}"; do
            host=$(echo "$host" | xargs)  # trim whitespace
            if [ ! -z "$peer_urls" ]; then
                peer_urls="$peer_urls,"
            fi
            # Auto-use HTTPS port 5443 for encrypted P2P
            peer_urls="${peer_urls}https://${host}:5443"
        done
        
        # Enable P2P sync
        sed -i "s/P2P_SYNC_ENABLED=.*/P2P_SYNC_ENABLED=true/" .env
        sed -i "s|PEER_URLS=.*|PEER_URLS=$peer_urls|" .env
        
        # Set peer name
        read -p "Enter a name for this container (e.g., office-1, home-main): " peer_name
        if [ ! -z "$peer_name" ]; then
            sed -i "s/PEER_NAME=.*/PEER_NAME=$peer_name/" .env
        fi
        
        echo ""
        echo "✅ P2P mesh configured with HTTPS encryption:"
        echo "   - Peers: $peer_urls"
        echo "   - Name: ${peer_name:-auto}"
        echo "   - Sync: Every 3 minutes (encrypted)"
        echo "   - 🔐 All ML training data encrypted in transit"
    fi
else
    echo "ℹ️  Running in standalone mode (no peer sharing)"
    echo "   You can configure peers later in .env file"
fi

# Build and start container
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Building and Starting Container"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd server
docker compose build
docker compose up -d

# Get configured ports from .env
dashboard_port=$(grep "^DASHBOARD_PORT=" ../.env 2>/dev/null | cut -d'=' -f2)
dashboard_port=${dashboard_port:-60000}
p2p_port=$(grep "^P2P_PORT=" ../.env 2>/dev/null | cut -d'=' -f2)
p2p_port=${p2p_port:-60001}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Container Started Successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 Dashboard: http://localhost:$dashboard_port"
echo "🌐 P2P Port:  https://your-ip:$p2p_port (for peer connections)"
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
    echo "📌 Remember to open port $p2p_port on your firewall!"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Open browser
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:$dashboard_port
elif command -v open &> /dev/null; then
    open http://localhost:$dashboard_port
fi
