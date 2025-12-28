#!/bin/bash
# Client Container Setup for Companies & Homes
# This connects to the central threat intelligence server

set -e

echo "============================================"
echo "🏢 Client Security Container Setup"
echo "============================================"
echo ""
echo "This deploys a security container that:"
echo "  • Monitors your local network"
echo "  • Detects and blocks threats"
echo "  • Shares threats with global network (encrypted)"
echo "  • Learns from attacks on other clients"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed!"
    echo ""
    echo "Installing Docker..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker $USER
        echo "✅ Docker installed. Please log out and log back in, then run this script again."
        exit 0
    else
        echo "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop"
        exit 1
    fi
fi

if ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is not installed!"
    exit 1
fi

echo "✅ Docker: $(docker --version)"
echo ""

# Download ExploitDB if not exists
if [ ! -d "AI/exploitdb" ]; then
    echo "📥 Downloading ExploitDB database (46,948 exploits)..."
    cd AI
    if [ -f "setup_exploitdb.sh" ]; then
        bash setup_exploitdb.sh
    else
        git clone https://github.com/offensive-security/exploitdb.git
    fi
    cd ..
    echo "✅ ExploitDB downloaded"
else
    echo "✅ ExploitDB already present"
fi

# Create .env if not exists
if [ ! -f ".env" ]; then
    echo ""
    echo "📝 Creating configuration file..."
    cp .env.example .env
    
    echo ""
    echo "============================================"
    echo "⚙️  Configuration Required"
    echo "============================================"
    echo ""
    
    # VirusTotal API Key
    echo "1️⃣  VirusTotal API Key (REQUIRED)"
    echo "   Get FREE key at: https://www.virustotal.com/gui/join-us"
    echo ""
    read -p "   Enter VirusTotal API key (or press Enter to skip): " vt_key
    if [ ! -z "$vt_key" ]; then
        sed -i "s/VIRUSTOTAL_API_KEY=.*/VIRUSTOTAL_API_KEY=$vt_key/" .env
        echo "   ✅ VirusTotal configured"
    else
        echo "   ⚠️  Skipped - you can add this later in .env file"
    fi
    
    echo ""
    echo "2️⃣  Central Threat Intelligence Server"
    echo "   Connect to global threat sharing network?"
    echo ""
    read -p "   Do you want to connect to central server? (y/n): " connect_central
    
    if [[ "$connect_central" =~ ^[Yy]$ ]]; then
        echo ""
        read -p "   Central server URL (e.g., https://your-server:5001): " server_url
        
        if [ ! -z "$server_url" ]; then
            # Register with central server
            echo ""
            echo "   📡 Registering with central server..."
            read -p "   Your organization name: " org_name
            
            # Try to register
            registration_response=$(curl -k -s -X POST "$server_url/api/v1/register" \
                -H "Content-Type: application/json" \
                -d "{\"client_name\": \"$org_name\"}" 2>/dev/null || echo "")
            
            if [ ! -z "$registration_response" ]; then
                api_key=$(echo "$registration_response" | grep -o '"api_key":"[^"]*' | cut -d'"' -f4)
                
                if [ ! -z "$api_key" ]; then
                    sed -i "s|CENTRAL_SERVER_URL=.*|CENTRAL_SERVER_URL=$server_url|" .env
                    sed -i "s/CENTRAL_SERVER_API_KEY=.*/CENTRAL_SERVER_API_KEY=$api_key/" .env
                    sed -i "s/SYNC_ENABLED=.*/SYNC_ENABLED=true/" .env
                    echo "   ✅ Successfully registered with central server!"
                    echo "   🔑 API Key saved to .env"
                else
                    echo "   ⚠️  Registration failed. Please register manually."
                fi
            else
                echo "   ⚠️  Could not connect to server. You can configure this later in .env"
            fi
        fi
    else
        echo "   ℹ️  Running in standalone mode (no global sharing)"
        sed -i "s/SYNC_ENABLED=.*/SYNC_ENABLED=false/" .env
    fi
    
    echo ""
    echo "✅ Configuration saved to .env"
else
    echo "✅ Configuration file exists (.env)"
fi

# Build and start
echo ""
echo "🔨 Building security container..."
cd server
docker compose build

echo ""
echo "🚀 Starting security container..."
docker compose up -d

echo ""
echo "⏳ Waiting for services to start..."
sleep 10

# Check health
echo ""
echo "🏥 Health check..."
container_status=$(docker compose ps | grep enterprise-security || echo "not running")

if [[ "$container_status" =~ "running" ]] || [[ "$container_status" =~ "Up" ]]; then
    echo "✅ Container is running!"
else
    echo "⚠️  Container may still be starting. Check logs:"
    echo "   cd server && docker compose logs -f"
fi

echo ""
echo "============================================"
echo "✅ Security System Deployed!"
echo "============================================"
echo ""
echo "📊 Dashboard: http://localhost:5000"
echo "   (or http://$(hostname -I | awk '{print $1}'):5000 from other devices)"
echo ""
echo "🔧 Management:"
echo "   View logs:    cd server && docker compose logs -f"
echo "   Restart:      cd server && docker compose restart"
echo "   Stop:         cd server && docker compose down"
echo ""
echo "📖 Configuration:"
echo "   Edit .env file to add/change:"
echo "   • VirusTotal API key"
echo "   • Central server connection"
echo "   • Timezone settings"
echo ""
echo "🌍 Connected to Global Network:"
sync_enabled=$(grep SYNC_ENABLED .env | cut -d'=' -f2)
if [[ "$sync_enabled" == "true" ]]; then
    server_url=$(grep CENTRAL_SERVER_URL .env | cut -d'=' -f2)
    echo "   ✅ Yes - Connected to: $server_url"
    echo "   🎓 Your AI learns from all attacks globally!"
else
    echo "   ❌ No - Running standalone"
    echo "   💡 To enable: Edit .env and set SYNC_ENABLED=true"
fi
echo ""
echo "🎉 Your network is now protected!"
echo ""

# Open browser
if command -v xdg-open &> /dev/null; then
    echo "🌐 Opening dashboard in browser..."
    sleep 2
    xdg-open http://localhost:5000 2>/dev/null || true
elif command -v open &> /dev/null; then
    echo "🌐 Opening dashboard in browser..."
    sleep 2
    open http://localhost:5000 2>/dev/null || true
fi
