#!/bin/bash
#
# Enterprise Security System - Auto Setup Script (Linux/Mac)
# One-command installation
#

set -e  # Exit on any error

echo "=============================================="
echo "🛡️  Enterprise Security System Setup"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root for Docker
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ Do not run this script as root/sudo${NC}"
   echo "Run as normal user. Script will ask for sudo when needed."
   exit 1
fi

echo "Step 1/6: Checking prerequisites..."
echo "--------------------------------------------"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found${NC}"
    echo ""
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo -e "${GREEN}✅ Docker installed${NC}"
    echo -e "${YELLOW}⚠️  Please log out and log back in, then run this script again${NC}"
    exit 0
else
    echo -e "${GREEN}✅ Docker found: $(docker --version)${NC}"
fi

# Check Docker Compose
if ! command -v docker compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose not found${NC}"
    echo "Please install Docker Compose plugin"
    exit 1
else
    echo -e "${GREEN}✅ Docker Compose found${NC}"
fi

echo ""
echo "Step 2/6: Setting up ExploitDB database..."
echo "--------------------------------------------"

cd AI
if [ ! -d "exploitdb" ]; then
    echo "Downloading ExploitDB (46,948 exploits)..."
    chmod +x setup_exploitdb.sh
    ./setup_exploitdb.sh
else
    echo -e "${GREEN}✅ ExploitDB already exists${NC}"
fi
cd ..

echo ""
echo "Step 3/6: Configuring environment..."
echo "--------------------------------------------"

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file..."
    cat > .env << 'EOF'
# VirusTotal API Key (REQUIRED - Get free key from https://www.virustotal.com)
VIRUSTOTAL_API_KEY=

# AbuseIPDB API Key (Optional - Get from https://www.abuseipdb.com)
ABUSEIPDB_API_KEY=

# Timezone
TZ=UTC

# Flask Environment
FLASK_ENV=production

# AI Learning
AI_LEARNING_ENABLED=true
EOF
    echo -e "${YELLOW}⚠️  Created .env file${NC}"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Edit .env and add your VirusTotal API key!${NC}"
    echo ""
    read -p "Press Enter to edit .env now, or Ctrl+C to do it later..."
    ${EDITOR:-nano} .env
else
    echo -e "${GREEN}✅ .env file exists${NC}"
fi

echo ""
echo "Step 4/6: Building Docker image..."
echo "--------------------------------------------"

cd server
sudo docker compose build

echo ""
echo "Step 5/6: Starting services..."
echo "--------------------------------------------"

sudo docker compose up -d

echo ""
echo "Step 6/6: Waiting for services to start..."
echo "--------------------------------------------"

echo -n "Waiting for server to be ready"
for i in {1..30}; do
    if curl -s http://localhost:5000/health &>/dev/null || curl -s http://localhost:5000 &>/dev/null; then
        echo ""
        echo -e "${GREEN}✅ Server is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

echo ""
echo "=============================================="
echo -e "${GREEN}🎉 Setup Complete!${NC}"
echo "=============================================="
echo ""
echo "📊 Dashboard: http://localhost:5000"
echo "🐳 Container Status:"
sudo docker compose ps
echo ""
echo "📝 View Logs:"
echo "   sudo docker compose logs -f"
echo ""
echo "🛑 Stop System:"
echo "   cd server && sudo docker compose down"
echo ""
echo "⚙️  Next Steps:"
echo "   1. Open http://localhost:5000 in your browser"
echo "   2. Add your VirusTotal API key in .env if you haven't"
echo "   3. Restart if you added API key: sudo docker compose restart"
echo ""
echo "=============================================="
