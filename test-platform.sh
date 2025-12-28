#!/bin/bash
###############################################################################
# Platform Deployment Test Script
# Tests if the system can be deployed on various platforms
###############################################################################

echo "🧪 Enterprise Security - Platform Deployment Tests"
echo "=================================================="
echo ""

# Test 1: Check Docker availability
echo "Test 1: Docker Engine"
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    echo "✅ PASS: Docker installed ($DOCKER_VERSION)"
else
    echo "❌ FAIL: Docker not found"
    echo "   Install: curl -fsSL https://get.docker.com | bash"
fi
echo ""

# Test 2: Check Docker Compose
echo "Test 2: Docker Compose"
if docker compose version &> /dev/null 2>&1; then
    COMPOSE_VERSION=$(docker compose version)
    echo "✅ PASS: Docker Compose available ($COMPOSE_VERSION)"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_VERSION=$(docker-compose --version)
    echo "✅ PASS: Docker Compose available ($COMPOSE_VERSION)"
else
    echo "❌ FAIL: Docker Compose not found"
    echo "   Install: sudo apt-get install docker-compose-plugin"
fi
echo ""

# Test 3: Check required ports
echo "Test 3: Port Availability"
PORT_60000_FREE=true
PORT_60001_FREE=true

if command -v lsof &> /dev/null; then
    if sudo lsof -i :60000 &> /dev/null; then
        PORT_60000_FREE=false
    fi
    if sudo lsof -i :60001 &> /dev/null; then
        PORT_60001_FREE=false
    fi
elif command -v netstat &> /dev/null; then
    if netstat -an | grep -q ":60000 "; then
        PORT_60000_FREE=false
    fi
    if netstat -an | grep -q ":60001 "; then
        PORT_60001_FREE=false
    fi
fi

if [ "$PORT_60000_FREE" = true ]; then
    echo "✅ PASS: Port 60000 available (dashboard)"
else
    echo "⚠️  WARN: Port 60000 in use (configure custom port)"
fi

if [ "$PORT_60001_FREE" = true ]; then
    echo "✅ PASS: Port 60001 available (P2P)"
else
    echo "⚠️  WARN: Port 60001 in use (configure custom port)"
fi
echo ""

# Test 4: System Resources
echo "Test 4: System Resources"
TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
if [ "$TOTAL_RAM" -ge 1024 ]; then
    echo "✅ PASS: RAM: ${TOTAL_RAM}MB (minimum 1GB required)"
else
    echo "❌ FAIL: RAM: ${TOTAL_RAM}MB (minimum 1GB required)"
fi

TOTAL_DISK=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$TOTAL_DISK" -ge 5 ]; then
    echo "✅ PASS: Disk: ${TOTAL_DISK}GB free (minimum 5GB required)"
else
    echo "⚠️  WARN: Disk: ${TOTAL_DISK}GB free (minimum 5GB recommended)"
fi
echo ""

# Test 5: Network Connectivity
echo "Test 5: Network Connectivity"
if ping -c 1 google.com &> /dev/null; then
    echo "✅ PASS: Internet connection available"
else
    echo "❌ FAIL: No internet connection"
    echo "   Required for initial setup (ExploitDB download)"
fi
echo ""

# Test 6: Required Commands
echo "Test 6: Required Commands"
MISSING_COMMANDS=()

for cmd in git curl bash; do
    if command -v $cmd &> /dev/null; then
        echo "✅ PASS: $cmd available"
    else
        echo "❌ FAIL: $cmd not found"
        MISSING_COMMANDS+=($cmd)
    fi
done
echo ""

# Test 7: Operating System
echo "Test 7: Operating System"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "✅ PASS: OS detected - $PRETTY_NAME"
    
    # Check if supported
    SUPPORTED=false
    case "$ID" in
        ubuntu|debian|rhel|centos|fedora|arch|manjaro)
            SUPPORTED=true
            ;;
    esac
    
    if [ "$SUPPORTED" = true ]; then
        echo "✅ PASS: OS is supported"
    else
        echo "⚠️  WARN: OS may not be officially supported (should still work)"
    fi
else
    echo "⚠️  WARN: Cannot detect OS"
fi
echo ""

# Test 8: User Permissions
echo "Test 8: User Permissions"
if groups | grep -q docker; then
    echo "✅ PASS: User in docker group"
elif [ "$EUID" -eq 0 ]; then
    echo "✅ PASS: Running as root"
else
    echo "⚠️  WARN: User not in docker group (may need sudo)"
    echo "   Fix: sudo usermod -aG docker \$USER && newgrp docker"
fi
echo ""

# Summary
echo "=================================================="
echo "📊 Test Summary"
echo "=================================================="

CRITICAL_PASS=true
if ! command -v docker &> /dev/null; then CRITICAL_PASS=false; fi
if ! (docker compose version &> /dev/null 2>&1 || command -v docker-compose &> /dev/null); then CRITICAL_PASS=false; fi

if [ "$CRITICAL_PASS" = true ]; then
    echo "✅ System is READY for deployment!"
    echo ""
    echo "🚀 Quick Deploy:"
    echo "   ./setup_peer.sh"
    echo ""
    echo "🌐 Cloud Deploy:"
    echo "   curl -fsSL https://raw.githubusercontent.com/yuhisern7/enterprise-security/main/cloud-deploy.sh | bash"
else
    echo "❌ System is NOT ready for deployment"
    echo ""
    echo "📋 Missing requirements:"
    if ! command -v docker &> /dev/null; then
        echo "   • Docker Engine"
    fi
    if ! (docker compose version &> /dev/null 2>&1 || command -v docker-compose &> /dev/null); then
        echo "   • Docker Compose"
    fi
    echo ""
    echo "🔧 Quick Fix:"
    echo "   curl -fsSL https://get.docker.com | sudo bash"
fi
echo ""
