#!/bin/bash
# Quick start script for Linux (uses host networking for full device scanning)

echo "🐧 Starting Enterprise Security on Linux..."
echo "Using host networking mode for full network device discovery"
echo ""

cd server
docker compose -f docker-compose.linux.yml down 2>/dev/null
docker compose -f docker-compose.linux.yml up -d --build

echo ""
echo "✅ Container starting..."
echo "Dashboard: http://localhost:60000"
echo "P2P Port: https://localhost:60001"
echo ""
echo "Waiting for container to be healthy..."
sleep 30

docker compose -f docker-compose.linux.yml ps

echo ""
echo "✅ Full network scanning enabled (host mode)"
echo "Will detect all devices on your WiFi network"
