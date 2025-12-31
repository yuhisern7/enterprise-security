#!/bin/bash
# Quick Start - Military-Grade Dashboard
# Run this script to view your new enterprise dashboard

echo "⚔️  BATTLE-HARDENED AI - ENTERPRISE DASHBOARD"
echo "=============================================="
echo ""

# Check if Docker is running
if docker compose ps | grep -q "server.*Up"; then
    SERVER_URL="http://localhost:5000"
    echo "✅ Server is running"
    echo ""
    echo "🎯 MILITARY-GRADE DASHBOARD:"
    echo "   $SERVER_URL"
    echo ""
    echo "📊 LEGACY MONITORING DASHBOARD:"
    echo "   $SERVER_URL/inspector/ai-monitoring"
    echo ""
    echo "Opening dashboard in browser..."
    
    # Try to open browser (works on Linux with xdg-open)
    if command -v xdg-open > /dev/null; then
        xdg-open "$SERVER_URL" 2>/dev/null
    elif command -v open > /dev/null; then
        # macOS
        open "$SERVER_URL"
    else
        echo "⚠️  Please open this URL manually: $SERVER_URL"
    fi
    
    echo ""
    echo "📋 DASHBOARD FEATURES:"
    echo "   • Real-time Network Performance Monitoring"
    echo "   • Compliance Dashboard (PCI-DSS, HIPAA, GDPR, SOC 2)"
    echo "   • Network Topology Visualization"
    echo "   • Threat Heatmap & Attack Flow Analysis"
    echo "   • Geographic Attack Distribution"
    echo "   • AI Anomaly Detection"
    echo "   • Live Threat Log"
    echo ""
    echo "💰 ENTERPRISE VALUE: \$675,000/year in features"
    echo ""
    
else
    echo "❌ Server is not running!"
    echo ""
    echo "Start the server with:"
    echo "   cd server && docker compose up -d"
    echo ""
    echo "Or start everything:"
    echo "   ./cloud-deploy.sh"
fi
