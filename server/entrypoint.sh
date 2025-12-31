#!/bin/bash

echo "🔐 Enterprise Security - HTTPS Server Starting..."

# Check if SSL certificates exist
if [ ! -f /app/ssl/cert.pem ] || [ ! -f /app/ssl/key.pem ]; then
    echo "❌ SSL certificates not found!"
    exit 1
fi

echo "✅ SSL certificates found"
echo "📊 Dashboard: https://0.0.0.0:60000 (HTTPS - Secure)"
echo "⚠️  Your browser will show SSL warning (self-signed cert) - this is NORMAL"
echo "    Click 'Advanced' → 'Proceed to localhost' to access dashboard"
echo ""

# Start Gunicorn with SSL, proxying to Flask
# Gunicorn listens on HTTPS 60000, forwards to Flask on HTTP 5000
cd /app

# Start Flask in background
python server.py &
FLASK_PID=$!

echo "Waiting for Flask to initialize..."
sleep 10

echo "🔐 Starting Gunicorn with HTTPS (SSL)..."

# Run Gunicorn with SSL on port 60000, proxying to Flask on 5000
exec gunicorn \
    --certfile=/app/ssl/cert.pem \
    --keyfile=/app/ssl/key.pem \
    --bind 0.0.0.0:60000 \
    --workers 2 \
    --threads 4 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    server:app
