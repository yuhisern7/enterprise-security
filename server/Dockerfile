# Home WiFi Security System - Docker Image
FROM python:3.11-slim

# Install system dependencies for network monitoring
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    gcc \
    openssl \
    iproute2 \
    samba-common-bin \
    avahi-utils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY server/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy AI folder (contains pcs_ai.py, dashboard, and ml_models)
COPY AI/ AI/

# Copy server files
COPY server/server.py .
COPY server/network_monitor.py .
COPY server/device_scanner.py .
COPY server/device_blocker.py .
COPY server/report_generator.py .

# Create and copy JSON data directory
RUN mkdir -p json
COPY server/json/ json/

# Generate self-signed SSL certificate for encrypted P2P communication
RUN mkdir -p /app/ssl && \
    openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /app/ssl/key.pem \
    -out /app/ssl/cert.pem \
    -days 3650 \
    -subj "/C=US/ST=State/L=City/O=Security/CN=enterprise-security"

# Expose ports (HTTP and HTTPS)
EXPOSE 5000 5443

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run as root (required for network monitoring)
USER root

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000', verify=False)" || exit 1

# Start the server
CMD ["python", "server.py"]
