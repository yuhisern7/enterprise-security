FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    git \
    curl \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY relay/requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Create app directory
WORKDIR /app/relay

# Copy relay server files
COPY relay/relay_server.py .
COPY relay/training_sync_api.py .
COPY relay/signature_sync.py .
COPY relay/ai_retraining.py .
COPY relay/gpu_trainer.py .
COPY relay/start_services.py .

# Copy AI module (needed for pcs_ai imports - includes all enterprise features)
COPY AI /app/AI

# Create directories for keys (will be mounted/copied manually)
RUN mkdir -p /app/relay/customer_keys

# Create directories
RUN mkdir -p /app/relay/ai_training_materials/ml_models
RUN mkdir -p /app/relay/ml_models
RUN mkdir -p /app/relay/json

# Generate self-signed SSL certificates for HTTPS
RUN mkdir -p /app/relay/ssl && \
    openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /app/relay/ssl/relay.key \
    -out /app/relay/ssl/relay.crt \
    -days 3650 -sha256 \
    -subj "/C=US/ST=Cloud/L=VPS/O=Battle-Hardened-AI/CN=relay-server"

# Expose ports
# WebSocket relay
EXPOSE 60001
# Model distribution API
EXPOSE 60002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.connect(('localhost', 60001)); s.close()"

# Default command - starts BOTH relay server AND model distribution API
CMD ["python3", "start_services.py"]
