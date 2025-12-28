FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    flask==3.0.0 \
    flask-cors==4.0.0 \
    cryptography==41.0.7

# Create directories
RUN mkdir -p /app/data /app/certs

# Copy server
COPY server.py /app/

# Generate self-signed SSL certificate (for production, use real certs)
RUN openssl req -x509 -newkey rsa:4096 \
    -keyout /app/certs/key.pem \
    -out /app/certs/cert.pem \
    -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=central-threat-server"

# Expose port
EXPOSE 5001

# Run server
CMD ["python3", "server.py"]
