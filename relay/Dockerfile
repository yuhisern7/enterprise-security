FROM python:3.11-slim

# Install dependencies
RUN pip install --no-cache-dir websockets

# Copy relay server
WORKDIR /app
COPY relay_server.py .

# Expose WebSocket port
EXPOSE 60001

# Run relay server
CMD ["python3", "relay_server.py"]
