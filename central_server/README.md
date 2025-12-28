# Central Threat Intelligence Server

**Centralized threat aggregation and distribution for all connected client nodes.**

## Overview

This server collects threats from all deployed client containers (companies, homes, etc.) and distributes the learning globally. When one client detects an attack, all other clients learn about it instantly.

## Architecture

```
┌─────────────────────────────────────────┐
│   Central Server (Your Infrastructure)  │
│   • Aggregates all threats              │
│   • Distributes global threat feed      │
│   • Encrypted HTTPS + API key auth      │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┼─────────┐
        │         │         │
    ┌───▼───┐ ┌──▼───┐ ┌──▼───┐
    │Client1│ │Client2│ │Client3│
    │Company│ │ Home  │ │Branch│
    │   A   │ │   B   │ │   C  │
    └───────┘ └──────┘ └──────┘
```

## Quick Start

### 1. Deploy Central Server

```bash
cd central_server
docker compose up -d
```

Server starts on: `https://your-server:5001`

### 2. Get Master API Key

```bash
docker compose logs | grep "master API key"
```

**Output:**
```
Generated new master API key: abc123xyz...
SAVE THIS KEY - it will not be shown again!
```

### 3. Register Client Nodes

Each company/home that deploys your client container must register:

```bash
curl -k -X POST https://your-server:5001/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Company ABC",
    "client_info": {
      "location": "New York",
      "network_size": "500 users"
    }
  }'
```

**Response:**
```json
{
  "client_id": "a1b2c3d4e5f6g7h8",
  "api_key": "xyz789abc123...",
  "message": "Registration successful. SAVE YOUR API KEY!"
}
```

### 4. Configure Client Containers

On each client machine, edit `.env`:

```bash
# Central server connection
CENTRAL_SERVER_URL=https://your-server:5001
CENTRAL_SERVER_API_KEY=xyz789abc123...
SYNC_ENABLED=true
SYNC_INTERVAL=300  # Sync every 5 minutes
```

Restart client:
```bash
cd server
docker compose restart
```

## API Endpoints

### Public Endpoints

**`GET /health`** - Health check (no auth required)

**`POST /api/v1/register`** - Register new client
```bash
curl -k -X POST https://server:5001/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"client_name": "My Company"}'
```

### Client Endpoints (Require API Key)

**`POST /api/v1/submit-threats`** - Submit threats from client
```bash
curl -k -X POST https://server:5001/api/v1/submit-threats \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "threats": [
      {
        "ip": "1.2.3.4",
        "attack_type": "port_scan",
        "severity": "high",
        "timestamp": "2025-12-28T10:00:00"
      }
    ]
  }'
```

**`GET /api/v1/get-threats`** - Get global threat feed
```bash
# Get all recent threats
curl -k https://server:5001/api/v1/get-threats \
  -H "X-API-Key: YOUR_API_KEY"

# Get threats since timestamp
curl -k "https://server:5001/api/v1/get-threats?since=2025-12-28T00:00:00&limit=500" \
  -H "X-API-Key: YOUR_API_KEY"

# Get specific attack types
curl -k "https://server:5001/api/v1/get-threats?attack_type=port_scan&attack_type=ddos" \
  -H "X-API-Key: YOUR_API_KEY"
```

**`GET /api/v1/threat-patterns`** - Get aggregated patterns
```bash
curl -k https://server:5001/api/v1/get-threat-patterns \
  -H "X-API-Key: YOUR_API_KEY"
```

**`GET /api/v1/stats`** - Get server statistics
```bash
curl -k https://server:5001/api/v1/stats \
  -H "X-API-Key: YOUR_API_KEY"
```

### Admin Endpoints (Require Master API Key)

**`GET /api/v1/clients`** - List all registered clients
```bash
curl -k https://server:5001/api/v1/clients \
  -H "X-API-Key: MASTER_API_KEY"
```

**`POST /api/v1/admin/reset-key/<client_id>`** - Reset client API key
```bash
curl -k -X POST https://server:5001/api/v1/admin/reset-key/a1b2c3d4 \
  -H "X-API-Key: MASTER_API_KEY"
```

## Security

### Encryption
- **HTTPS/TLS 1.3**: All communication encrypted
- **Self-signed cert**: Auto-generated (replace with real cert for production)
- **API Key Auth**: 32-byte secure tokens per client

### Authentication
- Each client gets unique API key
- Master key for admin operations
- Keys never logged or transmitted in plaintext

### Production SSL Setup

Replace self-signed cert with real certificate:

```bash
# Using Let's Encrypt
certbot certonly --standalone -d your-server.com

# Copy certificates
cp /etc/letsencrypt/live/your-server.com/fullchain.pem central_server/certs/cert.pem
cp /etc/letsencrypt/live/your-server.com/privkey.pem central_server/certs/key.pem

# Restart
cd central_server
docker compose restart
```

## Data Storage

All data stored in `central_server/data/`:

- `global_threats.json` - All submitted threats (last 10,000)
- `client_registry.json` - Registered clients
- `threat_patterns.json` - Aggregated attack patterns
- `api_keys.json` - Client API keys (encrypted)

### Backup

```bash
# Backup all data
tar -czf central-backup-$(date +%Y%m%d).tar.gz central_server/data/

# Automated daily backup (cron)
0 2 * * * cd /path/to/enterprise-security && tar -czf backups/central-$(date +\%Y\%m\%d).tar.gz central_server/data/
```

## Monitoring

### Health Check
```bash
curl -k https://your-server:5001/health
```

### View Logs
```bash
cd central_server
docker compose logs -f
```

### Statistics
```bash
curl -k https://your-server:5001/api/v1/stats \
  -H "X-API-Key: YOUR_API_KEY" | python3 -m json.tool
```

## Firewall Configuration

Open port 5001 on your central server:

```bash
# UFW (Ubuntu)
sudo ufw allow 5001/tcp

# firewalld (CentOS/RHEL)
sudo firewall-cmd --add-port=5001/tcp --permanent
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 5001 -j ACCEPT
```

## Scaling

### High Availability

Deploy multiple central servers with load balancer:

```bash
# Nginx load balancer
upstream central_servers {
    server central1.example.com:5001;
    server central2.example.com:5001;
    server central3.example.com:5001;
}

server {
    listen 443 ssl;
    server_name threat-intel.example.com;
    
    location / {
        proxy_pass https://central_servers;
    }
}
```

### Database Backend (Optional)

For 100K+ clients, replace JSON files with PostgreSQL:

```python
# In server.py, replace file operations with:
import psycopg2

conn = psycopg2.connect("postgresql://user:pass@db:5432/threats")
# Use proper DB schema for global_threats, client_registry, etc.
```

## Troubleshooting

**"SSL certificate verify failed"**
- Use `-k` flag with curl for self-signed certs
- Or install real SSL certificate

**"API key required"**
- Add header: `-H "X-API-Key: YOUR_KEY"`
- Ensure client is registered

**"Connection refused"**
- Check firewall: `sudo ufw status`
- Verify container running: `docker ps`
- Check logs: `docker compose logs`

**"No threats received"**
- Verify clients have SYNC_ENABLED=true
- Check client logs: `docker compose logs | grep sync`
- Verify network connectivity between client and central server

## Commercial Deployment

### Pricing Model

Charge companies per client connection:

- **Startup**: $49/month - 1-5 client nodes
- **Business**: $149/month - 6-25 client nodes  
- **Enterprise**: $499/month - Unlimited nodes

### SaaS Hosting

Host central server and provide:
- `CENTRAL_SERVER_URL=https://threat-intel.yourcompany.com`
- Unique API key per customer
- Dashboard to view their network's contribution to global intelligence

## Benefits

✅ **Collective Learning** - All clients learn from each other's attacks  
✅ **Real-time Updates** - New threats distributed within 5 minutes  
✅ **Encrypted** - HTTPS/TLS for all communication  
✅ **Scalable** - Handles 1000s of connected clients  
✅ **Privacy** - Only threat metadata shared, not internal network data  
✅ **Resilient** - Clients continue working if central server is down
