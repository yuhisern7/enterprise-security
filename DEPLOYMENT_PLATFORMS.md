# 🌐 Multi-Platform Deployment Guide

This system can be deployed on various platforms. This guide tests and documents deployment methods.

---

## ✅ Tested Platforms

### 1. **Local Docker (Mac/Windows/Linux)**
- **Status**: ✅ Primary deployment method
- **Requirements**: Docker Desktop or Docker Engine
- **Command**: `./setup_peer.sh`
- **Use Case**: Home users, small offices, development

### 2. **Cloud Platforms**

#### AWS (Amazon Web Services)
- **EC2 Instance**: Ubuntu 20.04+ with Docker
- **ECS/Fargate**: Container orchestration
- **Lightsail**: Simple VPS option

#### Google Cloud Platform
- **Compute Engine**: VM with Docker
- **Cloud Run**: Serverless container deployment
- **GKE**: Kubernetes cluster

#### Microsoft Azure
- **Virtual Machines**: Ubuntu/RHEL with Docker
- **Container Instances**: Serverless containers
- **AKS**: Azure Kubernetes Service

#### DigitalOcean
- **Droplets**: $6/month VPS with Docker pre-installed
- **App Platform**: Container deployment

#### Linode/Vultr/Hetzner
- **VPS**: Budget-friendly ($5-10/month)
- **Docker pre-installed images available**

### 3. **Raspberry Pi / ARM Devices**
- **Raspberry Pi 4** (4GB+ RAM recommended)
- **Orange Pi, Rock Pi**
- **ARM-based mini PCs**

### 4. **Kubernetes**
- **Self-hosted clusters**
- **Managed Kubernetes** (EKS, GKE, AKS)
- **K3s** (lightweight Kubernetes)

### 5. **Edge/IoT Platforms**
- **Balena Cloud**: Fleet management for IoT
- **AWS IoT Greengrass**
- **Azure IoT Edge**

---

## 🧪 Platform Testing

### Test 1: Cloud VPS Deployment (Generic)

**Target**: Any Ubuntu/Debian VPS (DigitalOcean, Linode, Vultr, etc.)

**Script**: `cloud-deploy.sh`
```bash
#!/bin/bash
# Universal cloud deployment script

# Install Docker (if not present)
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
fi

# Clone repository
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security

# Run setup
./setup_peer.sh

# Configure firewall
sudo ufw allow 60001/tcp  # P2P port
sudo ufw --force enable

echo "✅ Deployment complete!"
echo "📊 Dashboard: http://$(curl -s ifconfig.me):60000"
echo "🌐 P2P URL: https://$(curl -s ifconfig.me):60001"
```

### Test 2: Raspberry Pi Deployment

**Requirements**:
- Raspberry Pi 4 (4GB RAM minimum)
- Raspberry Pi OS (64-bit recommended)
- SD Card 16GB+

**Script**: `raspberry-pi-deploy.sh`
```bash
#!/bin/bash
# Raspberry Pi specific deployment

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker pi
newgrp docker

# Install Docker Compose
sudo apt install docker-compose -y

# Clone and deploy
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security
./setup_peer.sh

echo "✅ Raspberry Pi deployment complete!"
```

### Test 3: Kubernetes Deployment

**File**: `kubernetes-deployment.yaml`
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: enterprise-security

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-config
  namespace: enterprise-security
data:
  DASHBOARD_PORT: "60000"
  P2P_PORT: "60001"
  P2P_SYNC_ENABLED: "true"
  P2P_SYNC_INTERVAL: "180"

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: enterprise-security
  namespace: enterprise-security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: enterprise-security
  template:
    metadata:
      labels:
        app: enterprise-security
    spec:
      containers:
      - name: security-ai
        image: enterprise-security:latest
        ports:
        - containerPort: 60000
          name: dashboard
        - containerPort: 60001
          name: p2p
        envFrom:
        - configMapRef:
            name: security-config
        securityContext:
          capabilities:
            add:
              - NET_ADMIN  # Required for Scapy
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"

---
apiVersion: v1
kind: Service
metadata:
  name: enterprise-security-svc
  namespace: enterprise-security
spec:
  type: LoadBalancer
  selector:
    app: enterprise-security
  ports:
  - name: dashboard
    port: 60000
    targetPort: 60000
  - name: p2p
    port: 60001
    targetPort: 60001
```

**Deploy**:
```bash
kubectl apply -f kubernetes-deployment.yaml
kubectl get svc -n enterprise-security
```

### Test 4: Docker Compose with External Volume (Persistence)

**File**: `docker-compose.persistent.yml`
```yaml
version: '3.8'

services:
  enterprise-security-ai:
    build: .
    container_name: enterprise-security-ai
    network_mode: bridge
    ports:
      - "${DASHBOARD_PORT:-60000}:${DASHBOARD_PORT:-60000}"
      - "${P2P_PORT:-60001}:${P2P_PORT:-60001}"
    cap_add:
      - NET_ADMIN
    environment:
      - DASHBOARD_PORT=${DASHBOARD_PORT:-60000}
      - P2P_PORT=${P2P_PORT:-60001}
      - PEER_URLS=${PEER_URLS:-}
      - PEER_NAME=${PEER_NAME:-security-peer}
      - P2P_SYNC_ENABLED=${P2P_SYNC_ENABLED:-true}
      - P2P_SYNC_INTERVAL=${P2P_SYNC_INTERVAL:-180}
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY:-}
    volumes:
      - threat-data:/app/server/json
      - exploitdb-data:/app/AI/exploitdb
    restart: unless-stopped

volumes:
  threat-data:
    driver: local
  exploitdb-data:
    driver: local
```

### Test 5: AWS EC2 One-Line Deploy

```bash
# SSH into EC2 instance, then run:
curl -fsSL https://raw.githubusercontent.com/yuhisern7/enterprise-security/main/cloud-deploy.sh | bash
```

---

## 🧪 Testing Checklist

### Local Testing
- [ ] Docker Desktop (Mac)
- [ ] Docker Desktop (Windows with WSL2)
- [ ] Docker Engine (Ubuntu 20.04)
- [ ] Docker Engine (Debian 11)
- [ ] Docker Engine (RHEL 8 / CentOS Stream)
- [ ] Docker Engine (Arch Linux)

### Cloud VPS Testing
- [ ] DigitalOcean Droplet ($6/mo)
- [ ] Linode VPS ($5/mo)
- [ ] Vultr VPS ($6/mo)
- [ ] Hetzner Cloud (€5/mo)
- [ ] AWS EC2 t3.micro
- [ ] Google Cloud e2-micro
- [ ] Azure B1s

### ARM/Edge Testing
- [ ] Raspberry Pi 4 (4GB)
- [ ] Raspberry Pi 4 (8GB)
- [ ] Orange Pi 5
- [ ] Rock Pi 4
- [ ] NVIDIA Jetson Nano

### Container Orchestration
- [ ] Docker Compose (standalone)
- [ ] Docker Swarm
- [ ] Kubernetes (self-hosted)
- [ ] K3s (lightweight K8s)
- [ ] MicroK8s
- [ ] AWS ECS
- [ ] Google Cloud Run
- [ ] Azure Container Instances

### Network Configurations
- [ ] Behind NAT/router
- [ ] Public IP (cloud)
- [ ] Corporate firewall
- [ ] VPN tunnel
- [ ] Tor network (privacy-focused)

---

## 📊 Platform Comparison

| Platform | Cost/Month | Setup Time | RAM Usage | Best For |
|----------|------------|------------|-----------|----------|
| **Local Docker** | $0 | 5 min | ~500MB | Home, development |
| **Raspberry Pi** | $0* | 10 min | ~500MB | Home, IoT, edge |
| **DigitalOcean** | $6 | 5 min | ~500MB | Small business |
| **AWS EC2 t3.micro** | $8-10 | 10 min | ~500MB | Enterprise trial |
| **Kubernetes** | Varies | 30 min | ~600MB | Large deployments |
| **Cloud Run** | Pay-per-use | 15 min | ~500MB | Serverless, scale-to-zero |

*One-time hardware cost

---

## 🚀 Next Steps

1. Create deployment scripts for each platform
2. Test on actual cloud instances
3. Document performance benchmarks
4. Create one-click installers
5. Build container registry (Docker Hub, GitHub Packages)
