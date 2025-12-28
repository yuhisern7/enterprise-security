# 🌐 Multi-Platform Deployment Guide

This system can be deployed on various platforms. This guide documents deployment methods for each operating system.

---

## ✅ Supported Platforms

### 1. **Local Docker**

#### 🪟 **Windows**
- **Requirements**: Docker Desktop for Windows, Git for Windows
- **Installation**: Manual step-by-step (see README.md Windows section)
- **Use Case**: Home users, small offices, development
- **Setup Time**: 10-15 minutes

#### 🍎 **macOS**
- **Requirements**: Docker Desktop for Mac, Git
- **Installation**: Manual step-by-step (see README.md macOS section)
- **Use Case**: Home users, small offices, development
- **Setup Time**: 10-15 minutes

#### 🐧 **Linux**
- **Requirements**: Docker Engine, Docker Compose, Git
- **Installation**: Automated script (`./setup_peer.sh`)
- **Use Case**: Home users, small offices, development, servers
- **Setup Time**: 5 minutes (automated)

### 2. **Cloud Platforms (Linux Only)**

#### AWS (Amazon Web Services)
- **EC2 Instance**: Ubuntu 20.04+ with Docker
- **Deployment**: `cloud-deploy.sh` script
- **ECS/Fargate**: Container orchestration (manual configuration)
- **Lightsail**: Simple VPS option

#### Google Cloud Platform
- **Compute Engine**: VM with Docker
- **Deployment**: `cloud-deploy.sh` script
- **Cloud Run**: Serverless container deployment (manual)
- **GKE**: Kubernetes cluster

#### Microsoft Azure
- **Virtual Machines**: Ubuntu/RHEL with Docker
- **Deployment**: `cloud-deploy.sh` script
- **Container Instances**: Serverless containers (manual)
- **AKS**: Azure Kubernetes Service

#### DigitalOcean
- **Droplets**: $6/month VPS with Docker pre-installed
- **Deployment**: `cloud-deploy.sh` script
- **App Platform**: Container deployment (manual)

#### Linode/Vultr/Hetzner
- **VPS**: Budget-friendly ($5-10/month)
- **Deployment**: `cloud-deploy.sh` script
- **Docker pre-installed images available**

### 3. **Raspberry Pi / ARM Devices (Linux)**
- **Raspberry Pi 4** (4GB+ RAM recommended)
- **Orange Pi, Rock Pi**
- **ARM-based mini PCs**
- **Deployment**: Manual Linux steps (same as Linux desktop)

### 4. **Kubernetes (All Platforms)**
- **Self-hosted clusters**
- **Managed Kubernetes** (EKS, GKE, AKS)
- **K3s** (lightweight Kubernetes)
- **Deployment**: `kubernetes-deployment.yaml` manifest

### 5. **Edge/IoT Platforms (Linux)**
- **Balena Cloud**: Fleet management for IoT
- **AWS IoT Greengrass**
- **Azure IoT Edge**

---

## 📋 Installation Methods by Platform

### 🪟 Windows Installation

**No automated script available. Follow manual steps:**

1. **Install Prerequisites**
   - Docker Desktop for Windows
   - Git for Windows

2. **Clone Repository**
   ```powershell
   git clone https://github.com/yuhisern7/enterprise-security.git
   cd enterprise-security
   ```

3. **Download ExploitDB**
   ```powershell
   cd AI
   git clone https://github.com/offensive-security/exploitdb.git exploitdb
   cd ..
   ```

4. **Configure Environment**
   ```powershell
   copy .env.example server\.env
   notepad server\.env
   ```

5. **Build and Start**
   ```powershell
   cd server
   docker compose up -d --build
   ```

6. **Access Dashboard**
   - Open browser: http://localhost:60000

**See README.md for detailed Windows installation steps.**

---

### 🍎 macOS Installation

**No automated script available. Follow manual steps:**

1. **Install Prerequisites**
   - Docker Desktop for Mac
   - Git (usually pre-installed)

2. **Clone Repository**
   ```bash
   git clone https://github.com/yuhisern7/enterprise-security.git
   cd enterprise-security
   ```

3. **Download ExploitDB**
   ```bash
   cd AI
   git clone https://github.com/offensive-security/exploitdb.git exploitdb
   cd ..
   ```

4. **Configure Environment**
   ```bash
   cp .env.example server/.env
   nano server/.env
   ```

5. **Build and Start**
   ```bash
   cd server
   docker compose up -d --build
   ```

6. **Access Dashboard**
   - Open browser: http://localhost:60000

**See README.md for detailed macOS installation steps.**

---

### 🐧 Linux Installation (Automated)

**One-command setup:**
```bash
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security
chmod +x setup_peer.sh
./setup_peer.sh
```

The script automatically:
- Downloads ExploitDB database
- Configures ports and environment
- Builds and starts container
- Opens dashboard

**Manual Linux Installation:**
Follow the same steps as macOS above.

---

### ☁️ Cloud VPS Deployment (Linux Only)**

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

### ☁️ Cloud VPS Deployment (Linux Only)

**One-command deployment for any Linux VPS:**
```bash
# SSH into your cloud instance, then run:
curl -fsSL https://raw.githubusercontent.com/yuhisern7/enterprise-security/main/cloud-deploy.sh | bash
```

**Supported Cloud Platforms:**
- ✅ DigitalOcean ($6/month)
- ✅ Linode ($5/month)
- ✅ Vultr ($6/month)
- ✅ AWS EC2 (t3.micro)
- ✅ Google Cloud (e2-micro)
- ✅ Azure (B1s)
- ✅ Hetzner (€5/month)

**Minimum VPS Requirements:**
- RAM: 1GB (2GB recommended)
- CPU: 1 core
- Storage: 5GB
- OS: Ubuntu 20.04+, Debian 11+, RHEL 8+

**The script automatically:**
- Installs Docker & Docker Compose
- Clones repository
- Downloads ExploitDB database
- Configures firewall (opens P2P port 60001)
- Detects public IP
- Builds and starts container
- Shows dashboard and P2P URLs

---

### 🥧 Raspberry Pi Deployment (Linux ARM)

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

### 🥧 Raspberry Pi Deployment (Linux ARM)

### ☸️ Kubernetes Deployment

**Supported Kubernetes Platforms:**
- Self-hosted clusters
- K3s (lightweight Kubernetes)
- MicroK8s
- AWS EKS
- Google Cloud GKE
- Azure AKS

**Deployment Manifest:**

Create `kubernetes-deployment.yaml`:
- Raspberry Pi 4 (4GB RAM minimum, 8GB recommended)
- Raspberry Pi OS (64-bit recommended)
- SD Card 16GB+

**Installation Steps:**

1. **Update System**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Docker**
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo usermod -aG docker pi
   newgrp docker
   ```

3. **Install Docker Compose**
   ```bash
   sudo apt install docker-compose -y
   ```

4. **Clone and Deploy**
   ```bash
   git clone https://github.com/yuhisern7/enterprise-security.git
   cd enterprise-security
   ```

5. **Manual Setup (same as Linux desktop)**
   ```bash
   cd AI
   git clone https://github.com/offensive-security/exploitdb.git exploitdb
   cd ..
   cp .env.example server/.env
   nano server/.env
   cd server
   docker compose up -d --build
   ```

6. **Access Dashboard**
   - Open browser on Pi or remote: http://raspberry-pi-ip:60000

**Note:** Raspberry Pi can use the automated `./setup_peer.sh` script, but manual steps give you more control.

---

### ☸️ Kubernetes Deployment

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
  DASHBO to Kubernetes:**
```bash
kubectl apply -f kubernetes-deployment.yaml
kubectl get svc -n enterprise-security
# Note the LoadBalancer IP, then access:
# http://<EXTERNAL-IP>:60000
```

### 📦 Docker Compose with Persistent Storage

**For production deployments where you need to preserve threat data across container restarts.**

Create `docker-compose.persistent.yml`:
```bash
kubectl get pods -n enterprise-security
kubectl logs -n enterprise-security deployment/enterprise-security
```

---

### 📦 Docker Compose with Persistent Storage
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
**Deploy:**
```bash
docker compose -f docker-compose.persistent.yml up -d --build
```

**Benefits:**
- Threat data persists across container restarts
- ExploitDB database cached (no re-download)
- Faster restarts

---

## 📊 Platform Comparison

| Platform | OS | Setup Method | Setup Time | Best For |
|----------|-------|--------------|------------|----------|
| **Windows Desktop** | Windows 10/11 | Manual steps | 10-15 min | Home users, dev |
| **macOS Desktop** | macOS 10.15+ | Manual steps | 10-15 min | Home users, dev |
| **Linux Desktop** | Ubuntu/Debian/RHEL | Automated script | 5 min | Power users |
| **Raspberry Pi** | Raspberry Pi OS | Manual/Script | 10-15 min | Home IoT, edge |
| **Cloud VPS** | Linux (any) | One-line command | 5 min | Small business |
| **Kubernetes** | Any | YAML manifest | 15-30 min | Enterprise, scale |

**Cost Comparison:**

| Platform | Cost/Month | RAM Usage | Scaling |
|----------|------------|-----------|---------|
| **Local (Windows/Mac/Linux)** | $0 | ~500MB | Single node |
| **Raspberry Pi** | $0* | ~500MB | Single/few nodes |
| **DigitalOcean Droplet** | $6 | ~500MB | Easy multi-node |
| **AWS EC2 t3.micro** | $8-10 | ~500MB | Enterprise scale |
| **Kubernetes (managed)** | Varies | ~600MB/pod | Auto-scaling |

*One-time hardware cost

---

## 🧪 Testing Checklist

### Desktop Platforms
- [ ] ✅ Windows 10/11 with Docker Desktop (manual install)
- [ ] ✅ macOS 10.15+ with Docker Desktop (manual install)
- [ ] ✅ Ubuntu 20.04/22.04 with Docker Engine (automated script)
- [ ] Debian 11/12 with Docker Engine (automated script)
- [ ] RHEL 8/9 / CentOS Stream (automated script)
- [ ] Arch Linux with Docker (manual/script)

### Cloud VPS Platforms
- [ ] DigitalOcean Droplet ($6/mo) - Linux automated
- [ ] Linode VPS ($5/mo) - Linux automated
- [ ] Vultr VPS ($6/mo) - Linux automated
- [ ] Hetzner Cloud (€5/mo) - Linux automated
- [ ] AWS EC2 t3.micro - Linux automated
- [ ] Google Cloud e2-micro - Linux automated
- [ ] Azure B1s - Linux automated

### ARM/Edge Devices
- [ ] Raspberry Pi 4 (4GB) - Linux manual/script
- [ ] Raspberry Pi 4 (8GB) - Linux manual/script
- [ ] Orange Pi 5 - Linux manual
- [ ] Rock Pi 4 - Linux manual
- [ ] NVIDIA Jetson Nano - Linux manual

### Container Orchestration
- [ ] Docker Compose (all platforms)
- [ ] Kubernetes self-hosted (Linux)
- [ ] K3s lightweight K8s (Linux)
- [ ] MicroK8s (Linux)
- [ ] AWS EKS (managed K8s)
- [ ] Google Cloud GKE (managed K8s)
- [ ] Azure AKS (managed K8s)

---

## ⚠️ Platform-Specific Notes

### Windows
- ❌ **No .sh script support** - Use manual PowerShell steps
- ✅ Docker Desktop required (includes Docker Compose)
- ✅ WSL 2 recommended for better performance
- ✅ Git for Windows required
- ⚠️ ExploitDB download takes longer (Git clone in PowerShell)

### macOS
- ❌ **No .sh script support** - Use manual Terminal steps
- ✅ Docker Desktop required (includes Docker Compose)
- ✅ Git usually pre-installed
- ✅ Native Terminal commands (bash/zsh)
- ✅ ExploitDB download via Git clone

### Linux
- ✅ **Automated script available** (`./setup_peer.sh`)
- ✅ Can also use manual steps (same as macOS)
- ✅ Best performance (native Docker)
- ✅ Cloud/VPS automated deployment
- ✅ Supports all architectures (x86_64, ARM)

### Raspberry Pi (Linux ARM)
- ✅ Can use automated script OR manual steps
- ⚠️ Requires 4GB+ RAM (8GB recommended)
- ⚠️ Slower build times (ARM architecture)
- ✅ Excellent for home edge deployment
- ✅ Low power consumption

### Kubernetes
- ✅ Platform-agnostic (Windows/Mac/Linux master nodes)
- ✅ YAML manifest provided
- ⚠️ Requires existing K8s cluster
- ✅ Best for large-scale deployments (10+ nodes)
- ✅ Auto-scaling capabilities

---

## 🚀 Recommended Deployment Methods

**Home Users:**
- **Windows/Mac**: Manual installation (10-15 min)
- **Linux**: Automated script (5 min)
- **Raspberry Pi**: Manual installation for learning

**Small Business:**
- **Cloud VPS**: One-line deployment (5 min)
- **Multi-office**: Deploy on each office's server/PC
- **Budget**: DigitalOcean/Linode/Vultr ($5-6/month per location)

**Enterprise:**
- **Kubernetes**: Managed cluster (EKS/GKE/AKS)
- **Auto-scaling**: Based on threat volume
- **Multi-region**: Deploy pods in different regions
- **High availability**: LoadBalancer + replicas

**Government/Critical Infrastructure:**
- **On-premise**: Linux servers with automated script
- **Air-gapped**: Manual installation with offline ExploitDB
- **Kubernetes**: Self-hosted cluster for full control
- **Compliance**: Docker volumes for audit trails

---

## 📝 Quick Reference Commands

### Windows (PowerShell)
```powershell
# Clone
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security

# Setup
cd AI; git clone https://github.com/offensive-security/exploitdb.git exploitdb; cd ..
copy .env.example server\.env
notepad server\.env

# Deploy
cd server
docker compose up -d --build

# Access
Start-Process "http://localhost:60000"
```

### macOS/Linux (Terminal/Bash)
```bash
# Clone
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security

# Automated (Linux only)
chmod +x setup_peer.sh && ./setup_peer.sh

# Manual (macOS/Linux)
cd AI && git clone https://github.com/offensive-security/exploitdb.git exploitdb && cd ..
cp .env.example server/.env
nano server/.env
cd server && docker compose up -d --build

# Access
open http://localhost:60000  # macOS
xdg-open http://localhost:60000  # Linux
```

### Cloud/VPS (Linux)
```bash
# One-line deployment
curl -fsSL https://raw.githubusercontent.com/yuhisern7/enterprise-security/main/cloud-deploy.sh | bash
```

### Kubernetes (Any Platform)
```bash
kubectl apply -f kubernetes-deployment.yaml
kubectl get svc -n enterprise-security
```

---

## 🎯 Next Steps After Installation

1. **Access Dashboard**: http://localhost:60000 (or your server IP)
2. **Configure VirusTotal**: Add API key in `.env` (optional but recommended)
3. **Connect Peers**: Add peer URLs for P2P mesh network
4. **Monitor Logs**: `docker compose logs -f`
5. **Verify P2P**: Check dashboard for "Connected Peers" count

---

**Need Help?** See README.md for detailed platform-specific instructions.
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
