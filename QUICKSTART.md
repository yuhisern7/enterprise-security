# 🚀 QUICK START GUIDE

## For ALL Platforms (Windows, Linux, macOS)

### 1. Install Docker

**Windows/macOS:**
- Download Docker Desktop: https://www.docker.com/products/docker-desktop
- Install and start Docker Desktop

**Linux:**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Log out and back in
```

### 2. Get the Code

```bash
git clone https://github.com/yourusername/enterprise-security.git
cd enterprise-security/server
```

### 3. Start the System

```bash
./quickstart.sh
```

**That's it!** Dashboard available at: **http://localhost:5000**

---

## Manual Docker Commands

```bash
cd home-security/server

# Start
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down

# Restart
docker compose restart
```

---

## Access from Other Devices

1. Find your server's IP:
   - **Windows**: `ipconfig`
   - **Linux**: `hostname -I`
   - **macOS**: `ipconfig getifaddr en0`

2. Open browser on phone/tablet/other computer:
   - `http://YOUR_IP:5000`
   - Example: `http://192.168.1.100:5000`

---

## File Structure

```
home-security/
├── README.md              # Complete documentation
├── AI/                    # AI engine & dashboard
│   ├── ml_models/         # ML models (auto-generated)
│   ├── pcs_ai.py          # AI security engine
│   └── inspector_ai_monitoring.html
└── server/                # Web server & monitoring
    ├── json/              # Data storage
    ├── quickstart.sh      # One-command start
    ├── docker-compose.yml # Docker config
    └── ... (other files)
```

---

## Troubleshooting

**Port 5000 already in use:**
```bash
# Find and kill process using port 5000
# Linux/macOS:
sudo lsof -i :5000
# Windows:
netstat -ano | findstr :5000
```

**Can't access from other devices:**
```bash
# Allow port 5000 through firewall
# Linux:
sudo ufw allow 5000/tcp
# Windows:
New-NetFirewallRule -DisplayName "Security Dashboard" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

**Docker not starting:**
```bash
# View error logs
docker compose logs

# Rebuild
docker compose down
docker compose build --no-cache
docker compose up -d
```

---

## For Full Documentation

See [README.md](../README.md) for:
- Complete installation instructions
- Detailed troubleshooting
- Security best practices
- API documentation
- Architecture details

---

**Need help?** Open an issue: https://github.com/yourusername/enterprise-security/issues
