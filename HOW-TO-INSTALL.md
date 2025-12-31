# 🚀 Battle-Hardened AI - Installation Guide

**Super Simple Setup for Windows & Linux Users**

---

## 📋 Before You Start

### What You Need:
- ✅ **Docker** - The container platform (like a virtual machine but lighter)
- ✅ **Git** - Tool to download the code
- ⏱️ **10-15 minutes** - Total installation time

### Choose Your Path:
- 💎 **Premium Mode** ($25/month) - EASIEST! Zero setup, no downloads
- 🆓 **Free Mode** - Works great but requires ExploitDB download (824 MB)

---

## 🪟 WINDOWS INSTALLATION

### Step 1: Install Docker Desktop

1. **Download Docker Desktop:**
   - Visit: https://www.docker.com/products/docker-desktop
   - Click **Download for Windows**
   - Run the installer (accept all defaults)

2. **Start Docker Desktop:**
   - Search for "Docker Desktop" in Start Menu
   - Click to open
   - Wait for "Docker Desktop is running" in system tray
   - ✅ You're ready when you see the whale icon in your taskbar

3. **Verify Installation:**
   ```cmd
   docker --version
   ```
   Should show: `Docker version 24.x.x` or higher

### Step 2: Install Git

1. **Download Git:**
   - Visit: https://git-scm.com/download/win
   - Download automatically starts
   - Run installer (use all default settings)

2. **Verify Installation:**
   ```cmd
   git --version
   ```
   Should show: `git version 2.x.x` or higher

### Step 3: Download Battle-Hardened AI

1. **Open Command Prompt or PowerShell:**
   - Press `Win + R`
   - Type: `cmd` or `powershell`
   - Press Enter

2. **Navigate to your desired folder:**
   ```cmd
   cd C:\Users\YourName\Documents
   ```

3. **Download the code:**
   ```cmd
   git clone https://github.com/yuhisern7/enterprise-security.git
   cd enterprise-security
   ```

### Step 4: Configure Settings

1. **Copy the configuration template:**
   ```cmd
   cd server
   copy .env.windows .env
   ```

2. **Edit the configuration:**
   ```cmd
   notepad .env
   ```

3. **IMPORTANT - Update these settings:**

   **Find your network range:**
   ```cmd
   ipconfig
   ```
   Look for "IPv4 Address" (e.g., `192.168.1.105`)
   
   **In the .env file, change:**
   ```bash
   # Example: If your IP is 192.168.1.105
   NETWORK_RANGE=192.168.1.0/24
   
   # Example: If your IP is 192.168.0.105  
   NETWORK_RANGE=192.168.0.0/24
   
   # Example: If your IP is 10.0.0.105
   NETWORK_RANGE=10.0.0.0/24
   ```

   **For Premium Mode ($25/month) - ADD THIS:**
   ```bash
   RELAY_ENABLED=true
   RELAY_URL=ws://YOUR-RELAY-SERVER-IP:60001
   ```
   *(Replace `YOUR-RELAY-SERVER-IP` with the IP provided when you subscribe)*

   **Save and close** the file

### Step 5: Start the System

1. **Make sure you're in the server directory:**
   ```cmd
   cd C:\Users\YourName\Documents\enterprise-security\server
   ```

2. **Start the container:**
   ```cmd
   docker compose up -d --build
   ```

3. **Wait 2-3 minutes** for everything to start

4. **Check if it's running:**
   ```cmd
   docker ps
   ```
   You should see a container named `enterprise-security-ai`

### Step 6: Open Firewall Ports

**Option 1: PowerShell (Easy - Recommended)**

1. **Right-click Start Menu → Windows PowerShell (Admin)**

2. **Run these commands:**
   ```powershell
   New-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" -Direction Inbound -Protocol TCP -LocalPort 60000 -Action Allow
   
   New-NetFirewallRule -DisplayName "Battle-Hardened AI P2P" -Direction Inbound -Protocol TCP -LocalPort 60001 -Action Allow
   ```

**Option 2: Windows Firewall GUI**

1. Press `Win + R`, type `wf.msc`, press Enter
2. Click **Inbound Rules** → **New Rule**
3. Rule Type: **Port** → Next
4. Protocol: **TCP**, Port: **60000** → Next
5. Action: **Allow** → Next
6. Check all profiles → Next
7. Name: **Battle-Hardened AI Dashboard** → Finish
8. Repeat for port **60001**

### Step 7: Access Your Dashboard

1. **Open your browser**
2. **Go to:** http://localhost:60000
3. **You should see the military-grade dashboard!** 🎉

---

## 🐧 LINUX INSTALLATION

### Step 1: Install Docker

**Ubuntu/Debian:**
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to docker group (avoid using sudo)
sudo usermod -aG docker $USER

# Log out and log back in for changes to take effect
```

**CentOS/RHEL:**
```bash
sudo yum install -y docker docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Log out and log back in
```

**Verify Installation:**
```bash
docker --version
docker compose version
```

### Step 2: Install Git

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y git
```

**CentOS/RHEL:**
```bash
sudo yum install -y git
```

**Verify Installation:**
```bash
git --version
```

### Step 3: Download Battle-Hardened AI

```bash
cd ~
git clone https://github.com/yuhisern7/enterprise-security.git
cd enterprise-security
```

### Step 4: Configure Settings

1. **Copy the configuration template:**
   ```bash
   cd server
   cp .env.linux .env
   ```

2. **Edit the configuration:**
   ```bash
   nano .env
   ```
   *(Or use `vim`, `vi`, or any text editor you prefer)*

3. **IMPORTANT - Update these settings:**

   **Find your network range:**
   ```bash
   hostname -I
   # Or: ip addr show
   ```
   Look for your IP address (e.g., `192.168.1.105`)
   
   **In the .env file, change:**
   ```bash
   # Example: If your IP is 192.168.1.105
   NETWORK_RANGE=192.168.1.0/24
   
   # Example: If your IP is 192.168.0.105  
   NETWORK_RANGE=192.168.0.0/24
   
   # Example: If your IP is 10.0.0.105
   NETWORK_RANGE=10.0.0.0/24
   ```

   **For Premium Mode ($25/month) - ADD THIS:**
   ```bash
   RELAY_ENABLED=true
   RELAY_URL=ws://YOUR-RELAY-SERVER-IP:60001
   ```
   *(Replace `YOUR-RELAY-SERVER-IP` with the IP provided when you subscribe)*

   **Save:** Press `Ctrl+O`, then Enter  
   **Exit:** Press `Ctrl+X`

### Step 5: Start the System

**Automated Installation (Recommended):**
```bash
bash installation/install.sh
```

**Manual Installation:**
```bash
# Make sure you're in the server directory
cd ~/enterprise-security/server

# Start the container
docker compose up -d --build

# Wait 2-3 minutes for everything to start
```

### Step 6: Configure Firewall

**Ubuntu/Debian (UFW):**
```bash
# Allow dashboard port
sudo ufw allow 60000/tcp comment 'Battle-Hardened AI Dashboard'

# Allow P2P port
sudo ufw allow 60001/tcp comment 'Battle-Hardened AI P2P'

# Enable firewall (if not already enabled)
sudo ufw enable

# Check status
sudo ufw status
```

**CentOS/RHEL (Firewalld):**
```bash
# Allow dashboard port
sudo firewall-cmd --permanent --add-port=60000/tcp

# Allow P2P port  
sudo firewall-cmd --permanent --add-port=60001/tcp

# Reload firewall
sudo firewall-cmd --reload

# Check status
sudo firewall-cmd --list-ports
```

### Step 7: Access Your Dashboard

1. **Find your server IP:**
   ```bash
   hostname -I
   # Example output: 192.168.1.100
   ```

2. **Open your browser**
3. **Go to:** http://YOUR-SERVER-IP:60000
   - Example: http://192.168.1.100:60000
   - From same machine: http://localhost:60000

4. **You should see the military-grade dashboard!** 🎉

---

## 🔧 Verification & Testing

### Check if Container is Running

**Windows:**
```cmd
docker ps
```

**Linux:**
```bash
docker ps
```

You should see:
```
CONTAINER ID   IMAGE                     STATUS
xxxxx          enterprise-security-ai    Up 2 minutes (healthy)
```

### View Logs

**Windows:**
```cmd
docker logs enterprise-security-ai
```

**Linux:**
```bash
docker logs enterprise-security-ai
```

You should see:
```
[INFO] System started successfully
[INFO] Dashboard available at http://0.0.0.0:60000
[INFO] AI monitoring active
```

### Test Dashboard Access

1. Open browser
2. Go to: http://localhost:60000
3. You should see:
   - ✅ Network statistics
   - ✅ Threat detection metrics
   - ✅ Connected devices
   - ✅ Real-time monitoring

---

## 🆘 Troubleshooting

### Windows Issues

**Problem: "Docker daemon is not running"**
```cmd
# Solution: Start Docker Desktop
# Search for "Docker Desktop" in Start Menu and open it
# Wait for whale icon to appear in system tray
```

**Problem: "docker: command not found"**
```cmd
# Solution: Restart Command Prompt after installing Docker
# Or reinstall Docker Desktop
```

**Problem: Dashboard shows "Connection refused"**
```cmd
# Solution: Check firewall rules
# Run PowerShell as Admin:
Get-NetFirewallRule -DisplayName "*Battle*" | Format-Table DisplayName, Enabled
# If not showing or Enabled=False, re-add firewall rules (Step 6)
```

**Problem: Container won't start**
```cmd
# Check logs
docker logs enterprise-security-ai

# Try clean restart
docker compose down
docker compose up -d --build
```

### Linux Issues

**Problem: "permission denied" when running docker**
```bash
# Solution: Add your user to docker group
sudo usermod -aG docker $USER

# Log out and log back in
```

**Problem: "Cannot connect to Docker daemon"**
```bash
# Solution: Start Docker service
sudo systemctl start docker

# Enable on boot
sudo systemctl enable docker
```

**Problem: Port already in use**
```bash
# Find what's using port 60000
sudo lsof -i :60000

# Kill the process or change port in .env file
```

**Problem: Firewall blocking connections**
```bash
# Check UFW status
sudo ufw status

# Make sure ports 60000 and 60001 are allowed
sudo ufw allow 60000/tcp
sudo ufw allow 60001/tcp
```

---

## 📝 Post-Installation

### Access Dashboard from Other Devices

**Find your computer's IP address:**

**Windows:**
```cmd
ipconfig
```
Look for "IPv4 Address"

**Linux:**
```bash
hostname -I
```

**Then on any device on the same network:**
- Open browser
- Go to: http://YOUR-COMPUTER-IP:60000
- Example: http://192.168.1.100:60000

### Update Your Installation

See **HOW-TO-UPDATE.txt** for update instructions.

### Stop the System

**Windows:**
```cmd
cd C:\Users\YourName\Documents\enterprise-security\server
docker compose down
```

**Linux:**
```bash
cd ~/enterprise-security/server
docker compose down
```

### Restart the System

**Windows:**
```cmd
cd C:\Users\YourName\Documents\enterprise-security\server
docker compose restart
```

**Linux:**
```bash
cd ~/enterprise-security/server
docker compose restart
```

---

## 💎 Premium vs Free Mode

### Premium Mode ($25/month) - RECOMMENDED
✅ **Zero setup** - No ExploitDB download  
✅ **280 KB download** - Only pre-trained AI models  
✅ **Global threat intelligence** - Learn from 100+ countries  
✅ **Auto-updates** - AI retrains every 6 hours  
✅ **Priority support** - Email & WhatsApp  

**Contact for Premium:**
- 📧 Email: yuhisern@protonmail.com
- 📱 WhatsApp: +60172791717

### Free Mode
⚠️ **824 MB download** - ExploitDB database required  
⚠️ **Local only** - No global threat intelligence  
⚠️ **Manual updates** - You manage AI training  
✅ **Fully functional** - All features work  

---

## 🎉 Success!

If you see the dashboard, **congratulations!** You now have:

- ✅ **Enterprise-grade network security** ($675K/year value)
- ✅ **AI-powered threat detection** (50K+ attack patterns)
- ✅ **Real-time monitoring** for all network devices
- ✅ **Compliance reporting** (PCI-DSS, HIPAA, GDPR, SOC 2)
- ✅ **Network performance metrics** with AI anomaly detection
- ✅ **Military-grade dashboard** for visualization

**What's next?**
1. Check your dashboard at http://localhost:60000
2. Monitor connected devices
3. Watch threats being blocked in real-time
4. Generate compliance reports
5. Enjoy enterprise security for $300/year (vs $675K/year)!

---

**Need Help?**
- 📧 Email: yuhisern@protonmail.com
- 📱 WhatsApp: +60172791717
- 💻 GitHub Issues: https://github.com/yuhisern7/enterprise-security/issues

**Built with ⚔️ by Battle-Hardened AI**  
*When your network deserves military-grade protection*
