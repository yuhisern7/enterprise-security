# AI Training Troubleshooting Commands

## Force AI Training

### Run Training Manually
```bash
docker exec security-relay-server python3 -c "import sys; sys.path.insert(0, '/app/relay'); from ai_retraining import force_retrain_now; force_retrain_now()"
```

### Check Available Arguments
```bash
docker exec security-relay-server python3 ai_retraining.py --help
```

### Check Training Status
```bash
docker exec security-relay-server python3 ai_retraining.py
```

## Verify ExploitDB Loading

### Check Total Exploit Count
```bash
docker exec security-relay-server python3 -c "import json,os; os.chdir('/app/relay'); print(sum(len(json.load(open(f'ai_training_materials/exploitdb_signatures/{f}'))['exploits']) for f in os.listdir('ai_training_materials/exploitdb_signatures') if f.endswith('_exploits.json')))"
```

### Check Files Exist
```bash
docker exec security-relay-server ls -lh /app/relay/ai_training_materials/exploitdb_signatures/
```

### Count JSON Files
```bash
docker exec security-relay-server ls -1 /app/relay/ai_training_materials/exploitdb_signatures/*.json | wc -l
```

### Check Specific Platform Exploits
```bash
docker exec security-relay-server python3 -c "import json; data=json.load(open('/app/relay/ai_training_materials/exploitdb_signatures/windows_exploits.json')); print(f\"Windows: {len(data['exploits'])} exploits\")"
docker exec security-relay-server python3 -c "import json; data=json.load(open('/app/relay/ai_training_materials/exploitdb_signatures/php_exploits.json')); print(f\"PHP: {len(data['exploits'])} exploits\")"
docker exec security-relay-server python3 -c "import json; data=json.load(open('/app/relay/ai_training_materials/exploitdb_signatures/linux_exploits.json')); print(f\"Linux: {len(data['exploits'])} exploits\")"
```

## Container Management

### Restart Container
```bash
cd ~/battle-hardened-ai/relay
docker compose restart
```

### Rebuild Container (No Cache)
```bash
cd ~/battle-hardened-ai/relay
docker compose down
docker compose build --no-cache
docker compose up -d
```

### View Live Logs
```bash
docker compose logs -f relay-server
```

### View Last 50 Log Lines
```bash
docker compose logs relay-server --tail=50
```

### Check Container Status
```bash
docker compose ps
```

## Debugging

### Check for Errors in Logs
```bash
docker compose logs relay-server | grep -E "Error|Traceback|NameError|Failed"
```

### Verify ExploitDB Messages
```bash
docker compose logs relay-server | grep -E "ExploitDB|43,971|Loaded.*exploits"
```

### Check Python File Exists
```bash
docker exec security-relay-server ls -lh /app/relay/ai_retraining.py
```

### Verify Class Names in Code
```bash
docker exec security-relay-server grep -n "class RelayAITrainer" /app/relay/ai_retraining.py
docker exec security-relay-server grep -n "AIRetrainingManager" /app/relay/ai_retraining.py
```

### Check Python Environment
```bash
docker exec security-relay-server python3 --version
docker exec security-relay-server python3 -c "import tensorflow; print(tensorflow.__version__)"
docker exec security-relay-server python3 -c "import sklearn; print(sklearn.__version__)"
```

## API Testing

### Check Training Stats
```bash
curl https://localhost:60002/stats -k
```

### Test Model Distribution API
```bash
curl https://localhost:60002/api/models/latest -k
```

### Check Relay Server Health
```bash
curl https://localhost:60001/health -k
```

## Git Workflow (VPS Deployment)

### Pull Latest Changes
```bash
# Backup crypto keys first
cp relay/crypto_keys/shared_secret.key /tmp/shared_secret.key.backup

# Pull from GitHub
cd ~/battle-hardened-ai
git fetch --all
git reset --hard origin/main

# Restore crypto keys
cp /tmp/shared_secret.key.backup relay/crypto_keys/shared_secret.key

# Rebuild and restart
cd relay
docker compose down
docker compose build --no-cache
docker compose up -d
sleep 5

# Verify
docker compose logs relay-server --tail=20
```

### Check Current Git Commit
```bash
cd ~/battle-hardened-ai
git log --oneline -5
```

## File System Checks

### Clear Python Cache
```bash
docker exec security-relay-server find /app/relay -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
docker exec security-relay-server find /app/relay -name "*.pyc" -delete
```

### Check Disk Usage
```bash
docker exec security-relay-server du -sh /app/relay/ai_training_materials/exploitdb_signatures/
```

### List Training Materials
```bash
docker exec security-relay-server ls -lh /app/relay/ai_training_materials/
```

## Expected Output

When training runs successfully, you should see:

```
✅ Total ExploitDB exploits loaded: 43,971
   • 43,971 ExploitDB platform exploits (windows, linux, php, etc.)
   • 15 attack type categories (SQL injection, XSS, RCE, etc.)
   • 554 global attacks from worldwide subscribers
   • 43,971 learned attack patterns

🧠 Retraining ML models with combined training data...
📦 Copied anomaly_detector.pkl to distribution folder
📦 Copied threat_classifier.pkl to distribution folder
📦 Copied ip_reputation.pkl to distribution folder
📦 Copied feature_scaler.pkl to distribution folder
✅ Relay AI retrain complete! Models trained on 554 attacks
⏰ Next scheduled retrain: 2026-01-07 04:20 UTC
```

## Common Issues

### NameError: 'AIRetrainingManager' is not defined
**Cause:** Container has old cached code  
**Fix:** Rebuild container with `--no-cache`

### No module named 'exploitdb_scraper'
**Cause:** Normal warning - scraper runs on relay server, not inside container  
**Fix:** Ignore - not needed for AI training

### AUTHORIZED_CUSTOMERS is not defined
**Cause:** Old relay_server.py code  
**Fix:** Pull latest from GitHub (commit c2cdbef or later)

### ExploitDB exploits: 0
**Cause:** JSON files not loaded or missing  
**Fix:** Check file existence and run force_retrain_now()
