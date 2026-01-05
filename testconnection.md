# HMAC + Relay Connection Test Guide

This document shows how to verify that:

- Your **Windows customer node** is generating HMAC-signed messages.
- Your **relay server on the VPS** is loading the shared secret and verifying HMAC.

> Replace all occurrences of `<YOUR_VPS_IP>` with your actual relay VPS IP when you run the commands.

---

## 1. Windows: Verify Client HMAC Generation

These commands are run **on your Windows machine** (where Docker Desktop is running the customer container).

### 1.1. Preconditions

- You have built and started the Windows stack from the `server` folder:
  ```powershell
  cd C:\Users\<YourUser>\workspace\battle-hardened-ai\server
  docker compose -f docker-compose.windows.yml up -d --build
  ```
- The container name is `battle-hardened-ai` (as defined in `server/docker-compose.windows.yml`).

### 1.2. Generate a Test Signed Message (HMAC on Windows)

From PowerShell, in the `server` directory:

```powershell
cd C:\Users\<YourUser>\workspace\battle-hardened-ai\server

docker exec battle-hardened-ai python -c "from AI.crypto_security import get_message_security; import json; s=get_message_security(); m=s.sign_message({'attack_type':'TEST_HMAC','src_ip':'1.2.3.4'}); print(json.dumps(m, indent=2)); print('\nHas HMAC:', 'hmac' in m)"
```

**Expected result:**

- The printed JSON includes a field named `"hmac"` with a long hexadecimal value.
- The last line says:
  ```
  Has HMAC: True
  ```

If both are true, the Windows node is **correctly generating HMAC signatures** using the shared secret inside the container.

---

## 2. Linux (VPS): Verify Relay HMAC Verification

These commands are run **on your VPS** where the relay server is deployed.

### 2.1. SSH into the VPS

From your Windows machine (PowerShell or any terminal that has SSH):

```powershell
ssh root@<YOUR_VPS_IP>
```

Once logged in, go to the relay folder:

```bash
cd ~/battle-hardened-ai/relay
```

### 2.2. Confirm the Relay Loaded the Shared Secret and Enabled HMAC

Still on the VPS:

```bash
docker compose logs relay-server | grep -E "HMAC|Shared key HMAC"
```

**Expected log lines include:**

- `✅ Loaded shared HMAC secret for all customers`
- `🔐 Shared key HMAC verification ENABLED` (or similar wording)

If you see these, the relay has successfully loaded the same `shared_secret.key` and is **enforcing HMAC verification** on incoming messages.

### 2.3. Confirm the Key File Exists Inside the Relay Container

Optional, but useful for debugging.

On the VPS:

```bash
docker exec security-relay-server ls -l /app/ai_training_materials/crypto_keys/shared_secret.key
```

**Expected result:**

- A single file `shared_secret.key` with non-zero size is listed.

---

## 3. Connectivity + HMAC End-to-End Check

### 3.1. Test TCP Connectivity from Windows to Relay

From Windows PowerShell:

```powershell
Test-NetConnection -ComputerName <YOUR_VPS_IP> -Port 60001
```

**Expected result:**

- `TcpTestSucceeded : True`

This confirms the Windows node can reach the relay’s WebSocket port (60001).

### 3.2. Verify Relay Logs While the Windows Node is Running

With the Windows stack running (from step 1.1), tail the relay logs on the VPS:

```bash
cd ~/battle-hardened-ai/relay

docker compose logs -f relay-server
```

**What you’re looking for:**

- The earlier HMAC lines (loaded shared secret, HMAC verification enabled).
- Connection messages from a peer (your Windows node) joining.

If:

1. Windows test message shows `Has HMAC: True`, **and**
2. Relay logs show the shared secret is loaded and HMAC verification is enabled, **and**
3. Connectivity test to `<YOUR_VPS_IP>:60001` succeeds

then HMAC is working end-to-end between your Windows node and the relay server.
