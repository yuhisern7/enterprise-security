#!/usr/bin/env python3
"""
WebSocket Relay Server for Enterprise Security Mesh
Relays threat intelligence between unlimited security containers worldwide

FILE-BASED STORAGE (No Database Required):
- Stores attack signatures DIRECTLY to ai_training_materials/ai_signatures/learned_signatures.json
- Stores complete attacks to ai_training_materials/global_attacks.json
- AI reads from these files for training (simple, fast, no credentials needed)
- NO exploit code stored (deleted immediately at source)
- Privacy-compliant: Anonymous attack patterns only
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Set, Dict, Any
import websockets
from websockets.server import WebSocketServerProtocol

# Configure logging FIRST (before any log messages)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import cryptographic security (CRITICAL: Message verification)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Check if crypto is enabled from environment variable
CRYPTO_ENABLED = os.getenv('CRYPTO_ENABLED', 'true').lower() == 'true'

# Simple shared key (all customers use same key)
SHARED_SECRET = None

def load_shared_secret():
    """Load shared HMAC secret (same for all customers)"""
    global SHARED_SECRET
    try:
        secret_file = "crypto_keys/shared_secret.key"
        if os.path.exists(secret_file):
            with open(secret_file, 'rb') as f:
                SHARED_SECRET = f.read()
            logger.info("✅ Loaded shared HMAC secret for all customers")
        else:
            logger.warning(f"⚠️  Shared secret not found at {secret_file}")
    except Exception as e:
        logger.error(f"❌ Failed to load shared secret: {e}")

if CRYPTO_ENABLED:
    try:
        import hmac
        import hashlib
        load_shared_secret()
        if SHARED_SECRET:
            logger.info("🔐 Shared key HMAC verification ENABLED")
        else:
            CRYPTO_ENABLED = False
            logger.warning("⚠️  No shared secret - crypto disabled")
    except Exception as e:
        CRYPTO_ENABLED = False
        logger.warning(f"⚠️  Crypto verification DISABLED (import failed): {e}")
else:
    logger.info("ℹ️  Crypto verification DISABLED via environment variable")

def verify_customer_message(message: Dict[str, Any]) -> tuple[bool, str]:
    """
    Verify message HMAC using shared secret
    
    Returns:
        (is_valid, reason)
    """
    try:
        # Check required fields
        if 'hmac' not in message:
            return False, "Missing HMAC"
        
        # Verify HMAC using shared secret (same for all customers)
        if not SHARED_SECRET:
            return False, "No shared secret loaded"
        
        msg_copy = message.copy()
        expected_hmac = msg_copy.pop('hmac')
        msg_copy.pop('signature', None)  # Remove signature if present
        
        # Create canonical JSON (same format as customer signing)
        canonical_json = json.dumps(msg_copy, sort_keys=True, separators=(',', ':'))
        message_bytes = canonical_json.encode('utf-8')
        
        calculated_hmac = hmac.new(
            SHARED_SECRET,
            message_bytes,
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(calculated_hmac, expected_hmac):
            return False, "HMAC validation failed"
        
        return True, "OK"
        
    except Exception as e:
        logger.error(f"[CRYPTO] Verification error: {e}")
        return False, f"Verification failed: {e}"


# Import file-based signature sync (no database needed)
try:
    from signature_sync import handle_signature_upload, sync_service
    SIGNATURE_SYNC_ENABLED = True
    logger.info("✅ File-based signature storage enabled")
except Exception as e:
    SIGNATURE_SYNC_ENABLED = False
    logger.warning(f"⚠️  Signature sync not available: {e}")

# Connected clients (all security containers worldwide)
connected_clients: Set[WebSocketServerProtocol] = set()

# Peer authentication tracking
peer_public_keys: Dict[str, str] = {}  # peer_id -> public_key_pem
authenticated_peers: Dict[WebSocketServerProtocol, str] = {}  # websocket -> peer_id

# Centralized Attack Database (stored in ai_training_materials)
ATTACK_DB_PATH = "ai_training_materials/global_attacks.json"
ATTACK_STATS_PATH = "ai_training_materials/attack_statistics.json"

# Statistics
stats = {
    "total_connections": 0,
    "active_connections": 0,
    "messages_relayed": 0,
    "threats_shared": 0,
    "attacks_logged": 0,
    "messages_rejected": 0,  # NEW: Track rejected messages
    "authentication_failures": 0,  # NEW: Track auth failures
    "start_time": datetime.utcnow().isoformat()
}


async def register_client(websocket: WebSocketServerProtocol):
    """Register a new security container"""
    connected_clients.add(websocket)
    stats["total_connections"] += 1
    stats["active_connections"] = len(connected_clients)
    
    client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    logger.info(f"✅ New container connected: {client_info} (Total: {len(connected_clients)})")
    
    # Notify ALL other existing clients that a new peer joined
    if len(connected_clients) > 1:  # Only if there are other clients
        peer_count = len(connected_clients) - 1  # Other peers
        notification = {
            "type": "peer_joined",
            "active_peers": peer_count,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Broadcast to all OTHER clients (not the one that just joined)
        disconnected = set()
        for client in connected_clients:
            if client != websocket:  # Don't send to the new client
                try:
                    await client.send(json.dumps(notification))
                except Exception as e:
                    logger.debug(f"Failed to notify client of peer join: {e}")
                    disconnected.add(client)
        
        # Clean up any disconnected clients
        for client in disconnected:
            connected_clients.discard(client)
            stats["active_connections"] = len(connected_clients)


async def unregister_client(websocket: WebSocketServerProtocol):
    """Unregister a disconnected security container"""
    connected_clients.discard(websocket)
    
    # Remove from authenticated peers
    if websocket in authenticated_peers:
        peer_id = authenticated_peers.pop(websocket)
        logger.debug(f"Removed authenticated peer: {peer_id}")
    
    stats["active_connections"] = len(connected_clients)
    
    client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    logger.info(f"❌ Container disconnected: {client_info} (Total: {len(connected_clients)})")
    
    # Notify ALL remaining clients that a peer left
    if connected_clients:  # Only if there are remaining clients
        peer_count = len(connected_clients) - 1  # Other peers
        notification = {
            "type": "peer_left",
            "active_peers": peer_count,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Broadcast to all remaining clients
        disconnected = set()
        for client in connected_clients:
            try:
                await client.send(json.dumps(notification))
            except Exception as e:
                logger.debug(f"Failed to notify client of peer leaving: {e}")
                disconnected.add(client)
        
        # Clean up any disconnected clients
        for client in disconnected:
            connected_clients.discard(client)
            stats["active_connections"] = len(connected_clients)


async def log_attack_to_database(attack_data: Dict[str, Any]):
    """
    Log attack to centralized database for global AI training.
    All attacks from all containers stored here permanently.
    """
    try:
        # Load existing attacks
        attacks = []
        if os.path.exists(ATTACK_DB_PATH):
            with open(ATTACK_DB_PATH, 'r') as f:
                attacks = json.load(f)
        
        # Add new attack
        attacks.append({
            **attack_data,
            "logged_at_relay": datetime.utcnow().isoformat(),
            "relay_server": os.getenv("RELAY_NAME", "central-relay")
        })
        
        # Save to database
        with open(ATTACK_DB_PATH, 'w') as f:
            json.dump(attacks, f, indent=2)
        
        stats["attacks_logged"] += 1
        logger.debug(f"📝 Attack logged to database (Total: {stats['attacks_logged']})")
        
    except Exception as e:
        logger.error(f"Failed to log attack to database: {e}")


async def update_attack_statistics():
    """Update global attack statistics for analytics"""
    try:
        if not os.path.exists(ATTACK_DB_PATH):
            return
        
        with open(ATTACK_DB_PATH, 'r') as f:
            attacks = json.load(f)
        
        # Calculate statistics
        attack_types = {}
        countries = {}
        severities = {}
        
        for attack in attacks:
            # Attack types (prefer canonical attack_type, but fall back to threat_type)
            attack_type = attack.get('attack_type') or attack.get('threat_type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Countries
            country = attack.get('geolocation', {}).get('country', 'unknown')
            countries[country] = countries.get(country, 0) + 1
            
            # Severities
            severity = attack.get('level', 'unknown')
            severities[severity] = severities.get(severity, 0) + 1
        
        statistics = {
            "total_attacks": len(attacks),
            "last_updated": datetime.utcnow().isoformat(),
            "attack_types": attack_types,
            "countries": countries,
            "severities": severities,
            "relay_server": os.getenv("RELAY_NAME", "central-relay")
        }
        
        with open(ATTACK_STATS_PATH, 'w') as f:
            json.dump(statistics, f, indent=2)
        
        logger.info(f"📊 Statistics updated: {len(attacks)} total attacks logged")
        
    except Exception as e:
        logger.error(f"Failed to update statistics: {e}")


async def broadcast_message(message: dict, sender: WebSocketServerProtocol):
    """Broadcast threat intelligence to all containers except sender"""
    if not connected_clients:
        return
    
    # Add relay metadata
    message["relayed_at"] = datetime.utcnow().isoformat()
    message["relay_server"] = os.getenv("RELAY_NAME", "central-relay")
    
    message_str = json.dumps(message)
    stats["messages_relayed"] += 1
    
    # Count as threat if it contains threat data (check for both field names)
    if "threat_type" in message or "attack_type" in message or "threats" in message:
        stats["threats_shared"] += 1
        
        # Store signature to FILE (no database)
        if "signature" in message and SIGNATURE_SYNC_ENABLED:
            try:
                source_ip = sender.remote_address[0] if sender.remote_address else None
                result = await handle_signature_upload(message["signature"], source_ip)
                logger.info(f"✅ Signature stored to file: {result.get('pattern_hash', 'N/A')[:8]}...")
            except Exception as e:
                logger.error(f"Failed to store signature: {e}")
        
        # Store complete attack to global_attacks.json
        if SIGNATURE_SYNC_ENABLED:
            try:
                sync_service.store_global_attack(message)
            except Exception as e:
                logger.error(f"Failed to store attack: {e}")
    
    # Broadcast to all clients except sender
    disconnected = set()
    for client in connected_clients:
        if client != sender:
            try:
                await client.send(message_str)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                logger.error(f"Error sending to client: {e}")
                disconnected.add(client)
    
    # Clean up disconnected clients
    for client in disconnected:
        await unregister_client(client)
    
    logger.info(f"📡 Broadcast to {len(connected_clients) - 1} containers: {message.get('type', 'unknown')}")


async def handle_client(websocket: WebSocketServerProtocol):
    """Handle messages from a security container"""
    await register_client(websocket)
    
    try:
        # Send welcome message with server stats
        welcome = {
            "type": "welcome",
            "relay_server": os.getenv("RELAY_NAME", "central-relay"),
            "active_peers": len(connected_clients) - 1,
            "total_threats_shared": stats["threats_shared"],
            "server_uptime": stats["start_time"]
        }
        await websocket.send(json.dumps(welcome))
        
        # Listen for messages
        async for message in websocket:
            try:
                data = json.loads(message)
                
                # CRYPTOGRAPHIC VERIFICATION (if enabled)
                if CRYPTO_ENABLED and data.get("type") not in ["heartbeat", "stats"]:
                    is_valid, reason = verify_customer_message(data)
                    
                    if not is_valid:
                        stats["messages_rejected"] += 1
                        stats["authentication_failures"] += 1
                        logger.warning(f"🚫 REJECTED message from {websocket.remote_address[0]}: {reason}")
                        
                        # Send rejection notification
                        await websocket.send(json.dumps({
                            "type": "error",
                            "error": "Message verification failed",
                            "reason": reason
                        }))
                        continue  # Skip processing this message
                    
                    # Track authenticated peer
                    customer_id = data.get("customer_id")
                    if customer_id:
                        authenticated_peers[websocket] = customer_id
                        company_name = AUTHORIZED_CUSTOMERS[customer_id]['company_name']
                        logger.debug(f"✅ Verified message from: {company_name} ({customer_id})")
                
                # Handle different message types
                if data.get("type") == "heartbeat":
                    # Respond to heartbeat
                    await websocket.send(json.dumps({"type": "heartbeat_ack"}))
                    continue
                
                elif data.get("type") == "stats":
                    # Send server statistics
                    await websocket.send(json.dumps({
                        "type": "stats_response",
                        "stats": stats
                    }))
                    continue
                
                # Broadcast threat intelligence to all peers
                await broadcast_message(data, websocket)
                
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from {websocket.remote_address}")
            except Exception as e:
                logger.error(f"Error processing message: {e}")
    
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        logger.error(f"Client handler error: {e}")
    finally:
        await unregister_client(websocket)


async def stats_reporter():
    """Periodically log server statistics and update attack analytics"""
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        logger.info(f"📊 Stats - Active: {stats['active_connections']}, "
                   f"Total: {stats['total_connections']}, "
                   f"Messages: {stats['messages_relayed']}, "
                   f"Threats: {stats['threats_shared']}, "
                   f"Attacks Logged: {stats['attacks_logged']}")
        
        # Update global attack statistics
        await update_attack_statistics()


async def main():
    """Start the relay server"""
    host = os.getenv("RELAY_HOST", "0.0.0.0")
    port = int(os.getenv("RELAY_PORT", "60001"))
    
    logger.info(f"🚀 Starting WebSocket Relay Server on {host}:{port}")
    logger.info(f"🌍 Ready to relay threats between unlimited containers worldwide")
    logger.info(f"📝 Centralized Attack Database: {ATTACK_DB_PATH}")
    logger.info(f"📊 Attack Statistics: {ATTACK_STATS_PATH}")
    
    # Create ai_training_materials directory if not exists
    os.makedirs("ai_training_materials", exist_ok=True)
    
    # Start stats reporter
    asyncio.create_task(stats_reporter())
    
    # Start WebSocket server
    async with websockets.serve(handle_client, host, port, ping_interval=30, ping_timeout=10):
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Relay server stopped")
