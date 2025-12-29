#!/usr/bin/env python3
"""
WebSocket Relay Server for Enterprise Security Mesh
Relays threat intelligence between unlimited security containers worldwide
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Set
import websockets
from websockets.server import WebSocketServerProtocol

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Connected clients (all security containers worldwide)
connected_clients: Set[WebSocketServerProtocol] = set()

# Statistics
stats = {
    "total_connections": 0,
    "active_connections": 0,
    "messages_relayed": 0,
    "threats_shared": 0,
    "start_time": datetime.utcnow().isoformat()
}


async def register_client(websocket: WebSocketServerProtocol):
    """Register a new security container"""
    connected_clients.add(websocket)
    stats["total_connections"] += 1
    stats["active_connections"] = len(connected_clients)
    
    client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    logger.info(f"✅ New container connected: {client_info} (Total: {len(connected_clients)})")


async def unregister_client(websocket: WebSocketServerProtocol):
    """Unregister a disconnected security container"""
    connected_clients.discard(websocket)
    stats["active_connections"] = len(connected_clients)
    
    client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    logger.info(f"❌ Container disconnected: {client_info} (Total: {len(connected_clients)})")


async def broadcast_message(message: dict, sender: WebSocketServerProtocol):
    """Broadcast threat intelligence to all containers except sender"""
    if not connected_clients:
        return
    
    # Add relay metadata
    message["relayed_at"] = datetime.utcnow().isoformat()
    message["relay_server"] = os.getenv("RELAY_NAME", "central-relay")
    
    message_str = json.dumps(message)
    stats["messages_relayed"] += 1
    
    # Count as threat if it contains threat data
    if "threat_type" in message or "threats" in message:
        stats["threats_shared"] += 1
    
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
    """Periodically log server statistics"""
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        logger.info(f"📊 Stats - Active: {stats['active_connections']}, "
                   f"Total: {stats['total_connections']}, "
                   f"Messages: {stats['messages_relayed']}, "
                   f"Threats: {stats['threats_shared']}")


async def main():
    """Start the relay server"""
    host = os.getenv("RELAY_HOST", "0.0.0.0")
    port = int(os.getenv("RELAY_PORT", "60001"))
    
    logger.info(f"🚀 Starting WebSocket Relay Server on {host}:{port}")
    logger.info(f"🌍 Ready to relay threats between unlimited containers worldwide")
    
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
