#!/usr/bin/env python3
"""
Relay Server Multi-Service Launcher
Starts both WebSocket relay and Model Distribution API in parallel
"""

import os
import sys
import subprocess
import threading
import logging
import signal
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Process tracking
processes = []
shutdown_flag = threading.Event()


def run_service(name: str, script: str):
    """Run a service in a subprocess"""
    try:
        logger.info(f"🚀 Starting {name}...")
        process = subprocess.Popen(
            [sys.executable, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        processes.append((name, process))
        
        # Stream output (with None check)
        if process.stdout:
            for line in process.stdout:
                if line.strip():
                    logger.info(f"[{name}] {line.strip()}")
        
        process.wait()
        logger.warning(f"⚠️ {name} exited with code {process.returncode}")
        
    except Exception as e:
        logger.error(f"❌ {name} failed: {e}")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info("🛑 Shutdown signal received, stopping services...")
    shutdown_flag.set()
    
    # Kill all processes
    for name, process in processes:
        logger.info(f"🛑 Stopping {name}...")
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    
    sys.exit(0)


def main():
    """Start all relay services"""
    logger.info("================================")
    logger.info("🌍 Security Mesh Relay Server")
    logger.info("================================")
    logger.info("")
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start services in threads
    services = [
        ("WebSocket Relay", "relay_server.py"),
        ("Model Distribution API", "training_sync_api.py"),
    ]
    
    threads = []
    for name, script in services:
        thread = threading.Thread(target=run_service, args=(name, script), daemon=True)
        thread.start()
        threads.append(thread)
        time.sleep(1)  # Stagger startup
    
    logger.info("")
    logger.info("✅ All services started!")
    logger.info("   • WebSocket Relay: wss://0.0.0.0:60001")
    logger.info("   • Model Distribution API: https://0.0.0.0:60002")
    logger.info("")
    logger.info("Press Ctrl+C to stop all services")
    logger.info("")
    
    # Wait for threads
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)


if __name__ == "__main__":
    main()
