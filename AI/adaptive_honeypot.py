#!/usr/bin/env python3
"""
Adaptive Honeypot - Single honeypot that morphs into different services
Can impersonate FTP, SSH, HTTP, Telnet, MySQL, etc. by changing port and signature
"""

import socket
import threading
import logging
import time
import json
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AdaptiveHoneypot:
    """
    Single honeypot that can impersonate multiple services
    Changes behavior based on configured persona
    """
    
    def __init__(self):
        self.running = False
        self.server_thread = None
        self.server_socket = None
        self.attack_log = []
        
        # Current configuration
        self.enabled = False
        self.current_persona = "http_admin"
        self.current_port = 8080
        self.custom_banner = None
        
        # Service personas with templates
        self.personas = {
            "http_admin": {
                "name": "HTTP Admin Panel",
                "default_port": 8080,
                "protocol": "TCP",
                "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><title>Admin Login</title><body><h1>Admin Panel Login</h1></body></html>",
                "keywords": ["admin", "login", "password"]
            },
            "ftp": {
                "name": "FTP Server",
                "default_port": 2121,
                "protocol": "TCP",
                "banner": "220 ProFTPD 1.3.5 Server (Welcome) [::ffff:0.0.0.0]\r\n",
                "keywords": ["USER", "PASS", "LIST", "RETR"]
            },
            "ssh": {
                "name": "SSH Server",
                "default_port": 2222,
                "protocol": "TCP",
                "banner": "SSH-2.0-OpenSSH_7.4\r\n",
                "keywords": ["ssh", "publickey", "password"]
            },
            "telnet": {
                "name": "Telnet Server",
                "default_port": 2323,
                "protocol": "TCP",
                "banner": "Welcome to Telnet Server\r\nLogin: ",
                "keywords": ["login", "password", "admin"]
            },
            "mysql": {
                "name": "MySQL Server",
                "default_port": 3306,
                "protocol": "TCP",
                "banner": b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x32\x39\x00",  # MySQL handshake
                "keywords": ["mysql", "database", "root"]
            },
            "rdp": {
                "name": "Windows RDP",
                "default_port": 3389,
                "protocol": "TCP",
                "banner": b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02",  # RDP connection response
                "keywords": ["rdp", "windows", "remote"]
            },
            "smtp": {
                "name": "SMTP Mail Server",
                "default_port": 2525,
                "protocol": "TCP",
                "banner": "220 mail.example.com ESMTP Postfix\r\n",
                "keywords": ["MAIL", "RCPT", "DATA", "HELO"]
            },
            "http_wordpress": {
                "name": "WordPress Site",
                "default_port": 8081,
                "protocol": "TCP",
                "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: PHP/7.4\r\n\r\n<html><title>WordPress</title></html>",
                "keywords": ["wp-admin", "wp-login", "xmlrpc"]
            },
            "http_phpmyadmin": {
                "name": "phpMyAdmin",
                "default_port": 8082,
                "protocol": "TCP",
                "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html><title>phpMyAdmin</title></html>",
                "keywords": ["phpmyadmin", "database", "sql"]
            },
            "vnc": {
                "name": "VNC Remote Desktop",
                "default_port": 5900,
                "protocol": "TCP",
                "banner": "RFB 003.008\n",
                "keywords": ["vnc", "remote", "desktop"]
            },
            "docker_api": {
                "name": "Docker API",
                "default_port": 2375,
                "protocol": "TCP",
                "banner": "HTTP/1.1 200 OK\r\nApi-Version: 1.41\r\nDocker-Experimental: false\r\n\r\n",
                "keywords": ["docker", "container", "api"]
            },
            "redis": {
                "name": "Redis Database",
                "default_port": 6379,
                "protocol": "TCP",
                "banner": "+PONG\r\n",
                "keywords": ["redis", "set", "get", "ping"]
            }
        }
    
    def get_available_personas(self) -> Dict:
        """Get list of available service personas"""
        return {
            key: {
                "name": persona["name"],
                "default_port": persona["default_port"],
                "protocol": persona["protocol"]
            }
            for key, persona in self.personas.items()
        }
    
    def configure(self, persona: str, port: int, custom_banner: Optional[str] = None) -> bool:
        """
        Configure honeypot to impersonate a specific service
        
        Args:
            persona: Service type to impersonate (e.g., 'ftp', 'ssh', 'http_admin')
            port: Port number to listen on
            custom_banner: Optional custom banner/signature
        """
        if persona not in self.personas:
            logger.error(f"Unknown persona: {persona}")
            return False
        
        # Stop if running
        if self.running:
            self.stop()
        
        self.current_persona = persona
        self.current_port = port
        self.custom_banner = custom_banner
        
        logger.info(f"Honeypot configured: {self.personas[persona]['name']} on port {port}")
        return True
    
    def start(self) -> bool:
        """Start the adaptive honeypot"""
        if self.running:
            logger.warning("Honeypot already running")
            return False
        
        try:
            self.running = True
            self.enabled = True
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            
            persona_name = self.personas[self.current_persona]["name"]
            logger.info(f"🍯 Honeypot started: {persona_name} on port {self.current_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start honeypot: {e}")
            self.running = False
            self.enabled = False
            return False
    
    def stop(self):
        """Stop the honeypot"""
        self.running = False
        self.enabled = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        logger.info("🛑 Honeypot stopped")
    
    def _run_server(self):
        """Main server loop"""
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.current_port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Timeout for clean shutdown
            
            logger.info(f"Listening on port {self.current_port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    # Handle connection in separate thread
                    threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, address),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Accept error: {e}")
        
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def _handle_connection(self, client_socket: socket.socket, address: tuple):
        """Handle incoming connection"""
        try:
            ip_address = address[0]
            port = address[1]
            
            # Get persona configuration
            persona = self.personas[self.current_persona]
            
            # Send banner
            banner = self.custom_banner if self.custom_banner else persona["banner"]
            if isinstance(banner, str):
                banner = banner.encode('utf-8')
            client_socket.send(banner)
            
            # Receive attacker's input
            try:
                client_socket.settimeout(5.0)
                data = client_socket.recv(4096)
                attacker_input = data.decode('utf-8', errors='ignore')
            except:
                attacker_input = "<no input>"
            
            # Log attack
            attack_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': ip_address,
                'source_port': port,
                'honeypot_persona': self.current_persona,
                'honeypot_port': self.current_port,
                'service_name': persona['name'],
                'attacker_input': attacker_input[:500],  # Limit size
                'banner_sent': banner.decode('utf-8', errors='ignore')[:200]
            }
            
            self.attack_log.append(attack_entry)
            
            # Log to console
            logger.warning(f"🎣 HONEYPOT HIT: {ip_address}:{port} → {persona['name']} (port {self.current_port})")
            logger.info(f"Attacker sent: {attacker_input[:100]}")
            
            # Feed attack to AI training (sandbox)
            self._feed_to_ai_training(attack_entry)
            
            # Keep log size manageable
            if len(self.attack_log) > 1000:
                self.attack_log = self.attack_log[-500:]
        
        except Exception as e:
            logger.error(f"Connection handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def get_status(self) -> Dict:
        """Get current honeypot status"""
        return {
            'enabled': self.enabled,
            'running': self.running,
            'current_persona': self.current_persona,
            'persona_name': self.personas[self.current_persona]['name'],
            'port': self.current_port,
            'total_attacks': len(self.attack_log),
            'recent_attacks': self.attack_log[-10:] if self.attack_log else []
        }
    
    def get_attack_log(self, limit: int = 100) -> List[Dict]:
        """Get recent attack log"""
        return self.attack_log[-limit:] if self.attack_log else []
    
    def clear_log(self):
        """Clear attack log"""
        self.attack_log = []
        logger.info("Honeypot attack log cleared")
    
    def _feed_to_ai_training(self, attack_entry: Dict):
        """
        Feed honeypot attack to AI training system
        This is the sandbox - all attacks are safely logged and used to train ML models
        """
        try:
            # Import AI module (lazy import to avoid circular dependency)
            from AI.pcs_ai import log_honeypot_attack
            
            # Convert attack to threat log format
            threat_data = {
                'ip_address': attack_entry['source_ip'],
                'threat_type': f"honeypot_{attack_entry['honeypot_persona']}",
                'level': 'DANGEROUS',  # All honeypot hits are suspicious
                'details': f"{attack_entry['service_name']} attack: {attack_entry['attacker_input'][:100]}",
                'timestamp': attack_entry['timestamp'],
                'source': 'honeypot',
                'honeypot_persona': attack_entry['honeypot_persona'],
                'honeypot_port': attack_entry['honeypot_port']
            }
            
            # Feed to AI
            log_honeypot_attack(threat_data)
            logger.info(f"🤖 Fed attack to AI training: {attack_entry['source_ip']}")
            
        except ImportError:
            # AI module not available, skip
            pass
        except Exception as e:
            logger.error(f"Failed to feed attack to AI: {e}")


# Global instance
_honeypot = None

def get_honeypot() -> AdaptiveHoneypot:
    """Get or create global honeypot instance"""
    global _honeypot
    if _honeypot is None:
        _honeypot = AdaptiveHoneypot()
    return _honeypot


# Convenience functions
def start_honeypot(persona: str, port: int, custom_banner: Optional[str] = None) -> bool:
    """Start honeypot with specified configuration"""
    hp = get_honeypot()
    hp.configure(persona, port, custom_banner)
    return hp.start()

def stop_honeypot():
    """Stop the honeypot"""
    hp = get_honeypot()
    hp.stop()

def get_honeypot_status() -> Dict:
    """Get honeypot status"""
    hp = get_honeypot()
    return hp.get_status()

def get_available_personas() -> Dict:
    """Get available service personas"""
    hp = get_honeypot()
    return hp.get_available_personas()
