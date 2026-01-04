"""User and Identity Monitoring Module
Track network users via ARP, DHCP, and DNS - real data only.
For military/government/police use.
"""

import os
import json
import subprocess
import platform
import shutil
from datetime import datetime
from collections import defaultdict
from typing import Dict, List

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None

class UserTracker:
    """Track users on the network using real system data"""
    
    def __init__(self):
        # Use /app in Docker, ./server/json outside Docker
        base_dir = '/app' if os.path.exists('/app') else os.path.join(os.path.dirname(__file__), '..', 'server')
        self.users_file = os.path.join(base_dir, 'json', 'tracked_users.json')
        self.suspicious_activities = []
        
    def get_arp_table(self) -> List[Dict]:
        """Get ARP table to identify connected users (cross-platform)"""
        users = []
        try:
            # Run arp command (works on Linux, macOS, Windows)
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                system = platform.system()
                
                for line in result.stdout.split('\n'):
                    if not line.strip():
                        continue
                    
                    try:
                        # Windows format: Interface: 192.168.1.1 --- 0xb
                        #                  Internet Address      Physical Address      Type
                        #                  192.168.1.100        aa-bb-cc-dd-ee-ff     dynamic
                        if system == 'Windows':
                            if 'Interface:' in line or 'Internet Address' in line:
                                continue
                            parts = line.split()
                            if len(parts) >= 2:
                                ip = parts[0]
                                mac = parts[1].replace('-', ':')
                                if '.' in ip and ':' in mac:
                                    users.append({
                                        'hostname': 'Unknown',
                                        'ip': ip,
                                        'mac': mac,
                                        'last_seen': datetime.now().isoformat()
                                    })
                        
                        # macOS/Linux format: ? (192.168.1.100) at aa:bb:cc:dd:ee:ff [ether] on en0
                        #                or: hostname (192.168.1.100) at aa:bb:cc:dd:ee:ff [ether] on eth0
                        elif '(' in line and ')' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                hostname = parts[0] if parts[0] != '?' else 'Unknown'
                                ip = parts[1].strip('()')
                                mac = parts[3] if len(parts) > 3 else 'Unknown'
                                
                                if '.' in ip:  # Valid IP
                                    users.append({
                                        'hostname': hostname,
                                        'ip': ip,
                                        'mac': mac,
                                        'last_seen': datetime.now().isoformat()
                                    })
                    except:
                        continue  # Skip malformed lines
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"[USER_TRACKER] ARP error: {e}")
        
        return users
    
    def detect_suspicious_activity(self, users: List[Dict]) -> int:
        """Detect suspicious user behavior"""
        suspicious_count = 0
        
        # Load threat log to check if any user IPs are in blocklist
        try:
            base_dir = '/app' if os.path.exists('/app') else os.path.join(os.path.dirname(__file__), '..', 'server')
            threat_log = os.path.join(base_dir, 'json', 'threat_log.json')
            if os.path.exists(threat_log):
                with open(threat_log, 'r') as f:
                    threats = json.load(f)
                    blocked_ips = {t.get('src_ip') for t in threats if t.get('blocked')}
                    
                    for user in users:
                        if user['ip'] in blocked_ips:
                            suspicious_count += 1
                            self.suspicious_activities.append({
                                'user': user['hostname'],
                                'ip': user['ip'],
                                'reason': 'IP matches blocked threat',
                                'timestamp': datetime.now().isoformat()
                            })
        except Exception as e:
            print(f"[USER_TRACKER] Suspicious activity detection error: {e}")
        
        return suspicious_count
    
    def get_stats(self) -> Dict:
        """Get user tracking statistics"""
        users = self.get_arp_table()
        suspicious = self.detect_suspicious_activity(users)
        
        # Count active sessions using psutil (cross-platform)
        active_sessions = 0
        if psutil is not None:
            try:
                connections = psutil.net_connections(kind='inet')
                active_sessions = len([c for c in connections if c.status == 'ESTABLISHED'])
            except:
                pass
        
        # Insider threats are critical suspicious activities
        insider_threats = len([a for a in self.suspicious_activities if 'blocked threat' in a.get('reason', '')])
        
        # Save users to file
        try:
            with open(self.users_file, 'w') as f:
                json.dump(users, f, indent=2)
        except Exception:
            pass
        
        return {
            'tracked_users': len(users),
            'suspicious_activities': suspicious,
            'insider_threats': insider_threats,
            'active_sessions': active_sessions,
            'users': users
        }

# Global instance
user_tracker = UserTracker()
