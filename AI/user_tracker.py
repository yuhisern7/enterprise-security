"""User and Identity Monitoring Module
Track network users via ARP, DHCP, and DNS - real data only.
For military/government/police use.
"""

import os
import json
import subprocess
from datetime import datetime
from collections import defaultdict
from typing import Dict, List

class UserTracker:
    """Track users on the network using real system data"""
    
    def __init__(self):
        self.users_file = '/app/json/tracked_users.json'
        self.suspicious_activities = []
        
    def get_arp_table(self) -> List[Dict]:
        """Get ARP table to identify connected users"""
        users = []
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '(' in line and ')' in line:
                        # Parse: hostname (192.168.1.100) at aa:bb:cc:dd:ee:ff [ether] on eth0
                        parts = line.split()
                        if len(parts) >= 4:
                            hostname = parts[0] if parts[0] != '?' else 'Unknown'
                            ip = parts[1].strip('()')
                            mac = parts[3] if len(parts) > 3 else 'Unknown'
                            
                            users.append({
                                'hostname': hostname,
                                'ip': ip,
                                'mac': mac,
                                'last_seen': datetime.now().isoformat()
                            })
        except Exception as e:
            print(f"[USER_TRACKER] ARP error: {e}")
        
        return users
    
    def detect_suspicious_activity(self, users: List[Dict]) -> int:
        """Detect suspicious user behavior"""
        suspicious_count = 0
        
        # Load threat log to check if any user IPs are in blocklist
        try:
            if os.path.exists('/app/json/threat_log.json'):
                with open('/app/json/threat_log.json', 'r') as f:
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
        
        # Count active sessions from netstat/ss
        active_sessions = 0
        try:
            result = subprocess.run(['ss', '-tu'], capture_output=True, text=True)
            if result.returncode == 0:
                active_sessions = len([l for l in result.stdout.split('\n') if 'ESTAB' in l])
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
