"""PCAP Capture and Forensics Module
Real packet capture for threat hunting - military/government/police grade.
NO FAKE DATA - Actual network forensics.
"""

import os
import subprocess
import json
import shutil
from datetime import datetime
from typing import List, Dict, Optional

class PCAPCapture:
    """Real PCAP capture using tcpdump"""
    
    def __init__(self):
        # Use /app in Docker, ./server/pcap outside Docker
        base_dir = '/app' if os.path.exists('/app') else os.path.join(os.path.dirname(__file__), '..', 'server')
        self.pcap_dir = os.path.join(base_dir, 'pcap')
        self.index_file = os.path.join(base_dir, 'json', 'pcap_index.json')
        os.makedirs(self.pcap_dir, exist_ok=True)
        self.hunt_count = 0
        
    def is_tcpdump_available(self) -> bool:
        """Check if tcpdump is installed (cross-platform)"""
        try:
            # Use shutil.which (cross-platform)
            return shutil.which('tcpdump') is not None
        except:
            return False
    
    def start_capture(self, interface: str = 'any', duration: int = 3600) -> Optional[str]:
        """Start packet capture (requires root/CAP_NET_RAW)"""
        if not self.is_tcpdump_available():
            return None
        
        filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        filepath = os.path.join(self.pcap_dir, filename)
        
        try:
            # Start tcpdump in background
            cmd = [
                'tcpdump',
                '-i', interface,
                '-w', filepath,
                '-G', str(duration),  # Rotate after duration
                '-s', '65535',  # Full packet capture
                'not', 'port', '22'  # Don't capture SSH
            ]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return filepath
        except Exception as e:
            print(f"[PCAP] Capture failed: {e}")
            return None
    
    def get_total_size(self) -> str:
        """Get total PCAP storage size"""
        try:
            result = subprocess.run(['du', '-sh', self.pcap_dir], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.split()[0]
        except:
            pass
        return "0B"
    
    def search_pcap(self, query: str, timerange: str = '1h', protocol: str = 'all') -> List[Dict]:
        """Search PCAP files for threat hunting"""
        if not self.is_tcpdump_available():
            return []
        
        self.hunt_count += 1
        results = []
        
        try:
            # Find latest PCAP file
            pcap_files = sorted([
                os.path.join(self.pcap_dir, f) 
                for f in os.listdir(self.pcap_dir) 
                if f.endswith('.pcap')
            ])
            
            if not pcap_files:
                return []
            
            latest_pcap = pcap_files[-1]
            
            # Use tcpdump to search
            cmd = ['tcpdump', '-r', latest_pcap, '-n']
            
            # Add protocol filter
            if protocol != 'all':
                cmd.append(protocol.lower())
            
            # Add search filter (IP or port)
            if query:
                cmd.append(query)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n')[:100]:  # Limit to 100 results
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            results.append({
                                'timestamp': parts[0],
                                'protocol': parts[2] if len(parts) > 2 else 'Unknown',
                                'src_ip': parts[2] if len(parts) > 2 else 'N/A',
                                'info': ' '.join(parts[3:])
                            })
        except Exception as e:
            print(f"[PCAP] Search error: {e}")
        
        return results
    
    def get_stats(self) -> Dict:
        """Get PCAP statistics"""
        return {
            'pcap_size': self.get_total_size(),
            'hunt_queries': self.hunt_count,
            'available': self.is_tcpdump_available()
        }

# Global instance
pcap_capture = PCAPCapture()
