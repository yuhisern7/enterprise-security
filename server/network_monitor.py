#!/usr/bin/env python3
"""
Network Traffic Monitor - Monitors all devices on WiFi/LAN
Detects port scans, network attacks, suspicious traffic patterns
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
import sys
import os
import pytz
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import AI.pcs_ai as pcs_ai

# Import performance monitoring
try:
    import AI.network_performance as net_perf
    PERFORMANCE_TRACKING_AVAILABLE = True
    print("[NETWORK] Performance tracking enabled")
except ImportError:
    PERFORMANCE_TRACKING_AVAILABLE = False
    print("[WARNING] Performance tracking not available")

def _get_current_time():
    """Get current datetime in configured timezone"""
    try:
        tz_name = os.getenv('TZ', 'Asia/Kuala_Lumpur')
        tz = pytz.timezone(tz_name)
        return datetime.now(tz)
    except:
        return datetime.now(pytz.UTC)

try:
    from scapy.all import sniff, IP, TCP, UDP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not installed. Network monitoring disabled.")
    print("[INFO] Install with: pip install scapy")

# Persistent storage paths
NETWORK_MONITOR_STATE_FILE = os.path.join(os.path.dirname(__file__), 'json', 'network_monitor_state.json')

def _serialize_monitor_state(port_scan_tracker, arp_tracker, connection_tracker):
    """Convert monitor state to JSON-serializable format"""
    return {
        'port_scan_tracker': {
            ip: {
                'ports': list(data['ports']),
                'last_seen': data['last_seen'].isoformat() if isinstance(data.get('last_seen'), datetime) else data.get('last_seen')
            }
            for ip, data in port_scan_tracker.items()
        },
        'arp_tracker': dict(arp_tracker),
        'connection_tracker': dict(connection_tracker)
    }

def _deserialize_monitor_state(data):
    """Convert JSON data back to monitor state"""
    port_scan = defaultdict(lambda: defaultdict(set))
    for ip, info in data.get('port_scan_tracker', {}).items():
        port_scan[ip]['ports'] = set(info.get('ports', []))
        last_seen = info.get('last_seen')
        if last_seen:
            try:
                port_scan[ip]['last_seen'] = datetime.fromisoformat(last_seen)
            except:
                port_scan[ip]['last_seen'] = _get_current_time()
    
    arp = defaultdict(list)
    arp.update(data.get('arp_tracker', {}))
    
    conn = defaultdict(int)
    conn.update(data.get('connection_tracker', {}))
    
    return port_scan, arp, conn

def _save_monitor_state(port_scan_tracker, arp_tracker, connection_tracker):
    """Save network monitor state to disk"""
    try:
        os.makedirs(os.path.dirname(NETWORK_MONITOR_STATE_FILE), exist_ok=True)
        state = _serialize_monitor_state(port_scan_tracker, arp_tracker, connection_tracker)
        with open(NETWORK_MONITOR_STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Could not save network monitor state: {e}")

def _load_monitor_state():
    """Load network monitor state from disk"""
    try:
        if os.path.exists(NETWORK_MONITOR_STATE_FILE):
            with open(NETWORK_MONITOR_STATE_FILE, 'r') as f:
                data = json.load(f)
            port_scan, arp, conn = _deserialize_monitor_state(data)
            print(f"[NETWORK] Loaded monitor state: {len(port_scan)} IPs tracked")
            return port_scan, arp, conn
    except Exception as e:
        print(f"[WARNING] Could not load network monitor state: {e}")
    return defaultdict(lambda: defaultdict(set)), defaultdict(list), defaultdict(int)


class NetworkMonitor:
    """Monitor network traffic for security threats"""
    
    def __init__(self):
        self.running = False
        # Load previous state
        port_scan, arp, conn = _load_monitor_state()
        self.port_scan_tracker = port_scan
        self.arp_tracker = arp
        self.connection_tracker = conn
        
    def start(self):
        """Start monitoring network traffic"""
        if not SCAPY_AVAILABLE:
            print("[ERROR] Cannot start network monitoring - scapy not installed")
            return
        
        self.running = True
        print("[NETWORK] Starting packet capture...")
        print("[NETWORK] Monitoring all network interfaces...")
        
        # Start packet sniffing in a separate thread
        sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        sniff_thread.start()
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_old_data, daemon=True)
        cleanup_thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        print("[NETWORK] Network monitoring stopped")
    
    def _sniff_packets(self):
        """Sniff network packets and analyze them"""
        try:
            # Sniff packets on all interfaces
            # filter="tcp or udp or arp" limits to relevant protocols
            sniff(
                prn=self._analyze_packet,
                filter="tcp or udp or arp",
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("[ERROR] Permission denied - run as root/sudo for network monitoring")
        except Exception as e:
            print(f"[ERROR] Network monitoring error: {e}")
    
    def _analyze_packet(self, packet):
        """Analyze a single packet for threats"""
        try:
            # Get source IP
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Skip local traffic and private IPs from monitoring (too noisy)
                if src_ip.startswith(('127.', '192.168.', '10.', '172.')):
                    if not dst_ip.startswith(('8.8.', '1.1.', '208.67.')):  # Allow DNS
                        return
                
                # TCP packet analysis
                if TCP in packet:
                    self._analyze_tcp_packet(packet, src_ip, dst_ip)
                
                # UDP packet analysis
                if UDP in packet:
                    self._analyze_udp_packet(packet, src_ip, dst_ip)
            
            # ARP analysis (ARP spoofing detection)
            if ARP in packet:
                self._analyze_arp_packet(packet)
        
        except Exception as e:
            # Don't crash on packet analysis errors
            pass
    
    def _analyze_tcp_packet(self, packet, src_ip, dst_ip):
        """Analyze TCP packet for port scans and attacks"""
        tcp = packet[TCP]
        dst_port = tcp.dport
        
        # Performance tracking: bandwidth and packet counts
        if PERFORMANCE_TRACKING_AVAILABLE:
            try:
                packet_size = len(packet)
                net_perf.update_bandwidth(src_ip, packet_size, 0)  # Sent
                net_perf.update_bandwidth(dst_ip, 0, packet_size)  # Received
            except:
                pass
        
        # Track ports accessed by this IP
        self.port_scan_tracker[src_ip]['ports'].add(dst_port)
        self.port_scan_tracker[src_ip]['last_seen'] = _get_current_time()
        
        # Detect port scanning (accessing many different ports)
        ports_accessed = len(self.port_scan_tracker[src_ip]['ports'])
        
        if ports_accessed > 10:  # Accessing 10+ different ports = likely port scan
            # Allow internal network scans (device discovery), block external only
            if not (src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.')):
                pcs_ai._log_threat(
                    ip_address=src_ip,
                    threat_type="Port Scanning",
                    details=f"Port scan detected: {ports_accessed} different ports accessed in short time. Ports: {sorted(list(self.port_scan_tracker[src_ip]['ports']))[:20]}",
                    level=pcs_ai.ThreatLevel.DANGEROUS,
                    action="detected",
                    headers={}
                )
                # Block the scanner
                pcs_ai._block_ip(src_ip)
            # Clear tracker to avoid duplicate alerts
            self.port_scan_tracker[src_ip]['ports'].clear()
        
        # Detect SYN flood (DDoS)
        if tcp.flags == 'S':  # SYN packet
            self.connection_tracker[src_ip] += 1
            
            # If more than 100 SYN packets in tracking period
            if self.connection_tracker[src_ip] > 100:
                # Allow internal network activity, block external only
                if not (src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.')):
                    pcs_ai._log_threat(
                        ip_address=src_ip,
                        threat_type="SYN Flood Attack",
                        details=f"SYN flood detected: {self.connection_tracker[src_ip]} SYN packets",
                        level=pcs_ai.ThreatLevel.CRITICAL,
                        action="detected",
                        headers={}
                    )
                    pcs_ai._block_ip(src_ip)
                self.connection_tracker[src_ip] = 0
    
    def _analyze_udp_packet(self, packet, src_ip, dst_ip):
        """Analyze UDP packet for attacks"""
        udp = packet[UDP]
        dst_port = udp.dport
        
        # Performance tracking: bandwidth
        if PERFORMANCE_TRACKING_AVAILABLE:
            try:
                packet_size = len(packet)
                net_perf.update_bandwidth(src_ip, packet_size, 0)
            except:
                pass
        
        # Track UDP floods
        self.connection_tracker[f"udp_{src_ip}"] += 1
        
        if self.connection_tracker[f"udp_{src_ip}"] > 200:
            # Allow internal network activity, block external only
            if not (src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.')):
                pcs_ai._log_threat(
                    ip_address=src_ip,
                    threat_type="UDP Flood Attack",
                    details=f"UDP flood detected: {self.connection_tracker[f'udp_{src_ip}']} packets",
                    level=pcs_ai.ThreatLevel.CRITICAL,
                    action="detected",
                    headers={}
                )
                pcs_ai._block_ip(src_ip)
            self.connection_tracker[f"udp_{src_ip}"] = 0
    
    def _analyze_arp_packet(self, packet):
        """Analyze ARP packet for ARP spoofing"""
        arp = packet[ARP]
        
        # Track ARP requests
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        
        # Filter out 0.0.0.0 (DHCP negotiation and network initialization)
        if src_ip == "0.0.0.0":
            return
        
        # Store IP-MAC mapping
        key = f"{src_ip}_{src_mac}"
        self.arp_tracker[src_ip].append({
            'mac': src_mac,
            'time': _get_current_time()
        })
        
        # Detect ARP spoofing (same IP with different MAC addresses)
        unique_macs = set(entry['mac'] for entry in self.arp_tracker[src_ip])
        
        if len(unique_macs) > 1:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="ARP Spoofing",
                details=f"ARP spoofing detected: IP {src_ip} seen with multiple MAC addresses: {list(unique_macs)}",
                level=pcs_ai.ThreatLevel.CRITICAL,
                action="detected",
                headers={}
            )
    
    def _cleanup_old_data(self):
        """Clean up old tracking data periodically"""
        while self.running:
            time.sleep(300)  # Every 5 minutes
            
            cutoff = _get_current_time() - timedelta(minutes=10)
            
            # Clean port scan tracker
            for ip in list(self.port_scan_tracker.keys()):
                if self.port_scan_tracker[ip].get('last_seen', _get_current_time() - timedelta(days=1)) < cutoff:
                    del self.port_scan_tracker[ip]
            
            # Clean ARP tracker
            for ip in list(self.arp_tracker.keys()):
                self.arp_tracker[ip] = [
                    entry for entry in self.arp_tracker[ip]
                    if entry['time'] > cutoff
                ]
                if not self.arp_tracker[ip]:
                    del self.arp_tracker[ip]
            
            # Reset connection trackers
            self.connection_tracker.clear()
            
            # Save state to disk
            _save_monitor_state(self.port_scan_tracker, self.arp_tracker, self.connection_tracker)


if __name__ == '__main__':
    print("Network Monitor - Test Mode")
    print("Starting network monitoring...")
    
    monitor = NetworkMonitor()
    monitor.start()
    
    print("Monitoring... Press Ctrl+C to stop")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()
