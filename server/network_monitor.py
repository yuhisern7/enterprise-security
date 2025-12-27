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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import AI.pcs_ai as pcs_ai

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


class NetworkMonitor:
    """Monitor network traffic for security threats"""
    
    def __init__(self):
        self.running = False
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))  # IP -> {port_count, ports_set}
        self.arp_tracker = defaultdict(list)  # Track ARP requests
        self.connection_tracker = defaultdict(int)  # Track connection attempts
        
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
        
        # Track ports accessed by this IP
        self.port_scan_tracker[src_ip]['ports'].add(dst_port)
        self.port_scan_tracker[src_ip]['last_seen'] = _get_current_time()
        
        # Detect port scanning (accessing many different ports)
        ports_accessed = len(self.port_scan_tracker[src_ip]['ports'])
        
        if ports_accessed > 10:  # Accessing 10+ different ports = likely port scan
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
        
        # Track UDP floods
        self.connection_tracker[f"udp_{src_ip}"] += 1
        
        if self.connection_tracker[f"udp_{src_ip}"] > 200:
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
