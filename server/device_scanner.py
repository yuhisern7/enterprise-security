#!/usr/bin/env python3
"""
Network Device Scanner - Discover all devices connected to the network
Identifies device types: iOS, Android, Windows, Mac, Linux, Routers, IoT devices
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
import socket
import struct
import os
import re

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not available for device scanning")

# MAC address vendor prefixes for device identification
MAC_VENDORS = {
    # Apple devices
    'apple': ['00:03:93', '00:05:02', '00:0a:27', '00:0a:95', '00:0d:93', '00:10:fa', '00:11:24', 
              '00:13:72', '00:14:51', '00:16:cb', '00:17:f2', '00:19:e3', '00:1b:63', '00:1c:b3',
              '00:1d:4f', '00:1e:52', '00:1e:c2', '00:1f:5b', '00:1f:f3', '00:21:e9', '00:22:41',
              '00:23:12', '00:23:32', '00:23:6c', '00:23:df', '00:24:36', '00:25:00', '00:25:4b',
              '00:25:bc', '00:26:08', '00:26:4a', '00:26:b0', '00:26:bb', '00:30:65', '00:3e:e1',
              '00:50:e4', '00:61:71', '00:88:65', '00:c6:10', '00:cd:fe', '00:f4:b9', '00:f7:6f',
              '04:0c:ce', '04:15:52', '04:1e:64', '04:26:65', '04:48:9a', '04:4b:ed', '04:54:53',
              '04:69:f8', '04:db:56', '04:e5:36', '04:f1:3e', '04:f7:e4', '08:00:07', '08:66:98',
              '08:6d:41', '08:70:45', '0c:3e:9f', '0c:4d:e9', '0c:74:c2', '0c:77:1a', '10:40:f3',
              '10:41:7f', '10:93:e9', '10:9a:dd', '10:dd:b1', '14:10:9f', '14:5a:05', '14:8f:c6',
              '14:99:e2', '18:34:51', '18:3d:a2', '18:65:90', '18:af:61', '18:e7:f4', '1c:1a:c0',
              '1c:36:bb', '1c:ab:a7', '20:3c:ae', '20:78:f0', '20:a2:e4', '20:ab:37', '20:c9:d0',
              '24:1e:eb', '24:24:0e', '24:a0:74', '24:ab:81', '24:f0:94', '24:f6:77', '28:37:37',
              '28:5a:eb', '28:6a:ba', '28:cf:da', '28:cf:e9', '28:e0:2c', '28:e1:4c', '2c:1f:23',
              '2c:3a:e8', '2c:b4:3a', '2c:be:08', '30:10:e4', '30:90:ab', '30:f7:c5', '34:12:f9',
              '34:15:9e', '34:36:3b', '34:a3:95', '34:c0:59', '34:e2:fd', '38:0f:4a', '38:48:4c',
              '3c:07:54', '3c:2e:f9', '3c:a9:f4', '40:30:04', '40:33:1a', '40:3c:fc', '40:4d:7f',
              '40:a6:d9', '40:b3:95', '40:cb:c0', '44:2a:60', '44:4c:0c', '44:d8:84', '44:fb:42',
              '48:43:7c', '48:60:bc', '48:74:6e', '48:a1:95', '48:d7:05', '4c:3c:16', '4c:57:ca',
              '4c:7c:5f', '4c:8d:79', '50:1a:c5', '50:32:37', '50:7a:55', '50:b7:c3', '50:ea:d6',
              '54:26:96', '54:4e:90', '54:72:4f', '54:80:1d', '54:9f:13', '54:ea:a8', '54:ee:75',
              '58:1f:aa', '58:40:4e', '58:55:ca', '58:b0:35', '5c:59:48', '5c:95:ae', '5c:96:9d',
              '5c:f9:38', '60:33:4b', '60:69:44', '60:92:3a', '60:c5:47', '60:fa:cd', '60:fb:42',
              '64:20:0c', '64:9a:be', '64:a3:cb', '64:b0:a6', '64:e6:82', '68:09:27', '68:5b:35',
              '68:96:7b', '68:a8:6d', '68:db:f5', '68:fe:f7', '6c:19:c0', '6c:40:08', '6c:72:e7',
              '6c:94:66', '6c:96:cf', '6c:ab:31', '70:11:24', '70:48:0f', '70:56:81', '70:cd:60',
              '70:de:e2', '70:ec:e4', '74:1b:b2', '74:81:14', '74:e1:b6', '74:e2:f5', '78:31:c1',
              '78:67:d7', '78:7b:8a', '78:88:6d', '78:a3:e4', '78:ca:39', '78:d7:5f', '78:fd:94',
              '7c:01:91', '7c:11:be', '7c:6d:f8', '7c:c3:a1', '7c:d1:c3', '7c:f0:5f', '80:49:71',
              '80:92:9f', '80:e6:50', '84:38:35', '84:85:06', '84:89:ad', '84:fc:fe', '88:1f:a1',
              '88:53:95', '88:63:df', '88:66:5a', '88:ae:07', '88:cb:87', '88:e8:7f', '8c:00:6d',
              '8c:2d:aa', '8c:58:77', '8c:7b:9d', '8c:7c:92', '8c:85:90', '8c:8e:f2', '90:27:e4',
              '90:72:40', '90:84:0d', '90:8d:6c', '90:b0:ed', '90:b2:1f', '94:94:26', '94:e9:6a',
              '94:f6:a3', '98:01:a7', '98:03:d8', '98:5a:eb', '98:b8:e3', '98:d6:bb', '98:e0:d9',
              '98:f0:ab', '98:fe:94', '9c:04:eb', '9c:20:7b', '9c:35:eb', '9c:f4:8e', 'a0:99:9b',
              'a0:d7:95', 'a4:5e:60', 'a4:67:06', 'a4:b1:97', 'a4:c3:61', 'a4:d1:8c', 'a4:d9:31',
              'a8:20:66', 'a8:5b:78', 'a8:66:7f', 'a8:86:dd', 'a8:88:08', 'a8:96:8a', 'a8:be:27',
              'a8:fa:d8', 'ac:29:3a', 'ac:3c:0b', 'ac:61:ea', 'ac:87:a3', 'ac:bc:32', 'ac:cf:5c',
              'ac:de:48', 'b0:19:c6', 'b0:34:95', 'b0:65:bd', 'b0:70:2d', 'b0:9f:ba', 'b4:18:d1',
              'b4:8b:19', 'b4:f0:ab', 'b4:f6:1c', 'b8:09:8a', 'b8:17:c2', 'b8:41:a4', 'b8:44:d9',
              'b8:53:ac', 'b8:78:2e', 'b8:8d:12', 'b8:c1:11', 'b8:c7:5d', 'b8:e8:56', 'b8:f6:b1',
              'bc:3b:af', 'bc:52:b7', 'bc:67:1c', 'bc:6c:21', 'bc:92:6b', 'bc:9f:ef', 'c0:1a:da',
              'c0:63:94', 'c0:84:7d', 'c0:9f:42', 'c0:cc:f8', 'c0:ce:cd', 'c0:d0:12', 'c4:2c:03',
              'c8:1e:e7', 'c8:2a:14', 'c8:33:4b', 'c8:69:cd', 'c8:6f:1d', 'c8:85:50', 'c8:bc:c8',
              'c8:e0:eb', 'cc:08:8d', 'cc:25:ef', 'cc:29:f5', 'cc:44:63', 'cc:78:5f', 'cc:c7:60',
              'd0:03:4b', 'd0:23:db', 'd0:33:11', 'd0:4f:7e', 'd0:81:7a', 'd0:a6:37', 'd0:e1:40',
              'd4:61:9d', 'd4:90:9c', 'd4:a3:3d', 'd4:dc:cd', 'd4:f4:6f', 'd8:00:4d', 'd8:1d:72',
              'd8:30:62', 'd8:96:85', 'd8:9e:3f', 'd8:a2:5e', 'd8:bb:2c', 'd8:cf:9c', 'dc:0c:5c',
              'dc:2b:2a', 'dc:2b:61', 'dc:37:18', 'dc:56:e7', 'dc:86:d8', 'dc:9b:9c', 'dc:a4:ca',
              'dc:a9:04', 'dc:d3:a2', 'e0:5f:45', 'e0:66:78', 'e0:ac:cb', 'e0:b5:2d', 'e0:b9:a5',
              'e0:c9:7a', 'e0:f8:47', 'e4:25:e7', 'e4:8b:7f', 'e4:9a:79', 'e4:c6:3d', 'e4:ce:8f',
              'e8:04:0b', 'e8:06:88', 'e8:2a:ea', 'e8:40:f2', 'e8:80:2e', 'e8:b2:ac', 'ec:35:86',
              'ec:85:2f', 'f0:18:98', 'f0:24:75', 'f0:5c:19', 'f0:98:9d', 'f0:99:b6', 'f0:b4:79',
              'f0:c3:71', 'f0:cb:a1', 'f0:d1:a9', 'f0:db:e2', 'f0:dc:e2', 'f0:f6:1c', 'f4:0f:24',
              'f4:1b:a1', 'f4:37:b7', 'f4:5c:89', 'f4:f1:5a', 'f4:f9:51', 'f8:1e:df', 'f8:27:93',
              'f8:95:c7', 'fc:25:3f', 'fc:64:ba', 'fc:e9:98', 'fc:fc:48'],
    
    # Android manufacturers
    'samsung': ['00:12:fb', '00:13:77', '00:15:99', '00:15:b9', '00:16:32', '00:16:6b', '00:16:6c',
                '00:17:c9', '00:17:d5', '00:18:af', '00:1a:8a', '00:1b:98', '00:1c:43', '00:1d:25',
                '00:1d:f6', '00:1e:7d', '00:1f:cc', '00:21:19', '00:21:4c', '00:23:39', '00:23:d6',
                '00:23:d7', '00:24:54', '00:24:90', '00:24:91', '00:24:e9', '00:25:38', '00:25:66',
                '00:26:37', 'a0:21:95', 'a0:75:91', 'a4:08:ea', 'a8:a1:95', 'ac:36:13', 'b4:07:f9',
                'bc:20:ba', 'c0:bd:d1', 'cc:3a:61', 'd0:22:be', 'd0:66:7b', 'd4:87:d8', 'd8:57:ef',
                'dc:71:44', 'e4:12:1d', 'e4:40:e2', 'e8:03:9a', 'e8:50:8b', 'e8:e5:d6', 'ec:1d:8b',
                'f0:25:b7', 'f0:e7:7e', 'f4:09:d8', 'f4:7b:5e', 'f8:04:2e', 'f8:d0:bd'],
    'xiaomi': ['00:9e:c8', '04:cf:8c', '14:f6:5a', '18:59:36', '28:6c:07', '34:80:b3', '34:ce:00',
               '50:8f:4c', '64:09:80', '68:df:dd', '6c:fa:89', '74:23:44', '78:02:f8', '8c:be:be',
               '98:fa:e3', 'a0:86:c6', 'ac:c1:ee', 'ac:f7:f3', 'b0:e2:35', 'b4:0b:44', 'c4:0b:cb',
               'd0:7e:28', 'd4:61:fe', 'dc:d9:ae', 'f0:b4:29', 'f4:8b:32', 'f8:a4:5f'],
    'huawei': ['00:1e:10', '00:25:68', '00:46:4b', '00:66:4b', '00:9a:cd', '00:e0:fc', '04:02:1f',
               '04:c0:6f', '08:19:a6', '0c:37:dc', '0c:96:bf', '10:1f:74', '18:68:cb', '20:08:ed',
               '20:76:00', '28:31:52', '2c:ab:a4', '34:6b:d3', '40:4d:8e', '48:46:fb', '48:7d:2e',
               '4c:54:99', '50:01:bb', '54:25:ea', '58:2a:f7', '60:de:44', '64:3e:8c', '68:3e:34',
               '6c:4a:85', '6c:96:d7', '74:a7:8e', '78:d7:52', '84:a8:e4', '88:28:b3', '9c:28:ef',
               'a4:71:74', 'a8:7c:01', 'b4:30:52', 'b8:08:d7', 'bc:25:e0', 'c0:18:03', 'c4:f0:81',
               'c8:14:79', 'cc:96:a0', 'd0:7a:b5', 'd4:6a:a8', 'd8:49:0b', 'dc:d9:16', 'e0:19:1d',
               'e4:d3:32', 'f4:c7:14', 'f8:e7:1e'],
    'google': ['00:1a:11', '3c:5a:b4', '54:60:09', '68:c4:4d', '6c:ad:f8', '84:3a:4b', 'ac:37:43',
               'c4:43:8f', 'd4:f5:13', 'dc:a6:32', 'f4:f5:e8'],
    
    # Windows/PC manufacturers
    'dell': ['00:06:5b', '00:08:74', '00:0b:db', '00:0c:f1', '00:0d:56', '00:0f:1f', '00:11:43',
             '00:12:3f', '00:13:72', '00:14:22', '00:15:c5', '00:18:8b', '00:19:b9', '00:1a:a0',
             '00:1c:23', '00:1d:09', '00:1e:4f', '00:21:70', '00:21:9b', '00:22:19', '00:23:ae',
             '00:24:e8', '00:25:64', '00:26:b9', '18:03:73', '18:66:da', '18:a9:05', '1c:40:24',
             '20:47:47', '24:b6:fd', '28:c8:25', '34:17:eb', '34:e6:d7', '44:a8:42', '4c:76:25',
             '50:9a:4c', '5c:26:0a', '5c:f9:dd', '74:86:7a', '78:2b:cb', '78:45:c4', '80:18:44',
             '84:2b:2b', '84:7b:eb', '90:b1:1c', 'a4:ba:db', 'b0:83:fe', 'b8:2a:72', 'b8:ac:6f',
             'bc:30:5b', 'c8:1f:66', 'd0:67:e5', 'd4:81:d7', 'd4:ae:52', 'd4:be:d9', 'e0:db:55',
             'e4:54:e8', 'f0:1f:af', 'f0:4d:a2', 'f8:b1:56', 'f8:bc:12', 'f8:ca:b8'],
    'hp': ['00:01:e6', '00:01:e7', '00:02:a5', '00:04:ea', '00:08:83', '00:0a:57', '00:0e:7f',
           '00:0f:20', '00:10:83', '00:11:0a', '00:12:79', '00:13:21', '00:14:38', '00:14:c2',
           '00:15:60', '00:16:35', '00:17:08', '00:17:a4', '00:18:fe', '00:19:bb', '00:1a:4b',
           '00:1b:78', '00:1c:c4', '00:1e:0b', '00:1f:29', '00:21:5a', '00:22:64', '00:23:7d',
           '00:24:81', '00:25:b3', '00:26:55', '08:00:09', '10:1f:74', '14:58:d0', '18:a9:05',
           '1c:c1:de', '2c:27:d7', '2c:41:38', '2c:44:fd', '30:e1:71', '34:64:a9', '38:ea:a7',
           '40:a8:f0', '44:1e:a1', '48:0f:cf', '4c:39:09', '58:20:b1', '64:51:06', '70:5a:0f',
           '78:24:af', '78:e3:b5', '80:c1:6e', '98:4b:e1', '9c:2a:70', 'a0:1d:48', 'a0:8c:fd',
           'a4:5d:36', 'a8:66:7f', 'b4:99:ba', 'b8:ac:6f', 'c8:cb:b8', 'd0:7e:28', 'd4:85:64',
           'd8:9d:67', 'e4:11:5b', 'e8:39:35', 'ec:9a:74', 'f0:de:f1', 'f4:ce:46'],
    'lenovo': ['00:0d:60', '00:13:ce', '00:16:ea', '00:17:c4', '00:18:de', '00:19:d1', '00:1a:6b',
               '00:1b:38', '00:1c:25', '00:1d:72', '00:1e:33', '00:1f:16', '00:21:5c', '00:23:24',
               '00:26:55', '1c:3e:84', '28:d2:44', '30:f9:ed', '40:16:7e', '50:3d:e5', '54:ee:75',
               '5c:f9:dd', '68:f7:28', '6c:ae:8b', '74:e5:43', '78:84:3c', '80:18:44', '88:88:87',
               '8c:ec:4b', '94:65:9c', '9c:b6:54', 'a0:b3:cc', 'a4:4e:31', 'b0:83:fe', 'b8:76:3f',
               'bc:16:65', 'c0:18:85', 'd0:50:99', 'd4:be:d9', 'e4:a7:c5', 'f0:de:f1', 'f8:a9:63'],
    'asus': ['00:01:80', '00:0c:6e', '00:0e:a6', '00:11:2f', '00:13:d4', '00:15:f2', '00:17:31',
             '00:18:f3', '00:19:66', '00:1a:92', '00:1b:fc', '00:1d:60', '00:1e:8c', '00:1f:c6',
             '00:22:15', '00:23:54', '00:24:8c', '00:25:90', '00:26:18', '04:d4:c4', '08:60:6e',
             '0c:9d:92', '10:7b:44', '10:bf:48', '14:dd:a9', '1c:87:2c', '1c:b7:2c', '28:e3:47',
             '30:5a:3a', '38:d5:47', '40:16:7e', '50:46:5d', '54:04:a6', '60:45:cb', '70:4d:7b',
             '74:d0:2b', '78:24:af', '9c:5c:8e', 'a8:5e:45', 'ac:22:0b', 'ac:9e:17', 'b0:6e:bf',
             'bc:ee:7b', 'c8:60:00', 'd0:17:c2', 'd8:50:e6', 'e0:3f:49', 'f0:79:59', 'f4:6d:04'],
    
    # Linux/Raspberry Pi
    'raspberry': ['b8:27:eb', 'dc:a6:32', 'e4:5f:01'],
}

# Connected devices storage
_connected_devices = {}
_devices_lock = threading.Lock()
_last_scan_time = None


class DeviceScanner:
    """Scan network to discover connected devices"""
    
    def __init__(self):
        self.running = False
        self.scan_interval = 60  # Scan every 60 seconds
    
    def start(self):
        """Start device scanning"""
        if not SCAPY_AVAILABLE:
            print("[WARNING] Device scanning disabled - scapy not available")
            return
        
        self.running = True
        print("[DEVICE SCANNER] Starting network device discovery...")
        
        # Start scanning thread
        scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        scan_thread.start()
    
    def stop(self):
        """Stop device scanning"""
        self.running = False
        print("[DEVICE SCANNER] Device scanning stopped")
    
    def _scan_loop(self):
        """Continuous scanning loop"""
        while self.running:
            try:
                self._scan_network()
            except Exception as e:
                print(f"[ERROR] Device scan error: {e}")
            
            # Wait before next scan
            time.sleep(self.scan_interval)
    
    def _scan_network(self):
        """Scan network for connected devices"""
        global _connected_devices, _last_scan_time
        
        try:
            # Get network interface and IP range
            ip_range = self._get_network_range()
            if not ip_range:
                print("[WARNING] Could not determine network range")
                return
            
            print(f"[DEVICE SCANNER] Scanning network: {ip_range}")
            
            # Create ARP request packet
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send ARP request and get responses
            conf.verb = 0  # Disable scapy verbosity
            result = srp(packet, timeout=3, retry=2)[0]
            
            devices = {}
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                
                # Identify device type
                device_type = self._identify_device(mac)
                hostname = self._get_hostname(ip)
                
                devices[mac] = {
                    'ip': ip,
                    'mac': mac,
                    'type': device_type,
                    'hostname': hostname,
                    'last_seen': datetime.now().isoformat(),
                    'first_seen': _connected_devices.get(mac, {}).get('first_seen', datetime.now().isoformat())
                }
            
            # Update global device list
            with _devices_lock:
                _connected_devices = devices
                _last_scan_time = datetime.now().isoformat()
            
            print(f"[DEVICE SCANNER] Found {len(devices)} devices on network")
            
        except Exception as e:
            print(f"[ERROR] Network scan failed: {e}")
    
    def _get_network_range(self):
        """Get the network IP range to scan"""
        try:
            # Get default gateway
            import subprocess
            import platform
            
            if platform.system() == 'Linux':
                # Try to get network interface and IP
                result = subprocess.check_output(['ip', 'route']).decode()
                for line in result.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            # Get interface
                            interface = parts[4]
                            # Get IP of interface
                            ip_result = subprocess.check_output(['ip', 'addr', 'show', interface]).decode()
                            for ip_line in ip_result.split('\n'):
                                if 'inet ' in ip_line and '127.0.0.1' not in ip_line:
                                    ip_addr = ip_line.strip().split()[1]
                                    # Convert to network range (e.g., 192.168.1.0/24)
                                    base_ip = '.'.join(ip_addr.split('.')[:3]) + '.0/24'
                                    return base_ip
            
            # Fallback: common private network ranges
            return '192.168.1.0/24'
            
        except Exception as e:
            print(f"[WARNING] Could not determine network range: {e}")
            return '192.168.1.0/24'  # Default fallback
    
    def _identify_device(self, mac):
        """Identify device type based on MAC address"""
        mac = mac.lower()
        mac_prefix = ':'.join(mac.split(':')[:3])
        
        # Check against known vendors
        for device_type, prefixes in MAC_VENDORS.items():
            if mac_prefix in [p.lower() for p in prefixes]:
                if device_type == 'apple':
                    return 'iOS/macOS'
                elif device_type in ['samsung', 'xiaomi', 'huawei', 'google']:
                    return 'Android'
                elif device_type in ['dell', 'hp', 'lenovo', 'asus']:
                    return 'Windows/Linux'
                elif device_type == 'raspberry':
                    return 'Linux (Raspberry Pi)'
        
        # Unknown device
        return 'Unknown'
    
    def _get_hostname(self, ip):
        """Try to get device hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return 'Unknown'


def get_connected_devices():
    """Get list of all connected devices"""
    with _devices_lock:
        return {
            'devices': list(_connected_devices.values()),
            'total_count': len(_connected_devices),
            'last_scan': _last_scan_time,
            'device_summary': _get_device_summary()
        }


def _get_device_summary():
    """Get summary of device types"""
    summary = defaultdict(int)
    for device in _connected_devices.values():
        device_type = device['type']
        summary[device_type] += 1
    return dict(summary)


# Global scanner instance
scanner = DeviceScanner()
