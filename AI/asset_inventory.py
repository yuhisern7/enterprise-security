"""Asset Inventory & Management Module
Complete asset database with software tracking, licenses, EOL detection.
NO FAKE DATA - Real system inventory.
"""

import os
import json
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict

class AssetInventory:
    """Track hardware and software assets across the network"""
    
    def __init__(self):
        # Use /app in Docker, ./server/json outside Docker
        base_dir = '/app' if os.path.exists('/app') else os.path.join(os.path.dirname(__file__), '..', 'server')
        self.inventory_file = os.path.join(base_dir, 'json', 'asset_inventory.json')
        self.software_file = os.path.join(base_dir, 'json', 'software_inventory.json')
        self.assets = self.load_inventory()
        
    def load_inventory(self) -> Dict:
        """Load asset inventory from disk"""
        try:
            if os.path.exists(self.inventory_file):
                with open(self.inventory_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {'hardware': [], 'software': [], 'licenses': []}
    
    def save_inventory(self):
        """Save asset inventory to disk"""
        try:
            with open(self.inventory_file, 'w') as f:
                json.dump(self.assets, f, indent=2)
        except Exception as e:
            print(f"[ASSET] Save error: {e}")
    
    def scan_software(self) -> List[Dict]:
        """Scan installed software packages (cross-platform)"""
        software = []
        system = platform.system()
        
        # Linux (Debian/Ubuntu) - dpkg
        if system == 'Linux' and shutil.which('dpkg'):
            try:
                result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('ii'):
                            parts = line.split()
                            if len(parts) >= 3:
                                software.append({
                                    'name': parts[1],
                                    'version': parts[2],
                                    'type': 'system_package',
                                    'package_manager': 'dpkg',
                                    'last_seen': datetime.now().isoformat()
                                })
            except:
                pass
        
        # macOS - Homebrew
        if system == 'Darwin' and shutil.which('brew'):
            try:
                result = subprocess.run(['brew', 'list', '--versions'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                software.append({
                                    'name': parts[0],
                                    'version': parts[1],
                                    'type': 'system_package',
                                    'package_manager': 'brew',
                                    'last_seen': datetime.now().isoformat()
                                })
            except:
                pass
        
        # Windows - via PowerShell Get-Package or wmic
        if system == 'Windows':
            try:
                # Try PowerShell Get-Package first
                result = subprocess.run(
                    ['powershell', '-Command', 'Get-Package | Select-Object Name,Version | ConvertTo-Csv -NoTypeInformation'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    lines = result.stdout.split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.strip('\"').split('\",\"')
                            if len(parts) >= 2:
                                software.append({
                                    'name': parts[0],
                                    'version': parts[1],
                                    'type': 'system_package',
                                    'package_manager': 'windows',
                                    'last_seen': datetime.now().isoformat()
                                })
            except:
                pass
        
        # Python packages (cross-platform)
        if shutil.which('pip3') or shutil.which('pip'):
            try:
                pip_cmd = 'pip3' if shutil.which('pip3') else 'pip'
                result = subprocess.run([pip_cmd, 'list'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n')[2:]:  # Skip header
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                software.append({
                                    'name': parts[0],
                                    'version': parts[1],
                                    'type': 'python_package',
                                    'package_manager': pip_cmd,
                                    'last_seen': datetime.now().isoformat()
                                })
            except:
                pass
        
        return software[:100]  # Limit to 100 for performance
    
    def detect_eol_software(self, software_list: List[Dict]) -> List[Dict]:
        """Detect end-of-life software (simplified detection)"""
        eol_software = []
        
        # Known EOL patterns (simplified - in production, use API)
        eol_patterns = {
            'python2': '2020-01-01',
            'python3.6': '2021-12-23',
            'ubuntu18.04': '2023-05-31',
            'debian9': '2022-06-30'
        }
        
        for software in software_list:
            name_lower = software['name'].lower()
            for pattern, eol_date in eol_patterns.items():
                if pattern in name_lower:
                    eol_software.append({
                        **software,
                        'eol_date': eol_date,
                        'status': 'end_of_life',
                        'risk': 'high'
                    })
                    break
        
        return eol_software
    
    def detect_shadow_it(self, software_list: List[Dict]) -> List[Dict]:
        """Detect unauthorized/shadow IT software"""
        shadow_it = []
        
        # Unauthorized software patterns (example)
        unauthorized_patterns = ['torrent', 'telegram', 'discord', 'teamviewer']
        
        for software in software_list:
            name_lower = software['name'].lower()
            for pattern in unauthorized_patterns:
                if pattern in name_lower:
                    shadow_it.append({
                        **software,
                        'reason': f'Unauthorized software: {pattern}',
                        'detected_at': datetime.now().isoformat()
                    })
                    break
        
        return shadow_it
    
    def calculate_asset_criticality(self, asset: Dict) -> str:
        """Calculate asset criticality score"""
        # Simplified criticality logic
        asset_type = asset.get('type', '').lower()
        
        if 'server' in asset_type or 'router' in asset_type:
            return 'critical'
        elif 'computer' in asset_type or 'laptop' in asset_type:
            return 'high'
        elif 'camera' in asset_type or 'iot' in asset_type:
            return 'medium'
        else:
            return 'low'
    
    def get_stats(self) -> Dict:
        """Get asset inventory statistics"""
        # Scan software
        software = self.scan_software()
        eol_software = self.detect_eol_software(software)
        shadow_it = self.detect_shadow_it(software)
        
        # Get hardware count from device scanner
        hardware_count = len(self.assets.get('hardware', []))
        
        return {
            'total_assets': hardware_count + len(software),
            'hardware_assets': hardware_count,
            'software_packages': len(software),
            'eol_software': len(eol_software),
            'shadow_it': len(shadow_it),
            'licenses_tracked': len(self.assets.get('licenses', [])),
            'critical_assets': sum(1 for a in self.assets.get('hardware', []) if self.calculate_asset_criticality(a) == 'critical'),
            'eol_list': eol_software[:10],  # Top 10 EOL items
            'shadow_it_list': shadow_it[:10]  # Top 10 shadow IT items
        }

# Global instance
asset_inventory = AssetInventory()
