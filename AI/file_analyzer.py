"""File Analysis and Sandbox Module
Real file hash checking and basic malware detection.
NO FAKE VERDICTS - Real analysis only.
"""

import os
import hashlib
import subprocess
import json
import mimetypes
import platform
import shutil
from datetime import datetime
from typing import Dict, Optional

class FileAnalyzer:
    """Analyze files for threats using hashes and file type detection"""
    
    def __init__(self):
        # Use /app in Docker, ./server/json outside Docker
        base_dir = '/app' if os.path.exists('/app') else os.path.join(os.path.dirname(__file__), '..', 'server')
        self.analysis_log = os.path.join(base_dir, 'json', 'file_analysis.json')
        self.stats = {
            'analyzed': 0,
            'malicious': 0,
            'suspicious': 0,
            'clean': 0
        }
        self.load_stats()
        
    def load_stats(self):
        """Load analysis statistics"""
        try:
            if os.path.exists(self.analysis_log):
                with open(self.analysis_log, 'r') as f:
                    data = json.load(f)
                    self.stats = data.get('stats', self.stats)
        except:
            pass
    
    def save_stats(self):
        """Save analysis statistics"""
        try:
            with open(self.analysis_log, 'w') as f:
                json.dump({'stats': self.stats, 'updated': datetime.now().isoformat()}, f)
        except:
            pass
    
    def get_file_hash(self, filepath: str) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            print(f"[FILE_ANALYZER] Hash error: {e}")
        return hashes
    
    def get_file_type(self, filepath: str) -> str:
        """Detect file type (cross-platform)"""
        try:
            # Try mimetypes first (cross-platform)
            mime_type, _ = mimetypes.guess_type(filepath)
            if mime_type:
                return mime_type
            
            # Unix systems: try 'file' command
            if platform.system() in ['Linux', 'Darwin'] and shutil.which('file'):
                result = subprocess.run(['file', '-b', filepath], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return result.stdout.strip()[:100]
            
            # Fallback: check extension
            ext = os.path.splitext(filepath)[1].lower()
            ext_types = {
                '.txt': 'text/plain',
                '.pdf': 'application/pdf',
                '.exe': 'application/x-executable',
                '.dll': 'application/x-dll',
                '.sh': 'application/x-sh',
                '.py': 'text/x-python',
                '.js': 'text/javascript'
            }
            return ext_types.get(ext, 'application/octet-stream')
        except:
            return 'unknown'
    
    def analyze_file(self, filepath: str, filename: str) -> Dict:
        """Analyze uploaded file"""
        self.stats['analyzed'] += 1
        
        # Get file info
        file_size = os.path.getsize(filepath)
        file_type = self.get_file_type(filepath)
        hashes = self.get_file_hash(filepath)
        
        # Basic threat detection
        verdict = 'clean'
        threats_detected = 0
        analysis_notes = []
        
        # Check file type for suspicious patterns
        suspicious_types = ['executable', 'script', 'PE32', '.exe', 'batch', 'powershell']
        if any(s.lower() in file_type.lower() for s in suspicious_types):
            verdict = 'suspicious'
            threats_detected += 1
            analysis_notes.append('Executable file type detected')
            self.stats['suspicious'] += 1
        else:
            self.stats['clean'] += 1
        
        # Check for known malicious hashes (load from threat intel if available)
        if self.check_hash_reputation(hashes['sha256']):
            verdict = 'malicious'
            threats_detected += 1
            analysis_notes.append('Hash matches known malware')
            self.stats['malicious'] += 1
            self.stats['suspicious'] = max(0, self.stats['suspicious'] - 1)  # Reclassify
        
        self.save_stats()
        
        return {
            'success': True,
            'verdict': verdict,
            'filename': filename,
            'file_size': f"{file_size / 1024:.2f} KB" if file_size < 1024*1024 else f"{file_size / (1024*1024):.2f} MB",
            'file_type': file_type,
            'md5': hashes.get('md5', 'N/A'),
            'sha256': hashes.get('sha256', 'N/A'),
            'threats_detected': threats_detected,
            'analysis_notes': analysis_notes,
            'analysis_time': '< 1 second'
        }
    
    def check_hash_reputation(self, sha256: str) -> bool:
        """Check if hash is known malicious (checks local threat intel)"""
        try:
            # Check if hash exists in threat log
            sig_file = os.path.join(os.path.dirname(__file__), '..', 'relay', 'ai_training_materials', 'ai_signatures', 'learned_signatures.json')
            if os.path.exists(sig_file):
                with open(sig_file, 'r') as f:
                    data = json.load(f)
                    # This is a simplified check - would need proper hash database
                    if sha256 in str(data):
                        return True
        except:
            pass
        return False
    
    def get_stats(self) -> Dict:
        """Get analysis statistics"""
        return self.stats

# Global instance
file_analyzer = FileAnalyzer()
