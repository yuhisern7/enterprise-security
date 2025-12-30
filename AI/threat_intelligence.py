"""Advanced Threat Intelligence Integration Module

Integrates with external threat intelligence sources to enhance AI learning:
- VirusTotal: IP/URL/File reputation from 70+ vendors
- AbuseIPDB: Community-driven IP blacklist
- ExploitDB: Exploit signature database scraper
- Custom Honeypot: Collect real attack patterns

This module feeds threat data to the ML models for continuous learning.
"""

import requests
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict
import threading
import os
import sys

# Add AI directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Import ExploitDB scraper
try:
    from exploitdb_scraper import start_exploitdb_scraper, get_scraper
    SCRAPER_AVAILABLE = True
except ImportError as e:
    SCRAPER_AVAILABLE = False
    print(f"[WARNING] ExploitDB scraper not available: {e}")

# Import Threat Crawlers
try:
    from threat_crawler import (
        ThreatCrawlerManager,
        CVECrawler,
        MalwareBazaarCrawler,
        AlienVaultOTXCrawler,
        URLhausCrawler,
        AttackerKBCrawler
    )
    CRAWLER_AVAILABLE = True
except ImportError as e:
    CRAWLER_AVAILABLE = False
    print(f"[WARNING] Threat crawlers not available: {e}")

# Configuration - Load from environment variables
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")  # REQUIRED: Get free key from https://www.virustotal.com/gui/join-us
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")  # Optional: Get free key from https://www.abuseipdb.com/
EXPLOITDB_UPDATE_INTERVAL = 86400  # 24 hours
VIRUSTOTAL_RATE_LIMIT = 4  # requests per minute (free tier)

# Cache for API results (avoid duplicate queries)
_vt_cache = {}  # IP -> {result, timestamp}
_abuseipdb_cache = {}
_exploitdb_signatures = []  # List of exploit patterns
_threat_intel_log = []  # Log of threat intelligence findings

# Rate limiting
_vt_request_times = []
_abuseipdb_request_times = []


class ThreatIntelligence:
    """Main threat intelligence aggregator"""
    
    def __init__(self):
        self.vt_enabled = bool(VIRUSTOTAL_API_KEY)
        self.abuseipdb_enabled = bool(ABUSEIPDB_API_KEY)
        self.exploitdb_enabled = True
        
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP reputation across all threat intelligence sources.
        
        Returns aggregated threat score and details from:
        - VirusTotal (vendor detections)
        - AbuseIPDB (abuse reports)
        - Internal ML models
        """
        result = {
            "ip": ip_address,
            "timestamp": datetime.utcnow().isoformat(),
            "threat_score": 0,  # 0-100 (100 = maximum threat)
            "sources": [],
            "details": {},
            "recommendations": []
        }
        
        # Check VirusTotal
        if self.vt_enabled:
            vt_data = self._check_virustotal_ip(ip_address)
            if vt_data:
                result["sources"].append("VirusTotal")
                result["details"]["virustotal"] = vt_data
                result["threat_score"] += vt_data.get("threat_contribution", 0)
        
        # Check AbuseIPDB
        if self.abuseipdb_enabled:
            abuse_data = self._check_abuseipdb(ip_address)
            if abuse_data:
                result["sources"].append("AbuseIPDB")
                result["details"]["abuseipdb"] = abuse_data
                result["threat_score"] += abuse_data.get("threat_contribution", 0)
        
        # Generate recommendations
        if result["threat_score"] >= 80:
            result["recommendations"].append("BLOCK_IMMEDIATELY")
            result["recommendations"].append("ADD_TO_FIREWALL_BLACKLIST")
        elif result["threat_score"] >= 50:
            result["recommendations"].append("RATE_LIMIT_AGGRESSIVE")
            result["recommendations"].append("REQUIRE_CAPTCHA")
        elif result["threat_score"] >= 20:
            result["recommendations"].append("MONITOR_CLOSELY")
        
        # Cap threat score at 100
        result["threat_score"] = min(result["threat_score"], 100)
        
        # Log for ML training
        _threat_intel_log.append(result)
        
        return result
    
    def _check_virustotal_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal API for IP reputation"""
        
        # Check cache (valid for 1 hour)
        cache_key = ip_address
        if cache_key in _vt_cache:
            cached = _vt_cache[cache_key]
            if datetime.utcnow() - cached["timestamp"] < timedelta(hours=1):
                return cached["data"]
        
        # Rate limiting (4 requests/minute for free tier)
        if not self._check_rate_limit(_vt_request_times, VIRUSTOTAL_RATE_LIMIT, 60):
            print(f"[ThreatIntel] VirusTotal rate limit reached, using cache")
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Accept": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            _vt_request_times.append(time.time())
            
            if response.status_code == 200:
                data = response.json()
                analysis = data.get("data", {}).get("attributes", {})
                
                # Extract key metrics
                last_analysis_stats = analysis.get("last_analysis_stats", {})
                malicious = last_analysis_stats.get("malicious", 0)
                suspicious = last_analysis_stats.get("suspicious", 0)
                harmless = last_analysis_stats.get("harmless", 0)
                total_vendors = malicious + suspicious + harmless
                
                result = {
                    "malicious_vendors": malicious,
                    "suspicious_vendors": suspicious,
                    "harmless_vendors": harmless,
                    "total_vendors": total_vendors,
                    "reputation": analysis.get("reputation", 0),
                    "country": analysis.get("country", "Unknown"),
                    "asn": analysis.get("asn", "Unknown"),
                    "as_owner": analysis.get("as_owner", "Unknown"),
                    "threat_contribution": 0
                }
                
                # Calculate threat contribution (0-60 points)
                if total_vendors > 0:
                    malicious_ratio = malicious / total_vendors
                    result["threat_contribution"] = int(malicious_ratio * 60)
                    
                    # Add suspicious vendors (half weight)
                    suspicious_ratio = suspicious / total_vendors
                    result["threat_contribution"] += int(suspicious_ratio * 30)
                
                # Cache result
                _vt_cache[cache_key] = {
                    "data": result,
                    "timestamp": datetime.utcnow()
                }
                
                print(f"[ThreatIntel] VirusTotal: {ip_address} flagged by {malicious}/{total_vendors} vendors")
                return result
            
            elif response.status_code == 404:
                # IP not in VirusTotal database (likely clean)
                return {
                    "malicious_vendors": 0,
                    "total_vendors": 0,
                    "threat_contribution": 0,
                    "note": "IP not found in VirusTotal database"
                }
            else:
                print(f"[ThreatIntel] VirusTotal API error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[ThreatIntel] VirusTotal query failed: {e}")
            return None
    
    def _check_abuseipdb(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB for IP abuse reports"""
        
        if not ABUSEIPDB_API_KEY:
            return None
        
        # Check cache (valid for 6 hours)
        cache_key = ip_address
        if cache_key in _abuseipdb_cache:
            cached = _abuseipdb_cache[cache_key]
            if datetime.utcnow() - cached["timestamp"] < timedelta(hours=6):
                return cached["data"]
        
        # Rate limiting (1000 requests/day = ~1 per minute to be safe)
        if not self._check_rate_limit(_abuseipdb_request_times, 1, 60):
            return None
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            _abuseipdb_request_times.append(time.time())
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                
                result = {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported": data.get("lastReportedAt", None),
                    "country_code": data.get("countryCode", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "usage_type": data.get("usageType", "Unknown"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "threat_contribution": 0
                }
                
                # Calculate threat contribution (0-40 points)
                confidence = data.get("abuseConfidenceScore", 0)
                result["threat_contribution"] = int(confidence * 0.4)
                
                # Cache result
                _abuseipdb_cache[cache_key] = {
                    "data": result,
                    "timestamp": datetime.utcnow()
                }
                
                print(f"[ThreatIntel] AbuseIPDB: {ip_address} confidence={confidence}%, reports={result['total_reports']}")
                return result
            else:
                print(f"[ThreatIntel] AbuseIPDB API error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[ThreatIntel] AbuseIPDB query failed: {e}")
            return None
    
    def _check_rate_limit(self, request_times: List[float], max_requests: int, time_window: int) -> bool:
        """Check if we're within rate limits"""
        now = time.time()
        # Remove old timestamps outside the time window
        while request_times and now - request_times[0] > time_window:
            request_times.pop(0)
        
        return len(request_times) < max_requests
    
    def scrape_exploitdb_signatures(self) -> int:
        """
        Scrape ExploitDB for latest exploit signatures.
        Returns number of new signatures added.
        """
        try:
            print("[ThreatIntel] Scraping ExploitDB for exploit signatures...")
            
            # ExploitDB CSV feed (updated daily)
            url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
            
            response = requests.get(url, timeout=30)
            if response.status_code != 200:
                print(f"[ThreatIntel] ExploitDB scrape failed: HTTP {response.status_code}")
                return 0
            
            # Parse CSV (id,file,description,date,author,type,platform,port)
            lines = response.text.split('\n')[1:]  # Skip header
            new_signatures = 0
            
            for line in lines[:1000]:  # Limit to latest 1000 exploits
                if not line.strip():
                    continue
                
                try:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        exploit_id = parts[0]
                        description = parts[2].lower()
                        exploit_type = parts[5] if len(parts) > 5 else "unknown"
                        
                        # Extract attack patterns from description
                        signature = {
                            "id": f"exploitdb-{exploit_id}",
                            "description": description,
                            "type": exploit_type,
                            "patterns": self._extract_attack_patterns(description)
                        }
                        
                        # Add if not duplicate
                        if not any(sig["id"] == signature["id"] for sig in _exploitdb_signatures):
                            _exploitdb_signatures.append(signature)
                            new_signatures += 1
                
                except Exception as e:
                    continue
            
            print(f"[ThreatIntel] ExploitDB: Added {new_signatures} new signatures (Total: {len(_exploitdb_signatures)})")
            return new_signatures
            
        except Exception as e:
            print(f"[ThreatIntel] ExploitDB scrape error: {e}")
            return 0
    
    def _extract_attack_patterns(self, description: str) -> List[str]:
        """Extract attack patterns from exploit description"""
        patterns = []
        
        # Common attack indicators
        keywords = [
            'sql injection', 'sqli', 'xss', 'cross-site scripting',
            'buffer overflow', 'rce', 'remote code execution',
            'lfi', 'rfi', 'file inclusion', 'directory traversal',
            'csrf', 'ssrf', 'xxe', 'ssti', 'command injection',
            'ldap injection', 'xpath injection', 'authentication bypass'
        ]
        
        for keyword in keywords:
            if keyword in description:
                patterns.append(keyword)
        
        return patterns
    
    def get_threat_intelligence_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics for dashboard"""
        return {
            "virustotal_enabled": self.vt_enabled,
            "abuseipdb_enabled": self.abuseipdb_enabled,
            "exploitdb_signatures": len(_exploitdb_signatures),
            "virustotal_cache_size": len(_vt_cache),
            "abuseipdb_cache_size": len(_abuseipdb_cache),
            "threat_intel_queries": len(_threat_intel_log),
            "last_exploitdb_update": datetime.utcnow().isoformat()
        }


# Honeypot Crawler System
class HoneypotCrawler:
    """
    Deploy fake vulnerable services on different ports to attract and learn from attackers.
    Each service can be enabled/disabled individually.
    """
    
    def __init__(self):
        self.attack_log = []
        self.learned_patterns = []
        
        # Available honeypot services (configurable)
        self.available_honeypots = {
            "web_admin": {
                "name": "Fake Admin Panel",
                "port": 8080,
                "protocol": "HTTP",
                "enabled": True,
                "description": "Fake web admin login (catches brute force, credential stuffing)",
                "endpoints": ["/admin/login.php", "/admin/", "/administrator/"],
                "attacks": 0
            },
            "wordpress": {
                "name": "Fake WordPress",
                "port": 8081,
                "protocol": "HTTP",
                "enabled": True,
                "description": "Fake WordPress site (catches WP-specific exploits)",
                "endpoints": ["/wp-admin/", "/wp-login.php", "/xmlrpc.php"],
                "attacks": 0
            },
            "phpmyadmin": {
                "name": "Fake phpMyAdmin",
                "port": 8082,
                "protocol": "HTTP",
                "enabled": True,
                "description": "Fake database admin (catches DB exploitation attempts)",
                "endpoints": ["/phpmyadmin/", "/pma/", "/mysql/"],
                "attacks": 0
            },
            "ftp": {
                "name": "Fake FTP Server",
                "port": 2121,
                "protocol": "FTP",
                "enabled": False,
                "description": "Fake FTP server (catches file upload exploits, brute force)",
                "endpoints": ["ftp://fake-server:2121"],
                "attacks": 0
            },
            "ssh": {
                "name": "Fake SSH Server",
                "port": 2222,
                "protocol": "SSH",
                "enabled": False,
                "description": "Fake SSH server (catches SSH brute force, key exploits)",
                "endpoints": ["ssh://fake-server:2222"],
                "attacks": 0
            },
            "telnet": {
                "name": "Fake Telnet Server",
                "port": 2323,
                "protocol": "Telnet",
                "enabled": False,
                "description": "Fake Telnet server (catches IoT exploits, Mirai botnet)",
                "endpoints": ["telnet://fake-server:2323"],
                "attacks": 0
            },
            "rdp": {
                "name": "Fake RDP Server",
                "port": 3389,
                "protocol": "RDP",
                "enabled": False,
                "description": "Fake Windows RDP (catches ransomware, lateral movement)",
                "endpoints": ["rdp://fake-server:3389"],
                "attacks": 0
            },
            "netbios": {
                "name": "Fake NetBIOS/SMB",
                "port": 445,
                "protocol": "SMB",
                "enabled": False,
                "description": "Fake Windows file sharing (catches EternalBlue, WannaCry)",
                "endpoints": ["smb://fake-server:445"],
                "attacks": 0
            },
            "mysql": {
                "name": "Fake MySQL Server",
                "port": 3306,
                "protocol": "MySQL",
                "enabled": False,
                "description": "Fake MySQL database (catches SQL injection, DB exploits)",
                "endpoints": ["mysql://fake-server:3306"],
                "attacks": 0
            },
            "api": {
                "name": "Fake REST API",
                "port": 8083,
                "protocol": "HTTP",
                "enabled": True,
                "description": "Fake API endpoints (catches API abuse, injection)",
                "endpoints": ["/api/v1/users", "/api/admin", "/api/login"],
                "attacks": 0
            },
            "git": {
                "name": "Fake Git Repository",
                "port": 8084,
                "protocol": "HTTP",
                "enabled": True,
                "description": "Exposed .git folder (catches source code theft)",
                "endpoints": ["/.git/config", "/.git/HEAD", "/.env"],
                "attacks": 0
            },
            "vnc": {
                "name": "Fake VNC Server",
                "port": 5900,
                "protocol": "VNC",
                "enabled": False,
                "description": "Fake VNC remote desktop (catches remote access exploits)",
                "endpoints": ["vnc://fake-server:5900"],
                "attacks": 0
            }
        }
        
    def deploy_honeypots(self) -> List[str]:
        """
        Deploy enabled honeypot services.
        Returns list of active honeypot endpoints.
        """
        active_endpoints = []
        enabled_count = 0
        
        for service_id, service in self.available_honeypots.items():
            if service["enabled"]:
                active_endpoints.extend(service["endpoints"])
                enabled_count += 1
        
        print(f"[Honeypot] Deployed {enabled_count} honeypot services ({len(active_endpoints)} endpoints)")
        return active_endpoints
    
    def toggle_honeypot(self, service_id: str, enabled: bool) -> bool:
        """Enable or disable a specific honeypot service"""
        if service_id in self.available_honeypots:
            self.available_honeypots[service_id]["enabled"] = enabled
            status = "enabled" if enabled else "disabled"
            print(f"[Honeypot] {self.available_honeypots[service_id]['name']} {status}")
            return True
        return False
    
    def get_honeypot_status(self) -> Dict[str, Any]:
        """Get detailed status of all honeypots"""
        return {
            "services": self.available_honeypots,
            "total_services": len(self.available_honeypots),
            "enabled_services": sum(1 for s in self.available_honeypots.values() if s["enabled"]),
            "total_attacks": sum(s["attacks"] for s in self.available_honeypots.values()),
            "attack_log_size": len(self.attack_log),
            "learned_patterns": len(self.learned_patterns)
        }
        
    def log_honeypot_attack(self, endpoint: str, ip: str, headers: Dict, payload: str):
        """Log attack attempt on honeypot for ML training"""
        attack = {
            "timestamp": datetime.utcnow().isoformat(),
            "endpoint": endpoint,
            "ip": ip,
            "headers": headers,
            "payload": payload,
            "attack_type": self._classify_attack_type(endpoint, payload)
        }
        
        self.attack_log.append(attack)
        
        # Learn new patterns
        new_pattern = self._extract_attack_pattern(payload)
        if new_pattern and new_pattern not in self.learned_patterns:
            self.learned_patterns.append(new_pattern)
            print(f"[Honeypot] Learned new attack pattern: {new_pattern[:100]}")
        
        print(f"[Honeypot] Logged attack from {ip} on {endpoint}")
        return attack
    
    def _classify_attack_type(self, endpoint: str, payload: str) -> str:
        """Classify attack type based on endpoint and payload"""
        payload_lower = payload.lower()
        
        if "admin" in endpoint.lower():
            return "admin_panel_probe"
        elif "wp-" in endpoint.lower():
            return "wordpress_scan"
        elif ".env" in endpoint or ".git" in endpoint:
            return "sensitive_file_access"
        elif "select" in payload_lower and "from" in payload_lower:
            return "sql_injection"
        elif "<script" in payload_lower:
            return "xss_attempt"
        else:
            return "unknown_probe"
    
    def _extract_attack_pattern(self, payload: str) -> Optional[str]:
        """Extract reusable attack pattern from payload"""
        if len(payload) > 10:
            # Normalize payload for pattern matching
            pattern = payload.lower().strip()
            return pattern
        return None
    
    def get_honeypot_stats(self) -> Dict[str, Any]:
        """Get honeypot statistics"""
        attack_types = defaultdict(int)
        for attack in self.attack_log:
            attack_types[attack["attack_type"]] += 1
        
        return {
            "total_attacks": len(self.attack_log),
            "learned_patterns": len(self.learned_patterns),
            "attack_types": dict(attack_types),
            "unique_ips": len(set(a["ip"] for a in self.attack_log))
        }


# Global instances
threat_intel = ThreatIntelligence()
honeypot = HoneypotCrawler()


# Background thread for periodic ExploitDB updates
def _background_exploitdb_updater():
    """Background thread to update ExploitDB signatures daily"""
    while True:
        try:
            threat_intel.scrape_exploitdb_signatures()
            time.sleep(EXPLOITDB_UPDATE_INTERVAL)
        except Exception as e:
            print(f"[ThreatIntel] Background updater error: {e}")
            time.sleep(3600)  # Retry in 1 hour on error


def start_threat_intelligence_engine():
    """Start background threat intelligence services"""
    print("[ThreatIntel] Starting threat intelligence engine...")
    
    # Start ExploitDB scraper (comprehensive learning mode)
    if SCRAPER_AVAILABLE:
        # Check if local ExploitDB exists
        exploitdb_path = os.path.join(os.path.dirname(__file__), "exploitdb")
        if os.path.exists(exploitdb_path):
            print(f"[ThreatIntel] Using local ExploitDB at {exploitdb_path}")
            start_exploitdb_scraper(exploitdb_path=exploitdb_path, continuous=True)
        else:
            print("[ThreatIntel] No local ExploitDB found, using web scraping")
            start_exploitdb_scraper(exploitdb_path="exploitdb", continuous=True)
    else:
        # Fallback to simple scraping
        threat_intel.scrape_exploitdb_signatures()
        
        # Start background updater
        updater_thread = threading.Thread(target=_background_exploitdb_updater, daemon=True)
        updater_thread.start()
    
    # Start Threat Crawlers (for continuous intelligence gathering)
    if CRAWLER_AVAILABLE:
        print("[ThreatIntel] Starting threat intelligence crawlers...")
        crawler_manager = ThreatCrawlerManager()
        
        # ✅ ACTIONABLE CRAWLERS ONLY (hashes, URLs, scores - NOT English text)
        # MalwareBazaar: File hashes (MD5, SHA256, SHA1) - Direct signatures
        crawler_manager.add_crawler(MalwareBazaarCrawler())
        
        # URLhaus: Malicious URLs - Blocking/filtering
        crawler_manager.add_crawler(URLhausCrawler())
        
        # CVE: Vulnerability scores (CVSS numerical ratings)
        crawler_manager.add_crawler(CVECrawler())
        
        # ❌ DISABLED: Text-heavy crawlers (AI can't learn from English descriptions)
        # crawler_manager.add_crawler(AlienVaultOTXCrawler())  # English threat reports
        # crawler_manager.add_crawler(AttackerKBCrawler())     # English assessments
        
        # Start crawling in background (every 6 hours)
        def run_crawlers():
            while True:
                try:
                    print("[ThreatIntel] Running threat intelligence crawlers...")
                    threats = crawler_manager.crawl_all()
                    print(f"[ThreatIntel] Collected {len(threats)} threat indicators from crawlers")
                    
                    # Feed to ML models for training
                    global _threat_intel_log
                    _threat_intel_log.extend(threats)
                    
                    # Sleep for 6 hours
                    time.sleep(21600)
                except Exception as e:
                    print(f"[ThreatIntel] Crawler error: {e}")
                    time.sleep(3600)  # Retry in 1 hour
        
        crawler_thread = threading.Thread(target=run_crawlers, daemon=True)
        crawler_thread.start()
        print("[ThreatIntel] ✅ Threat crawlers started (running every 6 hours)")
    else:
        print("[ThreatIntel] ⚠️ Threat crawlers not available - install requests library")
    
    # Deploy honeypots
    honeypot.deploy_honeypots()
    
    print("[ThreatIntel] ✅ Threat intelligence engine started")


if __name__ == "__main__":
    # Test threat intelligence
    start_threat_intelligence_engine()
    
    # Test IP check
    test_ip = "208.95.112.1"
    result = threat_intel.check_ip_reputation(test_ip)
    print(f"\n[TEST] Threat Intelligence Report for {test_ip}:")
    print(json.dumps(result, indent=2))
