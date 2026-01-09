"""Enterprise Security Integration Module

Enables integration with corporate security infrastructure:
- SIEM systems (Splunk, IBM QRadar, ArcSight, Elastic SIEM)
- SOC platforms (Cortex XSOAR, Demisto, TheHive)
- Standardized event formats (CEF, Syslog, STIX/TAXII)
- REST API for external systems
- Webhooks for real-time alerts
- Multi-tenancy support for MSPs

This makes the system sellable to enterprise customers.
"""

import json
import socket
import hashlib
import hmac
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from collections import defaultdict
import threading
import queue
import requests


class SecurityEventFormatter:
    """
    Convert internal threat events to standardized formats
    for SIEM/SOC integration.
    """
    
    @staticmethod
    def to_cef(event: Dict[str, Any]) -> str:
        """
        Convert to Common Event Format (CEF) - ArcSight, Splunk, QRadar
        
        CEF Format:
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        # Map threat levels to CEF severity (0-10)
        severity_map = {
            "SAFE": 0,
            "SUSPICIOUS": 3,
            "DANGEROUS": 7,
            "CRITICAL": 10
        }
        
        severity = severity_map.get(event.get("level", "SUSPICIOUS"), 5)
        
        # CEF header
        cef_header = (
            f"CEF:0|"
            f"YourCompany|"
            f"HomeSecurityAI|"
            f"1.0|"
            f"{event.get('threat_type', 'Unknown').replace(' ', '_')}|"
            f"{event.get('threat_type', 'Security Threat')}|"
            f"{severity}|"
        )
        
        # CEF extensions (key-value pairs)
        extensions = []
        
        # Source IP
        if event.get("ip_address"):
            extensions.append(f"src={event['ip_address']}")
        
        # Geolocation
        geo = event.get("geolocation", {})
        if geo.get("country"):
            extensions.append(f"sourceGeoLocationCountry={geo['country']}")
        if geo.get("city"):
            extensions.append(f"sourceGeoLocationCity={geo['city']}")
        
        # Threat details
        if event.get("details"):
            # Escape pipes and backslashes in details
            details = event['details'].replace('\\', '\\\\').replace('|', '\\|')
            extensions.append(f"msg={details}")
        
        # Timestamp
        if event.get("timestamp"):
            # Convert to epoch milliseconds
            try:
                dt = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                epoch_ms = int(dt.timestamp() * 1000)
                extensions.append(f"rt={epoch_ms}")
            except:
                pass
        
        # Action taken
        if event.get("action"):
            extensions.append(f"act={event['action']}")
        
        # Anonymization detection
        anon = event.get("anonymization_detection", {})
        if anon.get("is_anonymized"):
            extensions.append(f"cs1Label=AnonymizationType")
            extensions.append(f"cs1={anon.get('anonymization_type', 'unknown')}")
            extensions.append(f"cn1Label=AnonymizationConfidence")
            extensions.append(f"cn1={anon.get('confidence', 0)}")
        
        # Combine header and extensions
        cef_message = cef_header + " ".join(extensions)
        return cef_message
    
    @staticmethod
    def to_leef(event: Dict[str, Any]) -> str:
        """
        Convert to Log Event Extended Format (LEEF) - IBM QRadar
        
        LEEF Format:
        LEEF:Version|Vendor|Product|Version|EventID|delimiter|key1=value1<delimiter>key2=value2
        """
        leef_header = (
            f"LEEF:2.0|"
            f"YourCompany|"
            f"HomeSecurityAI|"
            f"1.0|"
            f"{event.get('threat_type', 'Unknown').replace(' ', '_')}|"
            f"^|"
        )
        
        fields = []
        
        # Core fields
        fields.append(f"src={event.get('ip_address', 'Unknown')}")
        fields.append(f"severity={event.get('level', 'UNKNOWN')}")
        fields.append(f"cat={event.get('threat_type', 'Unknown')}")
        
        # Geolocation
        geo = event.get("geolocation", {})
        if geo.get("country"):
            fields.append(f"srcCountry={geo['country']}")
        
        # Details
        if event.get("details"):
            details = event['details'].replace('^', '').replace('|', '')[:255]
            fields.append(f"usrName={details}")
        
        # Timestamp
        if event.get("timestamp"):
            fields.append(f"devTime={event['timestamp']}")
        
        leef_message = leef_header + "^".join(fields)
        return leef_message
    
    @staticmethod
    def to_syslog(event: Dict[str, Any], facility: int = 16, severity: int = 4) -> str:
        """
        Convert to Syslog format (RFC 5424)
        
        Facility 16 = local use 0 (local0)
        Severity: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug
        """
        # Map threat levels to syslog severity
        severity_map = {
            "CRITICAL": 2,  # Critical
            "DANGEROUS": 3,  # Error
            "SUSPICIOUS": 4,  # Warning
            "SAFE": 6  # Informational
        }
        
        severity = severity_map.get(event.get("level", "SUSPICIOUS"), 4)
        priority = (facility * 8) + severity
        
        # Timestamp in RFC3339 format
        timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat() + "Z")
        
        # Hostname
        hostname = socket.gethostname()
        
        # App name and process ID
        app_name = "HomeSecurityAI"
        procid = "-"
        msgid = event.get("threat_type", "THREAT").replace(" ", "_")
        
        # Structured data
        structured_data = f"[threat@12345 "
        structured_data += f'ip="{event.get("ip_address", "Unknown")}" '
        structured_data += f'level="{event.get("level", "UNKNOWN")}" '
        structured_data += f'type="{event.get("threat_type", "Unknown")}"'
        
        geo = event.get("geolocation", {})
        if geo.get("country"):
            structured_data += f' country="{geo["country"]}"'
        
        structured_data += "]"
        
        # Message
        msg = event.get("details", "Security threat detected")
        
        syslog_message = (
            f"<{priority}>1 "
            f"{timestamp} "
            f"{hostname} "
            f"{app_name} "
            f"{procid} "
            f"{msgid} "
            f"{structured_data} "
            f"{msg}"
        )
        
        return syslog_message
    
    @staticmethod
    def to_stix(events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Convert to STIX 2.1 format (Structured Threat Information Expression)
        Used for threat intelligence sharing between organizations.
        """
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{hashlib.sha256(str(time.time()).encode()).hexdigest()}",
            "objects": []
        }
        
        for event in events:
            # Create STIX Indicator object
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{hashlib.sha256((event.get('ip_address', '') + event.get('timestamp', '')).encode()).hexdigest()}",
                "created": event.get("timestamp", datetime.now(timezone.utc).isoformat() + "Z"),
                "modified": event.get("timestamp", datetime.now(timezone.utc).isoformat() + "Z"),
                "name": f"{event.get('threat_type', 'Unknown Threat')} from {event.get('ip_address', 'Unknown')}",
                "description": event.get("details", "Security threat detected"),
                "pattern": f"[ipv4-addr:value = '{event.get('ip_address', '0.0.0.0')}']",
                "pattern_type": "stix",
                "valid_from": event.get("timestamp", datetime.now(timezone.utc).isoformat() + "Z"),
                "labels": [
                    event.get("threat_type", "malicious-activity").lower().replace(" ", "-"),
                    event.get("level", "medium").lower()
                ]
            }
            
            stix_bundle["objects"].append(indicator)
            
            # Create STIX Observed Data object
            observed_data = {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": f"observed-data--{hashlib.sha256((event.get('ip_address', '') + 'obs').encode()).hexdigest()}",
                "created": event.get("timestamp", datetime.now(timezone.utc).isoformat() + "Z"),
                "modified": event.get("timestamp", datetime.now(timezone.utc).isoformat() + "Z"),
                "first_observed": event.get("timestamp", datetime.now(timezone.utc).isoformat() + "Z"),
                "last_observed": event.get("timestamp", datetime.now(timezone.utc).isoformat() + "Z"),
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "ipv4-addr",
                        "value": event.get("ip_address", "0.0.0.0")
                    }
                }
            }
            
            stix_bundle["objects"].append(observed_data)
        
        return stix_bundle


class SIEMIntegration:
    """
    SIEM Integration Manager
    Sends security events to external SIEM systems.
    """
    
    def __init__(self):
        self.event_queue = queue.Queue()
        self.syslog_targets = []  # [(host, port, protocol)]
        self.webhook_targets = []  # [(url, secret)]
        self.running = False
        
    def add_syslog_target(self, host: str, port: int = 514, protocol: str = "UDP"):
        """Add syslog destination (Splunk, QRadar, etc.)"""
        self.syslog_targets.append({
            "host": host,
            "port": port,
            "protocol": protocol.upper()
        })
        print(f"[SIEM] Added syslog target: {host}:{port} ({protocol})")
    
    def add_webhook(self, url: str, secret: Optional[str] = None):
        """Add webhook for real-time alerts (Slack, Teams, PagerDuty, etc.)"""
        self.webhook_targets.append({
            "url": url,
            "secret": secret
        })
        print(f"[SIEM] Added webhook target: {url}")
    
    def send_event(self, event: Dict[str, Any], format_type: str = "CEF"):
        """
        Send security event to all configured destinations.
        
        Supported formats:
        - CEF (Common Event Format)
        - LEEF (Log Event Extended Format)
        - Syslog (RFC 5424)
        - JSON (native format)
        """
        self.event_queue.put((event, format_type))
    
    def start(self):
        """Start background event sender"""
        self.running = True
        sender_thread = threading.Thread(target=self._event_sender_loop, daemon=True)
        sender_thread.start()
        print("[SIEM] Integration service started")
    
    def stop(self):
        """Stop background event sender"""
        self.running = False
    
    def _event_sender_loop(self):
        """Background thread to send events"""
        while self.running:
            try:
                # Get event from queue (timeout to allow checking self.running)
                try:
                    event, format_type = self.event_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Format event
                if format_type == "CEF":
                    message = SecurityEventFormatter.to_cef(event)
                elif format_type == "LEEF":
                    message = SecurityEventFormatter.to_leef(event)
                elif format_type == "Syslog":
                    message = SecurityEventFormatter.to_syslog(event)
                else:  # JSON
                    message = json.dumps(event)
                
                # Send to syslog targets
                for target in self.syslog_targets:
                    self._send_syslog(message, target)
                
                # Send to webhooks
                for webhook in self.webhook_targets:
                    self._send_webhook(event, webhook)
                
            except Exception as e:
                print(f"[SIEM] Event sender error: {e}")
    
    def _send_syslog(self, message: str, target: Dict[str, Any]):
        """Send message to syslog server"""
        try:
            if target["protocol"] == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode('utf-8'), (target["host"], target["port"]))
                sock.close()
            elif target["protocol"] == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((target["host"], target["port"]))
                sock.send(message.encode('utf-8') + b'\n')
                sock.close()
        except Exception as e:
            print(f"[SIEM] Syslog send failed to {target['host']}: {e}")
    
    def _send_webhook(self, event: Dict[str, Any], webhook: Dict[str, Any]):
        """Send event to webhook (with HMAC signature if secret provided)"""
        try:
            payload = json.dumps(event)
            headers = {"Content-Type": "application/json"}
            
            # Add HMAC signature if secret provided
            if webhook.get("secret"):
                signature = hmac.new(
                    webhook["secret"].encode(),
                    payload.encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-Signature-SHA256"] = signature
            
            response = requests.post(
                webhook["url"],
                data=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code not in [200, 201, 202, 204]:
                print(f"[SIEM] Webhook failed: HTTP {response.status_code}")
        
        except Exception as e:
            print(f"[SIEM] Webhook send failed: {e}")


class EnterpriseAPI:
    """
    REST API for enterprise integration.
    Allows external systems to query threat data programmatically.
    """
    
    def __init__(self):
        self.api_keys = {}  # {api_key: {tenant_id, permissions, created_at}}
        self.request_counts = defaultdict(int)  # Rate limiting
        
    def generate_api_key(self, tenant_id: str, permissions: List[str]) -> str:
        """
        Generate API key for enterprise customer.
        
        Permissions: ['read:threats', 'read:stats', 'write:config', 'admin']
        """
        api_key = hashlib.sha256(f"{tenant_id}{time.time()}".encode()).hexdigest()
        
        self.api_keys[api_key] = {
            "tenant_id": tenant_id,
            "permissions": permissions,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "active": True
        }
        
        print(f"[API] Generated API key for tenant: {tenant_id}")
        return api_key
    
    def validate_api_key(self, api_key: str, required_permission: Optional[str] = None) -> bool:
        """Validate API key and check permission"""
        if api_key not in self.api_keys:
            return False
        
        key_data = self.api_keys[api_key]
        
        if not key_data.get("active"):
            return False
        
        if required_permission and required_permission not in key_data["permissions"]:
            return False
        
        # Rate limiting (100 requests per minute per key)
        count_key = f"{api_key}:{int(time.time() / 60)}"
        self.request_counts[count_key] += 1
        
        if self.request_counts[count_key] > 100:
            print(f"[API] Rate limit exceeded for {key_data['tenant_id']}")
            return False
        
        return True
    
    def get_enterprise_features(self) -> Dict[str, Any]:
        """Get list of enterprise features for sales/marketing"""
        return {
            "threat_intelligence": {
                "virustotal_integration": True,
                "abuseipdb_integration": True,
                "exploitdb_scraping": True,
                "custom_honeypots": True,
                "ml_learning": True
            },
            "siem_integration": {
                "cef_format": True,
                "leef_format": True,
                "syslog_output": True,
                "stix_taxii": True,
                "splunk_compatible": True,
                "qradar_compatible": True,
                "arcsight_compatible": True,
                "elastic_siem_compatible": True
            },
            "api_access": {
                "rest_api": True,
                "webhooks": True,
                "real_time_streaming": True,
                "bulk_export": True
            },
            "advanced_detection": {
                "ml_anomaly_detection": True,
                "behavioral_analysis": True,
                "vpn_tor_detection": True,
                "zero_day_detection": True,
                "threat_hunting": True
            },
            "multi_tenancy": {
                "isolated_environments": True,
                "per_tenant_config": True,
                "white_label_support": True,
                "msp_ready": True
            },
            "compliance": {
                "audit_logging": True,
                "data_retention_policies": True,
                "gdpr_compliant": True,
                "soc2_ready": True
            }
        }


# Global instances
siem_integration = SIEMIntegration()
enterprise_api = EnterpriseAPI()


def start_enterprise_integration():
    """Initialize enterprise integration services"""
    print("[Enterprise] Starting enterprise integration services...")
    
    # Start SIEM integration
    siem_integration.start()
    
    # Generate default API key for demo
    demo_key = enterprise_api.generate_api_key(
        tenant_id="demo-customer",
        permissions=["read:threats", "read:stats"]
    )
    
    print(f"[Enterprise] Demo API Key: {demo_key}")
    print("[Enterprise] ✅ Enterprise integration ready")
    
    return demo_key


if __name__ == "__main__":
    # Test enterprise integration
    start_enterprise_integration()
    
    # Test event formatting
    sample_event = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "ip_address": "203.0.113.42",
        "threat_type": "Port Scanning",
        "details": "Port scan detected: 15 ports scanned",
        "level": "DANGEROUS",
        "action": "blocked",
        "geolocation": {
            "country": "United States",
            "city": "New York"
        },
        "anonymization_detection": {
            "is_anonymized": False,
            "anonymization_type": "direct",
            "confidence": 0
        }
    }
    
    print("\n[TEST] CEF Format:")
    print(SecurityEventFormatter.to_cef(sample_event))
    
    print("\n[TEST] Syslog Format:")
    print(SecurityEventFormatter.to_syslog(sample_event))
    
    print("\n[TEST] STIX Format:")
    print(json.dumps(SecurityEventFormatter.to_stix([sample_event]), indent=2))
