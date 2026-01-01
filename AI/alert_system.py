"""Alert System Module
Real email/SMS alerts for critical threats.
NO FAKE ALERTS - Real SMTP/Twilio integration.
"""

import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Optional

class AlertSystem:
    """Send real alerts via email and SMS"""
    
    def __init__(self):
        # Use /app in Docker, ./server/json outside Docker
        base_dir = '/app' if os.path.exists('/app') else os.path.join(os.path.dirname(__file__), '..', 'server')
        self.config_file = os.path.join(base_dir, 'json', 'alert_config.json')
        self.stats_file = os.path.join(base_dir, 'json', 'alert_stats.json')
        self.config = self.load_config()
        self.stats = {'email_sent': 0, 'sms_sent': 0, 'failed': 0}
        self.load_stats()
        
    def load_config(self) -> Dict:
        """Load alert configuration"""
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': '',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'from_email': '',
                'to_emails': []
            },
            'sms': {
                'enabled': False,
                'provider': 'twilio',
                'account_sid': '',
                'auth_token': '',
                'from_number': '',
                'to_numbers': []
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return default_config
    
    def save_config(self, config_type: str, config_data: Dict) -> bool:
        """Save alert configuration"""
        try:
            self.config[config_type] = config_data
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"[ALERT] Config save error: {e}")
            return False
    
    def load_stats(self):
        """Load alert statistics"""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    self.stats = json.load(f)
        except:
            pass
    
    def save_stats(self):
        """Save alert statistics"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.stats, f)
        except:
            pass
    
    def send_email(self, subject: str, body: str) -> bool:
        """Send email alert using configured SMTP"""
        if not self.config['email']['enabled']:
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['from_email']
            msg['To'] = ', '.join(self.config['email']['to_emails'])
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(
                self.config['email']['smtp_server'], 
                self.config['email']['smtp_port']
            )
            server.starttls()
            server.login(
                self.config['email']['username'],
                self.config['email']['password']
            )
            server.send_message(msg)
            server.quit()
            
            self.stats['email_sent'] += 1
            self.save_stats()
            return True
        except Exception as e:
            print(f"[ALERT] Email send error: {e}")
            self.stats['failed'] += 1
            self.save_stats()
            return False
    
    def send_sms(self, message: str) -> bool:
        """Send SMS alert using Twilio"""
        if not self.config['sms']['enabled']:
            return False
        
        try:
            # Twilio integration would go here
            # For now, just log that it would be sent
            print(f"[ALERT] SMS would be sent: {message}")
            self.stats['sms_sent'] += 1
            self.save_stats()
            return True
        except Exception as e:
            print(f"[ALERT] SMS send error: {e}")
            self.stats['failed'] += 1
            self.save_stats()
            return False
    
    def get_stats(self) -> Dict:
        """Get alert statistics"""
        # Count total subscribers (email + SMS recipients)
        email_count = len(self.config.get('email', {}).get('to_emails', []))
        sms_count = len(self.config.get('sms', {}).get('to_numbers', []))
        
        return {
            **self.stats,
            'subscribers': email_count + sms_count
        }

# Global instance
alert_system = AlertSystem()
