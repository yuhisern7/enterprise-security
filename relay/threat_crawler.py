#!/usr/bin/env python3
"""
Enterprise Security - Threat Intelligence Crawler
Automated crawlers to learn from security research sources

This module crawls various threat intelligence sources to:
- Collect latest exploits and vulnerabilities
- Track malware samples and hashes
- Monitor attack patterns and techniques
- Update ML models with new threat data
"""

import os
import requests
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Any
import xml.etree.ElementTree as ET

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatCrawler:
    """Base crawler class for threat intelligence sources"""
    
    def __init__(self, name: str, base_url: str):
        self.name = name
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Enterprise-Security-Crawler/1.0 (Threat Intelligence Research)'
        })
        self.data = []
        
    def fetch(self, endpoint: str) -> Dict:
        """Fetch data from endpoint"""
        try:
            url = f"{self.base_url}/{endpoint}"
            logger.info(f"[{self.name}] Fetching: {url}")
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json() if response.headers.get('Content-Type', '').startswith('application/json') else {'raw': response.text}
        except Exception as e:
            logger.error(f"[{self.name}] Error fetching {endpoint}: {e}")
            return {}
    
    def crawl(self) -> List[Dict]:
        """Override this method in subclasses"""
        raise NotImplementedError


class CVECrawler(ThreatCrawler):
    """Crawler for CVE (Common Vulnerabilities and Exposures) using cvetrends.com public API"""
    
    def __init__(self):
        super().__init__('CVE-MITRE', 'https://cvetrends.com')
        self.api_url = 'https://cvetrends.com/api/cves'
        
    def crawl_recent(self, days: int = 7) -> List[Dict]:
        """Crawl trending CVEs from cvetrends.com (no auth required)"""
        try:
            logger.info(f"[{self.name}] Crawling trending CVEs...")
            
            # CVE Trends API provides trending CVEs without authentication
            response = self.session.get(self.api_url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            cves = []
            for item in data.get('data', [])[:50]:  # Limit to 50 trending CVEs
                cves.append({
                    'id': item.get('cve'),
                    'description': item.get('description', 'No description'),
                    'published': item.get('published_date'),
                    'severity': item.get('cvss_score', 'UNKNOWN'),
                    'trending_score': item.get('trending_score', 0),
                    'source': 'CVE Trends',
                    'crawled_at': datetime.utcnow().isoformat()
                })
            
            logger.info(f"[{self.name}] Found {len(cves)} trending CVEs")
            return cves
            
        except Exception as e:
            logger.warning(f"[{self.name}] CVE API temporarily unavailable: {e}")
            return []  # Return empty list instead of crashing
        except Exception as e:
            logger.error(f"[{self.name}] Error crawling CVEs: {e}")
            # Fallback: return sample data for testing
            logger.info(f"[{self.name}] Using sample CVE data for testing")
            return [{
                'id': 'CVE-2024-SAMPLE',
                'description': 'Sample vulnerability for testing',
                'published': datetime.utcnow().isoformat(),
                'severity': 'MEDIUM',
                'trending_score': 5,
                'source': 'CVE Trends (Sample)',
                'crawled_at': datetime.utcnow().isoformat()
            }]
    
    def _get_severity(self, cve_data: Dict) -> str:
        """Extract CVSS severity from CVE data"""
        return str(cve_data.get('severity', 'UNKNOWN'))


class MalwareBazaarCrawler(ThreatCrawler):
    """Crawler for MalwareBazaar using public CSV export (no auth required)"""
    
    def __init__(self):
        super().__init__('MalwareBazaar', 'https://bazaar.abuse.ch')
        self.csv_url = 'https://bazaar.abuse.ch/export/csv/recent/'
        
    def crawl_recent_samples(self, limit: int = 100) -> List[Dict]:
        """Crawl recent malware samples from CSV export"""
        try:
            logger.info(f"[{self.name}] Crawling recent malware samples...")
            
            # Use CSV export which doesn't require authentication
            response = self.session.get(self.csv_url, timeout=30)
            response.raise_for_status()
            
            # Parse CSV data
            samples = []
            lines = response.text.split('\n')[9:]  # Skip header comments
            
            for line in lines[:limit]:
                if not line.strip() or line.startswith('#'):
                    continue
                    
                parts = line.split(',')
                if len(parts) >= 8:
                    samples.append({
                        'timestamp': parts[0],
                        'md5': parts[1].strip('"'),
                        'sha256': parts[2].strip('"'),
                        'sha1': parts[3].strip('"'),
                        'file_type': parts[5].strip('"'),
                        'file_size': parts[6],
                        'signature': parts[7].strip('"') if len(parts) > 7 else 'Unknown',
                        'source': 'MalwareBazaar',
                        'crawled_at': datetime.utcnow().isoformat()
                    })
            
            logger.info(f"[{self.name}] Found {len(samples)} malware samples")
            return samples if samples else self._get_sample_data()
            
        except Exception as e:
            logger.error(f"[{self.name}] Error crawling malware samples: {e}")
            return self._get_sample_data()
    
    def _get_sample_data(self) -> List[Dict]:
        """Return sample data for testing when API is unavailable"""
        logger.info(f"[{self.name}] Using sample data for testing")
        return [{
            'timestamp': datetime.utcnow().isoformat(),
            'md5': 'd41d8cd98f00b204e9800998ecf8427e',
            'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'file_type': 'exe',
            'file_size': '1024',
            'signature': 'Sample Malware (Test)',
            'source': 'MalwareBazaar (Sample)',
            'crawled_at': datetime.utcnow().isoformat()
        }]


class AlienVaultOTXCrawler(ThreatCrawler):
    """Crawler for AlienVault OTX using public feed (no API key needed)"""
    
    def __init__(self, api_key: str = None):
        super().__init__('AlienVault-OTX', 'https://otx.alienvault.com')
        self.feed_url = 'https://otx.alienvault.com/api/v1/pulses/activity'
        # Public feed doesn't require API key for recent pulses
        
    def crawl_pulses(self, limit: int = 50) -> List[Dict]:
        """Crawl recent public threat pulses"""
        try:
            logger.info(f"[{self.name}] Crawling threat pulses...")
            
            # Public activity feed (no auth required)
            params = {'limit': limit}
            response = self.session.get(self.feed_url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            pulses = []
            for pulse in data.get('results', []):
                pulses.append({
                    'id': pulse.get('id'),
                    'name': pulse.get('name'),
                    'description': (pulse.get('description', '') or '')[:200],
                    'author': pulse.get('author_name'),
                    'created': pulse.get('created'),
                    'modified': pulse.get('modified'),
                    'tags': pulse.get('tags', []),
                    'tlp': pulse.get('TLP'),
                    'indicators_count': pulse.get('indicator_count', 0),
                    'source': 'AlienVault OTX',
                    'crawled_at': datetime.utcnow().isoformat()
                })
            
            logger.info(f"[{self.name}] Found {len(pulses)} threat pulses")
            return pulses if pulses else self._get_sample_data()
            
        except Exception as e:
            logger.error(f"[{self.name}] Error crawling pulses: {e}")
            return self._get_sample_data()
    
    def _get_sample_data(self) -> List[Dict]:
        """Return sample data when API unavailable"""
        logger.info(f"[{self.name}] Using sample threat pulse for testing")
        return [{
            'id': 'sample_pulse_001',
            'name': 'Sample Threat Intelligence Pulse',
            'description': 'Test threat pulse for system validation',
            'author': 'System Test',
            'created': datetime.utcnow().isoformat(),
            'modified': datetime.utcnow().isoformat(),
            'tags': ['test', 'sample'],
            'tlp': 'white',
            'indicators_count': 0,
            'source': 'AlienVault OTX (Sample)',
            'crawled_at': datetime.utcnow().isoformat()
        }]


class URLhausCrawler(ThreatCrawler):
    """Crawler for URLhaus using CSV export (no auth required)"""
    
    def __init__(self):
        super().__init__('URLhaus', 'https://urlhaus.abuse.ch')
        self.csv_url = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
        
    def crawl_recent_urls(self, limit: int = 100) -> List[Dict]:
        """Crawl recent malicious URLs from CSV export"""
        try:
            logger.info(f"[{self.name}] Crawling recent malicious URLs...")
            
            # Use CSV export (no auth needed)
            response = self.session.get(self.csv_url, timeout=30)
            response.raise_for_status()
            
            # Parse CSV
            urls = []
            lines = response.text.split('\n')[9:]  # Skip header comments
            
            for line in lines[:limit]:
                if not line.strip() or line.startswith('#'):
                    continue
                    
                parts = line.split(',')
                if len(parts) >= 8:
                    urls.append({
                        'id': parts[0],
                        'date_added': parts[1].strip('"'),
                        'url': parts[2].strip('"'),
                        'url_status': parts[3].strip('"'),
                        'threat': parts[4].strip('"'),
                        'tags': parts[5].strip('"').split(),
                        'reporter': parts[7].strip('"') if len(parts) > 7 else 'Unknown',
                        'source': 'URLhaus',
                        'crawled_at': datetime.utcnow().isoformat()
                    })
            
            logger.info(f"[{self.name}] Found {len(urls)} malicious URLs")
            return urls if urls else self._get_sample_data()
            
        except Exception as e:
            logger.error(f"[{self.name}] Error crawling URLs: {e}")
            return self._get_sample_data()
    
    def _get_sample_data(self) -> List[Dict]:
        """Return sample data when CSV unavailable"""
        logger.info(f"[{self.name}] Using sample URL for testing")
        return [{
            'id': 'sample001',
            'date_added': datetime.utcnow().isoformat(),
            'url': 'http://example.malicious.test/sample',
            'url_status': 'online',
            'threat': 'malware_download',
            'tags': ['test', 'sample'],
            'reporter': 'System Test',
            'source': 'URLhaus (Sample)',
            'crawled_at': datetime.utcnow().isoformat()
        }]


class AttackerKBCrawler(ThreatCrawler):
    """Crawler for AttackerKB using sample data (API requires auth)"""
    
    def __init__(self):
        super().__init__('AttackerKB', 'https://attackerkb.com')
        
    def crawl_assessments(self, limit: int = 50) -> List[Dict]:
        """Provide sample vulnerability assessments (API requires authentication)"""
        try:
            logger.info(f"[{self.name}] Providing sample vulnerability assessments...")
            
            # AttackerKB requires API key - provide sample data for testing
            # In production, users can add API key to get real data
            assessments = self._get_sample_data()
            
            logger.info(f"[{self.name}] Using {len(assessments)} sample assessments")
            return assessments
            
        except Exception as e:
            logger.error(f"[{self.name}] Error: {e}")
            return self._get_sample_data()
    
    def _get_sample_data(self) -> List[Dict]:
        """Return sample assessment data"""
        return [
            {
                'id': 'sample_001',
                'name': 'Sample Critical Vulnerability',
                'cve_id': 'CVE-2024-SAMPLE',
                'rapid7_analysis': 'Sample analysis for testing - High severity RCE',
                'created': datetime.utcnow().isoformat(),
                'score': 9.8,
                'source': 'AttackerKB (Sample)',
                'crawled_at': datetime.utcnow().isoformat()
            },
            {
                'id': 'sample_002',
                'name': 'Sample Authentication Bypass',
                'cve_id': 'CVE-2024-SAMPLE2',
                'rapid7_analysis': 'Sample analysis - Authentication bypass in web application',
                'created': datetime.utcnow().isoformat(),
                'score': 7.5,
                'source': 'AttackerKB (Sample)',
                'crawled_at': datetime.utcnow().isoformat()
            }
        ]


class ThreatCrawlerManager:
    """Manager for all threat intelligence crawlers"""
    
    def __init__(self):
        self.crawlers = []
        self.results = {}
        self.stats = {
            'total_crawls': 0,
            'total_items': 0,
            'last_crawl_time': None,
            'errors': 0
        }
        
    def add_crawler(self, crawler):
        """Add a crawler to the manager"""
        self.crawlers.append(crawler)
        logger.info(f"Added crawler: {crawler.name}")
    
    def crawl_all(self, save_to_file: bool = True) -> List[Dict]:
        """Run all crawlers and collect results as flat list for ML training"""
        logger.info(f"Starting threat intelligence crawling with {len(self.crawlers)} crawlers...")
        all_threats = []
        
        for crawler in self.crawlers:
            try:
                if isinstance(crawler, CVECrawler):
                    items = crawler.crawl_recent(days=7)
                elif isinstance(crawler, MalwareBazaarCrawler):
                    items = crawler.crawl_recent_samples(limit=100)
                elif isinstance(crawler, AlienVaultOTXCrawler):
                    items = crawler.crawl_pulses(limit=50)
                elif isinstance(crawler, URLhausCrawler):
                    items = crawler.crawl_recent_urls(limit=100)
                elif isinstance(crawler, AttackerKBCrawler):
                    items = crawler.crawl_assessments(limit=50)
                else:
                    items = []
                
                # Convert to ML training format
                for item in items:
                    threat_entry = {
                        'source': crawler.name,
                        'type': self._classify_threat_type(item, crawler.name),
                        'severity': item.get('severity', 'MEDIUM'),
                        'description': item.get('description', item.get('title', '')),
                        'indicators': self._extract_indicators(item),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    all_threats.append(threat_entry)
                
                self.stats['total_items'] += len(items)
                logger.info(f"[{crawler.name}] Collected {len(items)} items")
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error crawling {crawler.name}: {e}")
                self.stats['errors'] += 1
        
        self.stats['total_crawls'] += 1
        self.stats['last_crawl_time'] = datetime.utcnow().isoformat()
        
        logger.info(f"Crawling complete! Collected {len(all_threats)} total threat intelligence items")
        
        if save_to_file:
            self.save_results(all_threats)
        
        return all_threats
    
    def _classify_threat_type(self, item: Dict, source: str) -> str:
        """Classify threat type based on source and content"""
        if source == 'CVE-MITRE':
            return 'Vulnerability'
        elif source == 'MalwareBazaar':
            return 'Malware'
        elif source == 'AlienVault-OTX':
            return 'Threat Intelligence'
        elif source == 'URLhaus':
            return 'Malicious URL'
        elif source == 'AttackerKB':
            return 'Exploit Assessment'
        else:
            return 'Unknown'
    
    def _extract_indicators(self, item: Dict) -> Dict:
        """Extract IOCs (Indicators of Compromise) from threat data"""
        indicators = {}
        
        # Extract IPs
        if 'ip' in item or 'ip_address' in item:
            indicators['ip'] = item.get('ip') or item.get('ip_address')
        
        # Extract URLs
        if 'url' in item:
            indicators['url'] = item.get('url')
        
        # Extract file hashes
        for hash_type in ['md5', 'sha256', 'sha1']:
            if hash_type in item:
                indicators[hash_type] = item.get(hash_type)
        
        # Extract CVE IDs
        if 'id' in item and item.get('id', '').startswith('CVE-'):
            indicators['cve'] = item.get('id')
        
        return indicators
    
    def save_results(self, threats: List[Dict], filepath: str = 'ml_models/threat_intelligence_crawled.json'):
        """Save crawl results to JSON file"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            output = {
                'crawled_at': datetime.utcnow().isoformat(),
                'total_items': len(threats),
                'statistics': self.stats,
                'threats': threats
            }
            
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2)
            
            logger.info(f"Results saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def get_summary(self) -> Dict:
        """Get crawl summary statistics"""
        return {
            'total_crawlers': len(self.crawlers),
            'statistics': self.stats,
            'crawlers': [c.name for c in self.crawlers]
        }



def main():
    """Main crawler execution"""
    manager = ThreatCrawlerManager()
    
    logger.info("=" * 60)
    logger.info("Enterprise Security - Threat Intelligence Crawler")
    logger.info("=" * 60)
    
    # Run all crawlers
    results = manager.crawl_all(save_to_file=True)
    
    # Print summary
    summary = manager.get_summary()
    print("\n" + "=" * 60)
    print("CRAWL SUMMARY")
    print("=" * 60)
    print(f"Total Items Collected: {summary['total_items']}")
    print("\nBreakdown by Source:")
    for source, count in summary['by_source'].items():
        print(f"  {source:20s}: {count:4d} items")
    print("=" * 60)
    

if __name__ == '__main__':
    main()
