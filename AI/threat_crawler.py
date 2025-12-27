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
    """Crawler for CVE (Common Vulnerabilities and Exposures) database"""
    
    def __init__(self):
        super().__init__('CVE-MITRE', 'https://cve.mitre.org')
        self.nvd_api = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        
    def crawl_recent(self, days: int = 7) -> List[Dict]:
        """Crawl recent CVEs from NVD API"""
        try:
            logger.info(f"[{self.name}] Crawling CVEs from last {days} days...")
            # NVD API requires time range
            params = {
                'resultsPerPage': 100,
                'sortBy': 'published',
                'sortOrder': 'desc'
            }
            
            response = self.session.get(self.nvd_api, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            cves = []
            for item in data.get('vulnerabilities', [])[:50]:  # Limit to 50 most recent
                cve_data = item.get('cve', {})
                cves.append({
                    'id': cve_data.get('id'),
                    'description': cve_data.get('descriptions', [{}])[0].get('value', 'No description'),
                    'published': cve_data.get('published'),
                    'severity': self._get_severity(cve_data),
                    'source': 'NVD',
                    'crawled_at': datetime.utcnow().isoformat()
                })
            
            logger.info(f"[{self.name}] Found {len(cves)} recent CVEs")
            return cves
            
        except Exception as e:
            logger.error(f"[{self.name}] Error crawling CVEs: {e}")
            return []
    
    def _get_severity(self, cve_data: Dict) -> str:
        """Extract CVSS severity from CVE data"""
        metrics = cve_data.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
        cvss_data = cvss_v3.get('cvssData', {})
        return cvss_data.get('baseSeverity', 'UNKNOWN')


class MalwareBazaarCrawler(ThreatCrawler):
    """Crawler for MalwareBazaar (abuse.ch)"""
    
    def __init__(self):
        super().__init__('MalwareBazaar', 'https://mb-api.abuse.ch/api/v1/')
        
    def crawl_recent_samples(self, limit: int = 100) -> List[Dict]:
        """Crawl recent malware samples"""
        try:
            logger.info(f"[{self.name}] Crawling recent malware samples...")
            
            # MalwareBazaar API
            response = self.session.post(
                f"{self.base_url}",
                data={'query': 'get_recent', 'selector': limit},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            samples = []
            for item in data.get('data', []):
                samples.append({
                    'sha256': item.get('sha256_hash'),
                    'md5': item.get('md5_hash'),
                    'signature': item.get('signature'),
                    'file_type': item.get('file_type'),
                    'file_name': item.get('file_name'),
                    'first_seen': item.get('first_seen'),
                    'tags': item.get('tags', []),
                    'source': 'MalwareBazaar',
                    'crawled_at': datetime.utcnow().isoformat()
                })
            
            logger.info(f"[{self.name}] Found {len(samples)} malware samples")
            return samples
            
        except Exception as e:
            logger.error(f"[{self.name}] Error crawling malware samples: {e}")
            return []


class AlienVaultOTXCrawler(ThreatCrawler):
    """Crawler for AlienVault Open Threat Exchange"""
    
    def __init__(self, api_key: str = None):
        super().__init__('AlienVault-OTX', 'https://otx.alienvault.com/api/v1')
        self.api_key = api_key
        if api_key:
            self.session.headers.update({'X-OTX-API-KEY': api_key})
        
    def crawl_pulses(self, limit: int = 50) -> List[Dict]:
        """Crawl recent threat pulses"""
        try:
            logger.info(f"[{self.name}] Crawling threat pulses...")
            
            # OTX pulses endpoint
            params = {'limit': limit, 'page': 1}
            response = self.session.get(
                f"{self.base_url}/pulses/subscribed",
                params=params,
                timeout=30
            )
            
            if response.status_code == 403:
                logger.warning(f"[{self.name}] API key required for full access")
                return []
                
            response.raise_for_status()
            data = response.json()
            
            pulses = []
            for pulse in data.get('results', []):
                pulses.append({
                    'id': pulse.get('id'),
                    'name': pulse.get('name'),
                    'description': pulse.get('description', '')[:200],
                    'author': pulse.get('author_name'),
                    'created': pulse.get('created'),
                    'modified': pulse.get('modified'),
                    'tags': pulse.get('tags', []),
                    'tlp': pulse.get('TLP'),
                    'indicators_count': len(pulse.get('indicators', [])),
                    'source': 'OTX',
                    'crawled_at': datetime.utcnow().isoformat()
                })
            
            logger.info(f"[{self.name}] Found {len(pulses)} threat pulses")
            return pulses
            
        except Exception as e:
            logger.error(f"[{self.name}] Error crawling pulses: {e}")
            return []


class URLhausCrawler(ThreatCrawler):
    """Crawler for URLhaus (abuse.ch)"""
    
    def __init__(self):
        super().__init__('URLhaus', 'https://urlhaus-api.abuse.ch/v1')
        
    def crawl_recent_urls(self, limit: int = 100) -> List[Dict]:
        """Crawl recent malicious URLs"""
        try:
            logger.info(f"[{self.name}] Crawling recent malicious URLs...")
            
            response = self.session.post(
                f"{self.base_url}/urls/recent/limit/{limit}/",
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            urls = []
            for item in data.get('urls', []):
                urls.append({
                    'id': item.get('id'),
                    'url': item.get('url'),
                    'url_status': item.get('url_status'),
                    'threat': item.get('threat'),
                    'tags': item.get('tags', []),
                    'first_seen': item.get('date_added'),
                    'reporter': item.get('reporter'),
                    'source': 'URLhaus',
                    'crawled_at': datetime.utcnow().isoformat()
                })
            
            logger.info(f"[{self.name}] Found {len(urls)} malicious URLs")
            return urls
            
        except Exception as e:
            logger.error(f"[{self.name}] Error crawling URLs: {e}")
            return []


class AttackerKBCrawler(ThreatCrawler):
    """Crawler for AttackerKB vulnerability assessments"""
    
    def __init__(self):
        super().__init__('AttackerKB', 'https://api.attackerkb.com/v1')
        
    def crawl_assessments(self, limit: int = 50) -> List[Dict]:
        """Crawl vulnerability assessments"""
        try:
            logger.info(f"[{self.name}] Crawling vulnerability assessments...")
            
            # Note: AttackerKB may require API key for full access
            params = {'size': limit, 'sort': 'created'}
            response = self.session.get(
                f"{self.base_url}/topics",
                params=params,
                timeout=30
            )
            
            if response.status_code != 200:
                logger.warning(f"[{self.name}] API returned status {response.status_code}")
                return []
                
            data = response.json()
            
            assessments = []
            for topic in data.get('data', []):
                assessments.append({
                    'id': topic.get('id'),
                    'name': topic.get('name'),
                    'cve_id': topic.get('metadata', {}).get('cve_id'),
                    'rapid7_analysis': topic.get('rapid7Analysis'),
                    'created': topic.get('created'),
                    'score': topic.get('score'),
                    'source': 'AttackerKB',
                    'crawled_at': datetime.utcnow().isoformat()
                })
            
            logger.info(f"[{self.name}] Found {len(assessments)} assessments")
            return assessments
            
        except Exception as e:
            logger.error(f"[{self.name}] Error crawling assessments: {e}")
            return []


class ThreatCrawlerManager:
    """Manager for all threat intelligence crawlers"""
    
    def __init__(self):
        self.crawlers = {
            'cve': CVECrawler(),
            'malwarebazaar': MalwareBazaarCrawler(),
            'otx': AlienVaultOTXCrawler(),
            'urlhaus': URLhausCrawler(),
            'attackerkb': AttackerKBCrawler()
        }
        self.results = {}
        
    def crawl_all(self, save_to_file: bool = True) -> Dict[str, List[Dict]]:
        """Run all crawlers and collect results"""
        logger.info("Starting threat intelligence crawling...")
        
        # CVE Database
        self.results['cves'] = self.crawlers['cve'].crawl_recent(days=7)
        time.sleep(2)  # Rate limiting
        
        # MalwareBazaar
        self.results['malware_samples'] = self.crawlers['malwarebazaar'].crawl_recent_samples(limit=100)
        time.sleep(2)
        
        # AlienVault OTX
        self.results['threat_pulses'] = self.crawlers['otx'].crawl_pulses(limit=50)
        time.sleep(2)
        
        # URLhaus
        self.results['malicious_urls'] = self.crawlers['urlhaus'].crawl_recent_urls(limit=100)
        time.sleep(2)
        
        # AttackerKB
        self.results['assessments'] = self.crawlers['attackerkb'].crawl_assessments(limit=50)
        
        # Summary
        total = sum(len(v) for v in self.results.values())
        logger.info(f"Crawling complete! Collected {total} total threat intelligence items")
        
        if save_to_file:
            self.save_results()
        
        return self.results
    
    def save_results(self, filepath: str = 'AI/ml_models/threat_intelligence_crawled.json'):
        """Save crawl results to JSON file"""
        try:
            output = {
                'crawled_at': datetime.utcnow().isoformat(),
                'summary': {k: len(v) for k, v in self.results.items()},
                'data': self.results
            }
            
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2)
            
            logger.info(f"Results saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def get_summary(self) -> Dict:
        """Get crawl summary statistics"""
        return {
            'total_items': sum(len(v) for v in self.results.values()),
            'by_source': {k: len(v) for k, v in self.results.items()},
            'last_crawl': datetime.utcnow().isoformat()
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
