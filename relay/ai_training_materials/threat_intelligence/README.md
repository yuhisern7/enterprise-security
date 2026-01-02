# Threat Intelligence Data

Aggregated threat intelligence from external sources and crawlers.

## Sources:

### threat_intelligence_crawled.json
- **Sources:** Dark web forums, paste sites, threat feeds
- **Content:** CVE references, IOCs, attack trends, emerging threats
- **Update Frequency:** Every 12 hours
- **Privacy:** Public threat intel only, no private network data

### crawled_YYYYMMDD.json
- **Purpose:** Daily snapshots of crawled threat intelligence
- **Retention:** Last 30 days kept for trend analysis
- **Usage:** Feed to ML models for threat classification improvement

## Data Types:
- CVE identifiers and descriptions
- Known malicious IPs/domains (reputation feeds)
- Attack technique descriptions (MITRE ATT&CK mapping)
- Exploit trends and emerging vulnerabilities
- Dark web threat actor activity (public sources only)

## Privacy Policy:
✅ **Shared:** Aggregated threat trends, CVE data, public IOCs
❌ **NOT Shared:** Network-specific detections, local threat logs

## Integration:
- Used by `AI/threat_intelligence.py` module
- Feeds into `ip_reputation.pkl` training
- Enhances signature extraction with latest attack patterns
