# AI Signatures Storage

This folder stores all AI-generated and extracted attack signatures in JSON format.

## Files Stored Here:

### learned_signatures.json (910 KB)
- **Source:** ExploitDB scraper
- **Content:** 3,066 attack signatures from 6,000+ exploits
- **Types:** SQL injection, XSS, command injection, buffer overflow, etc.
- **Privacy:** Patterns only - NO exploit payloads stored
- **Shared:** Via relay to subscriber nodes (patterns only)

### Future Files:
- `live_extracted_patterns.json` - Runtime-extracted signatures from detected attacks
- `behavioral_signatures.json` - Behavioral anomaly patterns (local only)
- `graph_signatures.json` - Graph-based attack patterns (local only)
- `sequence_signatures.json` - State-transition attack sequences

## Privacy Policy:
✅ **Stored:** Keywords, encodings, regex patterns, statistical features
❌ **NOT Stored:** Exploit payloads, malicious code, raw attack strings

## Access:
- **Relay Server:** Distributes signatures to subscribers
- **Local Nodes:** Symlink from `AI/learned_signatures.json` for backwards compatibility
- **Global Sharing:** Only abstract patterns shared, never raw data
