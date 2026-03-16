# SecureTrace - IP Threat Intelligence

Enterprise-grade IP threat analysis platform built on Cloudflare Pages with Workers.

## Overview

SecureTrace provides comprehensive IP threat intelligence by aggregating data from multiple security sources. Analyze any IP address to get detailed threat assessments, reputation scores, and network information.

## Features

- IP Analysis: Detailed threat assessment for any IPv4/IPv6 address
- Multi-source Intelligence: AbuseIPDB, VirusTotal, Shodan, Cloudflare Radar
- Traffic Analysis: Bot vs Human traffic statistics per ASN
- IP Blocking: Block individual IPs, subnets (/24, /25), or entire ASNs
- Blocklist Export: Generate blocklists in multiple formats
- Real-time Data: Live queries to threat intelligence APIs

## Data Sources

| Source | Information Provided |
|--------|---------------------|
| AbuseIPDB | Abuse confidence score, report count, ISP, usage type |
| VirusTotal | Malicious detections from 90+ security vendors |
| Shodan | Open ports, services, vulnerabilities |
| Cloudflare Radar | Bot/Human traffic ratio per ASN |
| IPInfo | Geolocation, ASN, organization |

## API Endpoints

### Analysis

```
POST /api/analyze-ip
Content-Type: application/json

{"ip": "8.8.8.8"}
```

### Blocking

```
POST /api/block-ip      - Block single IP (/32)
POST /api/block-subnet  - Block /24 or /25 subnet
POST /api/block-asn     - Block entire ASN
POST /api/unblock-ip    - Remove from blocklist
GET  /api/blocked-list  - List all blocked entries
```

### Export

```
GET /api/generate-blocklist?format=json|csv|txt
```

## Deployment

Deployed on Cloudflare Pages with Functions (Workers).

### Environment Variables

Required in Cloudflare Pages settings:

- `ABUSEIPDB_KEY` - AbuseIPDB API key
- `VIRUSTOTAL_KEY` - VirusTotal API key
- `SHODAN_KEY` - Shodan API key
- `CLOUDFLARE_API_TOKEN` - Cloudflare API token (for Radar)

### KV Namespace

Create a KV namespace named `blocked-ips` and bind it as `BLOCKED_IPS`.

## Project Structure

```
/
├── index.html          # Main HTML
├── app.js              # Frontend application
├── styles.css          # Styles
├── _headers            # Cloudflare headers config
└── functions/
    └── api/
        ├── analyze-ip.js       # IP analysis endpoint
        ├── block-ip.js         # Block single IP
        ├── block-subnet.js     # Block /24 or /25
        ├── block-asn.js        # Block ASN
        ├── unblock-ip.js       # Remove from blocklist
        ├── blocked-list.js     # List blocked entries
        └── generate-blocklist.js # Export blocklist
```

## License

Proprietary - Internal use only.
