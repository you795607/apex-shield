# Apex Shield Backend v2 - 100% Real

## Overview
This backend performs REAL VAPT/Bug Bounty operations. Every endpoint executes real network calls, real CVE lookups, real port scans, real SQLi/XSS probes, real genetic algorithm mutations, real CISA KEV, real HIBP, real Shodan InternetDB, real crt.sh, real NVD, real DNS via Cloudflare DoH, real TLS inspection via crt.sh.

## Quick Deploy (Free Tier)

### Option 1: Railway.app (recommended)
1. Push this directory to GitHub
2. Go to https://railway.app
3. New Project → Deploy from GitHub repo
4. Railway auto-detects Dockerfile
5. Get URL: `https://your-app.up.railway.app`

### Option 2: Render.com
1. Push to GitHub
2. Go to https://render.com → New Web Service
3. Connect repo → Select "Docker"
4. Free plan available

### Option 3: Local Docker
```bash
docker build -t apex-backend .
docker run -p 8080:8080 apex-backend
```

## Endpoints (All Real)

| Endpoint | Real Operation |
|----------|----------------|
| `POST /api/scan/full` | All 16 modules |
| `POST /api/scan/module/{name}` | Single module |
| `GET /api/zeroday/fresh?days=7` | NVD last 7 days |
| `GET /api/cisa/kev` | CISA Known Exploited |
| `GET /api/breaches/{domain}` | HIBP public breaches |
| `GET /api/report/{scan_id}?format=html` | HTML/JSON report |

## Modules

1. **dns-recon** — dnspython queries to 1.1.1.1/8.8.8.8/9.9.9.9
2. **subdomain-enum** — crt.sh JSON API
3. **headers** — httpx real HTTP probe
4. **portscan** — nmap if available, else socket connect
5. **sqli** — sqlmap if available, else error-based detection
6. **xss** — Real payload reflection
7. **cors** — Real OPTIONS request
8. **tls** — crt.sh certificate chain
9. **nvd** — services.nvd.nist.gov REST API
10. **cisa-kev** — CISA JSON feed
11. **hibp** — haveibeenpwned.com v3
12. **shodan** — internetdb.shodan.io
13. **waf** — Multi-User-Agent probing
14. **nuclei** — Real nuclei templates (if installed)
15. **genetic-ai** — Real genetic algorithm payload mutation
16. **stealth** — Real Tor SOCKS check
17. **takeover** — Subdomain takeover fingerprinting

## Frontend Integration
Set `window.APEX_BACKEND_URL = 'https://your-backend.up.railway.app'` in index.html.
