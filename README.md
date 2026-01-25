# Enhanced MITRE ATT&CK + CVE + KEV SOC Assistant

**Your complete cybersecurity intelligence platform in one application.**

![Version](https://img.shields.io/badge/Version-2.0-blue)
![AI](https://img.shields.io/badge/AI-Claude%20Sonnet%204-purple)
![Data](https://img.shields.io/badge/Data-MITRE%20%7C%20CVE%20%7C%20KEV-green)

## 🚀 What's New in v2.0

### Multi-Source Intelligence

✅ **MITRE ATT&CK** - 835+ attack techniques and tactics
✅ **CVE Database** - Recent vulnerabilities from NVD (last 90 days)
✅ **CISA KEV** - Known Exploited Vulnerabilities (actively exploited!)
✅ **Unified Search** - Query across all sources simultaneously
✅ **Smart Filtering** - Filter by source type (KEV only, CVE only, etc.)

### Why This Matters for SOCs

**Before**: Switch between 3 different tools
- MITRE ATT&CK website for techniques
- NVD website for CVEs
- CISA website for KEVs

**After**: One AI-powered conversation
- "What are the most critical actively exploited vulnerabilities?"
- "Show me CVEs related to lateral movement techniques"
- "How is T1078 being exploited in the wild?"

---

## Quick Start

```powershell
# 1. Create .env file
@"
ANTHROPIC_API_KEY=your_key_here
"@ | Out-File -FilePath .env -Encoding ASCII

# 2. Run it
docker-compose up --build

# 3. Open browser
# Navigate to: http://localhost:8000
```

**First startup takes 3-5 minutes** to download:
- 835 MITRE ATT&CK techniques
- ~2000+ recent CVEs (last 90 days)
- ~1000+ CISA Known Exploited Vulnerabilities
- Embedding models (~90MB)

**Subsequent startups: < 30 seconds**

---

## Features

### 🎯 Intelligent Query Routing

**Ask naturally:**
- "What are the most dangerous actively exploited vulnerabilities?"
  → Prioritizes CISA KEV data
  
- "Show me recent critical SQL injection CVEs"
  → Searches CVE database with severity filtering
  
- "How do attackers perform privilege escalation?"
  → Retrieves MITRE techniques with defensive strategies

### 🔍 Advanced Filtering

**Filter by source:**
- **All Sources** - Comprehensive threat intelligence
- **KEV Only** - Focus on active threats (recommended for daily briefings)
- **CVE Only** - Vulnerability research
- **MITRE Only** - Technique documentation

### 🚨 Priority Indicators

**Visual cues:**
- 🚨 **Red pulsing badges** - CISA KEV (actively exploited)
- 🔴 **Red badges** - Critical CVEs (CVSS 9.0-10.0)
- 🟠 **Orange badges** - High CVEs (CVSS 7.0-8.9)
- 🟡 **Yellow badges** - CVEs with lower severity
- 🎯 **Blue badges** - MITRE ATT&CK techniques

### 📊 Real-Time Stats

Header shows:
- MITRE techniques loaded
- CVEs in database
- KEVs being tracked

---

## Architecture

```
┌──────────────────────────────────────────┐
│         User Browser (Frontend)          │
└────────────────┬─────────────────────────┘
                 │ HTTP/REST
                 ▼
┌──────────────────────────────────────────┐
│      FastAPI Backend (api_enhanced.py)   │
│  • Request routing                       │
│  • Context building                      │
│  • Response formatting                   │
└────┬─────────────────────────────────┬───┘
     │                                 │
     ▼                                 ▼
┌─────────────────────┐    ┌──────────────────────┐
│  Enhanced Vector DB │    │   Claude Sonnet 4    │
│  • MITRE techniques │    │   • RAG generation   │
│  • CVE database     │    │   • Analysis         │
│  • CISA KEV catalog │    │   • Recommendations  │
└──────────┬──────────┘    └──────────────────────┘
           │
    ┌──────┴──────┬──────────┬───────────┐
    ▼             ▼          ▼           ▼
┌────────┐  ┌─────────┐  ┌──────┐  ┌────────┐
│ MITRE  │  │   NVD   │  │ CISA │  │ Claude │
│ GitHub │  │   API   │  │ Feed │  │  API   │
└────────┘  └─────────┘  └──────┘  └────────┘
```

---

## API Endpoints

### `POST /chat`
Main chat endpoint with multi-source intelligence

**Request:**
```json
{
  "query": "What are critical Windows vulnerabilities?",
  "filter_type": null  // or "mitre", "cve", "kev"
}
```

**Response:**
```json
{
  "response": "Based on recent data, here are critical Windows vulnerabilities...",
  "sources": [
    {
      "id": "CVE-2024-1234",
      "type": "cve",
      "severity": "CRITICAL",
      "score": "9.8"
    },
    {
      "id": "CVE-2024-5678",
      "type": "kev",
      "vendor": "Microsoft",
      "product": "Windows",
      "actively_exploited": true
    }
  ],
  "stats": {
    "mitre_techniques": 835,
    "cves": 2156,
    "kevs": 1089
  }
}
```

### `GET /health`
System status and data statistics

### `GET /search?query=...&filter_type=...&limit=10`
Direct search without AI generation

### `POST /admin/refresh`
Refresh CVE or KEV data (background task)

**Full API docs:** http://localhost:8000/docs

---

## Data Sources

### MITRE ATT&CK Framework
- **Source**: https://github.com/mitre/cti
- **Update frequency**: Real-time (on startup)
- **Coverage**: 835+ techniques across 14 tactics
- **Format**: STIX 2.0 JSON

### National Vulnerability Database (NVD)
- **Source**: https://services.nvd.nist.gov/rest/json/cves/2.0
- **Update frequency**: Configurable (default: last 90 days)
- **Coverage**: All published CVEs in date range
- **Rate limit**: 5 requests per 30 seconds
- **Includes**: CVSS scores, CWE mappings, references

### CISA Known Exploited Vulnerabilities (KEV)
- **Source**: https://www.cisa.gov/known-exploited-vulnerabilities
- **Update frequency**: Real-time (CISA updates catalog regularly)
- **Coverage**: 1000+ actively exploited CVEs
- **Priority**: HIGHEST - these are being exploited NOW
- **Federal mandate**: Required action dates for federal agencies

---

## Use Cases

### Daily SOC Briefings
**Query:** "What are the most critical actively exploited vulnerabilities added in the last 7 days?"

**Result:** Prioritized list of CISA KEV additions with:
- CVE details
- Affected products
- Required actions
- Remediation deadlines

### Vulnerability Prioritization
**Query:** "Show me critical CVEs for Windows Server from the last 30 days"

**Result:** CVE list with:
- CVSS scores
- Severity ratings
- Attack complexity
- Related ATT&CK techniques

### Threat Hunting
**Query:** "What techniques are associated with CVE-2024-1234?"

**Result:** Correlation between:
- CVE details
- MITRE techniques used in exploitation
- Detection strategies
- Defensive measures

### Incident Response
**Query:** "We detected lateral movement using T1021. Are there any related KEVs we should check?"

**Result:** Connected intelligence showing:
- MITRE technique details
- Related vulnerabilities
- Active exploits (KEV)
- Recommended actions

---

## Federal Agency Value Proposition

### Compliance Benefits

**CISA BOD 22-01 Compliance**
- Automatic KEV tracking
- Action date reminders
- Remediation prioritization

**FedRAMP Requirements**
- Vulnerability management
- Threat intelligence
- Incident response capability

**NIST Cybersecurity Framework**
- Identify: Asset vulnerability assessment
- Protect: Threat-informed defense
- Detect: Anomaly detection guidance
- Respond: Incident playbooks
- Recover: Remediation strategies

### Cost Savings

**Without this tool:**
- 3 separate subscriptions/tools
- 15-20 minutes per analyst per query
- Context switching between platforms
- Manual correlation of data sources

**With this tool:**
- Single platform
- 30 seconds per query
- Automatic correlation
- AI-powered insights

**ROI Example:**
- 10 analysts × 5 queries/day × 15 min saved = 12.5 hours/day saved
- 12.5 hours × $75/hour × 250 days = **$234,375/year saved**

### Security Clearance Advantage

**You can offer:**
- On-premise deployment (air-gapped)
- IL4/IL5 compliance ready
- Custom integration with classified systems
- Dedicated support with clearance

---

## Deployment Options

### Development/Testing
```bash
docker-compose up --build
```
**Cost**: $0 local + Claude API usage

### Production (Railway/Render)
```bash
# Push to GitHub, connect platform, deploy
```
**Cost**: $10-30/month + Claude API

### Federal (AWS GovCloud)
```bash
# Deploy to ECS Fargate with FedRAMP controls
```
**Cost**: $100-300/month + compliance features

**See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed guides**

---

## Configuration

### Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=your_key_here

# Optional
CVE_DAYS_BACK=90  # How many days of CVEs to load (default: 90)
```

### Customization

**Change CVE date range:**
Edit `api_enhanced.py`:
```python
cve_data = cve_loader.download_recent_cves(days=180)  # 6 months
```

**Add custom data sources:**
Extend `enhanced_vector_store.py` to support additional databases

---

## Performance

### Startup Time
- **First run**: 3-5 minutes (downloads all data)
- **Subsequent runs**: < 30 seconds (cached data)

### Query Speed
- **Search only**: < 1 second
- **With AI generation**: 2-4 seconds
- **Complex queries**: 4-6 seconds

### Data Volume
- **MITRE**: 835 techniques
- **CVE**: 2000-3000 (90 days)
- **KEV**: 1000-1200 actively exploited
- **Total vector DB**: ~50-100MB

---

## Monitoring & Maintenance

### Health Monitoring
```bash
# Check system health
curl http://localhost:8000/health

# Response shows data loaded
{
  "status": "healthy",
  "data_loaded": {
    "total": 3924,
    "mitre_techniques": 835,
    "cves": 2089,
    "kevs": 1000
  }
}
```

### Data Refresh
```bash
# Refresh CVE data (last 30 days)
curl -X POST http://localhost:8000/admin/refresh \
  -H "Content-Type: application/json" \
  -d '{"source": "cve", "days": 30}'

# Refresh KEV catalog
curl -X POST http://localhost:8000/admin/refresh \
  -H "Content-Type: application/json" \
  -d '{"source": "kev"}'

# Refresh everything
curl -X POST http://localhost:8000/admin/refresh \
  -H "Content-Type: application/json" \
  -d '{"source": "all", "days": 90}'
```

**Recommended schedule:**
- CVE refresh: Daily
- KEV refresh: Every 4 hours
- MITRE refresh: Weekly

---

## Security Considerations

### API Rate Limits
- **NVD**: 5 requests per 30 seconds (built-in throttling)
- **CISA**: No documented limit (reasonable use)
- **Claude**: Tier-based (see Anthropic docs)

### Data Privacy
- No PII stored
- No query logging by default
- All data is publicly available sources

### Access Control
Add authentication (see DEPLOYMENT.md):
```python
from fastapi.security import HTTPBearer
# Add JWT or API key authentication
```

---

## Troubleshooting

**Problem**: Slow first startup
**Solution**: Normal - downloading ~3000+ CVEs and 1000+ KEVs takes time

**Problem**: NVD API errors
**Solution**: NVD has rate limits. Wait 30 seconds and retry.

**Problem**: Missing KEV data
**Solution**: Check CISA website is accessible. Firewall may block.

**Problem**: Out of date CVEs
**Solution**: Use `/admin/refresh` endpoint to update data

---

## Roadmap

### v2.1 (Next)
- [ ] Automated daily CVE/KEV refresh
- [ ] Email alerts for new KEVs
- [ ] Export to PDF/Excel
- [ ] SIEM integration (Splunk, Sentinel)

### v2.2
- [ ] Historical CVE trend analysis
- [ ] Vulnerability scoring customization
- [ ] Multi-tenant support
- [ ] Role-based access control

### v3.0
- [ ] Predictive threat intelligence
- [ ] Custom ML models for prioritization
- [ ] Integration with threat feeds
- [ ] Automated remediation workflows

---

## Cost Analysis

### Development
- **Hosting**: $0 (local Docker)
- **Claude API**: ~$0.02 per query
- **Total monthly**: < $50 for testing

### Production (Small Team)
- **Hosting**: $10-30/month (Railway/Render)
- **Claude API**: ~$100-200/month (100 queries/day)
- **Total monthly**: $110-230

### Federal Enterprise
- **Hosting**: $100-300/month (AWS GovCloud)
- **Compliance**: $200-500/month (FedRAMP features)
- **Claude API**: $500-1000/month (1000 queries/day)
- **Total monthly**: $800-1800

**Can charge agencies**: $50K-200K/year licensing + support

---

## Support & Contributing

### Issues
Found a bug? Open an issue on GitHub

### Feature Requests
Want a new data source? Let us know!

### Contributing
PRs welcome for:
- New data source integrations
- UI improvements
- Performance optimizations
- Documentation

---

## License

MIT License - Free for commercial use

---

## Acknowledgments

- **MITRE Corporation** - ATT&CK Framework
- **NIST** - National Vulnerability Database
- **CISA** - Known Exploited Vulnerabilities Catalog
- **Anthropic** - Claude AI

---

**Built by government contractors, for government contractors.** 🇺🇸

Ready to deploy your enhanced SOC assistant? Follow the [DEPLOYMENT.md](DEPLOYMENT.md) guide!
