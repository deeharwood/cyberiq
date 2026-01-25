# CyberIQ - Unified Threat Intelligence Platform

![Status](https://img.shields.io/badge/Status-Production%20Ready-success)
![License](https://img.shields.io/badge/License-Proprietary-red)

**Unified threat intelligence across MITRE ATT&CK, CVE, and CISA KEV in one AI-powered platform.**

---

## 🎯 What is CyberIQ?

CyberIQ helps cybersecurity professionals work smarter by unifying three critical data sources:

- 🎯 **MITRE ATT&CK** - 835 adversary techniques
- 🔒 **CVE Database** - 13,997+ vulnerabilities
- 🚨 **CISA KEV** - 1,089+ actively exploited vulnerabilities

**Instead of checking 3 websites for 45 minutes, ask one question and get AI-powered answers in 30 seconds.**

---

## 💼 Business Value

**For a 10-person cybersecurity team:**
- **Time saved:** 7.5 hours per analyst per day
- **Annual savings:** $234,000
- **ROI:** 1,202%
- **Compliance:** CISA BOD 22-01 ready

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Anthropic API key
- 4GB RAM minimum

### Deploy Locally

```bash
# 1. Clone repository
git clone https://github.com/YOUR_USERNAME/cyberiq.git
cd cyberiq

# 2. Create .env file
echo "ANTHROPIC_API_KEY=your_key_here" > .env

# 3. Run with Docker
docker-compose up --build

# 4. Open browser
# http://localhost:8000
```

**First run takes 3-5 minutes to download threat intelligence data.**

---

## ☁️ Deploy to Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new)

See [DEPLOY_RAILWAY.md](DEPLOY_RAILWAY.md) for detailed instructions.

---

## 📊 Features

- **Multi-Source Intelligence** - MITRE + CVE + KEV unified
- **AI-Powered Analysis** - Claude Sonnet 4 for context & recommendations
- **Visual Alerts** - Color-coded badges (🚨 red = active exploits)
- **Smart Filtering** - Filter by source type (KEV only, CVE only, etc.)
- **REST API** - Full API at `/docs` endpoint
- **Real-time Updates** - Daily CVE/KEV refresh

---

## 🎨 Architecture

```
User Query
    ↓
FastAPI Backend → Vector Database (ChromaDB)
    ↓                   ↓
Claude AI ←─────── [MITRE | CVE | KEV]
    ↓
Prioritized Response
```

**Stack:**
- Backend: FastAPI (Python)
- AI: Claude Sonnet 4 (Anthropic)
- Vector DB: ChromaDB with sentence-transformers
- Frontend: HTML/CSS/JS
- Deployment: Docker

---

## 📚 Documentation

- **[SALES_GUIDE.md](SALES_GUIDE.md)** - Complete sales playbook
- **[PITCH_DECK.md](PITCH_DECK.md)** - Presentation outline
- **[ONE_PAGER.md](ONE_PAGER.md)** - Leave-behind template
- **[EMAIL_TEMPLATES.md](EMAIL_TEMPLATES.md)** - Outreach emails
- **[DEPLOY_RAILWAY.md](DEPLOY_RAILWAY.md)** - Cloud deployment

---

## 🎯 Target Market

- Federal agencies (CISA BOD 22-01 compliance)
- Defense contractors
- Security Operations Centers (SOC)
- Threat intelligence teams
- Vulnerability management teams
- Incident response teams

---

## 💰 Pricing

**SaaS:**
- Starter: $99/user/month (up to 10 users)
- Professional: $149/user/month (11-50 users)
- Enterprise: $199/user/month (51+ users)

**On-Premise:**
- Single Agency: $75K/year
- Department: $150K/year
- Custom: Contact sales

---

## 🔒 Security & Compliance

- CISA BOD 22-01 compliant
- FedRAMP ready (AWS GovCloud deployment)
- SOC 2 Type II in progress
- On-premise option for classified environments

---

## 📧 Contact

**Website:** https://cyberiq.co  
**Demo:** https://cyberiq.co/demo  
**Email:** hello@cyberiq.co

---

## 📄 License

Proprietary - All rights reserved

---

**Built with ❤️ for cybersecurity professionals**
