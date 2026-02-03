from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from anthropic import Anthropic
import os
import requests
import json
from datetime import datetime
from typing import Optional

app = FastAPI()

# Initialize Anthropic client
client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

class QueryRequest(BaseModel):
    vendor: str = ""
    date_filter: str = ""
    query: str

class QueryResponse(BaseModel):
    response: str
    count: int = 0

@app.get("/")
async def read_root():
    """Serve the index.html file"""
    return FileResponse("index.html")

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}

def fetch_kev_data():
    """Fetch KEV data from CISA"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching KEV data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch KEV data: {str(e)}")

def fetch_cvss_data(cves):
    """Fetch CVSS scores from NVD"""
    cvss_scores = {}
    
    for cve in cves[:20]:  # Limit to first 20 CVEs
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    vuln_data = data['vulnerabilities'][0]['cve']
                    
                    # Try to get CVSS v3 score
                    if 'metrics' in vuln_data:
                        if 'cvssMetricV31' in vuln_data['metrics']:
                            cvss_scores[cve] = vuln_data['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                        elif 'cvssMetricV30' in vuln_data['metrics']:
                            cvss_scores[cve] = vuln_data['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                        elif 'cvssMetricV2' in vuln_data['metrics']:
                            cvss_scores[cve] = vuln_data['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
        except Exception as e:
            print(f"Error fetching CVSS for {cve}: {str(e)}")
            continue
    
    return cvss_scores

def fetch_epss_data(cves):
    """Fetch EPSS scores from FIRST.org"""
    epss_scores = {}
    
    try:
        # FIRST.org EPSS API - batch request
        cve_list = ','.join(cves[:20])
        url = f"https://api.first.org/data/v1/epss?cve={cve_list}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                for item in data['data']:
                    cve = item['cve']
                    epss = float(item['epss']) * 100  # Convert to percentage
                    epss_scores[cve] = round(epss, 2)
    except Exception as e:
        print(f"Error fetching EPSS data: {str(e)}")
    
    return epss_scores

def enrich_vulnerability_data(vulnerabilities, cvss_scores, epss_scores):
    """Enrich vulnerability data with CVSS and EPSS scores"""
    enriched = []
    
    for vuln in vulnerabilities:
        cve = vuln.get('cveID', '')
        enriched_vuln = vuln.copy()
        
        # Add CVSS score
        enriched_vuln['cvss_score'] = cvss_scores.get(cve, 'N/A')
        
        # Add EPSS score
        enriched_vuln['epss_score'] = epss_scores.get(cve, 'N/A')
        
        # Calculate priority label based on CVSS and EPSS
        cvss = cvss_scores.get(cve, 0)
        epss = epss_scores.get(cve, 0)
        
        if isinstance(cvss, (int, float)) and isinstance(epss, (int, float)):
            if cvss >= 9.0 and epss >= 10:
                priority = "🔴 URGENT"
            elif cvss >= 7.0 and epss >= 5:
                priority = "🟠 HIGH"
            elif cvss >= 4.0:
                priority = "🟡 MEDIUM"
            else:
                priority = "🟢 LOW"
        else:
            priority = "⚪ UNKNOWN"
        
        enriched_vuln['priority_label'] = priority
        
        enriched.append(enriched_vuln)
    
    # Sort by CVSS score (highest first)
    enriched.sort(key=lambda x: x.get('cvss_score', 0) if isinstance(x.get('cvss_score'), (int, float)) else 0, reverse=True)
    
    return enriched

def calculate_priority_label(cvss, epss):
    """Calculate priority label based on CVSS and EPSS scores"""
    if isinstance(cvss, (int, float)) and isinstance(epss, (int, float)):
        if cvss >= 9.0 and epss >= 10:
            return "🔴 URGENT"
        elif cvss >= 7.0 and epss >= 5:
            return "🟠 HIGH"
        elif cvss >= 4.0:
            return "🟡 MEDIUM"
        else:
            return "🟢 LOW"
    return "⚪ UNKNOWN"

def filter_vulnerabilities(kev_data, vendor, date_filter, query_text):
    """Filter vulnerabilities based on criteria"""
    vulnerabilities = kev_data.get('vulnerabilities', [])
    filtered = []
    
    for vuln in vulnerabilities:
        # Vendor filter
        if vendor and vendor.lower() not in vuln.get('vendorProject', '').lower():
            continue
        
        # Date filter
        if date_filter:
            vuln_date = vuln.get('dateAdded', '')
            if date_filter not in vuln_date:
                continue
        
        # Query text filter - search in multiple fields, but only if query_text is not empty
        if query_text:
            search_text = f"{vuln.get('vendorProject', '')} {vuln.get('product', '')} {vuln.get('vulnerabilityName', '')} {vuln.get('shortDescription', '')} {vuln.get('cveID', '')}".lower()
            if query_text.lower() not in search_text:
                continue
        
        filtered.append(vuln)
    
    return filtered

@app.post("/api/query", response_model=QueryResponse)
async def query(request: QueryRequest):
    """Process threat intelligence queries"""
    try:
        print(f"Query received: vendor={request.vendor}, date={request.date_filter}, query={request.query}")
        
        # Fetch KEV data
        kev_data = fetch_kev_data()
        
        # Filter vulnerabilities by vendor and date only
        # Don't filter by query_text - that's the question for Claude!
        filtered_data = filter_vulnerabilities(kev_data, request.vendor, request.date_filter, "")
        
        if not filtered_data:
            raise HTTPException(status_code=404, detail="No vulnerabilities found matching your criteria")
        
        print(f"Found {len(filtered_data)} matching vulnerabilities")
        
        # Get CVEs for enrichment
        cves = [vuln.get('cveID') for vuln in filtered_data]
        
        # Fetch CVSS and EPSS data
        print("Fetching CVSS data...")
        cvss_data = fetch_cvss_data(cves)
        
        print("Fetching EPSS data...")
        epss_data = fetch_epss_data(cves)
        
        # Enrich vulnerability data
        enriched_data = enrich_vulnerability_data(filtered_data, cvss_data, epss_data)
        
        # Build context for Claude
        import json
        context = f"""
You are a cybersecurity threat intelligence analyst.

User Query: "{request.query}"

Analyze these {len(enriched_data)} vulnerabilities from the CISA KEV catalog.

Vulnerabilities:
{json.dumps(enriched_data[:20], indent=2)}

RESPONSE FORMAT:

1. Create an HTML table showing the top 5-10 vulnerabilities:

<table style="width:100%; border-collapse: collapse; margin: 20px 0; border: 1px solid #ddd;">
<thead>
<tr style="background: linear-gradient(135deg, #667eea, #764ba2); color: white;">
<th style="padding: 12px; text-align: left; border: 1px solid #ddd;">CVE ID</th>
<th style="padding: 12px; text-align: left; border: 1px solid #ddd;">Vulnerability</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">CVSS</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">EPSS</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">Priority</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">Date Added</th>
</tr>
</thead>
<tbody>
[rows with border: 1px solid #ddd on each cell]
</tbody>
</table>

2. Brief analysis (2-3 sentences) - put this IMMEDIATELY after the table with NO blank lines

IMPORTANT:
- Add border: 1px solid #ddd to ALL table cells
- Use clickable CVE links: <a href="https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX" target="_blank" style="color: #667eea; font-weight: 600;">CVE-XXXX-XXXXX</a>
- Color code CVSS scores: 9.0-10.0=#dc2626, 7.0-8.9=#ea580c, 4.0-6.9=#f59e0b
- Show priority labels with emojis (🔴 URGENT, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW)
- DO NOT add excessive blank lines or newlines
- Keep it concise - NO SIEM queries in this response
"""
        
        print("Calling Claude API...")
        
        # Call Claude
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,  # Reduced - no queries needed!
            messages=[{"role": "user", "content": context}]
        )
        
        response_text = response.content[0].text
        
        # Strip ALL leading and trailing whitespace
        response_text = response_text.strip()
        
        # Remove excessive leading newlines
        import re
        response_text = re.sub(r'^\n+', '', response_text)
        
        return QueryResponse(
            response=response_text,
            count=len(enriched_data)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in query endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/generate-queries")
async def generate_queries(request: QueryRequest):
    """Generate SIEM detection queries for specific vulnerabilities"""
    try:
        print(f"Generate queries request: {request.query}")
        
        # Fetch KEV data
        kev_data = fetch_kev_data()
        
        # Filter vulnerabilities
        filtered_data = filter_vulnerabilities(kev_data, request.vendor, request.date_filter, "")
        
        if not filtered_data:
            raise HTTPException(status_code=404, detail="No vulnerabilities found")
        
        # Get CVEs
        cves = [vuln.get('cveID') for vuln in filtered_data[:10]]
        
        # Build context for SIEM queries
        context = f"""
Generate detection queries for these CVEs from the CISA KEV catalog:
{', '.join(cves)}

Create production-ready detection queries for ALL THREE SIEMs:

**Azure Sentinel (KQL):**
```kql
[Comprehensive KQL query for Azure Sentinel]
```

**Splunk (SPL):**
```spl
[Comprehensive SPL query for Splunk]
```

**Elasticsearch (EQL):**
```eql
[Comprehensive EQL query for Elasticsearch]
```

Make the queries:
- Production-ready and tested
- Cover authentication, process execution, network connections, and file operations
- Include relevant CVE indicators
- Be copy-paste ready
"""
        
        # Call Claude
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            messages=[{"role": "user", "content": context}]
        )
        
        return {"queries": response.content[0].text}
        
    except Exception as e:
        print(f"Error generating queries: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/generate-single-query")
async def generate_single_query(request: dict):
    """Generate a single SIEM query based on query type"""
    try:
        query_type = request.get('query_type', 'kql')
        last_query = request.get('query', '')
        
        print(f"Generate single query: {query_type}")
        
        # Fetch KEV data
        kev_data = fetch_kev_data()
        filtered_data = filter_vulnerabilities(kev_data, '', '', "")
        
        if not filtered_data:
            raise HTTPException(status_code=404, detail="No vulnerabilities found")
        
        # Get CVEs
        cves = [vuln.get('cveID') for vuln in filtered_data[:10]]
        
        # Build context based on query type
        if query_type == 'kql':
            platform = "Azure Sentinel (KQL)"
            language = "KQL"
        elif query_type == 'spl':
            platform = "Splunk (SPL)"
            language = "SPL"
        else:
            platform = "Elasticsearch (EQL)"
            language = "EQL"
        
        context = f"""
Generate a production-ready detection query for {platform}.

Target CVEs from CISA KEV catalog:
{', '.join(cves[:10])}

Create a comprehensive {language} query that:
- Detects exploitation attempts for these CVEs
- Covers authentication anomalies, process execution, network connections, file operations
- Is production-ready and copy-paste ready
- Includes CVE-specific indicators

Output ONLY the query code, no explanation.
"""
        
        # Call Claude
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": context}]
        )
        
        return {"query": response.content[0].text.strip()}
        
    except Exception as e:
        print(f"Error generating query: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
