from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from anthropic import Anthropic
import os
import requests
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Anthropic client
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Cache for EPSS data
epss_cache = {}

class QueryRequest(BaseModel):
    vendor: Optional[str] = ""
    date_filter: Optional[str] = ""
    query: Optional[str] = ""

def fetch_kev_data():
    """Fetch KEV data from CISA"""
    try:
        response = requests.get(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        return data.get('vulnerabilities', [])
    except Exception as e:
        print(f"Error fetching KEV data: {str(e)}")
        return []

def fetch_cvss_data(cves):
    """Fetch CVSS scores from NVD"""
    cvss_data = {}
    
    if not cves:
        return cvss_data
    
    for cve in cves[:50]:
        try:
            response = requests.get(
                f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    vuln = data['vulnerabilities'][0]
                    cve_data = vuln.get('cve', {})
                    metrics = cve_data.get('metrics', {})
                    
                    if 'cvssMetricV31' in metrics and len(metrics['cvssMetricV31']) > 0:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                        cvss_data[cve] = cvss_score
                    elif 'cvssMetricV30' in metrics and len(metrics['cvssMetricV30']) > 0:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                        cvss_data[cve] = cvss_score
                    elif 'cvssMetricV2' in metrics and len(metrics['cvssMetricV2']) > 0:
                        cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                        cvss_data[cve] = cvss_score
        except Exception as e:
            print(f"Error fetching CVSS for {cve}: {str(e)}")
            continue
    
    return cvss_data

def fetch_epss_data(cves):
    """Fetch EPSS scores from FIRST.org"""
    global epss_cache
    epss_data = {}
    
    if not cves:
        return epss_data
    
    uncached_cves = [cve for cve in cves if cve not in epss_cache]
    
    if uncached_cves:
        try:
            cve_list = ','.join(uncached_cves[:100])
            response = requests.get(
                f'https://api.first.org/data/v1/epss?cve={cve_list}',
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    for item in data['data']:
                        cve = item.get('cve')
                        epss = float(item.get('epss', 0))
                        epss_cache[cve] = epss
        except Exception as e:
            print(f"Error fetching EPSS data: {str(e)}")
    
    for cve in cves:
        if cve in epss_cache:
            epss_data[cve] = epss_cache[cve]
    
    return epss_data

def calculate_priority_label(cvss, epss):
    """Calculate priority label based on CVSS and EPSS"""
    if cvss is None or epss is None:
        return "🟡 MEDIUM"
    
    priority = cvss * epss
    
    if priority >= 7.0:
        return "🔴 URGENT"
    elif priority >= 3.0:
        return "🟠 HIGH"
    elif priority >= 1.0:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"

def filter_vulnerabilities(vulnerabilities, vendor, date_filter, query_text):
    """Filter vulnerabilities based on user input"""
    filtered = vulnerabilities
    
    if vendor:
        filtered = [v for v in filtered if vendor.lower() in v.get('vendorProject', '').lower()]
    
    if date_filter:
        days = int(date_filter)
        cutoff_date = datetime.now() - timedelta(days=days)
        filtered = [v for v in filtered if datetime.strptime(v.get('dateAdded', '2000-01-01'), '%Y-%m-%d') > cutoff_date]
    
    if query_text:
        query_lower = query_text.lower()
        filtered = [v for v in filtered if 
                   query_lower in v.get('vulnerabilityName', '').lower() or
                   query_lower in v.get('shortDescription', '').lower() or
                   query_lower in v.get('vendorProject', '').lower() or
                   query_lower in v.get('product', '').lower()]
    
    return filtered

def enrich_vulnerability_data(vulnerabilities, cvss_data, epss_data):
    """Enrich vulnerability data with CVSS and EPSS scores"""
    enriched = []
    
    for vuln in vulnerabilities:
        cve = vuln.get('cveID')
        cvss = cvss_data.get(cve)
        epss = epss_data.get(cve)
        
        priority_label = calculate_priority_label(cvss, epss)
        
        enriched.append({
            'cve': cve,
            'vendor': vuln.get('vendorProject'),
            'product': vuln.get('product'),
            'name': vuln.get('vulnerabilityName'),
            'description': vuln.get('shortDescription'),
            'date_added': vuln.get('dateAdded'),
            'due_date': vuln.get('dueDate'),
            'cvss': cvss,
            'epss': epss,
            'priority': priority_label
        })
    
    return enriched

@app.post("/api/query")
async def query(request: QueryRequest):
    """Main API endpoint for threat intelligence queries"""
    try:
        vendor = request.vendor or ""
        date_filter = request.date_filter or ""
        query_text = request.query or ""
        
        print(f"Query received: vendor={vendor}, date={date_filter}, query={query_text}")
        
        # Fetch KEV data
        kev_data = fetch_kev_data()
        
        if not kev_data:
            raise HTTPException(status_code=500, detail="Unable to fetch KEV data from CISA")
        
        # Filter vulnerabilities by vendor and date only
        # Don't filter by query_text - that's the question for Claude!
        filtered_data = filter_vulnerabilities(kev_data, vendor, date_filter, "")
        
        if not filtered_data:
            raise HTTPException(status_code=404, detail="No vulnerabilities found matching your criteria")
        
        print(f"Found {len(filtered_data)} matching vulnerabilities")
        
        # Get CVEs
        cves = [vuln.get('cveID') for vuln in filtered_data[:50]]
        
        # Fetch CVSS and EPSS data
        print("Fetching CVSS data...")
        cvss_data = fetch_cvss_data(cves)
        
        print("Fetching EPSS data...")
        epss_data = fetch_epss_data(cves)
        
        # Enrich vulnerability data
        enriched_data = enrich_vulnerability_data(filtered_data, cvss_data, epss_data)
        
        # Sort by priority
        priority_order = {"🔴 URGENT": 0, "🟠 HIGH": 1, "🟡 MEDIUM": 2, "🟢 LOW": 3}
        enriched_data.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        # Build context for Claude
        import json
        context = f"""
You are a cybersecurity threat intelligence analyst.

User Query: "{query_text}"

Analyze these {len(enriched_data)} vulnerabilities from the CISA KEV catalog.

Vulnerabilities:
{json.dumps(enriched_data[:20], indent=2)}

Based on the user's query above, provide a concise threat intelligence analysis:
1. Brief summary addressing their specific question (2-3 sentences)
2. Top 3-5 most relevant vulnerabilities with their priority labels and EPSS scores
3. Key patterns or trends you observe
4. Actionable recommendations for security teams

Be concise and focus on answering the user's specific question.
"""
        
        print("Calling Claude API...see if this works...")
        
        # Call Claude
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1500,
            messages=[{"role": "user", "content": context}]
        )
        
        response_text = response.content[0].text
        
        print("Response received from Claude....")
        
        return {
            'response': response_text,
            'count': len(enriched_data)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in query endpoint: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    """Health check endpoint to see if this works."""
    return {"status": "healthy"}

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main HTML page"""
    try:
        with open('index.html', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>CyberIQ API</h1><p>API is running. Upload index.html to see the interface.</p>"

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
