"""
CyberIQ API - Enhanced with better KEV search
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Dict
import anthropic
import os

# Import the functions from vulnerability_loaders
from vulnerability_loaders import load_kev_data, load_recent_cves

app = FastAPI(title="CyberIQ API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global data storage
mitre_data = []
kev_data = []
cve_data = []

# Initialize Anthropic client
anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
if not anthropic_api_key:
    raise ValueError("ANTHROPIC_API_KEY environment variable not set")

client = anthropic.Anthropic(api_key=anthropic_api_key)


class QueryRequest(BaseModel):
    query: str


class QueryResponse(BaseModel):
    response: str
    sources: Optional[List[Dict]] = []


@app.on_event("startup")
async def startup_event():
    """Load all data on startup"""
    global mitre_data, kev_data, cve_data
    
    print("🚀 Starting CyberIQ API...")
    
    # Load MITRE ATT&CK data
    try:
        print("📥 Loading MITRE ATT&CK data...")
        from mitre_loaders import load_attack_data
        mitre_data = load_attack_data()
        print(f"✅ Loaded {len(mitre_data)} MITRE ATT&CK techniques")
    except Exception as e:
        print(f"⚠️  Error loading MITRE data: {str(e)}")
        mitre_data = []
    
    # Load CISA KEV data
    try:
        print("⚠️  Loading CISA KEV data...")
        kev_data = load_kev_data()
        print(f"✅ Loaded {len(kev_data)} KEVs")
    except Exception as e:
        print(f"❌ Error loading KEV data: {str(e)}")
        kev_data = []
    
    # Skip CVE loading
    cve_data = []
    
    total_items = len(mitre_data) + len(kev_data)
    print(f"🎉 CyberIQ ready with {total_items} threat intelligence items!")


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the chat interface"""
    try:
        with open("index.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>CyberIQ</h1><p>Chat interface not found.</p>"


@app.get("/api/status")
async def status():
    """API health check"""
    return {
        "status": "online",
        "service": "CyberIQ Threat Intelligence Platform",
        "data_loaded": {
            "mitre_techniques": len(mitre_data),
            "cisa_kevs": len(kev_data),
            "total": len(mitre_data) + len(kev_data)
        }
    }


@app.post("/query", response_model=QueryResponse)
async def query(request: QueryRequest):
    """Process queries with improved KEV search"""
    try:
        query_lower = request.query.lower()
        
        # Build context
        context = f"""You are CyberIQ with access to:
- {len(mitre_data)} MITRE ATT&CK techniques
- {len(kev_data)} CISA Known Exploited Vulnerabilities

User Query: {request.query}

"""
        
        # Smart search
        relevant_items = search_data_smart(request.query)
        
        if relevant_items:
            context += "Relevant Intelligence:\n\n"
            for item in relevant_items[:15]:
                context += format_item_detailed(item) + "\n\n"
        
        # Call Claude
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": context}]
        )
        
        return QueryResponse(
            response=message.content[0].text,
            sources=relevant_items[:5]
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def search_data_smart(query: str) -> List[Dict]:
    """Smart search with KEV prioritization"""
    results = []
    q = query.lower()
    
    # Detect intent
    wants_recent = any(w in q for w in ['recent', 'latest', 'new', 'top'])
    wants_critical = any(w in q for w in ['critical', 'high', 'severe'])
    wants_ransomware = 'ransomware' in q
    wants_kev = any(w in q for w in ['kev', 'exploited', 'vulnerability', 'cve'])
    wants_mitre = any(w in q for w in ['technique', 'tactic', 'mitre', 'attack', 'phishing'])
    
    # KEV queries
    if wants_kev or wants_recent or not wants_mitre:
        kevs = sorted(kev_data, key=lambda x: x.get('date_added', ''), reverse=True)
        
        if wants_ransomware:
            kevs = [k for k in kevs if k.get('cisa_ransomware') or k.get('known_ransomware') == 'Known']
        
        for kev in kevs[:20]:
            results.append({"type": "kev", "data": kev})
    
    # MITRE queries
    if wants_mitre or (not wants_kev and not wants_recent):
        for item in mitre_data[:20]:
            if any(word in str(item).lower() for word in q.split() if len(word) > 3):
                results.append({"type": "mitre", "data": item})
                if len(results) >= 30:
                    break
    
    # Default: recent KEVs
    if not results:
        recent = sorted(kev_data, key=lambda x: x.get('date_added', ''), reverse=True)[:15]
        results = [{"type": "kev", "data": k} for k in recent]
    
    return results


def format_item_detailed(item: Dict) -> str:
    """Detailed formatting"""
    itype = item.get("type")
    data = item.get("data", {})
    
    if itype == "kev":
        return f"""KEV {data.get('cve_id', 'N/A')}: {data.get('vulnerability_name', 'N/A')}
Vendor/Product: {data.get('vendor_project', 'N/A')} {data.get('product', 'N/A')}
Date Added: {data.get('date_added', 'N/A')}
CVSS: {data.get('cvss_score', 'Pending')} ({data.get('cvss_severity', 'HIGH')})
Ransomware: {'Yes' if (data.get('cisa_ransomware') or data.get('known_ransomware') == 'Known') else 'No'}
Required Action: {data.get('required_action', 'N/A')}
Description: {data.get('short_description', 'N/A')[:200]}"""
    
    elif itype == "mitre":
        return f"MITRE {data.get('technique_id', 'N/A')}: {data.get('technique_name', 'N/A')}\n{data.get('description', 'N/A')[:200]}"
    
    return str(data)[:200]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)