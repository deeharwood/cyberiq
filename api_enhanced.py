"""
CyberIQ API - Enhanced with CVSS, CWE, NVD, and CISA ADP
Compatible with function-based vulnerability loaders
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
    
    # Load CISA KEV data with enrichment
    try:
        print("⚠️  Loading CISA KEV data with CVSS, CWE, NVD, and CISA ADP enrichment...")
        kev_data = load_kev_data()
        print(f"✅ Loaded {len(kev_data)} enriched KEVs")
    except Exception as e:
        print(f"❌ Error loading KEV data: {str(e)}")
        kev_data = []
    
    # Load recent CVE data with enrichment
    try:
        print("🔒 Loading recent CVE data with CVSS, CWE, NVD, and CISA ADP enrichment...")
        cve_data = load_recent_cves(days=90)
        print(f"✅ Loaded {len(cve_data)} enriched CVEs")
    except Exception as e:
        print(f"❌ Error loading CVE data: {str(e)}")
        cve_data = []
    
    total_items = len(mitre_data) + len(kev_data) + len(cve_data)
    print(f"🎉 CyberIQ ready with {total_items} threat intelligence items!")


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "CyberIQ Threat Intelligence Platform",
        "data_loaded": {
            "mitre_techniques": len(mitre_data),
            "cisa_kevs": len(kev_data),
            "recent_cves": len(cve_data),
            "total": len(mitre_data) + len(kev_data) + len(cve_data)
        },
        "features": [
            "CVSS Scoring",
            "CWE Classifications", 
            "NVD Links",
            "CISA ADP Government Analysis",
            "AI-Powered Analysis"
        ]
    }


@app.post("/query", response_model=QueryResponse)
async def query(request: QueryRequest):
    """
    Process a natural language query against threat intelligence data
    Returns AI-powered analysis with CVSS, CWE, NVD, and CISA ADP context
    """
    try:
        # Prepare context for Claude
        context = f"""You are CyberIQ, a unified threat intelligence assistant with access to comprehensive security data.

Available Data:
- {len(mitre_data)} MITRE ATT&CK techniques
- {len(kev_data)} CISA Known Exploited Vulnerabilities (enriched with CVSS, CWE, CISA ADP)
- {len(cve_data)} Recent CVEs (enriched with CVSS, CWE, CISA ADP)

Data Enrichment Features:
- CVSS Scores: Industry-standard severity ratings (v3.1, v3.0, v2.0)
- CWE Classifications: Common weakness types (SQL Injection, XSS, Buffer Overflow, etc.)
- NVD Links: Direct research links to National Vulnerability Database
- CISA ADP: Government analysis including exploitation status, ransomware flags, compliance deadlines

When discussing vulnerabilities, always mention:
1. CVSS score and severity (if available)
2. CWE classification (if available)
3. CISA exploitation status (if KEV)
4. Ransomware campaign usage (if known)
5. Required actions and due dates (if CISA mandated)

User Query: {request.query}

Provide a comprehensive, accurate response based on the available data."""

        # Search relevant data
        relevant_items = search_data(request.query)
        
        if relevant_items:
            context += "\n\nRelevant Intelligence:\n"
            for item in relevant_items[:10]:  # Limit to top 10
                context += f"\n{format_item_for_context(item)}"
        
        # Call Claude for analysis
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[
                {"role": "user", "content": context}
            ]
        )
        
        response_text = message.content[0].text
        
        return QueryResponse(
            response=response_text,
            sources=relevant_items[:5]  # Return top 5 sources
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def search_data(query: str) -> List[Dict]:
    """
    Search through all data sources for relevant items
    Returns combined results from MITRE, KEV, and CVE data
    """
    results = []
    query_lower = query.lower()
    
    # Search MITRE ATT&CK
    for item in mitre_data:
        if matches_query(item, query_lower):
            results.append({
                "type": "mitre",
                "data": item
            })
    
    # Search KEVs (with enrichment)
    for item in kev_data:
        if matches_query(item, query_lower):
            results.append({
                "type": "kev",
                "data": item
            })
    
    # Search CVEs (with enrichment)
    for item in cve_data:
        if matches_query(item, query_lower):
            results.append({
                "type": "cve",
                "data": item
            })
    
    return results


def matches_query(item: Dict, query: str) -> bool:
    """Check if item matches query string"""
    # Convert item to searchable text
    item_text = str(item).lower()
    
    # Simple keyword matching
    keywords = query.split()
    return any(keyword in item_text for keyword in keywords if len(keyword) > 2)


def format_item_for_context(item: Dict) -> str:
    """Format item for Claude context"""
    item_type = item.get("type", "unknown")
    data = item.get("data", {})
    
    if item_type == "mitre":
        return f"MITRE {data.get('technique_id', 'N/A')}: {data.get('technique_name', 'N/A')} - {data.get('description', 'N/A')[:200]}"
    
    elif item_type == "kev":
        cve_id = data.get('cve_id', 'N/A')
        cvss = data.get('cvss_score', 0)
        cvss_severity = data.get('cvss_severity', 'UNKNOWN')
        cwe = data.get('cwe_id', '')
        cwe_desc = data.get('cwe_description', '')
        cisa_exploited = data.get('cisa_known_exploited', False)
        ransomware = data.get('cisa_ransomware', False)
        
        result = f"KEV {cve_id}: {data.get('vulnerability_name', 'N/A')}"
        
        if cvss > 0:
            result += f" [CVSS: {cvss} {cvss_severity}]"
        
        if cwe:
            result += f" [CWE-{cwe}: {cwe_desc}]"
        
        if cisa_exploited:
            result += " [CISA: KNOWN EXPLOITED]"
        
        if ransomware:
            result += " [RANSOMWARE]"
        
        result += f" - {data.get('short_description', 'N/A')[:150]}"
        
        return result
    
    elif item_type == "cve":
        cve_id = data.get('cve_id', 'N/A')
        cvss = data.get('cvss_score', 0)
        cvss_severity = data.get('cvss_severity', 'UNKNOWN')
        cwe = data.get('cwe_id', '')
        cwe_desc = data.get('cwe_description', '')
        
        result = f"CVE {cve_id}"
        
        if cvss > 0:
            result += f" [CVSS: {cvss} {cvss_severity}]"
        
        if cwe:
            result += f" [CWE-{cwe}: {cwe_desc}]"
        
        result += f" - {data.get('description', 'N/A')[:150]}"
        
        return result
    
    return str(data)[:200]


@app.get("/stats")
async def stats():
    """Get statistics about loaded data"""
    kev_with_cvss = sum(1 for k in kev_data if k.get('cvss_score', 0) > 0)
    kev_with_cwe = sum(1 for k in kev_data if k.get('cwe_id', ''))
    kev_ransomware = sum(1 for k in kev_data if k.get('cisa_ransomware', False))
    
    return {
        "mitre": {
            "total": len(mitre_data),
            "tactics": len(set(item.get('tactic', '') for item in mitre_data if item.get('tactic')))
        },
        "kev": {
            "total": len(kev_data),
            "with_cvss": kev_with_cvss,
            "with_cwe": kev_with_cwe,
            "ransomware_campaigns": kev_ransomware
        },
        "cve": {
            "total": len(cve_data),
            "recent_days": 90
        },
        "enrichment": {
            "cvss_coverage": f"{(kev_with_cvss / len(kev_data) * 100):.1f}%" if kev_data else "0%",
            "cwe_coverage": f"{(kev_with_cwe / len(kev_data) * 100):.1f}%" if kev_data else "0%"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
