"""
CyberIQ API - With on-demand CVSS enrichment and table formatting
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Dict
import anthropic
import os

# Import loaders
from vulnerability_loaders import load_kev_data, load_recent_cves
from cvss_enricher import enrich_kevs_with_cvss

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
    
    # Load CISA KEV data (WITHOUT enrichment initially)
    try:
        print("⚠️  Loading CISA KEV data...")
        kev_data = load_kev_data()
        print(f"✅ Loaded {len(kev_data)} KEVs (CVSS enrichment on-demand)")
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


def clean_response_spacing(response_text: str) -> str:
    """
    Remove ALL content before HTML tables - table must appear first
    """
    import re
    
    print("=== BACKEND CLEANING DEBUG ===")
    print(f"Original text length: {len(response_text)}")
    print(f"Contains <table>: {'<table' in response_text.lower()}")
    print(f"First 200 chars: {response_text[:200]}")
    
    # Check if response contains a table
    if '<table' not in response_text.lower():
        print("No table found, returning original")
        return response_text
    
    # Find the position of the first <table> tag
    table_match = re.search(r'<table[^>]*>', response_text, re.IGNORECASE)
    if not table_match:
        print("Table tag not found by regex")
        return response_text
    
    table_start = table_match.start()
    print(f"Table starts at position: {table_start}")
    
    # Get everything before the table
    before_table = response_text[:table_start]
    print(f"Content before table length: {len(before_table)}")
    print(f"Content before table: {before_table[:100]}...")
    
    # Get the table and everything after
    table_and_after = response_text[table_start:]
    
    # AGGRESSIVE: Remove ALL content before table
    # User confirmed this looks best
    before_table = ''
    
    print(f"Cleaned response length: {len(table_and_after)}")
    print(f"Cleaned response (first 200 chars): {table_and_after[:200]}")
    
    return before_table + table_and_after


@app.post("/query", response_model=QueryResponse)
async def query(request: QueryRequest):
    """Process queries with on-demand CVSS enrichment and table formatting"""
    try:
        query_lower = request.query.lower()
        
        # Detect if user wants CVSS scores
        wants_cvss = any(w in query_lower for w in ['cvss', 'score', 'severity', 'highest', 'critical', 'top'])
        wants_top_n = any(w in query_lower for w in ['top', 'highest'])
        
        # Extract number if asking for "top N"
        import re
        top_n_match = re.search(r'top\s+(\d+)', query_lower)
        num_items = int(top_n_match.group(1)) if top_n_match else 10
        num_items = min(num_items, 20)  # Cap at 20 to avoid rate limits
        
        # Build context
        context = f"""You are CyberIQ with access to:
- {len(mitre_data)} MITRE ATT&CK techniques
- {len(kev_data)} CISA Known Exploited Vulnerabilities

User Query: {request.query}

IMPORTANT: If the user asks for KEVs from a specific time period (e.g., "December 2025", "2025", "last month"), 
the system has already filtered the results to only show KEVs from that period. If no results are shown, 
state clearly that no KEVs match the criteria for that time period.

KQL SUPPORT: If the user asks for KQL, Kusto queries, or Sentinel queries, provide a KQL query example 
after the table that searches for indicators related to the vulnerabilities shown. Use Azure Sentinel table 
names like SecurityAlert, SecurityEvent, CommonSecurityLog, etc.

When providing KQL queries, format them in a code block like this:
<pre><code>
SecurityAlert
| where TimeGenerated >= datetime(2025-12-01)
| where Severity in ("High", "Critical")
| where CVE has_any ("CVE-2025-52691", "CVE-2018-14634")
| project TimeGenerated, AlertName, CVE, Severity, Entities
</code></pre>

!!CRITICAL!! SHOW THE HTML TABLE FIRST - NO PREAMBLE, NO INTRODUCTION, NO EXPLANATION BEFORE THE TABLE.

Start your response IMMEDIATELY with <table>. Analysis comes AFTER.

CORRECT FORMAT:
<table style="width:100%; border-collapse: collapse; margin: 0 0 15px 0;">
[table rows here]
</table>

Analysis text here.

WRONG FORMAT (DO NOT DO THIS):
Here are the results...
Based on analysis...
Let me explain...
<table>

HTML TABLE STRUCTURE:

<table style="width:100%; border-collapse: collapse; margin: 0 0 15px 0;">
<thead>
<tr style="background: linear-gradient(135deg, #1e3a8a, #7c3aed); color: white;">
<th style="padding: 12px; text-align: left; border: 1px solid #ddd;">CVE ID</th>
<th style="padding: 12px; text-align: left; border: 1px solid #ddd;">Vulnerability</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">CVSS</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">Severity</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">Date Added</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">Ransomware</th>
</tr>
</thead>
<tbody>
<tr style="background: #f9fafb;">
<td style="padding: 12px; border: 1px solid #ddd;">
<a href="https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX" target="_blank" rel="noopener noreferrer" style="color: #1e3a8a; font-weight: 600; text-decoration: none; border-bottom: 2px solid #7c3aed;">CVE-XXXX-XXXXX ↗</a>
</td>
<td style="padding: 12px; border: 1px solid #ddd;">Vulnerability name</td>
<td style="padding: 12px; border: 1px solid #ddd; text-align: center; font-weight: 700; color: #dc2626;">9.8</td>
<td style="padding: 12px; border: 1px solid #ddd; text-align: center;"><span style="background: #dc2626; color: white; padding: 4px 12px; border-radius: 4px; font-size: 0.85em; font-weight: 600;">CRITICAL</span></td>
<td style="padding: 12px; border: 1px solid #ddd; text-align: center;">2026-01-26</td>
<td style="padding: 12px; border: 1px solid #ddd; text-align: center;">Yes</td>
</tr>
<tr style="background: white;">
<td style="padding: 12px; border: 1px solid #ddd;">
<a href="https://nvd.nist.gov/vuln/detail/CVE-YYYY-YYYYY" target="_blank" rel="noopener noreferrer" style="color: #1e3a8a; font-weight: 600; text-decoration: none; border-bottom: 2px solid #7c3aed;">CVE-YYYY-YYYYY ↗</a>
</td>
<td style="padding: 12px; border: 1px solid #ddd;">Another vulnerability</td>
<td style="padding: 12px; border: 1px solid #ddd; text-align: center; font-weight: 700; color: #ea580c;">8.5</td>
<td style="padding: 12px; border: 1px solid #ddd; text-align: center;"><span style="background: #ea580c; color: white; padding: 4px 12px; border-radius: 4px; font-size: 0.85em; font-weight: 600;">HIGH</span></td>
<td style="padding: 12px; border: 1px solid #ddd; text-align: center;">2026-01-25</td>
<td style="padding: 12px; border: 1px solid #ddd; text-align: center;">No</td>
</tr>
</tbody>
</table>

CVE LINKS: <a href="https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX" target="_blank" rel="noopener noreferrer" style="color: #1e3a8a; font-weight: 600; text-decoration: none; border-bottom: 2px solid #7c3aed;">CVE-XXXX-XXXXX ↗</a>

SEVERITY BADGES:
CRITICAL: <span style="background: #dc2626; color: white; padding: 4px 12px; border-radius: 4px; font-size: 0.85em; font-weight: 600;">CRITICAL</span>
HIGH: <span style="background: #ea580c; color: white; padding: 4px 12px; border-radius: 4px; font-size: 0.85em; font-weight: 600;">HIGH</span>
MEDIUM: <span style="background: #f59e0b; color: white; padding: 4px 12px; border-radius: 4px; font-size: 0.85em; font-weight: 600;">MEDIUM</span>
LOW: <span style="background: #84cc16; color: white; padding: 4px 12px; border-radius: 4px; font-size: 0.85em; font-weight: 600;">LOW</span>

CVSS COLORS: 9.0-10.0=#dc2626, 7.0-8.9=#ea580c, 4.0-6.9=#f59e0b, <4.0=#84cc16

Row backgrounds alternate: #f9fafb and white

After table: Brief key findings (2-3 sentences max).

"""
        
        # Smart search with CVSS enrichment if needed
        relevant_items = search_data_smart(request.query)
        
        # Check if date filtering was applied (look for empty results with date keywords)
        has_date_ref = any(word in query_lower for word in ['december', 'november', 'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', '2024', '2025', '2026'])
        
        if not relevant_items and has_date_ref:
            context += f"\n\nNo KEVs found matching the specified time period in the query."
        
        # If user wants CVSS and we have KEVs, enrich them
        if wants_cvss and relevant_items and relevant_items[0].get('type') == 'kev':
            print(f"🔍 Enriching top {num_items} KEVs with CVSS scores...")
            
            kevs_to_enrich = [item['data'] for item in relevant_items[:num_items] if item.get('type') == 'kev']
            enriched_kevs = enrich_kevs_with_cvss(kevs_to_enrich, max_items=num_items)
            
            # Replace with enriched versions
            for i, enriched in enumerate(enriched_kevs):
                if i < len(relevant_items):
                    relevant_items[i]['data'] = enriched
            
            print(f"✅ Enriched {len(enriched_kevs)} KEVs with CVSS scores")
        
        if relevant_items:
            context += "Relevant Intelligence:\n\n"
            for item in relevant_items[:num_items]:
                context += format_item_detailed(item) + "\n\n"
        
        # Call Claude
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": context}]
        )
        
        # Post-process response to remove excessive spacing before table
        response_text = clean_response_spacing(message.content[0].text)
        
        return QueryResponse(
            response=response_text,
            sources=relevant_items[:5]
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def search_data_smart(query: str) -> List[Dict]:
    """Smart search with KEV prioritization and date filtering"""
    import re
    from datetime import datetime
    
    results = []
    q = query.lower()
    
    # Detect intent
    wants_recent = any(w in q for w in ['recent', 'latest', 'new'])
    wants_top = 'top' in q
    wants_highest = any(w in q for w in ['highest', 'critical', 'severe'])
    wants_ransomware = 'ransomware' in q
    wants_kev = any(w in q for w in ['kev', 'exploited', 'vulnerability', 'cve', 'cross'])
    wants_mitre = any(w in q for w in ['technique', 'tactic', 'mitre', 'attack', 'phishing'])
    wants_kql = any(w in q for w in ['kql', 'kusto', 'sentinel', 'azure', 'query language'])
    
    # Parse date filters from query
    date_filter_start = None
    date_filter_end = None
    
    # Check for specific month/year patterns
    month_map = {
        'january': 1, 'february': 2, 'march': 3, 'april': 4,
        'may': 5, 'june': 6, 'july': 7, 'august': 8,
        'september': 9, 'october': 10, 'november': 11, 'december': 12,
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'jun': 6,
        'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
    }
    
    # Look for "Month YYYY" pattern (e.g., "December 2025")
    for month_name, month_num in month_map.items():
        month_year_pattern = f"{month_name}\\s+(\\d{{4}})"
        match = re.search(month_year_pattern, q, re.IGNORECASE)
        if match:
            year = int(match.group(1))
            # Filter for entire month
            date_filter_start = f"{year}-{month_num:02d}-01"
            
            # Calculate last day of month properly
            if month_num in [1, 3, 5, 7, 8, 10, 12]:  # 31 days
                last_day = 31
            elif month_num in [4, 6, 9, 11]:  # 30 days
                last_day = 30
            else:  # February
                last_day = 29  # Covering leap years
            
            date_filter_end = f"{year}-{month_num:02d}-{last_day}"
            
            print(f"📅 Date filter detected: {month_name.title()} {year}")
            print(f"   Start: {date_filter_start}, End: {date_filter_end}")
            break
    
    # Look for just year pattern (e.g., "2025")
    if not date_filter_start:
        year_match = re.search(r'\b(20\d{2})\b', q)
        if year_match:
            year = int(year_match.group(1))
            date_filter_start = f"{year}-01-01"
            date_filter_end = f"{year}-12-31"
            print(f"📅 Year filter detected: {year}")
    
    # KEV queries (most common)
    if wants_kev or wants_recent or wants_top or wants_highest or not wants_mitre:
        kevs = sorted(kev_data, key=lambda x: x.get('date_added', ''), reverse=True)
        
        # Apply date filter if detected
        if date_filter_start and date_filter_end:
            filtered_kevs = []
            for k in kevs:
                date_added = k.get('date_added', '')
                if date_added and date_filter_start <= date_added <= date_filter_end:
                    filtered_kevs.append(k)
            print(f"   Filtered from {len(kevs)} to {len(filtered_kevs)} KEVs")
            kevs = filtered_kevs
        
        # Apply ransomware filter
        if wants_ransomware:
            kevs = [k for k in kevs if k.get('cisa_ransomware') or k.get('known_ransomware') == 'Known']
        
        # Return top results (will be enriched if CVSS requested)
        for kev in kevs[:30]:  # Get more candidates
            results.append({"type": "kev", "data": kev})
    
    # MITRE queries
    elif wants_mitre:
        for item in mitre_data[:20]:
            if any(word in str(item).lower() for word in q.split() if len(word) > 3):
                results.append({"type": "mitre", "data": item})
                if len(results) >= 20:
                    break
    
    # Default: recent KEVs
    if not results:
        recent = sorted(kev_data, key=lambda x: x.get('date_added', ''), reverse=True)[:20]
        results = [{"type": "kev", "data": k} for k in recent]
    
    return results


def format_item_detailed(item: Dict) -> str:
    """Detailed formatting for Claude"""
    itype = item.get("type")
    data = item.get("data", {})
    
    if itype == "kev":
        cvss = data.get('cvss_score', 0)
        cvss_str = f"{cvss:.1f}" if cvss > 0 else "Pending"
        
        return f"""KEV {data.get('cve_id', 'N/A')}: {data.get('vulnerability_name', 'N/A')}
Vendor/Product: {data.get('vendor_project', 'N/A')} {data.get('product', 'N/A')}
Date Added: {data.get('date_added', 'N/A')}
CVSS Score: {cvss_str}
CVSS Severity: {data.get('cvss_severity', 'HIGH')}
CWE: {data.get('cwe_id', 'N/A')}
Ransomware: {'Yes' if (data.get('cisa_ransomware') or data.get('known_ransomware') == 'Known') else 'No'}
Required Action: {data.get('required_action', 'N/A')}
Due Date: {data.get('due_date', 'N/A')}
Description: {data.get('short_description', 'N/A')[:200]}"""
    
    elif itype == "mitre":
        return f"MITRE {data.get('technique_id', 'N/A')}: {data.get('technique_name', 'N/A')}\n{data.get('description', 'N/A')[:200]}"
    
    return str(data)[:200]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
