from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from anthropic import Anthropic
import os
import requests
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from bs4 import BeautifulSoup

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

@app.get("/api/status")
async def get_status():
    """Get current data status and counts"""
    try:
        # Fetch current data
        kev_data = fetch_kev_data()
        kev_count = len(kev_data.get('vulnerabilities', []))
        
        recent_nvd_cves = fetch_recent_nvd_cves(days=30)
        nvd_count = len(recent_nvd_cves)
        
        zdi_advisories = fetch_zdi_advisories(days=30)
        zdi_count = len(zdi_advisories)
        
        total_count = kev_count + nvd_count + zdi_count
        
        return {
            "status": "online",
            "data": {
                "zdi_advisories": zdi_count,
                "recent_nvd_cves": nvd_count,
                "cisa_kevs": kev_count,
                "total": total_count
            },
            "last_updated": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

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

def fetch_recent_nvd_cves(days=30):
    """Fetch recent CVEs from NVD (last N days) - High/Critical only"""
    print(f"Fetching recent CVEs from NVD (last {days} days)...")
    
    # Calculate date range
    from datetime import timedelta
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Format dates for NVD API (ISO 8601)
    start_date_str = start_date.strftime('%Y-%m-%dT00:00:00.000')
    end_date_str = end_date.strftime('%Y-%m-%dT23:59:59.999')
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={start_date_str}&pubEndDate={end_date_str}"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        # Extract CVEs
        cves = []
        for item in data.get('vulnerabilities', []):
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id', '')
            
            # Get CVSS score
            cvss_score = 0
            cvss_severity = 'UNKNOWN'
            metrics = cve_data.get('metrics', {})
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                cvss_severity = 'HIGH' if cvss_score >= 7.0 else 'MEDIUM'
            
            # Only include High/Critical (CVSS >= 7.0)
            if cvss_score < 7.0:
                continue
            
            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get published date
            published = cve_data.get('published', '')[:10]  # Just date part
            
            # Format as KEV-like structure for compatibility
            cve_entry = {
                'cveID': cve_id,
                'vendorProject': 'Various',
                'product': 'Various',
                'vulnerabilityName': f"{cve_id} - {cvss_severity}",
                'dateAdded': published,
                'shortDescription': description[:200] if description else 'No description available',
                'requiredAction': 'Review and patch as appropriate',
                'dueDate': '',
                'knownRansomwareCampaignUse': 'Unknown',
                'cvss_score': cvss_score,
                'cvss_severity': cvss_severity,
                'epss_score': 0,
                'priority': '🔴 URGENT' if cvss_score >= 9.0 else '🟠 HIGH',
                'source': 'NVD Recent'
            }
            
            cves.append(cve_entry)
        
        print(f"✅ Fetched {len(cves)} recent high-severity CVEs from NVD")
        return cves
        
    except Exception as e:
        print(f"❌ Error fetching NVD CVEs: {str(e)}")
        return []

def fetch_zdi_advisories(days=30):
    """Fetch recent Zero Day Initiative advisories from RSS feed"""
    print(f"Fetching ZDI advisories from RSS feed (last {days} days)...")
    
    try:
        # ZDI published advisories RSS feed
        url = "https://www.zerodayinitiative.com/rss/published/"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'xml')  # Use XML parser for RSS
        
        # Calculate cutoff date (timezone-aware for comparison with RSS dates)
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        advisories = []
        
        # Parse RSS items
        items = soup.find_all('item')
        
        for item in items:
            try:
                # Extract fields from RSS
                title = item.find('title').text if item.find('title') else ''
                link = item.find('link').text if item.find('link') else ''
                pub_date_str = item.find('pubDate').text if item.find('pubDate') else ''
                description = item.find('description').text if item.find('description') else ''
                
                # Parse publication date (RSS format: "Mon, 03 Feb 2026 00:00:00 GMT")
                try:
                    pub_date = datetime.strptime(pub_date_str, '%a, %d %b %Y %H:%M:%S %Z')
                    # strptime with %Z doesn't make datetime timezone-aware, so add UTC timezone
                    pub_date = pub_date.replace(tzinfo=timezone.utc)
                except:
                    try:
                        # Try alternative format with offset (e.g. +0000)
                        pub_date = datetime.strptime(pub_date_str, '%a, %d %b %Y %H:%M:%S %z')
                    except:
                        print(f"Could not parse date: {pub_date_str}")
                        continue
                
                # Check if within time window
                if pub_date < cutoff_date:
                    continue
                
                # Extract ZDI ID from title or link
                zdi_id_match = re.search(r'ZDI-\d{2}-\d+', title or link)
                zdi_id = zdi_id_match.group(0) if zdi_id_match else 'ZDI-UNKNOWN'
                
                # Extract CVE if present
                cve_match = re.search(r'CVE-\d{4}-\d+', title + ' ' + description)
                cve_id = cve_match.group(0) if cve_match else zdi_id
                
                # Extract vendor from title (usually first part before hyphen)
                vendor = 'Unknown'
                title_parts = title.split(' - ')
                if len(title_parts) > 0:
                    vendor = title_parts[0].split()[0] if title_parts[0] else 'Unknown'
                
                # Estimate severity from title keywords
                title_lower = (title + ' ' + description).lower()
                if any(word in title_lower for word in ['remote code execution', 'rce', 'arbitrary code execution', 'code execution', 'command injection']):
                    cvss_score = 9.0
                    severity = 'CRITICAL'
                elif any(word in title_lower for word in ['privilege escalation', 'authentication bypass', 'sql injection', 'xxe', 'deserialize']):
                    cvss_score = 8.5
                    severity = 'HIGH'
                elif any(word in title_lower for word in ['xss', 'cross-site', 'csrf', 'directory traversal', 'path traversal']):
                    cvss_score = 7.5
                    severity = 'HIGH'
                else:
                    cvss_score = 7.0
                    severity = 'HIGH'
                
                # Clean up title (remove ZDI ID if present)
                clean_title = re.sub(r'\(ZDI-\d{2}-\d+\)', '', title).strip()
                
                # Format as KEV-compatible structure
                advisory = {
                    'cveID': cve_id,
                    'vendorProject': vendor,
                    'product': 'Various',
                    'vulnerabilityName': clean_title[:100],
                    'dateAdded': pub_date.strftime('%Y-%m-%d'),
                    'shortDescription': (description[:200] if description else clean_title),
                    'requiredAction': 'Review ZDI advisory and apply vendor patches',
                    'dueDate': '',
                    'knownRansomwareCampaignUse': 'Unknown',
                    'cvss_score': cvss_score,
                    'cvss_severity': severity,
                    'epss_score': 0,
                    'priority': '🔴 URGENT' if cvss_score >= 9.0 else '🟠 HIGH',
                    'source': 'ZDI',
                    'zdi_id': zdi_id,
                    'advisory_url': link
                }
                
                advisories.append(advisory)
                
            except Exception as e:
                print(f"Error parsing ZDI RSS item: {str(e)}")
                continue
        
        print(f"✅ Fetched {len(advisories)} ZDI advisories from RSS feed")
        return advisories
        
    except Exception as e:
        print(f"❌ Error fetching ZDI RSS feed: {str(e)}")
        return []

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
        filtered_kev_data = filter_vulnerabilities(kev_data, request.vendor, request.date_filter, "")
        
        # Mark all KEVs with source
        for vuln in filtered_kev_data:
            vuln['source'] = 'CISA KEV'
        
        # Determine time window for NVD CVEs based on query
        nvd_days = 30  # Default: 30 days
        zdi_days = 30  # Default: 30 days for ZDI
        
        # For "latest" or "zero-day" queries, use shorter window
        if any(word in request.query.lower() for word in ['latest', 'zero-day', 'zero day', 'zeroday', '0-day', '0day']):
            nvd_days = 7  # Last 7 days only
            zdi_days = 14  # Last 14 days for ZDI (often published earlier)
            print(f"Query contains 'latest/zero-day' - using {nvd_days} days for NVD, {zdi_days} days for ZDI")
        
        # Fetch ZDI advisories (earliest disclosures)
        zdi_advisories = fetch_zdi_advisories(days=zdi_days)
        
        # Fetch recent NVD CVEs
        recent_nvd_cves = fetch_recent_nvd_cves(days=nvd_days)
        
        # Fallback: If zero results and looking for latest, expand to 30 days
        if len(recent_nvd_cves) == 0 and nvd_days < 30:
            print(f"No CVEs found in last {nvd_days} days, expanding to 30 days...")
            recent_nvd_cves = fetch_recent_nvd_cves(days=30)
            nvd_days = 30
        
        if len(zdi_advisories) == 0 and zdi_days < 30:
            print(f"No ZDI advisories found in last {zdi_days} days, expanding to 30 days...")
            zdi_advisories = fetch_zdi_advisories(days=30)
            zdi_days = 30
        
        print(f"Found {len(zdi_advisories)} ZDI advisories from last {zdi_days} days")
        print(f"Found {len(recent_nvd_cves)} NVD Recent CVEs from last {nvd_days} days")
        
        # Combine all three sources: ZDI + NVD + KEVs
        filtered_data = zdi_advisories + recent_nvd_cves + filtered_kev_data
        
        print(f"Total: {len(zdi_advisories)} ZDI + {len(recent_nvd_cves)} NVD + {len(filtered_kev_data)} KEVs = {len(filtered_data)} vulnerabilities")
        
        # Special handling for ransomware queries
        if 'ransomware' in request.query.lower():
            print("Filtering for ransomware KEVs...")
            filtered_data = [vuln for vuln in filtered_data 
                           if vuln.get('knownRansomwareCampaignUse', '').lower() in ['known', 'yes', 'true', 'y']]
            print(f"Found {len(filtered_data)} ransomware KEVs")
            
            # If still too few, show all KEVs and let Claude filter
            if len(filtered_data) < 10:
                print("Too few ransomware KEVs found, letting Claude filter from all KEVs")
                filtered_data = filtered_kev_data
        
        # Special handling for "zero-day" queries - prioritize ZDI + NVD (earliest sources)
        elif any(word in request.query.lower() for word in ['zero-day', 'zero day', 'zeroday', '0-day', '0day']):
            print("Zero-day query detected - showing ZDI + NVD Recent (earliest disclosures)...")
            filtered_data = zdi_advisories + recent_nvd_cves
            # Sort by date, newest first
            filtered_data.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
            print(f"Found {len(zdi_advisories)} ZDI + {len(recent_nvd_cves)} NVD CVEs")
        
        # Special handling for "recent", "latest", "new", "emerging" - prioritize ZDI and NVD
        elif any(word in request.query.lower() for word in ['recent', 'new', 'latest', 'emerging']):
            print("Recent/latest query detected - prioritizing ZDI + NVD...")
            # Show ZDI first, then NVD, then KEVs
            filtered_data = zdi_advisories + recent_nvd_cves + filtered_kev_data
            # Sort by date, newest first
            filtered_data.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
            print(f"Returning {len(zdi_advisories)} ZDI + {len(recent_nvd_cves)} NVD + {len(filtered_kev_data)} KEVs, sorted by date")
        
        if not filtered_data:
            raise HTTPException(status_code=404, detail="No vulnerabilities found matching your criteria")
        
        print(f"Returning {len(filtered_data)} total vulnerabilities")
        
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
        
        # Count sources
        kev_count = len([v for v in enriched_data if v.get('source') == 'CISA KEV'])
        nvd_count = len([v for v in enriched_data if v.get('source') == 'NVD Recent'])
        zdi_count = len([v for v in enriched_data if v.get('source') == 'ZDI'])
        
        # Build time window message
        time_window_msg = f"NVD: last {nvd_days} days, ZDI: last {zdi_days} days"
        
        # Create a diverse sample showing all sources
        sample_data = []
        zdi_items = [v for v in enriched_data if v.get('source') == 'ZDI']
        nvd_items = [v for v in enriched_data if v.get('source') == 'NVD Recent']
        kev_items = [v for v in enriched_data if v.get('source') == 'CISA KEV']
        
        # Take proportional samples from each source (up to 20 total)
        if zdi_count > 0:
            sample_data.extend(zdi_items[:8])  # Show up to 8 ZDI
        if nvd_count > 0:
            sample_data.extend(nvd_items[:8])  # Show up to 8 NVD
        if kev_count > 0:
            sample_data.extend(kev_items[:4])  # Show up to 4 KEVs
        
        # If we have less than 20, take more from the largest source
        if len(sample_data) < 20:
            remaining = 20 - len(sample_data)
            if len(enriched_data) > len(sample_data):
                for item in enriched_data:
                    if item not in sample_data:
                        sample_data.append(item)
                        remaining -= 1
                        if remaining == 0:
                            break
        
        context = f"""
Analyze these {len(enriched_data)} vulnerabilities for: "{request.query}"

Data includes THREE intelligence sources:
- {zdi_count} ZDI Advisories (Zero Day Initiative - earliest disclosures, often pre-CVE)
- {nvd_count} NVD Recent CVEs (newly disclosed in last {nvd_days} days, CVSS >= 7.0)
- {kev_count} CISA KEVs (confirmed actively exploited in the wild)

Time windows: {time_window_msg}

Sample Data (showing diverse mix of all sources): {json.dumps(sample_data, indent=2)}

CRITICAL INSTRUCTIONS:
- You MUST include ZDI advisories in your response if zdi_count > 0
- Show ZDI results FIRST (they are the earliest disclosures)
- Use GREEN badges for ZDI, BLUE badges for NVD, RED badges for CISA KEV
- If showing "zero-day" or "latest" results, prioritize ZDI advisories as they represent the earliest warnings

OUTPUT FORMAT:

Generate a table with 10-15 vulnerabilities (prioritize showing ZDI advisories first, then NVD, then KEVs):

<table style="width:100%; border-collapse: collapse; margin: 20px 0; border: 1px solid #ddd;">
<thead>
<tr style="background: linear-gradient(135deg, #667eea, #764ba2); color: white;">
<th style="padding: 12px; text-align: left; border: 1px solid #ddd;">CVE ID</th>
<th style="padding: 12px; text-align: left; border: 1px solid #ddd;">Vulnerability</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">CVSS</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">EPSS</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">Priority</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">Source</th>
<th style="padding: 12px; text-align: center; border: 1px solid #ddd;">Date</th>
</tr>
</thead>
<tbody>
[10-15 rows with proper source badges - show ZDI results first!]
</tbody>
</table>
Brief analysis (2-3 sentences) directly after table.

RULES:
- CVE links: <a href="https://nvd.nist.gov/vuln/detail/CVE-XXXX" target="_blank" style="color: #667eea; font-weight: 600;">CVE-XXXX</a>
- Source badges (IMPORTANT - Always include the Source column with HTML badges!): 
  * ZDI (Zero Day Initiative - earliest disclosures): <span style="background: #10b981; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 600;">ZDI</span>
  * NVD Recent (newly disclosed): <span style="background: #2563eb; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 600;">NVD</span>
  * CISA KEV (confirmed exploited): <span style="background: #dc2626; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 600;">CISA KEV</span>

EXAMPLE ROW (use this exact format):
<tr style="border: 1px solid #ddd;">
<td style="padding: 12px;"><a href="https://nvd.nist.gov/vuln/detail/CVE-2025-61808" target="_blank" style="color: #667eea; font-weight: 600;">CVE-2025-61808</a></td>
<td style="padding: 12px;">Adobe ColdFusion RCE</td>
<td style="padding: 12px; text-align: center; color: #dc2626; font-weight: 600;">9.0</td>
<td style="padding: 12px; text-align: center;">5.4%</td>
<td style="padding: 12px; text-align: center;">🔴 URGENT</td>
<td style="padding: 12px; text-align: center;"><span style="background: #10b981; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 600;">ZDI</span></td>
<td style="padding: 12px; text-align: center;">2026-02-06</td>
</tr>

- CVSS colors: 9.0-10.0=#dc2626, 7.0-8.9=#ea580c, 4.0-6.9=#f59e0b
- Priority: 🔴 URGENT, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW
- NO extra blank lines
- NO SIEM queries

IMPORTANT NOTES:
- THREE SOURCES with different timing:
  1. ZDI (GREEN badge) = Earliest disclosures, often published BEFORE CVE assignment
  2. NVD (BLUE badge) = Newly disclosed CVEs (last 7-30 days), CVSS >= 7.0
  3. CISA KEV (RED badge) = Confirmed active exploitation in the wild
- "Zero-day" queries prioritize ZDI + NVD (earliest sources)
- "Latest/Recent" queries show all 3 sources, sorted by date (newest first)
- Always emphasize ZDI advisories as the EARLIEST warning available
- Always show the Source column so users understand the intelligence timeline
"""
        
        # Call Claude with sufficient tokens for 10-15 results
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2500,  # Increased to fit 10-15 table rows
            messages=[{"role": "user", "content": context}]
        )
        
        response_text = response.content[0].text
        
        # AGGRESSIVE: Remove ALL newlines if there's a table
        if '<table' in response_text:
            # Remove ALL newlines, tabs, extra spaces
            response_text = re.sub(r'\n+', '', response_text)
        else:
            # For non-table responses, keep them
            response_text = response_text.strip()
        
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
            platform = "Azure Sentinel KQL"
        elif query_type == 'spl':
            platform = "Splunk SPL"
        else:
            platform = "Elasticsearch EQL"
        
        context = f"""
Generate a {platform} detection query for these CVEs:
{', '.join(cves[:10])}

Requirements:
- Production-ready, copy-paste ready
- Detect authentication, process, network, file events
- Include CVE indicators
- Keep it concise but comprehensive

Output ONLY the query code, no explanation.
"""
        
        # Call Claude with reduced tokens
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,  # Reduced from 2000
            messages=[{"role": "user", "content": context}]
        )
        
        return {"query": response.content[0].text.strip()}
        
    except Exception as e:
        print(f"Error generating query: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
