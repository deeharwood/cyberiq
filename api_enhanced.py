from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from anthropic import Anthropic
import os
import requests
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from bs4 import BeautifulSoup
import asyncio
import time
from threading import Lock

app = FastAPI()

# Initialize Anthropic client
client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

# ========================================
# ROUTING: Landing Page & Demo
# ========================================

@app.get("/")
async def read_root():
    """Serve landing page at cyberiq.co/"""
    return FileResponse("index.html")

@app.get("/demo")
async def read_demo():
    """Serve demo app at cyberiq.co/demo"""
    return FileResponse("demo/index.html")

# ========================================
# V2.0 LLM-POWERED QUERY PARSING
# ========================================

def parse_query_with_claude(query_text: str) -> dict:
    """
    Use Claude Opus to parse natural language queries into structured filters.
    This is the v2.0 LLM-powered query understanding layer.
    """
    try:
        parse_start = time.time()
        
        prompt = f"""Parse this cybersecurity threat intelligence query into structured filters.

Query: "{query_text}"

Extract and return ONLY valid JSON (no markdown, no explanation):

{{
  "data_sources": ["KEV"|"NVD"|"ZDI"],
  "search_keywords": ["keyword1", "keyword2"],
  "filters": {{
    "year": "2025" or null,
    "vendor": "microsoft" or null,
    "limit": 50 or null
  }},
  "sort_by": "date"|"cvss"|null
}}

Guidelines:
- For APT/threat actor queries: include keywords like ["APT", "advanced persistent threat", "state-sponsored", "nation-state", "threat actor", "cyber espionage"]
- For ransomware: ["ransomware", "encryption", "extortion", "ransom", "campaign"]
- For supply chain: ["supply chain", "third-party", "dependency", "software supply"]
- For specific CVE types: ["RCE", "remote code execution", "SQL injection", "XSS", etc.]
- Extract vendor names: Microsoft, Adobe, Cisco, etc.
- Extract years: 2024, 2025, 2026
- Extract limits: "top 10" = 10, "show me 50" = 50, "all" = null
- Default data_sources: ["KEV"] if "KEV" mentioned, otherwise ["KEV", "NVD", "ZDI"]

Return ONLY the JSON object, nothing else."""

        response = client.messages.create(
            model="claude-opus-4-5-20251101",  # Using Opus 4.5 for best quality
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        parse_time = time.time() - parse_start
        
        # Extract JSON from response
        response_text = response.content[0].text.strip()
        
        # Remove markdown code blocks if present
        if response_text.startswith('```'):
            response_text = response_text.split('```')[1]
            if response_text.startswith('json'):
                response_text = response_text[4:]
            response_text = response_text.strip()
        
        parsed_intent = json.loads(response_text)
        
        print(f"🧠 Claude Opus parsed query in {parse_time:.2f}s:")
        print(f"   - Keywords: {parsed_intent.get('search_keywords', [])[:5]}")
        print(f"   - Sources: {parsed_intent.get('data_sources', [])}")
        print(f"   - Filters: {parsed_intent.get('filters', {})}")
        
        return parsed_intent
        
    except Exception as e:
        print(f"❌ Query parsing failed: {e}")
        # Fallback to empty keywords if Claude fails
        return {
            "data_sources": ["KEV", "NVD", "ZDI"],
            "search_keywords": [],
            "filters": {"year": None, "vendor": None, "limit": None},
            "sort_by": None
        }

def smart_keyword_search(vulnerabilities: list, keywords: list) -> list:
    """
    Search vulnerability descriptions and names for keywords.
    This is the v2.0 smart filtering layer.
    """
    if not keywords:
        return vulnerabilities
    
    results = []
    keywords_lower = [k.lower() for k in keywords]
    
    for vuln in vulnerabilities:
        # Combine searchable text
        searchable = f"{vuln.get('vulnerabilityName', '')} {vuln.get('shortDescription', '')}".lower()
        
        # Check if ANY keyword matches
        if any(keyword in searchable for keyword in keywords_lower):
            results.append(vuln)
    
    print(f"🔍 Keyword search: {len(results)} matches from {len(vulnerabilities)} total")
    return results

# ========================================
# CACHING LAYER (In-Memory with TTL)
# ========================================

class SimpleCache:
    """Simple in-memory cache with TTL"""
    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.lock = Lock()
    
    def get(self, key: str):
        """Get cached value if not expired"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                if time.time() < entry['expires']:
                    return entry['value']
                else:
                    del self.cache[key]
        return None
    
    def set(self, key: str, value: Any, ttl_seconds: int):
        """Set cached value with TTL"""
        with self.lock:
            self.cache[key] = {
                'value': value,
                'expires': time.time() + ttl_seconds
            }
    
    def clear(self):
        """Clear all cache"""
        with self.lock:
            self.cache.clear()

# Global cache instance
cache = SimpleCache()

# Cache TTLs
KEV_CACHE_TTL = 300  # 5 minutes
NVD_CACHE_TTL = 300  # 5 minutes
ZDI_CACHE_TTL = 300  # 5 minutes
CVSS_CACHE_TTL = 3600  # 1 hour
EPSS_CACHE_TTL = 3600  # 1 hour

# ========================================

class QueryRequest(BaseModel):
    vendor: str = ""
    date_filter: str = ""
    query: str
    page: int = 1
    per_page: int = 10

class QueryResponse(BaseModel):
    response: str
    count: int = 0
    total_count: int = 0
    current_page: int = 1
    total_pages: int = 1

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
    """Fetch KEV data from CISA with caching"""
    cache_key = "kev_data"
    
    # Try cache first
    cached = cache.get(cache_key)
    if cached is not None:
        print("✅ KEV data loaded from cache")
        return cached
    
    # Fetch from API
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        print("⏳ Fetching KEV data from CISA...")
        start = time.time()
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Cache it
        cache.set(cache_key, data, KEV_CACHE_TTL)
        print(f"✅ KEV data fetched and cached ({time.time() - start:.2f}s)")
        return data
    except Exception as e:
        print(f"❌ Error fetching KEV data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch KEV data: {str(e)}")


def fetch_recent_nvd_cves(days=30):
    """Fetch recent CVEs from NVD (last N days) - High/Critical only with caching"""
    cache_key = f"nvd_cves_{days}"
    
    # Try cache first
    cached = cache.get(cache_key)
    if cached is not None:
        print(f"✅ NVD CVEs (last {days} days) loaded from cache")
        return cached
    
    print(f"⏳ Fetching recent CVEs from NVD (last {days} days)...")
    start_time = time.time()
    
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
            
            # Create meaningful vulnerability name from description
            # Extract first sentence or first 100 chars
            vuln_name = description[:100] if description else f"{cve_id} - {cvss_severity}"
            if '.' in vuln_name:
                vuln_name = vuln_name.split('.')[0] + '.'
            
            # Format as KEV-like structure for compatibility
            cve_entry = {
                'cveID': cve_id,
                'vendorProject': 'Various',
                'product': 'Various',
                'vulnerabilityName': vuln_name,
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
        
        # Cache it
        cache.set(cache_key, cves, NVD_CACHE_TTL)
        print(f"✅ Fetched {len(cves)} recent high-severity CVEs from NVD ({time.time() - start_time:.2f}s)")
        return cves
        
    except Exception as e:
        print(f"❌ Error fetching NVD CVEs: {str(e)}")
        return []

def fetch_zdi_advisories(days=30):
    """Fetch recent Zero Day Initiative advisories from RSS feed with caching"""
    cache_key = f"zdi_advisories_{days}"
    
    # Try cache first
    cached = cache.get(cache_key)
    if cached is not None:
        print(f"✅ ZDI advisories (last {days} days) loaded from cache")
        return cached
    
    print(f"⏳ Fetching ZDI advisories from RSS feed (last {days} days)...")
    start_time = time.time()
    
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
        
        # Cache it
        cache.set(cache_key, advisories, ZDI_CACHE_TTL)
        print(f"✅ Fetched {len(advisories)} ZDI advisories from RSS feed ({time.time() - start_time:.2f}s)")
        return advisories
        
    except Exception as e:
        print(f"❌ Error fetching ZDI RSS feed: {str(e)}")
        return []

def fetch_cvss_data(cves):
    """Fetch CVSS scores from NVD with caching"""
    cvss_scores = {}
    cves_to_fetch = []
    
    # Check cache first
    for cve in cves[:20]:  # Limit to first 20 CVEs
        cache_key = f"cvss_{cve}"
        cached = cache.get(cache_key)
        if cached is not None:
            cvss_scores[cve] = cached
        else:
            cves_to_fetch.append(cve)
    
    if cves_to_fetch:
        print(f"⏳ Fetching CVSS scores for {len(cves_to_fetch)} CVEs...")
    else:
        print(f"✅ All CVSS scores loaded from cache")
    
    # Fetch uncached CVEs
    for cve in cves_to_fetch:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    vuln_data = data['vulnerabilities'][0]['cve']
                    
                    # Try to get CVSS v3 score
                    if 'metrics' in vuln_data:
                        score = None
                        if 'cvssMetricV31' in vuln_data['metrics']:
                            score = vuln_data['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                        elif 'cvssMetricV30' in vuln_data['metrics']:
                            score = vuln_data['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                        elif 'cvssMetricV2' in vuln_data['metrics']:
                            score = vuln_data['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                        
                        if score is not None:
                            cvss_scores[cve] = score
                            # Cache it
                            cache.set(f"cvss_{cve}", score, CVSS_CACHE_TTL)
        except Exception as e:
            print(f"Error fetching CVSS for {cve}: {str(e)}")
            continue
    
    return cvss_scores

def fetch_epss_data(cves):
    """Fetch EPSS scores from FIRST.org with caching"""
    epss_scores = {}
    cves_to_fetch = []
    
    # Check cache first
    for cve in cves[:20]:  # Limit to first 20
        cache_key = f"epss_{cve}"
        cached = cache.get(cache_key)
        if cached is not None:
            epss_scores[cve] = cached
        else:
            cves_to_fetch.append(cve)
    
    if not cves_to_fetch:
        print(f"✅ All EPSS scores loaded from cache")
        return epss_scores
    
    print(f"⏳ Fetching EPSS scores for {len(cves_to_fetch)} CVEs...")
    
    try:
        # FIRST.org EPSS API - batch request
        cve_list = ','.join(cves_to_fetch)
        url = f"https://api.first.org/data/v1/epss?cve={cve_list}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                for item in data['data']:
                    cve = item['cve']
                    epss = float(item['epss']) * 100  # Convert to percentage
                    score = round(epss, 2)
                    epss_scores[cve] = score
                    # Cache it
                    cache.set(f"epss_{cve}", score, EPSS_CACHE_TTL)
    except Exception as e:
        print(f"Error fetching EPSS data: {str(e)}")
    
    return epss_scores

def enrich_vulnerability_data(vulnerabilities, cvss_scores, epss_scores):
    """Enrich vulnerability data with CVSS and EPSS scores"""
    enriched = []
    
    for vuln in vulnerabilities:
        cve = vuln.get('cveID', '')
        enriched_vuln = vuln.copy()
        
        # Add CVSS score - preserve estimated score if it exists (e.g., from ZDI)
        if 'cvss_score' in vuln and vuln['cvss_score'] not in [0, None, 'N/A']:
            # Keep existing estimated score (from ZDI/NVD fetch)
            enriched_vuln['cvss_score'] = vuln['cvss_score']
        else:
            # Try to get from NVD lookup
            enriched_vuln['cvss_score'] = cvss_scores.get(cve, 'N/A')
        
        # Add EPSS score - preserve if exists, otherwise lookup
        if 'epss_score' in vuln and vuln['epss_score'] not in [0, None, 'N/A']:
            enriched_vuln['epss_score'] = vuln['epss_score']
        else:
            enriched_vuln['epss_score'] = epss_scores.get(cve, 'N/A')
        
        # Calculate priority label based on CVSS and EPSS
        cvss = enriched_vuln.get('cvss_score', 0)
        epss = enriched_vuln.get('epss_score', 0)
        
        # Convert to float for comparison
        try:
            cvss = float(cvss) if cvss != 'N/A' else 0
        except:
            cvss = 0
        try:
            epss = float(epss) if epss != 'N/A' else 0
        except:
            epss = 0
        
        if cvss >= 9.0 and epss >= 10:
            priority = "🔴 URGENT"
        elif cvss >= 9.0:  # High CVSS alone = URGENT
            priority = "🔴 URGENT"
        elif cvss >= 7.0 and epss >= 5:
            priority = "🟠 HIGH"
        elif cvss >= 7.0:
            priority = "🟠 HIGH"
        elif cvss >= 4.0:
            priority = "🟡 MEDIUM"
        else:
            priority = "🟢 LOW"
        
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

def extract_vendor_from_cve(vuln):
    """Extract vendor name from vulnerability data"""
    # Try vendorProject first (from KEV data)
    vendor = vuln.get('vendorProject', '').strip()
    if vendor and vendor.lower() not in ['various', 'unknown', 'n/a', '']:
        return vendor
    
    # Try to extract from vulnerability name or description
    text = (vuln.get('vulnerabilityName', '') + ' ' + 
            vuln.get('shortDescription', '') + ' ' +
            vuln.get('cveID', '')).lower()
    
    # Common vendors (in priority order)
    vendors = [
        'Microsoft', 'Adobe', 'Apple', 'Google', 'Oracle', 'Cisco', 'VMware',
        'SAP', 'IBM', 'Dell', 'HP', 'Juniper', 'Fortinet', 'Palo Alto',
        'Citrix', 'Linux', 'Red Hat', 'Ubuntu', 'Debian', 'SUSE',
        'WordPress', 'Drupal', 'Joomla', 'PHP', 'Apache', 'Nginx',
        'MySQL', 'PostgreSQL', 'MongoDB', 'Jenkins', 'Docker', 'Kubernetes',
        'AWS', 'Azure', 'Firefox', 'Chrome', 'Safari', 'Android', 'iOS',
        'Windows', 'Exchange', 'SharePoint', 'Office', 'Outlook',
        'Acrobat', 'Reader', 'Photoshop', 'Flash', 'Java', 'OpenSSL',
        'Zoom', 'Teams', 'Slack', 'Salesforce', 'ServiceNow',
        'SonicWall', 'Sophos', 'Trend Micro', 'McAfee', 'Symantec',
        'F5', 'Barracuda', 'Check Point', 'Ivanti', 'Splunk'
    ]
    
    for v in vendors:
        if v.lower() in text:
            return v
    
    return 'Unknown'

def classify_vulnerability_type(vuln):
    """Classify vulnerability type based on description"""
    text = (vuln.get('vulnerabilityName', '') + ' ' + 
            vuln.get('shortDescription', '')).lower()
    
    vuln_types = []
    
    if any(word in text for word in ['remote code execution', 'rce', 'arbitrary code execution', 'code execution']):
        vuln_types.append('RCE')
    if any(word in text for word in ['sql injection', 'sqli']):
        vuln_types.append('SQL Injection')
    if any(word in text for word in ['cross-site scripting', 'xss']):
        vuln_types.append('XSS')
    if any(word in text for word in ['privilege escalation', 'escalation of privilege']):
        vuln_types.append('Privilege Escalation')
    if any(word in text for word in ['authentication bypass', 'auth bypass']):
        vuln_types.append('Authentication Bypass')
    if any(word in text for word in ['buffer overflow', 'heap overflow', 'stack overflow']):
        vuln_types.append('Buffer Overflow')
    if any(word in text for word in ['directory traversal', 'path traversal']):
        vuln_types.append('Directory Traversal')
    if any(word in text for word in ['command injection']):
        vuln_types.append('Command Injection')
    if any(word in text for word in ['denial of service', 'dos']):
        vuln_types.append('DoS')
    
    return vuln_types if vuln_types else ['Other']

def extract_filters_from_query(query):
    """Extract vendor and type filters from query"""
    query_lower = query.lower()
    
    vendor = None
    vuln_type = None
    
    # Vendors
    vendors = ['microsoft', 'adobe', 'apple', 'google', 'oracle', 'cisco', 'vmware',
               'linux', 'windows', 'php', 'wordpress', 'apache', 'nginx', 'zoom']
    
    for v in vendors:
        if v in query_lower:
            vendor = v
            break
    
    # Types
    if any(word in query_lower for word in ['rce', 'remote code', 'code execution']):
        vuln_type = 'rce'
    elif any(word in query_lower for word in ['sql injection', 'sqli']):
        vuln_type = 'sql'
    elif any(word in query_lower for word in ['xss', 'cross-site']):
        vuln_type = 'xss'
    
    return vendor, vuln_type

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

def optimize_query(query_text):
    """Analyze query to determine what data sources and limits to use"""
    query_lower = query_text.lower()
    
    # Detect source requirements
    needs_kev = any(word in query_lower for word in ['kev', 'exploited', 'cisa', 'ransomware', 'actively'])
    needs_nvd = any(word in query_lower for word in ['nvd', 'recent', 'latest', 'new', 'published'])
    needs_zdi = any(word in query_lower for word in ['zdi', 'zero-day', 'zero day', 'zeroday', '0-day', '0day', 'earliest'])
    
    # CRITICAL FIX: If query explicitly mentions KEV, prioritize KEV-only
    # "latest KEVs" means latest from KEV catalog, not latest from all sources
    if 'kev' in query_lower:
        # User explicitly asked for KEVs
        needs_nvd = False
        needs_zdi = False
        needs_kev = True
    # Similarly for ZDI
    elif 'zdi' in query_lower or any(word in query_lower for word in ['zero-day', 'zero day', 'zeroday', '0-day', '0day']):
        needs_kev = False
        needs_nvd = True  # Keep NVD for zero-days
        needs_zdi = True
    # If no specific source mentioned, include all
    elif not needs_kev and not needs_nvd and not needs_zdi:
        needs_kev = True
        needs_nvd = True
        needs_zdi = True
    
    # Detect result limit - RESPECT WHAT USER ASKS FOR!
    limit = None
    
    # Check for "all" keyword first - user wants EVERYTHING!
    if any(word in query_lower for word in [' all ', 'all ', ' all', 'every', 'entire', 'complete']):
        limit = None  # No limit - show EVERYTHING!
        print(f"🌟 User requested ALL results - no limit applied")
    else:
        # Look for actual numbers in the query
        import re
        
        # Try multiple patterns to catch numbers
        patterns = [
            r'\b(top|first|last|show|latest)\s+(\d+)\b',  # "top 80", "show 100"
            r'\b(\d+)\s+(kevs|vulnerabilities|vulns|cves|items)\b',  # "80 KEVs", "100 vulnerabilities"
            r'\bshow\s+me\s+(\d+)\b',  # "show me 50"
            r'\b(\d+)\s+of\b',  # "100 of the"
        ]
        
        for pattern in patterns:
            number_match = re.search(pattern, query_lower)
            if number_match:
                try:
                    # Extract the number from whichever group has it
                    for group in number_match.groups():
                        if group and group.isdigit():
                            limit = int(group)
                            print(f"📊 Detected limit: {limit} from pattern: {pattern}")
                            break
                    if limit:
                        break
                except:
                    pass
        
        # REMOVED: Don't apply default limit if user doesn't specify!
        # Old broken code was: if limit is None and 'show me' in query: limit = 20
        # This was causing "show me all KEVs" to show only 20!
    
    # Detect sorting preference
    sort_by_date = False
    if any(phrase in query_lower for phrase in ['order by date', 'sort by date', 'sorted by date', 'by date', 'chronological']):
        sort_by_date = True
        print(f"📅 User requested date sorting")
    
    # Detect year filtering
    year_filter = None
    import re
    year_match = re.search(r'\b(20\d{2})\b', query_lower)  # Matches 2024, 2025, 2026, etc.
    if year_match:
        year_filter = year_match.group(1)
        print(f"📅 Detected year filter: {year_filter}")
    
    return {
        'needs_kev': needs_kev,
        'needs_nvd': needs_nvd,
        'needs_zdi': needs_zdi,
        'limit': limit,
        'sort_by_date': sort_by_date,
        'year_filter': year_filter
    }

@app.post("/api/query", response_model=QueryResponse)
async def query(request: QueryRequest):
    """Process threat intelligence queries with optimized performance"""
    query_start = time.time()
    
    try:
        print(f"\n{'='*60}")
        print(f"🔍 Query received: {request.query}")
        print(f"{'='*60}")
        
        # V2.0: Use Claude Opus to parse query (LLM-powered!)
        parsed_intent = parse_query_with_claude(request.query)
        
        # Extract parsed information
        needs_kev = "KEV" in parsed_intent.get('data_sources', [])
        needs_nvd = "NVD" in parsed_intent.get('data_sources', [])
        needs_zdi = "ZDI" in parsed_intent.get('data_sources', [])
        search_keywords = parsed_intent.get('search_keywords', [])
        limit = parsed_intent.get('filters', {}).get('limit')
        year_filter = parsed_intent.get('filters', {}).get('year')
        vendor_filter = parsed_intent.get('filters', {}).get('vendor')
        sort_by = parsed_intent.get('sort_by')
        
        # Fetch only needed sources
        filtered_kev_data = []
        recent_nvd_cves = []
        zdi_advisories = []
        
        if needs_kev:
            # Fetch KEV data (cached)
            fetch_start = time.time()
            kev_data = fetch_kev_data()
            print(f"⏱️  KEV fetch: {time.time() - fetch_start:.2f}s")
            
            # Filter vulnerabilities by vendor and date only
            filtered_kev_data = filter_vulnerabilities(kev_data, request.vendor, request.date_filter, "")
            
            # Mark all KEVs with source
            for vuln in filtered_kev_data:
                vuln['source'] = 'CISA KEV'
            
            # Time-based filtering for KEV queries
            import re
            query_lower = request.query.lower()
            
            # Detect time ranges like "past X weeks/days/months"
            time_match = re.search(r'(past|last|recent)\s+(\d+)\s+(day|days|week|weeks|month|months)', query_lower)
            if time_match:
                number = int(time_match.group(2))
                unit = time_match.group(3)
                
                # Calculate cutoff date
                from datetime import datetime, timedelta
                if 'day' in unit:
                    cutoff = datetime.now() - timedelta(days=number)
                elif 'week' in unit:
                    cutoff = datetime.now() - timedelta(weeks=number)
                elif 'month' in unit:
                    cutoff = datetime.now() - timedelta(days=number*30)
                
                cutoff_str = cutoff.strftime('%Y-%m-%d')
                print(f"⏰ Time filter detected: Showing KEVs added after {cutoff_str}")
                
                # Filter by dateAdded
                filtered_kev_data = [v for v in filtered_kev_data 
                                   if v.get('dateAdded', '0000-00-00') >= cutoff_str]
                print(f"After time filter: {len(filtered_kev_data)} KEVs")
            
            # AGGRESSIVE EARLY LIMITING for KEV-only queries
            if not needs_nvd and not needs_zdi and limit:
                # Sort by date (latest first) and take only what we need
                filtered_kev_data.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
                filtered_kev_data = filtered_kev_data[:limit]
                print(f"⚡ EARLY LIMIT: Reduced KEVs to {len(filtered_kev_data)} (user wants top {limit})")
        
        # Determine time window for NVD CVEs based on query
        nvd_days = 30  # Default: 30 days
        zdi_days = 30  # Default: 30 days for ZDI
        
        # For "latest" or "zero-day" queries, use shorter window
        if any(word in request.query.lower() for word in ['latest', 'zero-day', 'zero day', 'zeroday', '0-day', '0day']):
            nvd_days = 7  # Last 7 days only
            zdi_days = 14  # Last 14 days for ZDI (often published earlier)
            print(f"Query contains 'latest/zero-day' - using {nvd_days} days for NVD, {zdi_days} days for ZDI")
        
        if needs_zdi:
            # Fetch ZDI advisories (earliest disclosures) - cached
            fetch_start = time.time()
            zdi_advisories = fetch_zdi_advisories(days=zdi_days)
            print(f"⏱️  ZDI fetch: {time.time() - fetch_start:.2f}s")
            
            # AGGRESSIVE EARLY LIMITING for ZDI-only queries
            if not needs_nvd and not needs_kev and limit:
                zdi_advisories.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
                zdi_advisories = zdi_advisories[:limit]
                print(f"⚡ EARLY LIMIT: Reduced ZDI to {len(zdi_advisories)} (user wants top {limit})")
        
        if needs_nvd:
            # Fetch recent NVD CVEs - cached
            fetch_start = time.time()
            recent_nvd_cves = fetch_recent_nvd_cves(days=nvd_days)
            print(f"⏱️  NVD fetch: {time.time() - fetch_start:.2f}s")
            
            # AGGRESSIVE EARLY LIMITING for NVD-only queries
            if not needs_zdi and not needs_kev and limit:
                recent_nvd_cves.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
                recent_nvd_cves = recent_nvd_cves[:limit]
                print(f"⚡ EARLY LIMIT: Reduced NVD to {len(recent_nvd_cves)} (user wants top {limit})")
        
        print(f"After source-level limiting: {len(zdi_advisories)} ZDI, {len(recent_nvd_cves)} NVD, {len(filtered_kev_data)} KEVs")
        
        # Combine all three sources: ZDI + NVD + KEVs
        filtered_data = zdi_advisories + recent_nvd_cves + filtered_kev_data
        
        print(f"Total: {len(zdi_advisories)} ZDI + {len(recent_nvd_cves)} NVD + {len(filtered_kev_data)} KEVs = {len(filtered_data)} vulnerabilities")
        
        # V2.0: Apply keyword search if Claude extracted keywords
        if search_keywords:
            print(f"🔍 Applying keyword search: {search_keywords[:3]}{'...' if len(search_keywords) > 3 else ''}")
            filtered_data = smart_keyword_search(filtered_data, search_keywords)
        
        # Apply vendor filter if Claude extracted one
        if vendor_filter:
            print(f"📊 Applying vendor filter: {vendor_filter}")
            filtered_data = [v for v in filtered_data 
                           if vendor_filter.lower() in extract_vendor_from_cve(v).lower()]
            print(f"After vendor filter: {len(filtered_data)} vulnerabilities")
        
        # Apply year filter if Claude extracted one
        if year_filter:
            print(f"📅 Applying year filter: {year_filter}")
            filtered_data = [v for v in filtered_data 
                           if v.get('dateAdded', '').startswith(year_filter)]
            print(f"After year filter: {len(filtered_data)} vulnerabilities from {year_filter}")
        
        # V2.0: Removed old special handling code
        # Keyword search already filters for ransomware, zero-days, etc.
        # No need for special cases anymore!
        
        if not filtered_data:
            raise HTTPException(status_code=404, detail="No vulnerabilities found matching your criteria")
        
        print(f"Before limiting: {len(filtered_data)} total vulnerabilities")
        
        # Apply sorting based on Claude's parsed intent
        if sort_by == 'date':
            # User explicitly requested date sorting
            filtered_data.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
            print(f"📅 Sorted by date (newest first) - Claude detected sort preference")
        elif sort_by == 'cvss' or any(word in request.query.lower() for word in ['top', 'highest', 'worst', 'critical']):
            # Sort by CVSS for "top" queries
            filtered_data.sort(key=lambda x: x.get('cvss_score', 0) if isinstance(x.get('cvss_score'), (int, float)) else 0, reverse=True)
            print(f"📊 Sorted by CVSS score (highest first)")
        
        # Apply result limit BEFORE enrichment to save processing
        if limit is not None:
            total_before_limit = len(filtered_data)
            filtered_data = filtered_data[:limit]
            print(f"⚡ Limited to {limit} results (was {total_before_limit})")
        else:
            print(f"✨ NO LIMIT - showing all {len(filtered_data)} results as requested")
        
        print(f"After limiting: {len(filtered_data)} vulnerabilities to process")
        
        # Get CVEs for enrichment (only for the limited set!)
        cves = [vuln.get('cveID') for vuln in filtered_data]
        print(f"Enriching only {len(cves)} CVEs (not all {len(filtered_data)} records)")
        
        # Fetch CVSS and EPSS data - cached
        enrich_start = time.time()
        cvss_data = fetch_cvss_data(cves)
        epss_data = fetch_epss_data(cves)
        
        # Enrich vulnerability data (only the limited set)
        enriched_data = enrich_vulnerability_data(filtered_data, cvss_data, epss_data)
        print(f"⏱️  Enrichment: {time.time() - enrich_start:.2f}s")
        
        # Build context for Claude
        import json
        
        # Count sources
        kev_count = len([v for v in enriched_data if v.get('source') == 'CISA KEV'])
        nvd_count = len([v for v in enriched_data if v.get('source') == 'NVD Recent'])
        zdi_count = len([v for v in enriched_data if v.get('source') == 'ZDI'])
        
        # Calculate pagination
        total_count = len(enriched_data)
        total_pages = (total_count + request.per_page - 1) // request.per_page
        start_idx = (request.page - 1) * request.per_page
        end_idx = min(request.page * request.per_page, total_count)
        page_data = enriched_data[start_idx:end_idx]
        
        print(f"📄 Pagination: Page {request.page}/{total_pages}, showing {len(page_data)} items")
        
        # Create LEAN data with only fields needed for table display
        # This drastically reduces context size and speeds up Claude API
        lean_data = []
        for item in page_data:
            lean_data.append({
                'cveID': item.get('cveID', 'N/A'),
                'vulnerability': item.get('vulnerabilityName', 'N/A'),
                'cvss': item.get('cvss_score', 'N/A'),
                'epss': item.get('epss_score', 'N/A'),
                'priority': item.get('priority_label', 'N/A'),
                'source': item.get('source', 'N/A'),
                'date': item.get('dateAdded', 'N/A')
            })
        
        print(f"📦 Generating table HTML directly (skipping Claude for formatting)")
        
        # Generate table HTML directly - MUCH faster than asking Claude
        def get_source_badge(source):
            if source == 'ZDI':
                return '<span style="background: #10b981; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 600;">ZDI</span>'
            elif source == 'NVD Recent':
                return '<span style="background: #3b82f6; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 600;">NVD Recent</span>'
            else:  # CISA KEV
                return '<span style="background: #dc2626; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 600;">CISA KEV</span>'
        
        def get_cvss_color(cvss):
            try:
                score = float(cvss)
                if score >= 9.0:
                    return '#dc2626'  # Red
                elif score >= 7.0:
                    return '#ea580c'  # Orange
                else:
                    return '#f59e0b'  # Yellow
            except:
                return '#6b7280'  # Gray for N/A
        
        # Build table HTML
        table_html = '''<table style="width:100%; border-collapse: collapse; margin: 20px 0; border: 1px solid #ddd;">
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
'''
        
        for item in page_data:
            cve = item.get('cveID', 'N/A')
            vuln = item.get('vulnerabilityName', 'N/A')[:100]
            # HTML escape to prevent breaking table
            import html
            vuln = html.escape(vuln)
            
            cvss = item.get('cvss_score', 'N/A')
            epss = item.get('epss_score', 'N/A')
            priority = item.get('priority_label', 'N/A')
            source = item.get('source', 'N/A')
            date = item.get('dateAdded', 'N/A')
            
            cvss_color = get_cvss_color(cvss)
            cvss_display = cvss if cvss != 'N/A' else 'N/A'
            epss_display = f"{epss}%" if epss != 'N/A' and epss != 0 else 'N/A'
            source_badge = get_source_badge(source)
            
            table_html += f'''<tr style="border: 1px solid #ddd;">
<td style="padding: 12px; border: 1px solid #ddd;"><a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank" style="color: #667eea; font-weight: 600;">{cve}</a></td>
<td style="padding: 12px; border: 1px solid #ddd;">{vuln}</td>
<td style="padding: 12px; text-align: center; color: {cvss_color}; font-weight: 600; border: 1px solid #ddd;">{cvss_display}</td>
<td style="padding: 12px; text-align: center; border: 1px solid #ddd;">{epss_display}</td>
<td style="padding: 12px; text-align: center; border: 1px solid #ddd;">{priority}</td>
<td style="padding: 12px; text-align: center; border: 1px solid #ddd;">{source_badge}</td>
<td style="padding: 12px; text-align: center; border: 1px solid #ddd;">{date}</td>
</tr>
'''
        
        table_html += '''</tbody>
</table>'''
        
        # Now ask Claude for brief analysis only (MUCH smaller context, MUCH faster)
        context = f"""Provide a brief 2-3 sentence analysis for this query: "{request.query}"

Results: {total_count} total ({zdi_count} ZDI, {nvd_count} NVD, {kev_count} KEV)
Showing page {request.page} of {total_pages}

Just give a brief analysis - the table is already generated.
"""
        
        
        # Call Claude - TINY context now, just for analysis
        claude_start = time.time()
        estimated_tokens = 200  # Very small - just brief analysis
        
        # Log context size for monitoring
        context_chars = len(context)
        context_tokens_estimate = context_chars // 4
        print(f"📝 Context: {context_chars} chars (~{context_tokens_estimate} tokens), Max response: {estimated_tokens} tokens")
        
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=estimated_tokens,
            messages=[{"role": "user", "content": context}]
        )
        print(f"⏱️  Claude API: {time.time() - claude_start:.2f}s (used {estimated_tokens} max_tokens)")
        
        analysis_text = response.content[0].text.strip()
        
        # Combine table + analysis
        response_text = table_html + "\n\n" + analysis_text
        
        # Calculate pagination metadata (already calculated above)
        
        # Log total query time
        total_time = time.time() - query_start
        print(f"{'='*60}")
        print(f"✅ TOTAL QUERY TIME: {total_time:.2f}s")
        print(f"{'='*60}\n")
        
        return QueryResponse(
            response=response_text,
            count=min(request.per_page, total_count - (request.page - 1) * request.per_page),
            total_count=total_count,
            current_page=request.page,
            total_pages=total_pages
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

@app.post("/api/export-csv")
async def export_csv(request: QueryRequest):
    """Export query results to CSV - matches query endpoint logic exactly"""
    try:
        import csv
        from io import StringIO
        
        print(f"CSV Export: query={request.query}")
        
        # Fetch KEV data
        kev_data = fetch_kev_data()
        
        # Filter vulnerabilities by vendor and date only
        filtered_kev_data = filter_vulnerabilities(kev_data, request.vendor, request.date_filter, "")
        
        # Mark all KEVs with source
        for vuln in filtered_kev_data:
            vuln['source'] = 'CISA KEV'
        
        # Determine time window for NVD CVEs based on query
        nvd_days = 30
        zdi_days = 30
        
        if any(word in request.query.lower() for word in ['latest', 'zero-day', 'zero day', 'zeroday', '0-day', '0day']):
            nvd_days = 7
            zdi_days = 14
        
        # Fetch ZDI advisories and NVD CVEs
        zdi_advisories = fetch_zdi_advisories(days=zdi_days)
        recent_nvd_cves = fetch_recent_nvd_cves(days=nvd_days)
        
        # Combine all three sources
        filtered_data = zdi_advisories + recent_nvd_cves + filtered_kev_data
        
        print(f"CSV Export: Combined {len(zdi_advisories)} ZDI + {len(recent_nvd_cves)} NVD + {len(filtered_kev_data)} KEVs = {len(filtered_data)} total")
        
        # Extract and apply smart filters from query
        vendor_filter, type_filter = extract_filters_from_query(request.query)
        
        if vendor_filter:
            print(f"CSV Export: Applying vendor filter: {vendor_filter}")
            filtered_data = [v for v in filtered_data 
                           if vendor_filter in extract_vendor_from_cve(v).lower()]
            print(f"CSV Export: After vendor filter: {len(filtered_data)} vulnerabilities")
        
        if type_filter:
            print(f"CSV Export: Applying vulnerability type filter: {type_filter}")
            filtered_data = [v for v in filtered_data
                           if any(type_filter in vt.lower() 
                                for vt in classify_vulnerability_type(v))]
            print(f"CSV Export: After type filter: {len(filtered_data)} vulnerabilities")
        
        # Special handling for ransomware queries
        if 'ransomware' in request.query.lower():
            print("CSV Export: Filtering for ransomware KEVs...")
            filtered_data = [vuln for vuln in filtered_data 
                           if vuln.get('knownRansomwareCampaignUse', '').lower() in ['known', 'yes', 'true', 'y']]
            print(f"CSV Export: Found {len(filtered_data)} ransomware KEVs")
            
            if len(filtered_data) < 10:
                print("CSV Export: Too few ransomware KEVs, using all KEVs")
                filtered_data = filtered_kev_data
        
        # Special handling for "zero-day" queries
        elif any(word in request.query.lower() for word in ['zero-day', 'zero day', 'zeroday', '0-day', '0day']):
            print("CSV Export: Zero-day query - showing ZDI + NVD Recent")
            filtered_data = zdi_advisories + recent_nvd_cves
            filtered_data.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
        
        # Special handling for "recent", "latest", "new", "emerging"
        elif any(word in request.query.lower() for word in ['recent', 'new', 'latest', 'emerging']):
            print("CSV Export: Recent/latest query - prioritizing ZDI + NVD")
            filtered_data = zdi_advisories + recent_nvd_cves + filtered_kev_data
            filtered_data.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
        
        print(f"CSV Export: Exporting {len(filtered_data)} total vulnerabilities")
        
        if not filtered_data:
            return {
                "csv": "",
                "count": 0,
                "error": "No vulnerabilities found matching your criteria"
            }
        
        # Extract CVE IDs for enrichment
        cves = [vuln.get('cveID') for vuln in filtered_data if vuln.get('cveID')]
        
        # Fetch CVSS and EPSS data
        print("CSV Export: Fetching CVSS data...")
        cvss_data = fetch_cvss_data(cves)
        
        print("CSV Export: Fetching EPSS data...")
        epss_data = fetch_epss_data(cves)
        
        # Enrich vulnerability data
        enriched_data = enrich_vulnerability_data(filtered_data, cvss_data, epss_data)
        
        print(f"CSV Export: Enriched {len(enriched_data)} vulnerabilities")
        
        # Create CSV with UTF-8 BOM for Excel compatibility
        output = StringIO()
        # Add UTF-8 BOM for Excel
        output.write('\ufeff')
        writer = csv.writer(output)
        
        # Headers
        writer.writerow(['CVE ID', 'Vendor', 'Product', 'Vulnerability', 'CVSS', 'EPSS', 
                        'Priority', 'Source', 'Date', 'Type', 'Description'])
        
        # Data rows - Export ALL results (no limit)
        exported_count = 0
        for vuln in enriched_data:
            try:
                vendor = extract_vendor_from_cve(vuln)
                vuln_types = ', '.join(classify_vulnerability_type(vuln))
                
                # Strip emojis from priority for CSV compatibility
                priority = vuln.get('priority_label', 'N/A')
                if priority != 'N/A':
                    # Remove emojis (just keep the text part)
                    priority = re.sub(r'[^\w\s-]', '', priority).strip()
                
                writer.writerow([
                    vuln.get('cveID', 'N/A'),
                    vendor,
                    vuln.get('product', 'N/A'),
                    (vuln.get('vulnerabilityName', 'N/A') or 'N/A')[:200],
                    vuln.get('cvss_score', 'N/A'),
                    vuln.get('epss_score', 'N/A'),
                    priority,  # Now without emojis
                    vuln.get('source', 'N/A'),
                    vuln.get('dateAdded', 'N/A'),
                    vuln_types,
                    (vuln.get('shortDescription', 'N/A') or 'N/A')[:500]
                ])
                exported_count += 1
            except Exception as e:
                print(f"CSV Export: Error writing row for {vuln.get('cveID', 'unknown')}: {str(e)}")
                continue
        
        print(f"CSV Export: Successfully exported {exported_count} rows")
        
        return {
            "csv": output.getvalue(),
            "count": exported_count
        }
        
    except Exception as e:
        print(f"Error exporting CSV: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/vendor-stats")
async def get_vendor_stats():
    """Get vendor statistics (top vendors by vuln count)"""
    try:
        # Fetch all data sources
        kev_data = fetch_kev_data()
        recent_nvd_cves = fetch_recent_nvd_cves(days=30)
        zdi_advisories = fetch_zdi_advisories(days=30)
        
        all_vulns = (kev_data.get('vulnerabilities', []) + 
                    recent_nvd_cves + zdi_advisories)
        
        # Count by vendor
        vendor_counts = {}
        for vuln in all_vulns:
            vendor = extract_vendor_from_cve(vuln)
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
        
        # Sort by count
        sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Top 15 vendors
        top_vendors = [
            {"vendor": v, "count": c} 
            for v, c in sorted_vendors[:15]
            if v != 'Unknown'
        ]
        
        return {
            "top_vendors": top_vendors,
            "total_vendors": len([v for v in vendor_counts if v != 'Unknown'])
        }
        
    except Exception as e:
        print(f"Error getting vendor stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/warm-cache")
async def warm_cache():
    """Warm up the cache by pre-fetching all data sources"""
    try:
        print("🔥 Warming cache...")
        start = time.time()
        
        # Fetch all data sources to cache them
        kev_data = fetch_kev_data()
        zdi_7 = fetch_zdi_advisories(days=7)
        zdi_14 = fetch_zdi_advisories(days=14)
        zdi_30 = fetch_zdi_advisories(days=30)
        nvd_7 = fetch_recent_nvd_cves(days=7)
        nvd_30 = fetch_recent_nvd_cves(days=30)
        
        elapsed = time.time() - start
        
        return {
            "status": "success",
            "message": "Cache warmed successfully",
            "time": f"{elapsed:.2f}s",
            "cached": {
                "kev": len(kev_data.get('vulnerabilities', [])),
                "zdi_7d": len(zdi_7),
                "zdi_14d": len(zdi_14),
                "zdi_30d": len(zdi_30),
                "nvd_7d": len(nvd_7),
                "nvd_30d": len(nvd_30)
            }
        }
    except Exception as e:
        print(f"Error warming cache: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.on_event("startup")
async def startup_event():
    """Warm cache on startup"""
    print("\n" + "="*60)
    print("🚀 CyberIQ Starting Up...")
    print("="*60)
    
    # Warm cache in background
    import threading
    def warm():
        try:
            print("🔥 Pre-warming cache...")
            fetch_kev_data()
            fetch_zdi_advisories(days=30)
            fetch_recent_nvd_cves(days=30)
            print("✅ Cache pre-warmed successfully!")
        except Exception as e:
            print(f"⚠️  Cache warming failed (will warm on first request): {str(e)}")
    
    thread = threading.Thread(target=warm)
    thread.daemon = True
    thread.start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
