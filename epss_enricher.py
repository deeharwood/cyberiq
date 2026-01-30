"""
On-Demand EPSS Enrichment
Fetches EPSS scores from FIRST.org API
EPSS predicts probability of exploitation in next 30 days
"""

import requests
import time
from typing import Dict, List

# Cache to avoid refetching same CVEs
epss_cache = {}


def fetch_epss_for_cve(cve_id: str) -> Dict:
    """
    Fetch EPSS score for a single CVE from FIRST.org
    Returns: dict with epss_score (0-1), epss_percentile (0-1)
    """
    # Check cache first
    if cve_id in epss_cache:
        return epss_cache[cve_id]
    
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        headers = {'User-Agent': 'CyberIQ/1.0'}
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if 'data' in data and len(data['data']) > 0:
                epss_data = data['data'][0]
                
                epss_score = float(epss_data.get('epss', 0))
                epss_percentile = float(epss_data.get('percentile', 0))
                
                result = {
                    'epss_score': epss_score,
                    'epss_percentile': epss_percentile
                }
                
                # Cache it
                epss_cache[cve_id] = result
                
                return result
        
        # If failed, return default
        return {'epss_score': 0.0, 'epss_percentile': 0.0}
    
    except Exception as e:
        print(f"Error fetching EPSS for {cve_id}: {str(e)}")
        return {'epss_score': 0.0, 'epss_percentile': 0.0}


def fetch_epss_bulk(cve_ids: List[str]) -> Dict[str, Dict]:
    """
    Fetch EPSS scores for multiple CVEs in one request
    FIRST API supports bulk queries which is MUCH faster
    """
    try:
        # FIRST API supports comma-separated CVEs
        cve_list = ','.join(cve_ids[:100])  # Limit to 100 CVEs per request
        url = f"https://api.first.org/data/v1/epss?cve={cve_list}"
        headers = {'User-Agent': 'CyberIQ/1.0'}
        
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            results = {}
            
            if 'data' in data:
                for item in data['data']:
                    cve_id = item.get('cve', '')
                    epss_score = float(item.get('epss', 0))
                    epss_percentile = float(item.get('percentile', 0))
                    
                    results[cve_id] = {
                        'epss_score': epss_score,
                        'epss_percentile': epss_percentile
                    }
                    
                    # Cache each result
                    epss_cache[cve_id] = results[cve_id]
            
            return results
        
        return {}
    
    except Exception as e:
        print(f"Error fetching bulk EPSS: {str(e)}")
        return {}


def enrich_kevs_with_epss(kevs: list, max_items: int = 10) -> list:
    """
    Enrich a list of KEVs with EPSS scores
    Uses bulk API when possible for speed
    """
    enriched = []
    
    # Get CVE IDs
    cve_ids = [kev.get('cve_id', '') for kev in kevs[:max_items] if kev.get('cve_id')]
    
    # Check cache first
    uncached_cves = [cve for cve in cve_ids if cve not in epss_cache]
    
    if uncached_cves:
        print(f"  Fetching EPSS scores for {len(uncached_cves)} CVEs...")
        # Fetch all at once (MUCH faster than one by one!)
        fetch_epss_bulk(uncached_cves)
        time.sleep(0.5)  # Small delay to be nice to API
    
    # Now enrich KEVs with cached data
    for kev in kevs[:max_items]:
        cve_id = kev.get('cve_id', '')
        
        # Get EPSS from cache (or default if not found)
        epss_data = epss_cache.get(cve_id, {'epss_score': 0.0, 'epss_percentile': 0.0})
        
        # Update KEV with EPSS data
        kev_copy = kev.copy()
        kev_copy['epss_score'] = epss_data['epss_score']
        kev_copy['epss_percentile'] = epss_data['epss_percentile']
        
        # Calculate priority score (CVSS × EPSS)
        cvss = kev_copy.get('cvss_score', 0)
        epss = epss_data['epss_score']
        kev_copy['priority_score'] = cvss * epss if cvss > 0 else 0
        
        enriched.append(kev_copy)
    
    return enriched


def get_epss_priority_label(epss_score: float) -> str:
    """
    Convert EPSS score to priority label
    """
    if epss_score >= 0.7:
        return "🔴 URGENT"
    elif epss_score >= 0.3:
        return "🟠 HIGH"
    elif epss_score >= 0.1:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"


def get_epss_color(epss_score: float) -> str:
    """
    Get hex color for EPSS score
    """
    if epss_score >= 0.7:
        return "#dc2626"  # Red
    elif epss_score >= 0.3:
        return "#ea580c"  # Orange
    elif epss_score >= 0.1:
        return "#f59e0b"  # Yellow
    else:
        return "#84cc16"  # Green
