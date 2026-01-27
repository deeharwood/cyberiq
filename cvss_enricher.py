"""
On-Demand CVSS Enrichment
Fetches CVSS scores only for specific CVEs when needed
"""

import requests
import time
from typing import Dict

# Cache to avoid refetching same CVEs
cvss_cache = {}


def fetch_cvss_for_cve(cve_id: str) -> Dict:
    """
    Fetch CVSS score for a single CVE from NVD
    Returns: dict with cvss_score, cvss_severity, cwe_id
    """
    # Check cache first
    if cve_id in cvss_cache:
        return cvss_cache[cve_id]
    
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {'User-Agent': 'CyberIQ/1.0'}
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                vuln = data['vulnerabilities'][0]
                cve = vuln.get('cve', {})
                metrics = cve.get('metrics', {})
                
                # Extract CVSS
                cvss_score = 0.0
                cvss_severity = 'UNKNOWN'
                
                # Try CVSS v3.1
                if 'cvssMetricV31' in metrics and len(metrics['cvssMetricV31']) > 0:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                
                # Try CVSS v3.0
                elif 'cvssMetricV30' in metrics and len(metrics['cvssMetricV30']) > 0:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                
                # Try CVSS v2
                elif 'cvssMetricV2' in metrics and len(metrics['cvssMetricV2']) > 0:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    if cvss_score >= 7.0:
                        cvss_severity = 'HIGH'
                    elif cvss_score >= 4.0:
                        cvss_severity = 'MEDIUM'
                    else:
                        cvss_severity = 'LOW'
                
                # Extract CWE
                cwe_id = ''
                weaknesses = cve.get('weaknesses', [])
                for weakness in weaknesses:
                    for desc in weakness.get('description', []):
                        cwe_value = desc.get('value', '')
                        if cwe_value.startswith('CWE-'):
                            cwe_id = cwe_value
                            break
                    if cwe_id:
                        break
                
                result = {
                    'cvss_score': cvss_score,
                    'cvss_severity': cvss_severity,
                    'cwe_id': cwe_id
                }
                
                # Cache it
                cvss_cache[cve_id] = result
                
                return result
        
        # If failed, return default
        return {'cvss_score': 0.0, 'cvss_severity': 'UNKNOWN', 'cwe_id': ''}
    
    except Exception as e:
        print(f"Error fetching CVSS for {cve_id}: {str(e)}")
        return {'cvss_score': 0.0, 'cvss_severity': 'UNKNOWN', 'cwe_id': ''}


def enrich_kevs_with_cvss(kevs: list, max_items: int = 10) -> list:
    """
    Enrich a list of KEVs with CVSS scores
    Only enriches up to max_items to avoid rate limits
    """
    enriched = []
    
    for i, kev in enumerate(kevs[:max_items]):
        # Rate limiting - wait between requests
        if i > 0:
            time.sleep(0.7)  # ~1.5 requests per second = safe
        
        cve_id = kev.get('cve_id', '')
        
        print(f"  Fetching CVSS for {cve_id}...")
        
        # Fetch CVSS
        cvss_data = fetch_cvss_for_cve(cve_id)
        
        # Update KEV with CVSS data
        kev_copy = kev.copy()
        kev_copy['cvss_score'] = cvss_data['cvss_score']
        kev_copy['cvss_severity'] = cvss_data['cvss_severity']
        if cvss_data['cwe_id']:
            kev_copy['cwe_id'] = cvss_data['cwe_id']
        
        enriched.append(kev_copy)
    
    return enriched
