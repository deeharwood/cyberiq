from flask import Flask, request, jsonify
from flask_cors import CORS
from anthropic import Anthropic
import os
import requests
import json
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Initialize Anthropic client
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Cache for EPSS data
epss_cache = {}

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

def filter_vulnerabilities(vulnerabilities, query_text):
    """Filter vulnerabilities based on query text"""
    if not query_text:
        return vulnerabilities[:20]
    
    query_lower = query_text.lower()
    
    # Extract filters from query
    vendor_filter = None
    date_filter = None
    severity_filter = None
    
    # Simple keyword extraction
    if 'microsoft' in query_lower:
        vendor_filter = 'microsoft'
    elif 'cisco' in query_lower:
        vendor_filter = 'cisco'
    elif 'adobe' in query_lower:
        vendor_filter = 'adobe'
    elif 'apple' in query_lower:
        vendor_filter = 'apple'
    elif 'google' in query_lower:
        vendor_filter = 'google'
    
    if 'last 7 days' in query_lower or 'past week' in query_lower:
        date_filter = 7
    elif 'last 30 days' in query_lower or 'past month' in query_lower:
        date_filter = 30
    elif 'last 90 days' in query_lower or 'past 90 days' in query_lower:
        date_filter = 90
    
    if 'critical' in query_lower:
        severity_filter = 'critical'
    
    # Filter
    filtered = vulnerabilities
    
    if vendor_filter:
        filtered = [v for v in filtered if vendor_filter in v.get('vendorProject', '').lower()]
    
    if date_filter:
        cutoff_date = datetime.now() - timedelta(days=date_filter)
        filtered = [v for v in filtered if datetime.strptime(v.get('dateAdded', '2000-01-01'), '%Y-%m-%d') > cutoff_date]
    
    if not vendor_filter and not severity_filter:
        filtered = [v for v in filtered if 
                   query_lower in v.get('vulnerabilityName', '').lower() or
                   query_lower in v.get('shortDescription', '').lower() or
                   query_lower in v.get('vendorProject', '').lower() or
                   query_lower in v.get('product', '').lower()]
    
    return filtered[:20]

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

@app.route('/api/query', methods=['POST'])
def query():
    """
    Main endpoint for threat intelligence analysis (NO query generation)
    """
    try:
        data = request.get_json()
        query_text = data.get('query', '')
        
        print(f"Query received: {query_text}")
        
        # Fetch KEV data
        kev_data = fetch_kev_data()
        
        if not kev_data:
            return jsonify({
                'error': 'Unable to fetch KEV data from CISA'
            }), 500
        
        # Filter vulnerabilities based on query
        filtered_data = filter_vulnerabilities(kev_data, query_text)
        
        if not filtered_data:
            return jsonify({
                'error': 'No vulnerabilities found matching your criteria'
            }), 404
        
        print(f"Found {len(filtered_data)} matching vulnerabilities")
        
        # Get CVEs
        cves = [vuln.get('cveID') for vuln in filtered_data]
        
        # Fetch CVSS and EPSS data
        print("Fetching CVSS and EPSS data...")
        cvss_data = fetch_cvss_data(cves)
        epss_data = fetch_epss_data(cves)
        
        # Enrich vulnerability data
        enriched_data = enrich_vulnerability_data(filtered_data, cvss_data, epss_data)
        
        # Sort by priority
        priority_order = {"🔴 URGENT": 0, "🟠 HIGH": 1, "🟡 MEDIUM": 2, "🟢 LOW": 3}
        enriched_data.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        # Build context for Claude (analysis only, NO queries)
        context = f"""
You are a cybersecurity threat intelligence analyst.

Analyze these {len(enriched_data)} vulnerabilities from the CISA KEV catalog.

User query: "{query_text}"

Vulnerabilities:
{json.dumps(enriched_data, indent=2)}

Provide a concise threat intelligence analysis:
1. Brief summary of the threat landscape (2-3 sentences)
2. Top 3-5 most critical vulnerabilities with their priority labels (URGENT/HIGH/MEDIUM/LOW) and EPSS scores
3. Key patterns or trends you observe
4. Actionable recommendations for security teams

Be concise and focus on actionable intelligence. Do NOT generate SIEM queries.
"""
        
        print("Calling Claude API for analysis...")
        
        # Use fast model with lower token count (no queries needed)
        response = client.messages.create(
            model="claude-sonnet-3-5-20241022-v2:0",
            max_tokens=1500,
            messages=[{"role": "user", "content": context}]
        )
        
        response_text = response.content[0].text
        
        print("Analysis complete")
        
        return jsonify({
            'response': response_text,
            'count': len(enriched_data),
            'vulnerabilities': enriched_data  # Return for query generation later
        })
        
    except Exception as e:
        print(f"Error in query endpoint: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-query', methods=['POST'])
def generate_query():
    """
    Separate endpoint for generating SIEM queries on demand
    """
    try:
        data = request.get_json()
        query_text = data.get('query', '')
        vulnerabilities = data.get('vulnerabilities', [])
        query_type = data.get('query_type', 'spl')
        
        print(f"Generating {query_type} query for: {query_text}")
        
        if not vulnerabilities:
            return jsonify({
                'error': 'No vulnerability data provided'
            }), 400
        
        # Build context for query generation
        query_type_names = {
            'spl': 'Splunk (SPL)',
            'kql': 'Azure Sentinel (KQL)',
            'eql': 'Elasticsearch (EQL)'
        }
        
        query_name = query_type_names.get(query_type, 'Unknown')
        
        context = f"""
You are a cybersecurity detection engineer.

Based on these vulnerabilities from the CISA KEV catalog, generate a production-ready detection query.

User query: "{query_text}"

Top Vulnerabilities:
{json.dumps(vulnerabilities[:10], indent=2)}

Generate a comprehensive {query_name} detection query that:
1. Detects exploitation attempts for these vulnerabilities
2. Is production-ready and well-commented
3. Includes multiple detection methods (process execution, network connections, file modifications, registry changes, etc.)
4. Uses proper syntax for {query_name}
5. Is optimized for performance

Output ONLY the query code, no explanation or markdown formatting.
"""
        
        print("Calling Claude API for query generation...")
        
        # Use standard model with more tokens for comprehensive query
        response = client.messages.create(
            model="claude-sonnet-3-5-20241022-v2:0",
            max_tokens=2000,
            messages=[{"role": "user", "content": context}]
        )
        
        query_code = response.content[0].text
        
        # Clean up any markdown formatting
        query_code = query_code.replace('```spl', '').replace('```kql', '').replace('```eql', '').replace('```', '').strip()
        
        print("Query generation complete")
        
        return jsonify({
            'query': query_code,
            'query_type': query_type
        })
        
    except Exception as e:
        print(f"Error in generate-query endpoint: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/')
def index():
    """Serve the main HTML page"""
    with open('index.html', 'r') as f:
        return f.read()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
