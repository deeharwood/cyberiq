"""
MITRE ATT&CK Data Loader
Loads tactics, techniques, and procedures from MITRE ATT&CK framework
"""

import requests
from typing import List, Dict


def load_attack_data() -> List[Dict]:
    """
    Load MITRE ATT&CK Enterprise framework data
    Returns list of techniques with tactics, descriptions, and metadata
    """
    print("📥 Loading MITRE ATT&CK Enterprise framework...")
    
    # MITRE ATT&CK Enterprise framework JSON
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        objects = data.get('objects', [])
        
        # Extract techniques and sub-techniques
        techniques = []
        
        for obj in objects:
            obj_type = obj.get('type', '')
            
            # We want attack-pattern objects (these are techniques)
            if obj_type == 'attack-pattern':
                # Skip deprecated or revoked techniques
                if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue
                
                # Extract basic info
                technique_id = None
                external_refs = obj.get('external_references', [])
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        break
                
                if not technique_id:
                    continue
                
                # Extract tactics (kill chain phases)
                tactics = []
                kill_chain = obj.get('kill_chain_phases', [])
                for phase in kill_chain:
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactic = phase.get('phase_name', '').replace('-', ' ').title()
                        tactics.append(tactic)
                
                # Extract platforms
                platforms = obj.get('x_mitre_platforms', [])
                
                # Determine if this is a technique or sub-technique
                is_subtechnique = '.' in technique_id
                
                technique = {
                    'technique_id': technique_id,
                    'technique_name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'tactics': tactics,
                    'platforms': platforms,
                    'is_subtechnique': is_subtechnique,
                    'url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                }
                
                # Add data sources if available
                if 'x_mitre_data_sources' in obj:
                    technique['data_sources'] = obj['x_mitre_data_sources']
                
                # Add detection info if available
                if 'x_mitre_detection' in obj:
                    technique['detection'] = obj['x_mitre_detection']
                
                techniques.append(technique)
        
        print(f"✅ Loaded {len(techniques)} MITRE ATT&CK techniques and sub-techniques")
        
        # Show breakdown
        main_techniques = sum(1 for t in techniques if not t['is_subtechnique'])
        sub_techniques = sum(1 for t in techniques if t['is_subtechnique'])
        print(f"   - {main_techniques} main techniques")
        print(f"   - {sub_techniques} sub-techniques")
        
        return techniques
    
    except Exception as e:
        print(f"❌ Error loading MITRE ATT&CK data: {str(e)}")
        return []


def get_tactic_description(tactic: str) -> str:
    """Get description for a MITRE ATT&CK tactic"""
    tactic_descriptions = {
        'Reconnaissance': 'Gathering information to plan future operations',
        'Resource Development': 'Establishing resources to support operations',
        'Initial Access': 'Trying to get into your network',
        'Execution': 'Trying to run malicious code',
        'Persistence': 'Trying to maintain their foothold',
        'Privilege Escalation': 'Trying to gain higher-level permissions',
        'Defense Evasion': 'Trying to avoid being detected',
        'Credential Access': 'Stealing account names and passwords',
        'Discovery': 'Trying to figure out your environment',
        'Lateral Movement': 'Moving through your environment',
        'Collection': 'Gathering data of interest',
        'Command And Control': 'Communicating with compromised systems',
        'Exfiltration': 'Stealing data',
        'Impact': 'Manipulating, interrupting, or destroying systems and data'
    }
    
    return tactic_descriptions.get(tactic, '')