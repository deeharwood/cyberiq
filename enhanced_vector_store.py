"""
Enhanced Vector Store - Multi-Source RAG System
Handles MITRE ATT&CK, CVEs, and CISA KEV in unified vector database
"""

import chromadb
from sentence_transformers import SentenceTransformer
from typing import List, Dict


class EnhancedVectorStore:
    """
    Multi-source vector store supporting:
    - MITRE ATT&CK techniques
    - CVE vulnerabilities
    - CISA Known Exploited Vulnerabilities
    """
    
    def __init__(self, collection_name: str = "cybersecurity_knowledge"):
        print("🧠 Initializing enhanced embedding model...")
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Initialize ChromaDB
        self.client = chromadb.PersistentClient(path="./chroma_db")
        
        # Get or create unified collection
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "Unified cybersecurity knowledge base"}
        )
        
    def add_items(self, items: List[Dict], source_type: str):
        """
        Add items to vector store
        
        Args:
            items: List of items (techniques, CVEs, or KEVs)
            source_type: Type identifier ('mitre', 'cve', or 'kev')
        """
        if not items:
            print(f"⚠️  No {source_type} items to add")
            return
            
        print(f"🔢 Adding {len(items)} {source_type} items to vector database...")
        
        # Prepare data
        documents = [item['searchable_text'] for item in items]
        ids = [f"{source_type}_{item['id']}" for item in items]
        
        # Create metadata for each item
        metadatas = []
        for item in items:
            meta = {
                'source_type': source_type,
                'id': item['id'],
                'description': item.get('description', '')[:500],  # Truncate
            }
            
            # Add source-specific metadata
            if source_type == 'mitre':
                meta['name'] = item.get('name', '')
                # Convert tactics list to comma-separated string
                tactics = item.get('tactics', [])
                meta['tactics'] = ', '.join(tactics) if isinstance(tactics, list) else str(tactics)
                meta['url'] = item.get('url', '')
            elif source_type == 'cve':
                meta['cvss_score'] = str(item.get('cvss_score', ''))
                meta['cvss_severity'] = item.get('cvss_severity', '')
                meta['published'] = item.get('published', '')
            elif source_type == 'kev':
                meta['vendor'] = item.get('vendor', '')
                meta['product'] = item.get('product', '')
                meta['date_added'] = item.get('date_added', '')
                meta['actively_exploited'] = 'true'
            
            metadatas.append(meta)
        
        # Add to collection in batches
        batch_size = 100
        for i in range(0, len(documents), batch_size):
            batch_docs = documents[i:i+batch_size]
            batch_ids = ids[i:i+batch_size]
            batch_meta = metadatas[i:i+batch_size]
            
            try:
                self.collection.add(
                    documents=batch_docs,
                    ids=batch_ids,
                    metadatas=batch_meta
                )
            except Exception as e:
                print(f"⚠️  Error adding batch: {e}")
                # Try to update existing items
                try:
                    self.collection.upsert(
                        documents=batch_docs,
                        ids=batch_ids,
                        metadatas=batch_meta
                    )
                except Exception as e2:
                    print(f"❌ Failed to upsert batch: {e2}")
        
        print(f"✅ Added {len(items)} {source_type} items")
    
    def search(self, query: str, n_results: int = 10, filter_type: str = None) -> List[Dict]:
        """
        Search across all sources or filter by type
        
        Args:
            query: Search query
            n_results: Number of results to return
            filter_type: Optional filter ('mitre', 'cve', 'kev', or None for all)
            
        Returns:
            List of results with metadata
        """
        where_filter = None
        if filter_type:
            where_filter = {"source_type": filter_type}
        
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_filter
            )
        except Exception as e:
            print(f"Search error: {e}")
            return []
        
        # Format results
        formatted = []
        if results and results['ids'] and len(results['ids'][0]) > 0:
            for i in range(len(results['ids'][0])):
                result = {
                    'id': results['metadatas'][0][i]['id'],
                    'source_type': results['metadatas'][0][i]['source_type'],
                    'description': results['metadatas'][0][i]['description'],
                }
                
                # Add source-specific fields
                metadata = results['metadatas'][0][i]
                source_type = metadata['source_type']
                
                if source_type == 'mitre':
                    result['name'] = metadata.get('name', '')
                    result['tactics'] = metadata.get('tactics', '')
                    result['url'] = metadata.get('url', '')
                elif source_type == 'cve':
                    result['cvss_score'] = metadata.get('cvss_score', '')
                    result['cvss_severity'] = metadata.get('cvss_severity', '')
                    result['published'] = metadata.get('published', '')
                elif source_type == 'kev':
                    result['vendor'] = metadata.get('vendor', '')
                    result['product'] = metadata.get('product', '')
                    result['date_added'] = metadata.get('date_added', '')
                    result['actively_exploited'] = True
                
                formatted.append(result)
        
        return formatted
    
    def get_stats(self) -> Dict:
        """Get statistics about the vector store"""
        total_count = self.collection.count()
        
        # Count by type
        mitre_results = self.collection.get(where={"source_type": "mitre"}, limit=1)
        cve_results = self.collection.get(where={"source_type": "cve"}, limit=1)
        kev_results = self.collection.get(where={"source_type": "kev"}, limit=1)
        
        # Get actual counts (approximate)
        mitre_count = len(self.collection.get(where={"source_type": "mitre"}, limit=10000)['ids'])
        cve_count = len(self.collection.get(where={"source_type": "cve"}, limit=10000)['ids'])
        kev_count = len(self.collection.get(where={"source_type": "kev"}, limit=10000)['ids'])
        
        return {
            'total': total_count,
            'mitre_techniques': mitre_count,
            'cves': cve_count,
            'kevs': kev_count
        }
