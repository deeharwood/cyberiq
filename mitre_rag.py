"""
MITRE ATT&CK RAG Chatbot
A learning-oriented prototype that demonstrates:
- Data ingestion from MITRE ATT&CK
- Vector embeddings and semantic search
- RAG (Retrieval Augmented Generation)
- LLM integration for cybersecurity use cases
"""

import json
import os
import requests
from typing import List, Dict
import anthropic
from sentence_transformers import SentenceTransformer
import chromadb


class MITREDataLoader:
    """Handles downloading and parsing MITRE ATT&CK data"""
    
    def __init__(self):
        self.enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
    def download_attack_data(self) -> Dict:
        """Download the latest MITRE ATT&CK Enterprise framework"""
        print("📥 Downloading MITRE ATT&CK data...")
        response = requests.get(self.enterprise_url)
        response.raise_for_status()
        return response.json()
    
    def parse_techniques(self, data: Dict) -> List[Dict]:
        """Extract techniques and tactics from STIX data"""
        print("🔍 Parsing techniques...")
        techniques = []
        
        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                # Extract core information
                technique = {
                    'id': obj.get('external_references', [{}])[0].get('external_id', 'Unknown'),
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'tactics': [phase.get('phase_name', '').replace('-', ' ').title() 
                               for phase in obj.get('kill_chain_phases', []) if isinstance(phase, dict)],
                    'url': obj.get('external_references', [{}])[0].get('url', ''),
                }
                
                # Create searchable text combining all fields
                technique['searchable_text'] = f"""
                Technique: {technique['name']} ({technique['id']})
                Tactics: {', '.join(technique['tactics']) if technique['tactics'] else 'N/A'}
                Description: {technique['description']}
                """.strip()
                
                techniques.append(technique)
        
        print(f"✅ Found {len(techniques)} techniques")
        return techniques


class VectorStore:
    """Manages embeddings and similarity search using ChromaDB"""
    
    def __init__(self, collection_name: str = "mitre_attack"):
        print("🧠 Initializing embedding model...")
        # Using a free, lightweight embedding model
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Initialize ChromaDB (local, file-based)
        self.client = chromadb.PersistentClient(path="./chroma_db")
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "MITRE ATT&CK techniques"}
        )
        
    def add_techniques(self, techniques: List[Dict]):
        """Add techniques to vector store"""
        print("🔢 Creating embeddings and storing in vector database...")
        
        # Check if already populated
        if self.collection.count() > 0:
            print(f"⚡ Vector store already has {self.collection.count()} techniques. Skipping ingestion.")
            return
        
        # Prepare data for ChromaDB
        documents = [t['searchable_text'] for t in techniques]
        ids = [t['id'] for t in techniques]
        metadatas = [{
            'name': t['name'],
            'description': t['description'][:500],  # Truncate for metadata
            'tactics': ', '.join(t['tactics']),
            'url': t['url']
        } for t in techniques]
        
        # Add to collection in batches
        batch_size = 100
        for i in range(0, len(documents), batch_size):
            batch_docs = documents[i:i+batch_size]
            batch_ids = ids[i:i+batch_size]
            batch_meta = metadatas[i:i+batch_size]
            
            self.collection.add(
                documents=batch_docs,
                ids=batch_ids,
                metadatas=batch_meta
            )
        
        print(f"✅ Stored {len(techniques)} techniques in vector database")
    
    def search(self, query: str, n_results: int = 5) -> List[Dict]:
        """Search for relevant techniques using semantic similarity"""
        results = self.collection.query(
            query_texts=[query],
            n_results=n_results
        )
        
        # Format results
        formatted = []
        for i in range(len(results['ids'][0])):
            formatted.append({
                'id': results['ids'][0][i],
                'name': results['metadatas'][0][i]['name'],
                'description': results['metadatas'][0][i]['description'],
                'tactics': results['metadatas'][0][i]['tactics'],
                'url': results['metadatas'][0][i]['url'],
                'relevance_score': results['distances'][0][i] if 'distances' in results else None
            })
        
        return formatted


class CyberSOCAssistant:
    """Main chatbot using RAG with Claude"""
    
    def __init__(self, api_key: str, vector_store: VectorStore):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.vector_store = vector_store
        
    def build_context(self, query: str, n_results: int = 5) -> str:
        """Retrieve relevant MITRE techniques for context"""
        results = self.vector_store.search(query, n_results)
        
        if not results:
            return "No relevant MITRE ATT&CK techniques found."
        
        context = "Relevant MITRE ATT&CK Techniques:\n\n"
        for i, result in enumerate(results, 1):
            context += f"{i}. {result['name']} ({result['id']})\n"
            context += f"   Tactics: {result['tactics']}\n"
            context += f"   Description: {result['description']}\n"
            context += f"   URL: {result['url']}\n\n"
        
        return context
    
    def chat(self, user_query: str) -> str:
        """Process user query with RAG"""
        # Retrieve relevant context
        context = self.build_context(user_query)
        
        # Build prompt for Claude
        system_prompt = """You are a cybersecurity expert assistant for SOC analysts. 
You have access to the MITRE ATT&CK framework and help analysts understand threats, techniques, and defensive measures.

When answering:
- Always cite specific MITRE ATT&CK technique IDs when relevant (e.g., T1078)
- Provide practical, actionable information
- Be concise but thorough
- If asked about detection or defense, suggest specific approaches
- If the query isn't covered by the provided techniques, say so clearly"""

        user_prompt = f"""Context from MITRE ATT&CK:
{context}

User Question: {user_query}

Please answer based on the MITRE ATT&CK context provided above. Cite specific technique IDs where relevant."""

        # Call Claude API
        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt}
            ]
        )
        
        return message.content[0].text


def main():
    """Main application flow"""
    print("🚀 MITRE ATT&CK Chatbot - SOC Assistant")
    print("=" * 50)
    
    # Check for API key
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        print("❌ Error: ANTHROPIC_API_KEY environment variable not set")
        print("Get your key from: https://console.anthropic.com/")
        return
    
    # Step 1: Load MITRE data
    loader = MITREDataLoader()
    try:
        data = loader.download_attack_data()
        techniques = loader.parse_techniques(data)
    except Exception as e:
        print(f"❌ Error loading MITRE data: {e}")
        return
    
    # Step 2: Initialize vector store
    vector_store = VectorStore()
    vector_store.add_techniques(techniques)
    
    # Step 3: Create assistant
    assistant = CyberSOCAssistant(api_key, vector_store)
    
    print("\n✅ System ready! Ask me about cybersecurity threats and techniques.")
    print("Type 'quit' to exit.\n")
    
    # Interactive chat loop
    while True:
        user_input = input("You: ").strip()
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("👋 Goodbye!")
            break
            
        if not user_input:
            continue
        
        try:
            print("\n🤔 Thinking...")
            response = assistant.chat(user_input)
            print(f"\nAssistant: {response}\n")
        except Exception as e:
            print(f"\n❌ Error: {e}\n")


if __name__ == "__main__":
    main()
