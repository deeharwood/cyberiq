"""
Enhanced FastAPI Server - Multi-Source Cybersecurity Assistant
Integrates MITRE ATT&CK, CVE, and CISA KEV data
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
import os
import sys

# Import loaders and vector store
sys.path.append('/app')
from mitre_rag import MITREDataLoader
from vulnerability_loaders import CVEDataLoader, CISAKEVLoader
from enhanced_vector_store import EnhancedVectorStore
import anthropic

# Initialize FastAPI
app = FastAPI(
    title="Enhanced MITRE ATT&CK & CVE SOC Assistant",
    description="AI-powered cybersecurity assistant with MITRE ATT&CK, CVE, and CISA KEV integration",
    version="2.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
vector_store = None
anthropic_client = None
is_initialized = False
stats = {}

# Request/Response models
class ChatRequest(BaseModel):
    query: str
    filter_type: Optional[str] = None  # 'mitre', 'cve', 'kev', or None for all
    
class ChatResponse(BaseModel):
    response: str
    sources: list = []
    stats: dict = {}

class HealthResponse(BaseModel):
    status: str
    data_loaded: dict
    
class RefreshRequest(BaseModel):
    source: str  # 'cve' or 'kev' or 'all'
    days: Optional[int] = 30  # For CVE: how many days back

# Startup: Initialize all data sources
@app.on_event("startup")
async def startup_event():
    """Initialize MITRE, CVE, and KEV data on startup"""
    global vector_store, anthropic_client, is_initialized, stats
    
    print("🚀 Initializing Enhanced Cybersecurity Assistant...")
    
    try:
        # Check API key
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")
        
        anthropic_client = anthropic.Anthropic(api_key=api_key)
        
        # Initialize vector store
        print("🧠 Initializing unified vector database...")
        vector_store = EnhancedVectorStore()
        
        # Load MITRE ATT&CK
        print("\n📚 Loading MITRE ATT&CK Framework...")
        mitre_loader = MITREDataLoader()
        mitre_data = mitre_loader.download_attack_data()
        mitre_techniques = mitre_loader.parse_techniques(mitre_data)
        vector_store.add_items(mitre_techniques, 'mitre')
        
        # Load recent CVEs
        print("\n🔒 Loading Recent CVEs...")
        cve_loader = CVEDataLoader()
        cve_data = cve_loader.download_recent_cves(days=90)
        cves = cve_loader.parse_cves(cve_data)
        vector_store.add_items(cves, 'cve')
        
        # Load CISA KEV
        print("\n⚠️  Loading CISA Known Exploited Vulnerabilities...")
        kev_loader = CISAKEVLoader()
        kev_data = kev_loader.download_kev_catalog()
        kevs = kev_loader.parse_kevs(kev_data)
        vector_store.add_items(kevs, 'kev')
        
        # Get stats
        stats = vector_store.get_stats()
        print(f"\n✅ System ready!")
        print(f"   - MITRE Techniques: {stats['mitre_techniques']}")
        print(f"   - CVEs: {stats['cves']}")
        print(f"   - KEVs: {stats['kevs']}")
        print(f"   - Total items: {stats['total']}")
        
        is_initialized = True
        
    except Exception as e:
        print(f"❌ Startup error: {e}")
        import traceback
        traceback.print_exc()
        is_initialized = False

# Health check
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Check system status and data loaded"""
    if not is_initialized:
        raise HTTPException(status_code=503, detail="System not initialized")
    
    return HealthResponse(
        status="healthy",
        data_loaded=stats
    )

# Enhanced chat endpoint
@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Enhanced chat with multi-source knowledge
    Searches across MITRE, CVE, and KEV data
    """
    if not is_initialized:
        raise HTTPException(status_code=503, detail="System not initialized")
    
    if not request.query or len(request.query.strip()) == 0:
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    
    try:
        # Search vector database
        results = vector_store.search(
            request.query, 
            n_results=10,
            filter_type=request.filter_type
        )
        
        # Build context from results
        context = build_context(results)
        
        # Build prompt for Claude
        system_prompt = """You are an expert cybersecurity analyst and SOC (Security Operations Center) assistant.
You have access to:
- MITRE ATT&CK framework (attack techniques and tactics)
- CVE database (Common Vulnerabilities and Exposures)
- CISA KEV (Known Exploited Vulnerabilities - actively exploited in the wild)

When answering:
- Cite specific technique IDs (T1234), CVE IDs (CVE-2024-1234), or mention if from CISA KEV
- For vulnerabilities, mention CVSS scores and severity when available
- PRIORITIZE KEV items - these are actively being exploited
- Provide practical, actionable information for SOC analysts
- Be concise but thorough"""

        user_prompt = f"""Context from cybersecurity databases:
{context}

User Question: {request.query}

Please answer based on the context provided above. Cite specific IDs where relevant."""

        # Call Claude API
        message = anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt}
            ]
        )
        
        response_text = message.content[0].text
        
        # Extract source IDs from results
        source_info = []
        for result in results:
            source = {
                'id': result['id'],
                'type': result['source_type'],
            }
            
            if result['source_type'] == 'mitre':
                source['name'] = result.get('name', '')
            elif result['source_type'] == 'cve':
                source['severity'] = result.get('cvss_severity', '')
                source['score'] = result.get('cvss_score', '')
            elif result['source_type'] == 'kev':
                source['vendor'] = result.get('vendor', '')
                source['product'] = result.get('product', '')
                source['actively_exploited'] = True
            
            source_info.append(source)
        
        return ChatResponse(
            response=response_text,
            sources=source_info[:5],  # Top 5 sources
            stats=stats
        )
        
    except Exception as e:
        print(f"Error processing query: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

def build_context(results: list) -> str:
    """Build context string from search results"""
    if not results:
        return "No relevant information found."
    
    context_parts = []
    
    for i, result in enumerate(results, 1):
        source_type = result['source_type'].upper()
        
        if result['source_type'] == 'mitre':
            context_parts.append(
                f"{i}. [MITRE ATT&CK] {result['name']} ({result['id']})\n"
                f"   Tactics: {result.get('tactics', 'N/A')}\n"
                f"   Description: {result['description']}\n"
                f"   URL: {result.get('url', '')}"
            )
        elif result['source_type'] == 'cve':
            severity = result.get('cvss_severity', 'UNKNOWN')
            score = result.get('cvss_score', 'N/A')
            context_parts.append(
                f"{i}. [CVE] {result['id']} - Severity: {severity} (Score: {score})\n"
                f"   Published: {result.get('published', 'N/A')}\n"
                f"   Description: {result['description']}"
            )
        elif result['source_type'] == 'kev':
            context_parts.append(
                f"{i}. [⚠️ CISA KEV - ACTIVELY EXPLOITED] {result['id']}\n"
                f"   Vendor: {result.get('vendor', 'N/A')}\n"
                f"   Product: {result.get('product', 'N/A')}\n"
                f"   Added to KEV: {result.get('date_added', 'N/A')}\n"
                f"   Description: {result['description']}"
            )
    
    return "\n\n".join(context_parts)

# Search endpoint
@app.get("/search")
async def search(query: str, limit: int = 10, filter_type: str = None):
    """Direct search without AI generation"""
    if not is_initialized:
        raise HTTPException(status_code=503, detail="System not initialized")
    
    try:
        results = vector_store.search(query, n_results=limit, filter_type=filter_type)
        return {"results": results, "count": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Refresh data endpoint
@app.post("/admin/refresh")
async def refresh_data(request: RefreshRequest, background_tasks: BackgroundTasks):
    """Refresh CVE or KEV data (admin endpoint)"""
    if not is_initialized:
        raise HTTPException(status_code=503, detail="System not initialized")
    
    # Run refresh in background
    background_tasks.add_task(perform_refresh, request.source, request.days)
    
    return {"status": "refresh_started", "source": request.source}

async def perform_refresh(source: str, days: int):
    """Background task to refresh data"""
    global stats
    
    try:
        if source in ['cve', 'all']:
            print(f"🔄 Refreshing CVE data (last {days} days)...")
            cve_loader = CVEDataLoader()
            cve_data = cve_loader.download_recent_cves(days=days)
            cves = cve_loader.parse_cves(cve_data)
            vector_store.add_items(cves, 'cve')
        
        if source in ['kev', 'all']:
            print("🔄 Refreshing CISA KEV data...")
            kev_loader = CISAKEVLoader()
            kev_data = kev_loader.download_kev_catalog()
            kevs = kev_loader.parse_kevs(kev_data)
            vector_store.add_items(kevs, 'kev')
        
        # Update stats
        stats = vector_store.get_stats()
        print("✅ Refresh complete")
        
    except Exception as e:
        print(f"❌ Refresh error: {e}")

# Serve frontend
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main HTML page"""
    html_file = "/app/static/index.html"
    
    if os.path.exists(html_file):
        with open(html_file, 'r') as f:
            return HTMLResponse(content=f.read())
    else:
        return HTMLResponse(content="<h1>Enhanced MITRE ATT&CK + CVE + KEV Assistant</h1><p>Frontend not found. API docs at /docs</p>")

# Mount static files
try:
    app.mount("/static", StaticFiles(directory="/app/static"), name="static")
except RuntimeError:
    pass  # Directory might not exist yet

if __name__ == "__main__":
   import os
port = int(os.environ.get("PORT", 8000))
uvicorn.run(app, host="0.0.0.0", port=port)
