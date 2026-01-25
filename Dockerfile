FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY mitre_rag.py .
COPY vulnerability_loaders.py .
COPY enhanced_vector_store.py .
COPY api_enhanced.py .

# Create static directory and copy frontend
RUN mkdir -p /app/static
COPY static/ /app/static/

# Create directory for ChromaDB
RUN mkdir -p /app/chroma_db

# Expose port
EXPOSE 8000

# Run the enhanced web server
CMD python -m uvicorn api_enhanced:app --host 0.0.0.0 --port ${PORT:-8000}
