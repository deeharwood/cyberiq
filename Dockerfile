FROM python:3.11-slim

WORKDIR /app

# Copy requirements first (for layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy everything
COPY . .

# Expose port
EXPOSE 8080

# Run the app
CMD ["uvicorn", "api_enhanced:app", "--host", "0.0.0.0", "--port", "8080"]
```

**This copies EVERYTHING, so any new files you add will automatically be included!**

---

## 🚀 Step-by-Step:

### 1. Edit Dockerfile on GitHub
```
1. github.com/deeharwood/cyberiq
2. Click "Dockerfile"
3. Click pencil ✏️
4. Replace content with the "Better Fix" above
5. Commit: "Fix Dockerfile to copy all Python files"
```

### 2. Railway Auto-Deploys
```
+30 sec: Railway detects change
+1 min: Starts rebuild
+3 min: Build complete
+4 min: Check logs
```

### 3. Check Logs
```
Should see:
✅ Loaded 835 MITRE ATT&CK techniques
✅ Loaded 1499 KEVs
🎉 CyberIQ ready with 2334 items!
```

### 4. Check API Response
```
Visit: https://demo.cyberiq.co
Should show:
{
  "mitre_techniques": 835,  ← Fixed!
  "cisa_kevs": 1499,
  "total": 2334
}
```

---

## 🔍 Why This Happened:

**Your Dockerfile was probably created before mitre_loaders.py existed:**
```
Timeline:
Day 1: Created Dockerfile with COPY api_enhanced.py
Day 1: Created Dockerfile with COPY vulnerability_loaders.py
Day 2: Added mitre_loaders.py to GitHub ✅
Day 2: But Dockerfile still only copies old files! ❌

Docker builds container from Dockerfile instructions
Dockerfile says: Copy these 2 files
Docker: Copies those 2 files only
mitre_loaders.py: Left behind! ❌
