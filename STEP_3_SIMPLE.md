# ✅ Step 3 - SIMPLIFIED!

## 🎯 You Need ONE File: api_enhanced.py

Download **api_enhanced.py** (the one I just created above)

This file has EVERYTHING:
- ✅ v2.0 LLM-powered Claude Opus query parsing
- ✅ Landing page routing (/)
- ✅ Demo routing (/demo)
- ✅ All your API endpoints

---

## 📂 What To Do:

### **1. Download the file:**
- Click **api_enhanced.py** from the files above
- Download it

### **2. Replace your old file:**

```bash
cd /path/to/your/local/cyberiq/folder

# Backup your old file (just in case)
mv api_enhanced.py api_enhanced.py.backup

# Copy the new downloaded file here
# (Drag it from Downloads or use cp command)

# Verify it's there
ls -l api_enhanced.py
```

### **3. That's it!**

You now have ONE complete file with everything.

---

## ❌ Ignore These Files:

- ~~api_enhanced_with_routing.py~~ - Just a snippet, not needed
- ~~api_enhanced_v2.0_LLM_POWERED.py~~ - Old name, not needed

---

## ✅ Your Folder Should Look Like:

```
cyberiq/
├── api_enhanced.py          # ← The ONE file you downloaded
├── landing-page.html        # ← Download this too
├── index.html              # ← Your existing demo
├── requirements.txt         # ← Your existing file
└── .git/
```

---

## 🚀 Then Push:

```bash
cd /path/to/cyberiq

git add api_enhanced.py landing-page.html
git commit -m "Add landing page with v2.0 LLM routing"
git push origin main
```

Done! Railway will deploy automatically. 🎉

---

## 🔍 What Changed in This File?

I added these lines right after `app = FastAPI()`:

```python
@app.get("/")
async def read_root():
    """Serve landing page at cyberiq.co/"""
    return FileResponse("landing-page.html")

@app.get("/demo")
async def read_demo():
    """Serve demo app at cyberiq.co/demo"""
    return FileResponse("index.html")
```

That's it! Everything else is your existing v2.0 code.
