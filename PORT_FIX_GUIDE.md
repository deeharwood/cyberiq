# 🔧 FIX: Invalid Port Number Error

## 🚨 The Problem

Railway is showing:
```
invalid port number $port
```

This means the `$PORT` environment variable isn't being expanded correctly in the Procfile.

---

## ✅ THE SOLUTION: Use Gunicorn Config File

Instead of trying to use `$PORT` in the Procfile, we'll create a Python config file that reads the PORT properly.

---

## 📋 Files You Need (3 files total):

### **1. Procfile**
```
web: gunicorn api_enhanced:app --config gunicorn_config.py
```

### **2. gunicorn_config.py** (NEW!)
```python
import os

# Bind to the port provided by Railway
port = os.environ.get('PORT', '8080')
bind = f"0.0.0.0:{port}"

# Worker configuration
workers = 2
worker_class = 'sync'
timeout = 120

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
```

### **3. railway.json** (OPTIONAL but recommended)
```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "gunicorn api_enhanced:app --config gunicorn_config.py",
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
```

---

## 🚀 Quick Deploy Steps

### **Step 1: Add Files to Your Repo**

Your repo should have:
```
your-repo/
├── index.html
├── api_enhanced.py
├── requirements.txt
├── Procfile                ← Update this
├── gunicorn_config.py      ← Add this (NEW!)
└── railway.json            ← Add this (OPTIONAL)
```

### **Step 2: Commit and Push**

```bash
# Add all files
git add .

# Commit
git commit -m "Fix Railway port configuration"

# Push
git push origin main
```

### **Step 3: Railway Auto-Deploys**

Watch the Railway dashboard:
- Should see "Deploying..."
- Wait 2-3 minutes
- Should turn green ✅

### **Step 4: Check Logs**

Should see:
```
✅ [INFO] Starting gunicorn 21.2.0
✅ [INFO] Listening at: http://0.0.0.0:XXXX
✅ [INFO] Using worker: sync
✅ [INFO] Booting worker with pid: 123
```

NOT:
```
❌ invalid port number $port
```

---

## 💡 Why This Works

**Old way (doesn't work on Railway):**
```
web: gunicorn api_enhanced:app --bind 0.0.0.0:$PORT
```
- Railway doesn't expand `$PORT` in Procfile
- Gets literal string "$PORT"
- Error! ❌

**New way (works!):**
```python
# gunicorn_config.py reads PORT in Python
port = os.environ.get('PORT', '8080')
bind = f"0.0.0.0:{port}"
```
- Python code reads environment variable
- Gets actual port number
- Works! ✅

---

## 🎯 Alternative Solutions

### **Option A: Use railway.json Only**

If you don't want a Procfile, just use railway.json:

```json
{
  "deploy": {
    "startCommand": "gunicorn api_enhanced:app --config gunicorn_config.py"
  }
}
```

Railway will use this instead of Procfile!

### **Option B: Use Railway Dashboard**

1. Go to Railway dashboard
2. Your service → Settings → Deploy
3. Set "Start Command":
   ```
   gunicorn api_enhanced:app --config gunicorn_config.py
   ```
4. Save and redeploy

But using files (Procfile + config) is better for version control!

---

## ✅ Verification Checklist

After pushing to GitHub:

☐ Railway detected the push
☐ Railway started deploying
☐ Logs show "Starting gunicorn"
☐ Logs show "Listening at: http://0.0.0.0:XXXX"
☐ Logs show "Booting worker with pid"
☐ No errors about port
☐ App loads at demo.cyberiq.co
☐ Can submit queries
☐ Everything works! 🎉

---

## 🚨 If Still Having Issues

### Check These:

1. **gunicorn_config.py exists in repo root**
   ```bash
   ls -la | grep gunicorn
   ```

2. **Procfile references config file**
   ```bash
   cat Procfile
   # Should show: web: gunicorn api_enhanced:app --config gunicorn_config.py
   ```

3. **Files are committed**
   ```bash
   git status
   # Should show "nothing to commit, working tree clean"
   ```

4. **Railway is watching correct branch**
   - Check Railway dashboard
   - Should be watching "main" or "master"

5. **Railway environment has PORT variable**
   - Railway sets this automatically
   - You don't need to set it manually

---

## 💪 Your Complete File List

Make sure your GitHub repo has:

```
✅ index.html                (Frontend)
✅ api_enhanced.py           (Backend)
✅ requirements.txt          (Dependencies)
✅ Procfile                  (Start command)
✅ gunicorn_config.py        (Gunicorn configuration) ← KEY FILE!
✅ railway.json              (Optional but recommended)
✅ .gitignore                (Optional)
✅ DEPLOYMENT_GUIDE.md       (Optional, for reference)
```

---

## 🎉 After It Works

You'll see:
```
✅ Railway deployment successful
✅ App running on https://demo.cyberiq.co
✅ Logs show proper startup
✅ Queries work
✅ Ready for Lumen demo! 🚀
```

---

## ⏱️ Timeline

```
Download files: 30 seconds
Add to repo: 1 minute
Commit & push: 30 seconds
Railway redeploy: 2-3 minutes

TOTAL: ~5 minutes to fix! ⚡
```

---

**Download the files above and push to GitHub now!** 🚀

**This will fix the port issue!** ✅
