# Quick Deploy to Railway - Get Public URL in 5 Minutes

Railway is the **easiest** way to deploy your SOC Assistant for demos. You'll get a public URL like `https://your-app.railway.app` that you can share with prospects.

## Prerequisites

- GitHub account
- Railway account (free tier available)
- Your Anthropic API key

---

## Step 1: Push to GitHub (2 minutes)

```bash
# In your project directory
cd C:\mitre_chatbot_web_enhanced

# Initialize git
git init

# Create .gitignore
echo "chroma_db/
.env
__pycache__/
*.pyc" > .gitignore

# Add all files
git add .
git commit -m "Enhanced MITRE ATT&CK + CVE + KEV SOC Assistant"

# Create new repo on GitHub.com
# Then push:
git remote add origin https://github.com/YOUR_USERNAME/soc-assistant.git
git branch -M main
git push -u origin main
```

---

## Step 2: Deploy to Railway (3 minutes)

### A. Sign Up

1. Go to https://railway.app/
2. Click **Start a New Project**
3. Sign in with GitHub

### B. Create Project

1. Click **Deploy from GitHub repo**
2. Select your `soc-assistant` repository
3. Railway auto-detects Dockerfile ✅

### C. Add Environment Variable

1. Click on your service
2. Go to **Variables** tab
3. Click **+ New Variable**
4. Add:
   - **Variable**: `ANTHROPIC_API_KEY`
   - **Value**: `your_api_key_here`
5. Click **Add**

### D. Deploy!

Railway will automatically:
- Build your Docker container
- Deploy to their infrastructure
- Give you a public URL

**Click the URL** and your app is live! 🎉

---

## Step 3: Get Your Public URL

1. Go to **Settings** tab
2. Scroll to **Networking**
3. Click **Generate Domain**
4. You'll get: `https://your-app-name.railway.app`

**Share this URL** with prospects for demos!

---

## Cost

**Free Tier:**
- $5 credit per month
- ~500 hours of compute
- Enough for demos/testing

**Paid:**
- $5/month for 500 hours
- $0.01 per additional hour
- **~$10-20/month** for light production use

---

## Customizing Your Domain

### Option 1: Railway Subdomain (Free)
`your-company-soc-assistant.railway.app`

### Option 2: Custom Domain ($12/year for domain)
1. Buy domain (e.g., Namecheap, Google Domains)
2. In Railway → Settings → Networking → Custom Domain
3. Add your domain: `soc-assistant.yourcompany.com`
4. Update DNS CNAME record
5. SSL automatically configured ✅

---

## Updating Your App

**After making code changes:**

```bash
git add .
git commit -m "Update features"
git push
```

Railway **automatically redeploys**! No manual steps needed.

---

## Monitoring

**Railway Dashboard shows:**
- Request logs
- Error messages
- CPU/Memory usage
- Deployment history

**Access at:** https://railway.app/dashboard

---

## Troubleshooting

### Issue: "Build Failed"
- Check logs in Railway dashboard
- Usually missing dependencies or Dockerfile error

### Issue: "Application Error"
- API key not set correctly
- Check Variables tab, make sure ANTHROPIC_API_KEY is there

### Issue: "Slow to Start"
- First request takes 3-5 minutes (downloading CVEs)
- Subsequent requests are fast
- This is normal!

### Issue: "Out of Memory"
- Upgrade to Hobby plan ($5/month)
- Gets more RAM for vector database

---

## Production Checklist

Before sharing with customers:

✅ API key set in Railway variables
✅ Custom domain configured (optional but professional)
✅ Test all major queries work
✅ Check /health endpoint returns 200
✅ Monitor logs for errors

---

## Demo Script

**When showing to prospects:**

1. **Open your Railway URL**
2. **Show it loading:** "835 ATT&CK | 13997 CVEs | 1089 KEVs"
3. **Run KEV query:** "What are the most critical actively exploited vulnerabilities?"
4. **Show results:** Point out red pulsing badges, CVSS scores
5. **Show filters:** Click KEV only, CVE only, etc.
6. **Show speed:** "30 seconds vs 45 minutes manually"

---

## Next Steps

1. ✅ Deploy to Railway
2. ✅ Test your public URL
3. ✅ Share with 3 prospects
4. ✅ Gather feedback
5. ✅ Iterate and improve

---

**You're 5 minutes away from a live demo!** 🚀

Go to https://railway.app/ and follow the steps above.
