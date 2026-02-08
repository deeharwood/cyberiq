# 🚀 Deploy Your New Landing Page - SIMPLE STEPS

## 📥 What You Downloaded:

1. ✅ **homepage.html** - Your NEW landing page with purple gradient + logo
2. ✅ **api_enhanced.py** - Backend with routing
3. ✅ **HOW_TO_EDIT.md** - Guide for editing the page

---

## 🎯 Quick Deploy (5 Minutes)

### **Step 1: Go to your cyberiq folder**
```bash
cd ~/cyberiq
# (or wherever your cyberiq folder is)
```

### **Step 2: Copy the downloaded files**
```bash
# From your Downloads folder, copy these 2 files:
# - homepage.html
# - api_enhanced.py

# Put them in your cyberiq folder
```

### **Step 3: Rename homepage.html**
```bash
# This becomes your landing page
mv homepage.html landing-page.html
```

### **Step 4: Push to GitHub**
```bash
git add api_enhanced.py landing-page.html
git commit -m "New purple landing page with logo, no pricing"
git push origin main
```

### **Step 5: Wait for Railway**
- Railway auto-deploys in ~2 minutes
- Check Railway dashboard for deployment status

### **Step 6: Test!**
```
cyberiq.co/       → New purple landing page ✨
cyberiq.co/demo   → Demo app still works ✅
```

---

## ✅ What Changed:

### **Old Landing Page:**
- ❌ White background
- ❌ No logo (just text)
- ❌ Had pricing section

### **NEW Landing Page:**
- ✅ Purple gradient (matches demo!)
- ✅ Neural Shield logo
- ✅ NO pricing section
- ✅ Same great content
- ✅ Easy to edit yourself

---

## ✏️ To Edit Content Later:

```bash
# 1. Open the file
code landing-page.html

# 2. Make changes (see HOW_TO_EDIT.md)

# 3. Test locally
open landing-page.html

# 4. Push to deploy
git add landing-page.html
git commit -m "Updated content"
git push origin main
```

---

## 📋 Your Files Should Look Like:

```
cyberiq/
├── api_enhanced.py          ✅ NEW (with routing)
├── landing-page.html        ✅ NEW (purple gradient + logo)
├── index.html              ✅ Existing (demo app)
├── requirements.txt         ✅ Existing
└── .git/
```

---

## 🎨 What's in homepage.html:

- Header with Neural Shield logo
- "Unified Threat Intelligence Platform" title
- Stats bar (835, 13,997, 1,089)
- Problem section (3 cards)
- Solution section with example query
- Features grid (6 cards)
- ROI metrics (4 cards)
- Trust badges
- Final CTA
- Footer

**All easily editable!**

---

## 🐛 Troubleshooting:

### **Landing page not showing?**
- Check api_enhanced.py has routing code
- Check landing-page.html is in root folder
- Check Railway logs for errors

### **Demo broke?**
- Make sure api_enhanced.py has BOTH routes:
  - `/` for landing page
  - `/demo` for demo app

### **Want to edit content?**
- Read HOW_TO_EDIT.md
- Or just ask me "how do I change X?"

---

## 🎉 You're Done!

Your landing page now has:
- ✅ Purple gradient
- ✅ Neural Shield logo  
- ✅ All your content
- ✅ NO pricing
- ✅ Easy to edit

**Just deploy and enjoy!** 🚀
