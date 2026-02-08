# ✏️ How to Edit Your Landing Page

## 📝 Easy Editing Guide

Your new `homepage.html` is simple HTML with inline CSS. Here's how to edit it!

---

## 🎯 Common Edits You'll Want to Make

### **1. Change Stats Numbers**

Find this section (around line 180):
```html
<div class="stats-bar">
    <div class="stat">
        <div class="stat-number">835</div>          👈 CHANGE THIS
        <div class="stat-label">NEW CISA KEVs</div> 👈 OR THIS
    </div>
    <!-- More stats... -->
</div>
```

**Just edit the numbers and labels!**

---

### **2. Change Header Text**

Find (around line 130):
```html
<h1>Unified Threat Intelligence Platform</h1>  👈 CHANGE THIS
<p class="subtitle">One question. Complete intelligence. 30 seconds.</p>  👈 OR THIS
```

---

### **3. Change Problem Cards**

Find (around line 220):
```html
<div class="problem-card">
    <span class="problem-icon">🔍</span>         👈 CHANGE EMOJI
    <h3 class="problem-title">CISA ATTACK</h3>   👈 CHANGE TITLE
    <p class="problem-desc">Check actors...</p>  👈 CHANGE DESCRIPTION
</div>
```

---

### **4. Change ROI Numbers**

Find (around line 380):
```html
<div class="roi-card">
    <div class="roi-value">$234K</div>           👈 CHANGE THIS
    <div class="roi-label">Annual Labor Savings</div>  👈 OR THIS
</div>
```

---

### **5. Change Button Links**

Find (around line 150):
```html
<a href="/demo" class="btn btn-primary">Try the Demo</a>  👈 CHANGE LINK OR TEXT
```

**Change `/demo` to any URL!**

---

### **6. Change Colors (Advanced)**

Find the CSS section (around line 10):
```css
body {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);  👈 CHANGE GRADIENT
}
```

**Try different gradients:**
- Blue to purple: `#667eea 0%, #764ba2 100%` (current)
- Blue to teal: `#4facfe 0%, #00f2fe 100%`
- Purple to pink: `#a8c0ff 0%, #3f2b96 100%`

---

## 🛠️ How to Edit

### **Option 1: VS Code (Recommended)**
```bash
# Open file
code homepage.html

# Edit and save
# File → Save (Cmd/Ctrl + S)
```

### **Option 2: TextEdit (Mac)**
```bash
# Open
open -a TextEdit homepage.html

# Make it plain text first:
# Format → Make Plain Text
```

### **Option 3: Notepad (Windows)**
```bash
notepad homepage.html
```

### **Option 4: Online Editor**
1. Open file in text editor
2. Copy ALL the code
3. Go to CodePen.io
4. Click "Create" → "Pen"
5. Paste in HTML section
6. Edit and see changes live!
7. Copy edited code back

---

## ✅ After Editing

### **Test Locally:**
```bash
# Just double-click the file!
# Opens in browser

# OR
open homepage.html  # Mac
start homepage.html # Windows
```

### **Deploy to Railway:**
```bash
cd ~/cyberiq

# Replace landing-page.html with your edited homepage.html
cp homepage.html landing-page.html

# Or rename if you want
mv homepage.html landing-page.html

# Commit and push
git add landing-page.html
git commit -m "Updated landing page content"
git push origin main
```

---

## 🎨 Quick Reference: Where Things Are

```
Lines 1-50:    CSS styles (colors, fonts, spacing)
Lines 130-160: Header with logo and title
Lines 180-200: Stats bar (3 numbers)
Lines 220-250: Problem section (3 cards)
Lines 270-300: Solution section
Lines 320-380: Features grid (6 cards)
Lines 390-420: ROI metrics (4 cards)
Lines 440-470: Trust badges
Lines 480-500: Final CTA
Lines 510-520: Footer
```

---

## 💡 Pro Tips

**Tip 1:** Always keep a backup before editing!
```bash
cp homepage.html homepage.html.backup
```

**Tip 2:** Test in browser after each change

**Tip 3:** Use Cmd+F / Ctrl+F to find text quickly

**Tip 4:** Change one thing at a time

**Tip 5:** If you break something, just re-download from Claude!

---

## 🆘 Common Mistakes

❌ **Deleting closing tags** (`</div>`, `</p>`, etc.)
✅ **Every `<div>` needs a `</div>`**

❌ **Breaking quotes** (`"title`)
✅ **Complete quotes** (`"title"`)

❌ **Deleting CSS curly braces** (`{` or `}`)
✅ **Every `{` needs a `}`**

---

## 📞 Need Help?

Just paste the section you're trying to edit and tell me what you want to change!

Example: "I want to change the header title to 'CyberIQ Pro'" 

I'll tell you EXACTLY what to edit! 🎯
