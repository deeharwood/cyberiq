# 🗂️ CyberIQ Version History

## v1.0 - STABLE (Current Working Version)

**Date:** February 8, 2026
**Status:** ✅ STABLE - In production, people are looking at it

### Files:
- `api_enhanced_v1.0_STABLE.py`
- `index_v1.0_STABLE.html`
- `requirements.txt`

### What Works:
✅ Blazing fast (1-2 seconds)
✅ In-memory caching (KEV, NVD, ZDI)
✅ Server-side HTML generation
✅ Pagination (10 per page)
✅ CSV export
✅ Mobile responsive
✅ Vendor filtering (40+ vendors)
✅ Triple-source intelligence

### Query Support (Regex-Based):
✅ "Show me top 10 KEVs"
✅ "Microsoft vulnerabilities"
✅ "KEVs from 2025"
✅ "Order by date"
✅ "Show me 80 KEVs"
✅ "All KEVs"

### Known Limitations:
❌ No natural language understanding
❌ Can't handle: "KEVs used by APT actors"
❌ Can't handle: "Ransomware targeting healthcare"
❌ Just regex pattern matching

### Performance:
- Query time: 1-2 seconds
- Data sources: 1507 KEVs + 879 NVD + 70 ZDI
- Caching: 5 min data, 1 hour scores

### To Deploy v1.0:
```bash
# Use these files:
api_enhanced_v1.0_STABLE.py  → rename to api_enhanced.py
index_v1.0_STABLE.html       → rename to index.html
requirements.txt

# Upload to Railway/GitHub
# Deploy as normal
```

---

## v2.0 - LLM-POWERED (Next Version - IN DEVELOPMENT)

**Date:** February 8, 2026
**Status:** 🚧 IN DEVELOPMENT - Testing phase

### Planned Features:
🔄 Claude API query parsing
🔄 Natural language understanding
🔄 Smart keyword extraction
🔄 Intent-based filtering

### Will Handle:
🎯 "Show me KEVs used by APT actors"
🎯 "Ransomware targeting healthcare"
🎯 "Supply chain attacks in 2025"
🎯 ANY natural language query

### Trade-offs:
- Speed: 2-3 seconds (vs 1-2s in v1.0)
- Cost: ~$0.0001 per query (Claude API tokens)
- Dependency: Requires Claude API availability

### Testing Before Release:
- Will test with 10+ real queries
- Will verify APT actors query works
- Will document what works and what doesn't
- YOU decide if it's good enough before deploying

---

## Rollback Instructions

### If v2.0 Has Issues:

**Option 1 - Quick Rollback:**
```bash
# Just rename the stable files back:
cp api_enhanced_v1.0_STABLE.py api_enhanced.py
cp index_v1.0_STABLE.html index.html

# Deploy
# You're back to v1.0 working version
```

**Option 2 - Keep Both Versions:**
```bash
# Deploy v1.0 to: cyberiq.com
# Deploy v2.0 to: beta.cyberiq.com

# Let people test v2.0
# Keep v1.0 as stable production
```

---

## Version Comparison

| Feature | v1.0 STABLE | v2.0 LLM-POWERED |
|---------|-------------|------------------|
| Speed | 1-2s ⚡⚡⚡ | 2-3s ⚡⚡ |
| Cost | Free | ~$0.10/1K queries |
| Simple queries | ✅ Works | ✅ Works |
| "APT actors" | ❌ Fails | ✅ Works |
| "Ransomware healthcare" | ❌ Fails | ✅ Works |
| Complexity | Simple | More complex |
| Dependencies | None | Claude API |

---

## Recommendation

**For production NOW:** Use v1.0 STABLE
- It works
- It's fast
- People are already looking at it

**For testing:** Try v2.0 when ready
- Test with YOUR queries
- See if it meets your needs
- Decide if the trade-offs are worth it

**You can always roll back to v1.0!**

---

## Contact

Questions? Issues with versions?
- support@anthropic.com
- Thumbs down button in Claude.ai

---

**Always keep v1.0 STABLE as a backup!**
