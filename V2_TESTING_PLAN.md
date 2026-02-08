# 🧪 v2.0 LLM-POWERED Testing Plan

## What Changed in v2.0:

### **REMOVED: Regex Pattern Matching**
```python
# OLD v1.0 (REMOVED):
if 'kev' in query_lower:
    needs_kev = True
if 'top 10' in query_lower:
    limit = 10
```

### **ADDED: Claude Opus 4.5 Query Parser**
```python
# NEW v2.0:
parsed_intent = parse_query_with_claude(query_text)
# Returns: {
#   "data_sources": ["KEV"],
#   "search_keywords": ["APT", "threat actor", "state-sponsored"],
#   "filters": {"year": "2025", "vendor": "microsoft", "limit": 10},
#   "sort_by": "date"
# }
```

### **ADDED: Smart Keyword Search**
```python
# NEW v2.0:
if search_keywords:
    filtered_data = smart_keyword_search(filtered_data, search_keywords)
# Searches descriptions for: "APT", "ransomware", "supply chain", etc.
```

---

## Test Queries:

### **Test 1: APT Actors (The One That Failed)**
```
Query: "Show me KEVs that use APT actors"

Expected Claude Parsing:
{
  "data_sources": ["KEV"],
  "search_keywords": ["APT", "advanced persistent threat", "state-sponsored", "threat actor"],
  "filters": {"limit": null},
  "sort_by": null
}

Expected Result:
- KEVs with descriptions containing "APT", "state-sponsored", "nation-state", etc.
- NOT all 1507 KEVs
```

### **Test 2: Ransomware Healthcare**
```
Query: "Ransomware targeting healthcare in 2025"

Expected Claude Parsing:
{
  "data_sources": ["KEV"],
  "search_keywords": ["ransomware", "healthcare", "medical", "hospital"],
  "filters": {"year": "2025", "limit": null},
  "sort_by": null
}

Expected Result:
- KEVs from 2025
- Mentioning ransomware + healthcare
```

### **Test 3: Microsoft RCE**
```
Query: "Microsoft RCE vulnerabilities from 2025"

Expected Claude Parsing:
{
  "data_sources": ["KEV", "NVD"],
  "search_keywords": ["RCE", "remote code execution"],
  "filters": {"vendor": "microsoft", "year": "2025", "limit": null},
  "sort_by": null
}

Expected Result:
- Microsoft vulnerabilities only
- From 2025
- With RCE keywords
```

### **Test 4: Supply Chain Attacks**
```
Query: "Supply chain attacks"

Expected Claude Parsing:
{
  "data_sources": ["KEV", "NVD", "ZDI"],
  "search_keywords": ["supply chain", "third-party", "dependency", "software supply"],
  "filters": {"limit": null},
  "sort_by": null
}

Expected Result:
- Vulnerabilities mentioning supply chain
```

### **Test 5: Top 50 KEVs Ordered by Date**
```
Query: "Show me top 50 KEVs ordered by date"

Expected Claude Parsing:
{
  "data_sources": ["KEV"],
  "search_keywords": [],
  "filters": {"limit": 50},
  "sort_by": "date"
}

Expected Result:
- 50 KEVs
- Sorted by date (newest first)
```

### **Test 6: All KEVs from 2025**
```
Query: "Show me all KEVs from 2025"

Expected Claude Parsing:
{
  "data_sources": ["KEV"],
  "search_keywords": [],
  "filters": {"year": "2025", "limit": null},
  "sort_by": null
}

Expected Result:
- All KEVs from 2025 (no limit)
- Could be 100, 200, 500 depending on how many exist
```

---

## What Could Go Wrong:

### **Problem 1: Claude Misparses Query**
```
Query: "KEVs used by Chinese hackers"
Bad Parse: Extracts no keywords
Result: Shows all KEVs ❌

Fix: Improve prompt with more examples
```

### **Problem 2: No Matches Found**
```
Query: "KEVs mentioning purple unicorns"
Parse: Keywords = ["purple", "unicorns"]
Result: 0 matches (correct behavior)

This is OK! Sometimes queries have no results.
```

### **Problem 3: Too Slow**
```
Query parsing: 1.5-2.5s (Opus is slow)
Total time: 3-4 seconds

vs v1.0: 1-2 seconds

This is expected with Opus.
```

### **Problem 4: Claude API Down**
```
Fallback: Returns empty keywords
Result: Shows all results (not ideal but doesn't crash)
```

---

## Success Criteria:

### **MUST WORK:**
✅ "Show me KEVs that use APT actors" → Finds APT-related KEVs
✅ "Ransomware targeting healthcare" → Finds ransomware + healthcare
✅ "Top 50 KEVs ordered by date" → 50 results, sorted by date

### **SHOULD WORK:**
✅ "Microsoft RCE from 2025" → Microsoft + RCE + 2025 filter
✅ "Supply chain attacks" → Supply chain keywords
✅ "All KEVs from 2025" → No limit, year filter

### **ACCEPTABLE FAILURES:**
⚠️ Very complex queries may not parse perfectly
⚠️ Obscure keywords might not match anything
⚠️ Ambiguous queries might need clarification

---

## Performance Expectations:

```
v1.0 STABLE:     1-2 seconds
v2.0 LLM (Opus): 3-4 seconds (slower but smarter)

Trade-off: +2 seconds for actual understanding
```

---

## Deployment Plan:

### **Option A: Replace v1.0**
```bash
# Upload v2.0 as api_enhanced.py
# Everyone gets LLM-powered version
# Risk: If it breaks, people are stuck
```

### **Option B: Keep Both (Recommended)**
```bash
# v1.0: cyberiq.railway.app (stable, fast)
# v2.0: cyberiq-beta.railway.app (testing)

# You test v2.0
# Others still have v1.0
# Switch when confident
```

### **Option C: Staged Rollout**
```bash
# Week 1: You test v2.0 privately
# Week 2: Share beta link with trusted users
# Week 3: If good, replace v1.0
# Always can roll back to v1.0 STABLE
```

---

## Testing Checklist:

Before deploying v2.0:

### **Phase 1: Basic Functionality**
- [ ] Test: "Show me KEVs that use APT actors"
- [ ] Test: "Ransomware targeting healthcare"
- [ ] Test: "Top 50 KEVs ordered by date"
- [ ] Verify: No crashes, returns results
- [ ] Verify: Speed is 3-4 seconds (acceptable)

### **Phase 2: Edge Cases**
- [ ] Test: "All KEVs from 2025"
- [ ] Test: "Microsoft vulnerabilities"
- [ ] Test: Query with no matches
- [ ] Verify: Handles empty results gracefully

### **Phase 3: Comparison**
- [ ] Same query on v1.0 vs v2.0
- [ ] Compare results quality
- [ ] Compare speed
- [ ] Decide if trade-off is worth it

---

## Rollback Plan:

If v2.0 doesn't work:

```bash
# Step 1: Stop using v2.0
cp api_enhanced_v1.0_STABLE.py api_enhanced.py
cp index_v1.0_STABLE.html index.html

# Step 2: Deploy
git push

# Step 3: You're back to working v1.0
```

---

## Next Steps:

1. **Deploy v2.0 to test environment**
2. **Run all test queries**
3. **Document what works vs what doesn't**
4. **YOU decide if it's good enough**
5. **Either deploy to production or stick with v1.0**

No pressure. v1.0 works and you can always keep it! 🎯
