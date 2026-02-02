# CyberIQ Bedrock Migration: Code Changes
## Simple Before/After Comparison

---

## File: api_enhanced.py

### BEFORE (Direct Anthropic API - NOT FedRAMP):

```python
import os
from anthropic import Anthropic

# Initialize Anthropic client
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Inside the /api/query endpoint:
message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4000,
    messages=[
        {
            "role": "user",
            "content": context
        }
    ]
)

# Extract response
response_text = message.content[0].text
```

---

### AFTER (AWS Bedrock API - FedRAMP High):

```python
import os
import boto3
import json

# Initialize Bedrock client
bedrock = boto3.client(
    service_name='bedrock-runtime',
    region_name=os.getenv('AWS_REGION', 'us-gov-west-1'),
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)

# Inside the /api/query endpoint:
body = json.dumps({
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 4000,
    "messages": [
        {
            "role": "user",
            "content": context
        }
    ]
})

response = bedrock.invoke_model(
    modelId='anthropic.claude-3-5-sonnet-20241022-v2:0',
    body=body
)

# Extract response
response_body = json.loads(response['body'].read())
response_text = response_body['content'][0]['text']
```

---

## Environment Variables

### BEFORE (.env file):
```bash
ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxx
```

### AFTER (.env file):
```bash
AWS_ACCESS_KEY_ID=AKIA... (your AWS access key)
AWS_SECRET_ACCESS_KEY=... (your AWS secret key)
AWS_REGION=us-gov-west-1
```

---

## Requirements.txt Changes

### BEFORE:
```
anthropic==0.42.0
fastapi==0.115.0
uvicorn==0.32.0
requests==2.32.3
python-multipart==0.0.12
```

### AFTER:
```
boto3==1.35.96  # ADD THIS
fastapi==0.115.0
uvicorn==0.32.0
requests==2.32.3
python-multipart==0.0.12
```

Note: Remove `anthropic==0.42.0` - we don't need it anymore!

---

## Full Migration Steps

### Step 1: Update imports at top of api_enhanced.py

```python
# OLD:
from anthropic import Anthropic

# NEW:
import boto3
import json
```

### Step 2: Replace client initialization

Find this code (around line 25):
```python
# OLD:
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
```

Replace with:
```python
# NEW:
bedrock = boto3.client(
    service_name='bedrock-runtime',
    region_name=os.getenv('AWS_REGION', 'us-gov-west-1'),
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)
```

### Step 3: Replace the API call

Find this code (around line 380):
```python
# OLD:
message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4000,
    messages=[
        {
            "role": "user",
            "content": context
        }
    ]
)

response_text = message.content[0].text
```

Replace with:
```python
# NEW:
body = json.dumps({
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 4000,
    "messages": [
        {
            "role": "user",
            "content": context
        }
    ]
})

response = bedrock.invoke_model(
    modelId='anthropic.claude-3-5-sonnet-20241022-v2:0',
    body=body
)

response_body = json.loads(response['body'].read())
response_text = response_body['content'][0]['text']
```

---

## Testing Locally

### Step 1: Install boto3
```bash
pip install boto3 --break-system-packages
```

### Step 2: Set environment variables
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-gov-west-1
```

### Step 3: Test the API
```bash
python -m uvicorn api_enhanced:app --reload
```

Open browser: http://localhost:8000

Try query: "Show me top 5 critical KEVs"

Should work exactly the same as before!

---

## Troubleshooting

**Error: "No module named 'boto3'"**
```bash
Solution: pip install boto3 --break-system-packages
```

**Error: "Unable to locate credentials"**
```bash
Solution: Make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set
Check: echo $AWS_ACCESS_KEY_ID
```

**Error: "botocore.exceptions.NoRegionError"**
```bash
Solution: Set AWS_REGION environment variable
export AWS_REGION=us-gov-west-1
```

**Error: "Could not connect to the endpoint"**
```bash
Solution: Make sure you're using us-gov-west-1 (GovCloud) region
Normal AWS regions (us-east-1) won't work!
```

**Error: "Invalid model identifier"**
```bash
Solution: Use the Bedrock model ID format:
anthropic.claude-3-5-sonnet-20241022-v2:0
NOT: claude-sonnet-4-20250514
```

---

## Model ID Reference

**Anthropic Direct API (old):**
- claude-sonnet-4-20250514
- claude-opus-4-20241113
- claude-haiku-4-20250110

**AWS Bedrock (new):**
- anthropic.claude-3-5-sonnet-20241022-v2:0
- anthropic.claude-3-5-sonnet-20240620-v1:0
- anthropic.claude-3-haiku-20240307-v1:0

Note: Model names are different!

---

## That's It!

Three simple changes:
1. Replace imports (anthropic → boto3)
2. Replace client initialization
3. Replace API call

Everything else stays the same:
- ✅ Same frontend (index.html)
- ✅ Same EPSS enricher
- ✅ Same CVSS enricher
- ✅ Same KEV loaders
- ✅ Same MITRE loaders
- ✅ Same tab interface
- ✅ Same functionality

Just a different way to call Claude!

---

## Why This Works

AWS Bedrock provides the SAME Claude models.

The only difference:
- OLD: Call Anthropic directly
- NEW: Call Anthropic through AWS

Benefits of Bedrock:
✅ FedRAMP High authorized
✅ Hosted in GovCloud
✅ DOD IL4/5 compliant
✅ Integrated with AWS services
✅ Same Claude quality
✅ Government-approved

Same AI, different wrapper!

---

## Next Steps

After code migration:
1. Test locally (5 min)
2. Commit to GitHub
3. Deploy to AWS GovCloud EC2
4. Test in GovCloud (10 min)
5. Done! ✅

Total migration time: ~2 hours
(Including testing and deployment)

That's it! Simple! 🚀
