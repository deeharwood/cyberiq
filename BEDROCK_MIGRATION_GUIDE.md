# CyberIQ AWS Bedrock Migration Guide
## FedRAMP High Compliance for CISA CDM PMO

---

## Phase 1: AWS Account Setup (Week 1)

### Step 1: Create AWS GovCloud Account
```
1. Go to: https://aws.amazon.com/govcloud-us/getting-started/
2. Click "Request AWS GovCloud (US) Account"
3. Fill out government entity information
4. Use your CISA email address
5. Approval: 1-3 business days
```

**Why GovCloud?**
- FedRAMP High authorized environment
- CISA data stays in US
- DOD IL4/5 compliant
- Required for CDM programs

### Step 2: Enable Amazon Bedrock
```
1. Login to AWS GovCloud Console
2. Region: us-gov-west-1 (Oregon) or us-gov-east-1 (Virginia)
3. Navigate to: Amazon Bedrock
4. Click "Get Started"
5. Request model access:
   - Claude 3.5 Sonnet
   - Claude 3 Haiku
6. Approval: Usually instant
```

### Step 3: Set Up IAM Credentials
```
1. IAM Console → Users → Create User
2. User name: cyberiq-service
3. Attach policies:
   - AmazonBedrockFullAccess
4. Create access key
5. Save Access Key ID and Secret Access Key
```

---

## Phase 2: Code Migration (Week 1-2)

### Current Architecture (NOT FedRAMP):
```
CyberIQ Demo (demo.cyberiq.co)
├─ Railway hosting (commercial cloud)
├─ Direct Anthropic API
└─ NOT FedRAMP compliant ❌
```

### New Architecture (FedRAMP High):
```
CyberIQ Gov (cyberiq-gov.cisa.gov)
├─ AWS GovCloud hosting ✅
├─ Amazon Bedrock (Claude via Bedrock API) ✅
├─ FedRAMP High authorized ✅
└─ CISA CDM approved ✅
```

### Code Changes Required:

**File: api_enhanced.py**

**OLD (Direct Anthropic API):**
```python
from anthropic import Anthropic

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4000,
    messages=[{"role": "user", "content": context}]
)

response_text = message.content[0].text
```

**NEW (AWS Bedrock API):**
```python
import boto3
import json
import os

# Initialize Bedrock client
bedrock = boto3.client(
    service_name='bedrock-runtime',
    region_name='us-gov-west-1',  # GovCloud Oregon
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)

# Call Claude via Bedrock
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

### Environment Variables:
```bash
# Remove (old):
ANTHROPIC_API_KEY=sk-ant-...

# Add (new):
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-gov-west-1
```

### Dependencies to Add:
```bash
pip install boto3 --break-system-packages
```

---

## Phase 3: Hosting Migration (Week 2)

### Option A: AWS GovCloud EC2 (Recommended)
```
✅ Full control
✅ FedRAMP High
✅ Elastic Load Balancer
✅ Auto-scaling
✅ VPC isolation

Setup:
1. Launch EC2 instance (t3.medium)
2. Install Python 3.11
3. Clone CyberIQ repo
4. Install dependencies
5. Run with systemd service
6. Configure ALB with SSL

Cost: ~$100/month
```

### Option B: AWS GovCloud Elastic Beanstalk
```
✅ Easier deployment
✅ FedRAMP High
✅ Auto-scaling built-in
✅ Less management

Setup:
1. Create Elastic Beanstalk application
2. Upload Python zip file
3. Configure environment variables
4. Deploy

Cost: ~$150/month
```

### Option C: AWS GovCloud ECS (Container)
```
✅ Docker-based
✅ FedRAMP High
✅ Most scalable
✅ Modern architecture

Setup:
1. Create Docker image
2. Push to ECR GovCloud
3. Create ECS cluster
4. Deploy service

Cost: ~$200/month
```

**Recommendation:** Start with EC2 (easiest), migrate to ECS later if needed.

---

## Phase 4: Security & Compliance (Week 2-3)

### Required Security Controls:

**1. SSL/TLS Certificate**
```
- Use AWS Certificate Manager (ACM)
- Request certificate for cyberiq-gov.cisa.gov
- Attach to Application Load Balancer
- Force HTTPS only
```

**2. VPC Security Groups**
```
Inbound Rules:
- 443 (HTTPS) from CISA IP ranges only
- 22 (SSH) from bastion host only

Outbound Rules:
- 443 to Bedrock endpoints
- 443 to NVD API
- 443 to FIRST.org (EPSS)
```

**3. CloudWatch Logging**
```
- Enable access logs
- Enable error logs
- Set retention: 90 days
- Configure alarms for errors
```

**4. IAM Roles (Least Privilege)**
```
- EC2 instance role with Bedrock access only
- No public keys in code
- Use IAM roles instead
```

**5. Encryption**
```
- EBS volumes encrypted (AES-256)
- Data in transit (TLS 1.2+)
- Secrets in AWS Secrets Manager
```

---

## Phase 5: Testing & Validation (Week 3)

### Functional Testing:
```
☐ Test CISA KEV queries
☐ Test EPSS enrichment
☐ Test multi-SIEM query generation
☐ Test tab interface
☐ Test copy functionality
☐ Test date filtering
☐ Test ransomware filtering
```

### Security Testing:
```
☐ Verify HTTPS only
☐ Verify authentication (if added)
☐ Verify logging works
☐ Verify no data leakage
☐ Verify API rate limiting
☐ Run vulnerability scan
```

### Performance Testing:
```
☐ Test with 10 concurrent users
☐ Test with 50 queries
☐ Measure response times
☐ Verify under 5 second response
```

---

## Phase 6: Documentation (Week 3-4)

### Required Documentation:

**1. System Security Plan (SSP)**
```
- Architecture diagram
- Data flow diagram
- Security controls implementation
- Incident response plan
```

**2. Privacy Impact Assessment (PIA)**
```
- What data is collected: None (uses public CISA data)
- How data is stored: None (stateless queries)
- Data retention: None (no user data stored)
```

**3. Authority to Operate (ATO) Package**
```
- Inherit from AWS Bedrock FedRAMP High
- Document additional controls
- Get CISA ISSO review
- Submit to authorizing official
```

**4. User Guide**
```
- How to access system
- Example queries
- Tab interface usage
- SIEM query integration
```

---

## Timeline Summary

**Week 1:**
- Day 1-2: Create AWS GovCloud account
- Day 3-4: Enable Bedrock, test API
- Day 5: Migrate code to Bedrock API

**Week 2:**
- Day 1-2: Set up EC2 hosting
- Day 3-4: Configure security (SSL, VPC)
- Day 5: Deploy and test

**Week 3:**
- Day 1-2: Testing and validation
- Day 3-4: Documentation
- Day 5: Internal demo prep

**Week 4:**
- Day 1-3: Create PowerPoint
- Day 4: Dry run presentation
- Day 5: Present to manager

---

## Cost Breakdown

### AWS GovCloud Costs:
```
EC2 (t3.medium):           $50/month
EBS Storage (50GB):        $5/month
Application Load Balancer: $20/month
Data Transfer:             $10/month
CloudWatch Logs:           $5/month
Total AWS:                 $90/month
```

### Claude via Bedrock:
```
Input tokens:  $3/million tokens
Output tokens: $15/million tokens

Estimated usage (100 queries/day):
- 100 queries × 30 days = 3,000 queries/month
- Avg 3,000 input tokens/query = 9M input tokens
- Avg 1,000 output tokens/query = 3M output tokens

Monthly cost:
- Input:  9M × $3/M = $27
- Output: 3M × $15/M = $45
Total Claude: $72/month
```

### Or... Use GSA OneGov:
```
Claude via GSA OneGov: $1/year (YES, ONE DOLLAR!)
This is for federal agencies!

Total cost: $90 AWS + $0.08 Claude = $90/month!
```

**Annual cost: $1,080 (vs. $100K+ for competitors!)**

---

## Success Criteria

Before presenting to CISA:
```
☑ Hosted in AWS GovCloud
☑ Using Bedrock API (FedRAMP High)
☑ HTTPS with valid certificate
☑ All features working (EPSS, tabs, queries)
☑ Response time < 5 seconds
☑ Documentation complete
☑ Demo ready
☑ PowerPoint created
```

---

## Support Contacts

**AWS GovCloud Support:**
- Web: https://aws.amazon.com/govcloud-us/
- Phone: 1-877-698-9682

**AWS Bedrock Documentation:**
- https://docs.aws.amazon.com/bedrock/

**FedRAMP Questions:**
- https://www.fedramp.gov/

**CISA CDM Program:**
- Your internal contacts (you know them!)

---

## Next Steps

1. **TODAY:** Request AWS GovCloud account
2. **Day 2-3:** Wait for approval
3. **Day 4:** Enable Bedrock, test API
4. **Day 5-7:** Migrate code
5. **Week 2:** Deploy to GovCloud
6. **Week 3:** Test and document
7. **Week 4:** Create PowerPoint and present

---

## Questions?

Contact me (Claude) with any questions during migration!
