# 🛡️ PhishShield AI: Enterprise SaaS Platform Blueprint

This document represents the complete, production-grade architectural and business blueprint for **PhishShield AI** — transforming it from a static analysis tool into an **Autonomous AI Cybersecurity System**.

---

## 1. 🤖 Agent-Based Architecture (Core System)

To achieve true autonomy, the monolithic backend is restructured into a pipeline of specialized AI agents.

### A. Detection Agent (The Sensor)
**Role:** Ingest emails, URLs, or messages and output a normalized risk score.
**Implementation:**
- Parallel processing of data using:
  1. **ML Sub-agent:** TF-IDF + Logistic Regression (L2 Normalized)
  2. **Rule Sub-agent:** Keyword/Context matching (Hindi/Telugu/English)
  3. **Network Sub-agent:** URL shortener expansion & TLD analysis
  4. **Header Sub-agent:** RFC 5322 spoofing detection (DMARC/DKIM/SPF heuristics)
- Outputs a normalized JSON object containing `riskScore` (0-100), `classification`, and explainable `reasons`.

### B. Investigation Agent (The Detective)
**Role:** Deep analysis on ambiguous threats (Score 40-70).
**Implementation:** 
- If the Detection Agent is unsure, the Investigation Agent temporarily halts delivery.
- It performs active resolution (e.g., pinging domains to check SSL certificates, checking domain age via WHOIS API).
- Feeds data back to update the normalized score.

### C. Response Agent (The Enforcer)
**Role:** Take automated actions based on the Detection Agent's output.
**Implementation:**
- Listens for webhook events or uses Gmail API directly via OAuth.
- **Safe (0-30):** Deliver normally.
- **Suspicious (31-70):** Deliver with a native warning banner injected via Add-on.
- **Phishing (71-100):** If "Auto Defense Mode" is enabled:
  - *Action 1:* Automatically move to Spam/Quarantine folder via Gmail API.
  - *Action 2:* Add sender to account-level blocklist.
  - *Action 3:* Alert IT Admin (if B2B).

### D. Learning Agent (The Brain)
**Role:** Process human feedback to minimize false positives.
**Implementation:**
- UI includes "Report as Safe" and "Report as Phishing" buttons.
- Feedback writes directly to the PostgreSQL `feedback` table.
- A nightly CRON job recalculates term frequency weights (retraining pipeline) based on verified human overrides.

### E. Threat Intelligence Agent (The Network)
**Role:** Global immune system.
**Implementation:**
- When User A marks a novel zero-day attack as phishing, the Threat Agent extracts the URL/Sender pattern.
- It broadcasts this pattern to a Redis cache (Global Blocklist).
- When User B receives the exact same attack 2 minutes later, the system blocks it in `0.05s` without needing ML evaluation.

---

## 2. ⚙️ Backend Architecture & Database Schema

### Tech Stack
- **API Engine:** Node.js + Express 5 (TypeScript)
- **Database:** SQLite (libSQL/Turso via Drizzle ORM)
- **Cache / Queues:** Redis (BullMQ for background processing)
- **Authentication:** JWT + API Keys (for B2B customers and extensions)

### Enterprise SQLite Schema

```sql
-- users: Core authentication and tier management
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR UNIQUE,
  role VARCHAR CHECK(role IN ('USER', 'ADMIN', 'SUPERADMIN')),
  tier VARCHAR CHECK(tier IN ('FREE', 'PRO', 'ENTERPRISE')),
  stripe_customer_id VARCHAR
);

-- organizations: For B2B admin dashboards
CREATE TABLE organizations (
  id UUID PRIMARY KEY,
  name VARCHAR,
  api_key VARCHAR UNIQUE,
  auto_defense_enabled BOOLEAN DEFAULT false
);

-- scans: The core activity log
CREATE TABLE scans (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  org_id UUID REFERENCES organizations(id),
  timestamp TIMESTAMPTZ,
  risk_score INT,
  classification VARCHAR,
  source VARCHAR CHECK(source IN ('GMAIL', 'EXTENSION', 'API')),
  metadata JSONB -- (reasons, highlights, IPs)
);

-- threat_intel: The Global Immune System network
CREATE TABLE threat_intel (
  id UUID PRIMARY KEY,
  indicator_type VARCHAR CHECK(indicator_type IN ('URL', 'SENDER_EMAIL', 'DOMAIN')),
  indicator_value VARCHAR UNIQUE,
  severity VARCHAR CHECK(severity IN ('LOW', 'HIGH', 'CRITICAL')),
  first_seen TIMESTAMPTZ,
  reported_by UUID REFERENCES users(id)
);

-- feedback: Pipeline for retraining
CREATE TABLE feedback (
  id UUID PRIMARY KEY,
  scan_id UUID REFERENCES scans(id),
  user_correction VARCHAR CHECK(user_correction IN ('SAFE', 'PHISHING')),
  processed_for_ml BOOLEAN DEFAULT false
);
```

---

## 3. 📩 Gmail Add-on Implementation (Google Apps Script)

This is how you get inside the user's Inbox without requiring them to visit a dashboard.

**Manifest (`appsscript.json`):**
Requires `gmail.addons.execute` and `gmail.addons.current.message.readonly`.

**Core Execution (`Code.gs`):**
```javascript
function onGmailMessageOpen(e) {
  var message = GmailApp.getMessageById(e.gmail.messageId);
  var emailBody = message.getPlainBody();
  var sender = message.getFrom();
  
  // Securely call your PhishShield SAAS API
  var response = UrlFetchApp.fetch("https://api.phishshield.com/v1/analyze", {
    method: "post",
    headers: { "Authorization": "Bearer " + getUserApiKey() },
    contentType: "application/json",
    payload: JSON.stringify({ emailText: emailBody, sender: sender })
  });
  
  var result = JSON.parse(response.getContentText());
  
  // Build the dynamic UI inside Gmail
  return buildWarningCard(result);
}

// Auto-Defense Implementation
function applyAutoDefense(message, result) {
  if (result.classification === "phishing" && result.autoDefenseEnabled) {
     message.moveToTrash(); // Or Quarantine label
     return buildBlockedCard();
  }
}
```

---

## 4. 🏢 B2B Admin Dashboard Overview

A dedicated Next.js (React) portal for IT Managers to oversee company health.
**Key Features:**
- **Fleet Overview:** "PhishShield has blocked 432 threats this month across 50 employee inboxes."
- **Attack Vectors:** Visual charts showing the most targeted employees (the "Whales").
- **Custom Whitelisting:** IT can override the AI to guarantee internal company emails are never flagged.
- **Reporting:** 1-Click PDF exports for compliance audits.

---

## 5. 💰 Monetization Strategy (SaaS Pricing)

**1. Free Tier (B2C Product-Led Growth):**
- Features: Chrome Extension & basic Gmail Add-on.
- Limits: 100 scans per month. Manual warnings only (no auto-defense).
- Goal: Create brand awareness and train your ML model with free user feedback.

**2. Pro Tier ($4.99/mo):**
- Features: Unlimited scans, Auto-Defense Mode (auto-moves to spam).
- Goal: Monetize power-users, freelancers, and small creators.

**3. Enterprise Tier ($12.00/user/mo):**
- Features: Organization Admin Dashboard, API Access, Global Threat Intelligence pooling, Custom Policies, SOC2 Compliance reporting.
- Target: Small-to-Medium Businesses (SMBs) who can't afford a $50k security suite but need employee protection.

---

## 6. ⚡ Scalability, Security & DevOps Plan

### Performance
- **Queueing Structure:** Instant scans are processed synchronously (<1s response). Bulk historical scans rely on **BullMQ** (Redis) to prevent server locking.
- **Rate Limiting:** IP and Token-based throttling via `express-rate-limit`.
- **Edge Caching:** The Threat Intelligence network (known bad URLs) is pushed to a CDN edge-cache (Cloudflare) so known attacks are blocked in `20ms`.

### Security & Privacy (Enterprise Grade)
- **Zero-Trust Storage:** Never store the actual email body in `scans` table. Only store heavily redacted snippets or cryptographic hashes of the payload. The `scans` table only logs metadata (`risk_score`, `URL`).
- **Encryption:** AES-256 for API keys and database at rest.

### CI/CD Deployment Architecture
1. **GitHub Actions:** Auto-runs Jest unit tests and ML regression tests on every push.
2. **Backend (Node.js/Express):** Deployed as Docker containers to AWS ECS (Fargate) or Render for infinite auto-scaling.
3. **Database:** Turso (Serverless SQLite) for ultra-fast global edge-reads and replicas.
4. **Frontend Dashboard:** Deployed to Vercel for fast global edge-delivery.

---

## 7. 🌍 Expansion Roadmap (Next 12 Months)

1. **Slack / Microsoft Teams Bot:** A silent observer bot that uses the same `api.phishshield.com/v1/analyze` endpoint to instantly delete malicious phishing links posted in company chat rooms.
2. **WhatsApp Forward Scanner:** A WhatsApp bot number where users can forward suspicious "Lottery" or "Urgent KYC" messages and receive an instant AI verification.
3. **Fine-Tuned LLM:** Migrate from TF-IDF to a quantized LLaMA-3 micro-model specifically fine-tuned strictly on Indian financial phishing vectors to catch context that math-based TF-IDF misses.

---

## 8. 🎯 First 100 Days: Go-To-Market (GTM)

**Days 1-30: Build the Funnel**
- Launch the Free Chrome Extension and Gmail Add-on on ProductHunt.
- Target niche subreddits (r/IndiaInvestments, r/tech) with stories of "How I built an AI to catch the exact SBI scam that fooled my uncle."

**Days 31-60: The Startup Sell**
- Approach Founders of 10-50 employee startups. Pitch: *"Your employees are your weakest security link. PhishShield protects your Slack and Gmail automatically for $100/month."*
- Offer a 14-day "Shadow Mode" trial where it just logs threats without blocking, proving the value on their actual network.

**Days 61-100: B2B Scaling**
- Standardize the onboarding via Stripe Billing.
- Expand marketing to "Compliance". Startups need basic security software to pass SOC2 compliance audits for enterprise clients; position PhishShield as the fastest way to check the "Email Security" box.
