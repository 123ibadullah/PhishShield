# PhishShield AI — Project Overview

PhishShield AI is a phishing email detection tool built specifically for the Indian internet context. Users paste any suspicious email — in English, Hindi, or Telugu — and instantly receive a risk score from 0 to 100, a plain-English explanation of what looks dangerous, suspicious words highlighted directly in the email text, and a running session dashboard of everything they have scanned.

---

## Purpose of the Project

PhishShield AI was built to give everyday Indian internet users a fast, transparent way to check whether an email is trying to scam them. Most phishing tools are built for Western audiences and English-only datasets. This tool was designed from the ground up around India's threat landscape — the banks people use, the payment apps on their phones, and the regional languages in which scammers increasingly write.

---

## The Problem It Solves

India recorded over **13.9 lakh reported cyber fraud cases in 2023**, a large proportion of which began with a phishing email. The challenge in India is not just volume — it is diversity:

- Scammers write in English, Hindi (Devanagari script), Telugu, and mixed scripts.
- They impersonate brands that Indians interact with daily: **SBI, HDFC, ICICI, Axis Bank, Paytm, PhonePe, GPay, BHIM UPI, IRCTC**, and government services like UIDAI and EPFO.
- They exploit India-specific financial workflows — UPI transfers, KYC compliance, OTP sharing, and PAN/Aadhaar verification.

Existing phishing detection tools trained on English-only Western datasets miss these regional patterns entirely. PhishShield AI was built to address this gap.

---

## Key Features

### 1. Four-Component Detection Engine
Every email is scored using four independent components that are combined into a single risk score:

| Component | Weight | What It Does |
|-----------|--------|--------------|
| ML Analysis (TF-IDF + Logistic Regression) | 25% | Behavioural analysis — measures frequency of urgency, financial, and social-engineering terms relative to email length using a vocabulary of 120 weighted features trained on 11,243 labelled emails |
| Rule-Based Pattern Matching | 38% | Keyword matching across urgency, financial lure, social engineering, brand impersonation, and Hindi/Telugu phishing patterns |
| URL Analysis | 22% | Per-URL risk scoring based on suspicious TLDs, URL shorteners, lookalike domains, and sensitive URL parameters |
| Email Header Analysis | 15% | Spoofing detection — From/Reply-To mismatch, freemail impersonation, suspicious sender TLDs, and spam server flags |

### 2. Risk Scoring System (0–100)

| Score | Classification | Meaning |
|-------|----------------|---------|
| 0 – 30 | **Safe** | No significant threat signals |
| 31 – 70 | **Suspicious** | Some risk signals — verify before acting |
| 71 – 100 | **Phishing** | High-confidence threat — do not interact |

Combination bonuses are applied when multiple strong signals appear together:
- Urgency + suspicious URL: **+20**
- Suspicious URL + financial keywords: **+20**
- Brand impersonation + urgency: **+15**
- All three together: **+10** additional

### 3. Explainable AI
The system does not just return a number. Every result includes:
- Human-readable reason cards explaining exactly what was found and why it is suspicious
- Severity level for each signal (low / medium / high)
- Suspicious words and phrases highlighted directly in the email text with hover tooltips
- ML feature importance bars showing which TF-IDF terms contributed most to the score
- Contextual safety tips and actionable warnings

### 4. URL Analysis
Each URL in the email is analysed independently:
- **Suspicious TLDs**: `.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`, `.top`, `.club`, `.online`, `.site`, `.icu`
- **URL shorteners**: `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, and others (they hide the real destination)
- **Lookalike domain patterns**: `sbi-secure-update.xyz`, `hdfcbank-kyc.tk`, `gpay-reward.ml`
- **Suspicious keywords in domain**: "secure", "verify", "kyc", "claim", "reward"
- **Sensitive URL parameters**: `token=`, `otp=`, `password=`, `pin=`

### 5. Indian Scam Detection
- Matches UPI, OTP, KYC, and banking fraud patterns specific to Indian financial infrastructure
- Detects impersonation of 20+ Indian banks and payment services
- Matches Hindi phishing keywords in Devanagari script: "तुरंत", "बंद", "इनाम", "खाता", "सत्यापन", etc.
- Detects Telugu script presence (Unicode range U+0C00–U+0C7F) for language identification; Telugu-specific keyword matching is not yet implemented and is planned as a future improvement

### 6. Email Header Spoofing Detection
When a full RFC 5322 email (including headers) is pasted, the system analyses:
- From / Reply-To domain mismatch (replies going to a different address than the sender)
- Freemail accounts (e.g., Gmail, Yahoo) claiming to be from known Indian brands
- Display name vs actual sending domain mismatch
- Return-Path domain differing from the From address
- X-Spam server flags from the receiving mail server

### 7. Session Dashboard
- Scan history — the server retains the last 10 scans in memory; the browser additionally persists up to 20 scans in local storage across page refreshes
- Threat breakdown chart by classification
- Live session counts (total scanned, phishing detected, suspicious, safe)
- Model performance metrics (accuracy, precision, recall, F1)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, Vite, Tailwind CSS v4, Framer Motion |
| UI Components | Radix UI (shadcn/ui), Lucide icons |
| Charts | Recharts |
| Backend | Node.js, Express 5, TypeScript |
| Backend Dev Server | tsx |
| Validation | Zod (shared between frontend and backend) |
| API Layer | OpenAPI spec + Orval codegen (typed React Query hooks) |
| Monorepo | pnpm workspaces |

---

## How the System Works — Step by Step

```
User pastes email text
       |
       v
  POST /api/analyze
       |
       +-- tfidfLRScore()          ML score: TF-IDF × LR weights → sigmoid → 0–100
       |
       +-- analyzeEmailHeaders()   Header score: From/Reply-To mismatch, freemail spoofing, X-Spam flags
       |
       +-- computeRuleScore()      Rule score: keyword matching, brand detection, Hindi keyword patterns (Telugu: script detection only)
       |
       +-- extractUrls()
       |        |
       |        +-- analyzeUrl()   Per-URL: TLD check, shortener detection, lookalike patterns, URL params
       |
       +-- urlScore = max(URL scores) × 0.7 + avg(URL scores) × 0.3
       |
       +-- combinedScore = mlScore×0.25 + ruleScore×0.38 + urlScore×0.22 + headerScore×0.15
       |
       +-- Combination bonuses (urgency+URL, financial+URL, impersonation+urgency)
       |
       +-- finalScore = min(combinedScore + bonusScore, 100)
       |
       +-- classification: safe (0–30) / suspicious (31–70) / phishing (71–100)
       |
       +-- confidence, warnings, safetyTips, suspiciousSpans, featureImportance
       |
       +-- addToHistory()          Stored in-memory for session dashboard
       |
       v
  JSON response → React frontend
       |
       +-- ScoreGauge              Animated semicircular gauge showing 0–100 score
       +-- Reason cards            Human-readable explanation of each detection signal
       +-- Score breakdown bars    ML / Rule / URL / Header component scores
       +-- ML Feature Importance   Top TF-IDF terms with contribution bars
       +-- Header analysis card    Spoofing risk, sender details, identified issues
       +-- HighlightText           Suspicious words underlined with wavy decoration + tooltips
       +-- URL analysis table      Per-URL risk scores and flags
```

---

## API Details

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/healthz` | Service health check |
| `POST` | `/api/analyze` | Analyze an email for phishing |
| `GET` | `/api/history` | Retrieve the last 10 scans from this session |
| `DELETE` | `/api/history` | Clear session history |
| `GET` | `/api/metrics` | Model performance metrics + live session counts |

### POST /api/analyze

**Request body:**
```json
{
  "emailText": "Dear Customer, Your SBI account has been suspended..."
}
```

**Response:**
```json
{
  "riskScore": 97,
  "classification": "phishing",
  "confidence": 0.99,
  "detectedLanguage": "en",
  "mlScore": 85,
  "ruleScore": 90,
  "urlScore": 75,
  "headerScore": 0,
  "reasons": [
    {
      "category": "urgency",
      "description": "This email is trying to rush you into action...",
      "severity": "high",
      "matchedTerms": ["suspended", "immediately", "24 hours", "urgently"]
    },
    {
      "category": "india_specific",
      "description": "The sender appears to be impersonating a well-known Indian bank...",
      "severity": "high",
      "matchedTerms": ["sbi"]
    },
    {
      "category": "url",
      "description": "We found a link in this email that looks suspicious...",
      "severity": "high",
      "matchedTerms": ["Suspicious TLD: .xyz", "Suspicious keyword in domain name", "Sensitive parameters in URL"]
    }
  ],
  "suspiciousSpans": [
    { "start": 13, "end": 21, "text": "Customer", "reason": "Suspicious term: \"dear customer\"" }
  ],
  "urlAnalyses": [
    {
      "url": "http://sbi-secure-update.xyz/verify?token=abc123",
      "domain": "sbi-secure-update.xyz",
      "riskScore": 100,
      "flags": ["Suspicious TLD: .xyz", "SBI lookalike domain", "Suspicious keyword in domain name", "Sensitive parameters in URL"],
      "isSuspicious": true
    }
  ],
  "featureImportance": [
    { "feature": "suspended", "contribution": 5.88, "direction": "phishing" },
    { "feature": "verify now", "contribution": 4.42, "direction": "phishing" }
  ],
  "safetyTips": [
    "Verify the sender's email address carefully — scammers use lookalike addresses",
    "Never share OTP, PIN, password, or Aadhaar/PAN details over email"
  ],
  "warnings": [
    "Do not click any links or reply to this email. This appears to be a phishing attempt.",
    "The links in this email lead to suspicious domains — not the real websites they claim to be."
  ]
}
```

---

## System Architecture

PhishShield AI is structured as a **pnpm monorepo** with three artifacts and a set of shared library packages. The frontend communicates with the backend exclusively through a typed API contract.

```
workspace/
├── artifacts/
│   ├── api-server/                 # Express 5 backend (Node.js + TypeScript)
│   │   └── src/
│   │       ├── lib/
│   │       │   ├── phishingDetector.ts   # Core detection engine (all scoring logic)
│   │       │   ├── tfidfModel.ts         # TF-IDF + Logistic Regression classifier
│   │       │   ├── emailHeaderParser.ts  # RFC 5322 header spoofing detection
│   │       │   └── historyStore.ts       # In-memory session history
│   │       └── routes/
│   │           ├── phishing.ts           # POST /api/analyze
│   │           └── dashboard.ts          # GET /api/history, DELETE /api/history, GET /api/metrics
│   │
│   ├── phishshield/                # React 19 + Vite frontend
│   │   └── src/
│   │       ├── pages/dashboard.tsx       # Main page (Analyze + Dashboard tabs)
│   │       ├── components/
│   │       │   ├── ScoreGauge.tsx        # Animated semicircular risk score display
│   │       │   └── HighlightText.tsx     # Suspicious word highlighting with tooltips
│   │       └── index.css                 # Design tokens and Tailwind theme
│   │
│   └── mockup-sandbox/             # Component design preview server (development)
│
└── lib/
    ├── api-spec/
    │   └── openapi.yaml                  # OpenAPI 3.1 contract (single source of truth)
    ├── api-client-react/
    │   └── src/generated/api.ts          # Auto-generated typed React Query hooks (Orval)
    └── api-zod/
        └── src/generated/api.schemas.ts  # Auto-generated Zod validation schemas (Orval)
```

**Data flow:**
- The OpenAPI spec (`lib/api-spec/openapi.yaml`) is the single source of truth for the API contract.
- Orval code-generation produces typed React Query hooks (`@workspace/api-client-react`) and Zod schemas (`@workspace/api-zod`) from that spec.
- The React frontend uses the generated hooks to call the backend; the backend uses the generated Zod schemas to validate requests and responses.
- No email content is sent to any external service — all analysis runs entirely on the backend server.

---

## Architecture Diagram

```
User pastes email
       |
       v
  POST /api/analyze
       |
       +-- computeMLScore()     (term frequency, urgency/financial ratios)
       |
       +-- computeRuleScore()   (keyword matching, brand detection, Hindi patterns)
       |
       +-- extractUrls()
       |        |
       |        +-- analyzeUrl()  (TLD check, lookalike patterns, URL params)
       |
       +-- Combination boosters  (urgency+URL, financial+URL, impersonation+urgency)
       |
       +-- Final score, classification, confidence
       |
       +-- addToHistory()        (saved in-memory for session dashboard)
       |
       v
  JSON response → React frontend
       |
       +-- ScoreGauge component
       +-- Reason cards (explainability)
       +-- Highlighted email text
       +-- URL analysis table
```

---

## How to Run on Replit

Three workflows are pre-configured and start automatically when the project is opened:

| Workflow | Service | Description |
|----------|---------|-------------|
| `API Server` | `artifacts/api-server` | Express backend (PORT assigned automatically) |
| `PhishShield web` | `artifacts/phishshield` | React + Vite frontend (PORT assigned automatically) |
| `Component Preview Server` | `artifacts/mockup-sandbox` | Design component preview (development only) |

**To test the application:**

1. Open the **PhishShield AI** preview pane.
2. Click the **"Load sample"** dropdown to choose from seven included demo emails:
   - **SBI account suspension notice** — classic account suspension with a fake `.xyz` link
   - **GPay reward claim** — prize scam with a `.tk` domain
   - **Paytm KYC verification request** — wallet blocking threat
   - **SBI notice in Hindi** — Devanagari-script phishing
   - **Spoofed HDFC header (with headers)** — full RFC 5322 email with From/Reply-To mismatch
   - **Internal team meeting invite** — a normal, safe email (scores 0–7)
   - **Amazon shipment notification** — another safe control email (scores 0–7)
3. Click **Scan Email** to see the result.
4. Switch to the **Dashboard** tab to see scan history, threat breakdown, and model metrics.

**To run locally** (requires Node.js 20+ and pnpm):

```bash
# Install all dependencies
pnpm install

# Start the backend
pnpm --filter @workspace/api-server run dev

# Start the frontend (in a separate terminal)
pnpm --filter @workspace/phishshield run dev

# Regenerate the API client after OpenAPI spec changes
pnpm --filter @workspace/api-spec run codegen
```

---

## Future Improvements

- **Browser extension** — scan emails directly inside Gmail and Outlook without copy-pasting
- **Real-time email integration** — connect to a mail server via IMAP/SMTP to scan incoming mail automatically
- **Advanced multilingual NLP** — train a proper language model on a large Hindi and Telugu phishing dataset, replacing the current keyword-based regional detection
- **SPF/DKIM header checking** — validate email authentication records against DNS to detect domain spoofing at the protocol level
- **Persistent database** — replace in-memory history with a real database for cross-session analytics and trend tracking
- **User feedback loop** — allow users to mark results as correct or incorrect, feeding back into model retraining

---

## Conclusion

PhishShield AI demonstrates that effective phishing detection for Indian users requires more than a generic spam filter. By combining a TF-IDF + Logistic Regression classifier with rule-based detection tuned for Indian brands and regional languages, per-URL risk scoring, and email header spoofing analysis — and by surfacing every decision in plain, human-readable language — the tool gives users real insight into why an email is suspicious, not just a binary verdict. It runs entirely offline, sends no user data anywhere, and is built on a clean, typed full-stack architecture that is straightforward to extend.
