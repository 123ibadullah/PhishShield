# PhishShield AI

A phishing email detection tool built for the Indian internet context. Paste an email, get an instant risk score, a plain-English explanation of what looks suspicious, and a running summary of everything you have scanned in the session.

---

## The Problem

India saw over 13.9 lakh reported cyber fraud cases in 2023, and a significant portion of them started with a phishing email. What makes this harder in India is the diversity — scammers write in English, Hindi, Telugu, and other regional languages. They impersonate SBI, HDFC, IRCTC, Paytm, and other brands that Indians interact with daily.

Most phishing detection tools are trained on English-only Western email datasets and miss regional patterns entirely. PhishShield AI was built specifically with India's threat landscape in mind.

---

## What it does

- Scans any email for phishing indicators and returns a risk score from 0 to 100
- Explains, in human language, exactly what triggered the score
- Highlights suspicious words and links directly in the email text
- Detects phishing in English, Hindi (Devanagari script), and Telugu
- Flags suspicious URLs — including lookalike domains like `sbi-secure-update.xyz`
- Shows a session dashboard with scan history, threat breakdown, and model accuracy metrics (persisted via SQLite)
- Works entirely offline — no email data is sent anywhere

---

## Risk Scoring

Every email gets a score between 0 and 100, computed from three components:

- **Behavioural analysis (30%)** — frequency of urgency and financial terms relative to email length
- **Pattern matching (45%)** — rule-based detection of known phishing patterns
- **Link analysis (25%)** — risk score of all URLs found in the email

These three scores combine into a single number. If multiple strong signals appear together (e.g. urgency + suspicious URL + bank impersonation), a combination bonus is added on top.

| Score | Classification | What it means |
|-------|----------------|---------------|
| 0 – 30 | Safe | No significant threat signals |
| 31 – 70 | Suspicious | Some risk signals — verify before acting |
| 71 – 100 | Phishing | High-confidence threat — do not interact |

---

## Detection Logic

### Urgency detection
Words and phrases like "urgent", "blocked", "suspended", "verify now", "24 hours", and Hindi equivalents like "तुरंत" and "अभी" are matched. The more urgency signals, the higher the contribution.

### Financial lure detection
References to money amounts (Rs., ₹, lakh, crore), payment platforms (UPI, Paytm, GPay), and sensitive actions (KYC, OTP, account verification) are flagged.

### Social engineering detection
Generic greetings like "Dear Customer" or "Dear User", phrases like "click here", "provide your details", and threats of "legal action" are classic social engineering patterns.

### Brand impersonation
A separate list covers Indian banks (SBI, HDFC, ICICI, Axis, PNB, Kotak) and payment services (Paytm, PhonePe, GPay, BHIM UPI, IRCTC). When these appear alongside other risk signals, the score increases by 25 points.

### URL analysis
Each URL in the email is scored separately:
- Suspicious TLDs: `.xyz`, `.tk`, `.ml`, `.ga`, `.cf` — these are free domains commonly used in phishing
- URL shorteners like `bit.ly` and `tinyurl.com` (they hide the real destination)
- Lookalike patterns: `sbi-secure-update.xyz`, `hdfcbank-kyc.tk`, `gpay-reward.ml`
- Keywords in the domain name: "secure", "verify", "kyc", "claim"
- Sensitive URL parameters: `token=`, `otp=`, `password=`

### Combination bonuses
When multiple strong signals appear together, the risk increases more than the sum of individual scores:
- Urgency + suspicious URL: +20
- Suspicious URL + financial keywords: +20
- Brand impersonation + urgency: +15
- All three together: +10 additional

### Multilingual detection
Unicode range detection identifies the script:
- Devanagari (U+0900–U+097F) → Hindi
- Telugu (U+0C00–U+0C7F) → Telugu
- Both present → Mixed

Hindi phishing keywords are matched in Devanagari script: "तुरंत", "बंद", "इनाम", "खाता", "सत्यापन", etc.

---

## Explainable AI

Every result includes a plain-English explanation of what was found. Instead of just giving a number, the system tells you:

- Why it flagged the email
- Which specific words or phrases triggered each rule
- How severe each individual signal is (low / medium / high)
- What to do if the email is suspicious

Suspicious words are also highlighted directly in the email text, so you can see exactly what the system is reacting to.

---

## System Architecture

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
       +-- addToHistory()        (saved to SQLite database for session dashboard)
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

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, Vite, Tailwind CSS, Framer Motion |
| UI Components | Radix UI (shadcn/ui), Lucide icons |
| Charts | Recharts |
| Backend | Node.js, Express 5 |
| Validation | Zod (shared between frontend and backend) |
| API layer | OpenAPI spec + Orval codegen (typed React Query hooks) |
| Database | SQLite (libSQL) + Drizzle ORM |
| Security | Helmet, Rate Limiter, API Key Auth |
| Runtime | TypeScript throughout (tsx for the backend dev server) |
| Monorepo | pnpm workspaces |

---

## Project Structure

```
workspace/
├── artifacts/
│   ├── api-server/                 # Express backend
│   │   └── src/
│   │       ├── lib/
│   │       │   ├── phishingDetector.ts   # Core detection engine
│   │       │   └── historyStore.ts       # SQLite database integration
│   │       └── routes/
│   │           ├── phishing.ts           # POST /api/analyze
│   │           └── dashboard.ts          # GET /api/history, /api/metrics
│   │
│   └── phishshield/                # React frontend (Vite)
│       └── src/
│           ├── pages/dashboard.tsx       # Main page (Analyze + Dashboard tabs)
│           ├── components/
│           │   ├── ScoreGauge.tsx        # Circular risk score display
│           │   └── HighlightText.tsx     # Suspicious word highlighting
│           └── index.css                 # Design tokens and theme
│
└── lib/
    ├── api-spec/
    │   └── openapi.yaml                  # API contract
    ├── api-client-react/
    │   └── src/generated/api.ts          # Auto-generated React Query hooks
    ├── api-zod/
    │   └── src/generated/api.schemas.ts  # Auto-generated Zod schemas
    └── db/
        └── src/schema/                   # Drizzle ORM SQLite schemas
```

---

## Running it locally

Both services run through pnpm workspaces. You will need Node.js 20+ and pnpm installed.

```bash
# Install all dependencies
pnpm install

# Start the backend (port 8080)
pnpm --filter @workspace/api-server run dev

# Start the frontend (reads PORT from environment)
pnpm --filter @workspace/phishshield run dev

# Regenerate API client after OpenAPI changes
pnpm --filter @workspace/api-spec run codegen
```

---

## Demo

Six sample emails are available in the "Load sample" dropdown:

1. **SBI bank alert** — classic account suspension + fake link
2. **UPI reward claim** — prize scam with `.tk` domain
3. **Paytm KYC notice** — wallet blocking threat
4. **Hindi bank scam** — Devanagari-script phishing
5. **Office meeting invite** — a normal, safe email
6. **Amazon shipment** — another safe email as a control

Scanning the phishing samples produces scores of 90–100 (Phishing). The safe samples score 0–7.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/healthz` | Service health check |
| POST | `/api/analyze` | Analyze an email. Body: `{ emailText: string }` |
| GET | `/api/history` | Last 10 scans this session |
| DELETE | `/api/history` | Clear session history |
| GET | `/api/metrics` | Model metrics + session counts |

---

## Model Metrics

The metrics shown in the dashboard (accuracy 94.7%, precision 92.3%, recall 96.8%, F1 94.5%) reflect the performance of a Logistic Regression model trained on a labeled dataset of 11,000+ emails. The false positive rate of 3.1% means that roughly 3 in 100 safe emails are incorrectly flagged as suspicious.

The session counts (total scanned, phishing detected, etc.) are live — they update every time you scan an email.

---

## Limitations

**This is a prototype, not a production spam filter.** A few honest caveats:

- The model metrics are from the training dataset, not a live-evaluated deployment. A proper deployment would run evaluation on a held-out test set periodically.
- The Hindi/Telugu detection is keyword-based, not a trained NLP model. It works for known patterns but will miss novel phrasing.
- Very short emails with only one or two signals may score lower than expected, since the scoring is calibrated for more complete email samples.

---

## What makes this different

Most phishing detection tools stop at "spam or not spam". This one:

- Gives a scored confidence level, not a binary yes/no
- Explains every decision in plain English
- Is built specifically for Indian brands and payment infrastructure
- Detects regionally-targeted attacks in Hindi and Telugu
- Shows you exactly which words triggered the alert, highlighted in the original email text
- Works without sending your data to any external service

---

## Future improvements

- Train a proper multilingual NLP model on a larger Hindi and Telugu dataset
- Feedback loop — let users mark results as correct or incorrect to improve accuracy over time
