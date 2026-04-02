# PhishShield AI

## Overview

Production-quality phishing email detection SaaS for Indian users. Built for national-level hackathon demo.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: SQLite (libSQL) + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)
- **Frontend**: React + Vite, Tailwind CSS, Framer Motion, Recharts, Lucide React

## Completed Features

- **Real TF-IDF + Logistic Regression ML engine** — 120-term vocabulary with pre-calibrated IDF/LR weights, sigmoid activation, top-8 feature contributions for explainability
- **Email header spoofing detection** — parses From/Reply-To/Return-Path headers, detects domain mismatch, freemail impersonation, suspicious TLDs, ALL-CAPS subjects, X-Spam flags
- **ML Feature Contributions UI** — horizontal bar chart showing which vocabulary terms drove the ML score (red=phishing, green=safe), with TF-IDF × LR weight magnitude
- **Email Header Analysis panel** — shows sender, display name, Reply-To with mismatch badge, spoofing risk level, detailed issue descriptions
- **4-component score breakdown** — ML Analysis (25%), Pattern Matching (38%), Link Risk (22%), Header Risk (15%)
- **SQLite history persistence** — scan history survives page refresh and is stored permanently on the backend in SQLite; frontend also caches up to 20 entries in localStorage
- India-specific intelligence: SBI, HDFC, ICICI, UPI (Paytm/PhonePe/GPay) patterns + Hindi/Telugu detection
- Real-time risk scoring (0-100) with Safe/Suspicious/Phishing classification thresholds (0-30/31-70/71-100)
- Explainable AI with human-readable reasons, severity levels, suspicious word highlighting
- URL lookalike domain detection (suspicious TLDs, URL shorteners, typosquatting patterns)
- 7 preloaded demo emails including a header-spoofed HDFC sample
- Fully offline — no external APIs required
- Dashboard: model metrics (accuracy/precision/recall/F1/FPR) + session scan history + risk distribution chart

## Structure

```text
artifacts-monorepo/
├── artifacts/
│   ├── api-server/          # Express API server (port 8080)
│   │   └── src/lib/
│   │       ├── phishingDetector.ts   # Core detection engine (4-component scoring)
│   │       ├── tfidfModel.ts         # TF-IDF + Logistic Regression classifier
│   │       └── emailHeaderParser.ts  # Email header parser + spoofing detector
│   └── phishshield/         # React + Vite frontend (preview path: /)
├── lib/
│   ├── api-spec/            # OpenAPI spec + Orval codegen config
│   ├── api-client-react/    # Generated React Query hooks
│   ├── api-zod/             # Generated Zod schemas from OpenAPI
│   └── db/                  # Drizzle ORM schema + DB connection
```

## Key API Endpoints

- `GET /api/healthz` — Health check
- `POST /api/analyze` — Analyze email; returns riskScore, classification, detectedLanguage, reasons, urlAnalyses, suspiciousSpans, featureImportance[], headerAnalysis
- `GET /api/history` — Last 50 scans this session (SQLite DB)
- `DELETE /api/history` — Clear scan history
- `GET /api/metrics` — Model metrics (accuracy/precision/recall/F1/FPR) + session counts

## Detection Engine

Four scoring components combined in `phishingDetector.ts`:

1. **ML Score** (25%) — `tfidfLRScore()` in `tfidfModel.ts`: TF-IDF vectorization + logistic regression dot product with sigmoid, 120-term vocabulary, bias=-2.5; returns score 0-100 + top-8 FeatureContribution[]
2. **Rule Score** (38%) — Pattern matching against urgency, financial scam, social engineering, India-specific bank/service, and Hindi urgency word lists
3. **URL Score** (22%) — Domain analysis: suspicious TLDs, URL shorteners, lookalike patterns (sbi-secure.xyz, hdfc-kyc.ml etc.), parameter analysis
4. **Header Score** (15%) — `analyzeEmailHeaders()` in `emailHeaderParser.ts`: From/Reply-To mismatch, freemail impersonation, suspicious TLD in sender domain, X-Spam flags, subject line signals

Combination boosters apply when multiple strong signals co-occur (urgency + suspicious URL = +20 bonus points).

## Running

- API server: `pnpm --filter @workspace/api-server run dev`
- Frontend: `pnpm --filter @workspace/phishshield run dev`
- Codegen (after OpenAPI changes): `pnpm --filter @workspace/api-spec run codegen`
