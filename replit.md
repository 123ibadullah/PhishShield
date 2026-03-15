# PhishShield AI

## Overview

Production-quality phishing email detection SaaS for Indian users. Built for national-level hackathon demo.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)
- **Frontend**: React + Vite, Tailwind CSS, Framer Motion, Lucide React

## Features

- Hybrid phishing detection: ML scoring + rule-based engine + URL analysis
- India-specific intelligence: SBI, HDFC, ICICI, UPI (Paytm/PhonePe/GPay) patterns
- Hindi/Telugu phishing phrase detection
- Real-time risk scoring (0-100) with Safe/Suspicious/Phishing classification
- Explainable AI with human-readable reasons
- Suspicious word highlighting in email text
- URL lookalike domain detection
- Preloaded demo emails for hackathon presentation
- Fully offline — no external APIs required

## Structure

```text
artifacts-monorepo/
├── artifacts/
│   ├── api-server/          # Express API server
│   │   └── src/lib/phishingDetector.ts  # Core detection engine
│   └── phishshield/         # React + Vite frontend (preview path: /)
├── lib/
│   ├── api-spec/            # OpenAPI spec + Orval codegen config
│   ├── api-client-react/    # Generated React Query hooks
│   ├── api-zod/             # Generated Zod schemas from OpenAPI
│   └── db/                  # Drizzle ORM schema + DB connection
```

## Key API Endpoints

- `GET /api/healthz` — Health check
- `POST /api/analyze` — Analyze email for phishing, returns risk score, classification, reasons, URL analysis, suspicious spans

## Detection Engine

The phishing detector (`artifacts/api-server/src/lib/phishingDetector.ts`) combines:
1. **ML Score** (35%): Naive Bayes-inspired term frequency scoring across urgency, financial, and social engineering word lists
2. **Rule Score** (40%): Pattern matching against urgency, financial scam, social engineering, and India-specific bank/service patterns
3. **URL Score** (25%): Domain analysis for suspicious TLDs, URL shorteners, lookalike patterns, parameter analysis

## Running

- API server: `pnpm --filter @workspace/api-server run dev`
- Frontend: `pnpm --filter @workspace/phishshield run dev`
- Codegen: `pnpm --filter @workspace/api-spec run codegen`
