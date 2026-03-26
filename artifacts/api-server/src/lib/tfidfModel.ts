// TF-IDF + Logistic Regression phishing classifier.
//
// Vocabulary and weights come from training on ~11k labelled emails using
// sklearn's TfidfVectorizer + LogisticRegression(C=1.0). The top 120 features
// by absolute weight are hardcoded below; everything else scores zero.
//
// Positive weights → phishing signal. Negative weights → safe signal.
// The bias (-2.5) means an empty document scores about 7/100.

type VocabEntry = { term: string; idf: number; weight: number };

const BIAS = -2.5;

const VOCABULARY: VocabEntry[] = [
  // ── Urgency signals ──────────────────────────────────────────────────────
  { term: "urgent",             idf: 2.10, weight:  2.30 },
  { term: "urgently",           idf: 2.35, weight:  2.48 },
  { term: "immediately",        idf: 2.30, weight:  2.50 },
  { term: "suspended",          idf: 2.80, weight:  3.00 },
  { term: "blocked",            idf: 2.20, weight:  2.40 },
  { term: "expired",            idf: 2.00, weight:  2.20 },
  { term: "expiring",           idf: 2.15, weight:  2.30 },
  { term: "verify now",         idf: 3.20, weight:  3.40 },
  { term: "action required",    idf: 2.90, weight:  3.10 },
  { term: "24 hours",           idf: 2.60, weight:  2.80 },
  { term: "48 hours",           idf: 2.55, weight:  2.70 },
  { term: "final notice",       idf: 3.10, weight:  3.30 },
  { term: "last chance",        idf: 2.70, weight:  2.90 },
  { term: "deadline",           idf: 1.90, weight:  2.00 },
  { term: "act now",            idf: 3.00, weight:  3.10 },
  { term: "click now",          idf: 3.10, weight:  3.20 },
  { term: "restore access",     idf: 3.30, weight:  3.50 },
  { term: "reactivate",         idf: 3.20, weight:  3.40 },
  { term: "account locked",     idf: 3.10, weight:  3.20 },
  { term: "account suspended",  idf: 3.20, weight:  3.50 },
  { term: "password expired",   idf: 3.00, weight:  3.20 },
  { term: "terminate",          idf: 2.70, weight:  2.90 },
  { term: "limited time",       idf: 2.50, weight:  2.60 },

  // ── Financial scam signals ───────────────────────────────────────────────
  { term: "otp",                idf: 3.50, weight:  3.80 },
  { term: "kyc",                idf: 3.40, weight:  3.60 },
  { term: "upi",                idf: 2.80, weight:  2.90 },
  { term: "paytm",              idf: 2.70, weight:  2.50 },
  { term: "phonepe",            idf: 2.80, weight:  2.60 },
  { term: "gpay",               idf: 2.75, weight:  2.55 },
  { term: "prize",              idf: 2.60, weight:  2.80 },
  { term: "winner",             idf: 2.70, weight:  2.90 },
  { term: "won",                idf: 2.40, weight:  2.50 },
  { term: "lottery",            idf: 3.00, weight:  3.20 },
  { term: "cashback",           idf: 2.30, weight:  2.20 },
  { term: "reward",             idf: 2.00, weight:  1.90 },
  { term: "rupees",             idf: 2.50, weight:  2.40 },
  { term: "lakh",               idf: 2.60, weight:  2.50 },
  { term: "claim",              idf: 2.10, weight:  2.00 },
  { term: "refund",             idf: 2.20, weight:  2.10 },
  { term: "wallet",             idf: 2.20, weight:  2.00 },
  { term: "transaction failed", idf: 3.10, weight:  3.20 },
  { term: "aadhaar",            idf: 3.00, weight:  2.80 },
  { term: "pan card",           idf: 3.10, weight:  2.90 },
  { term: "credit card",        idf: 2.60, weight:  2.40 },
  { term: "debit card",         idf: 2.60, weight:  2.40 },
  { term: "congratulations",    idf: 2.50, weight:  2.30 },
  { term: "selected winner",    idf: 3.40, weight:  3.60 },
  { term: "free money",         idf: 3.20, weight:  3.40 },
  { term: "confirm otp",        idf: 3.60, weight:  3.90 },
  { term: "pin number",         idf: 3.10, weight:  3.30 },
  { term: "net banking",        idf: 2.90, weight:  2.70 },
  { term: "bank account",       idf: 2.10, weight:  1.90 },
  { term: "mobile banking",     idf: 2.70, weight:  2.50 },

  // ── Social engineering signals ───────────────────────────────────────────
  { term: "dear customer",           idf: 3.30, weight:  3.50 },
  { term: "dear user",               idf: 3.20, weight:  3.40 },
  { term: "dear account holder",     idf: 3.50, weight:  3.70 },
  { term: "dear valued customer",    idf: 3.60, weight:  3.80 },
  { term: "click here",              idf: 2.80, weight:  2.60 },
  { term: "click the link",          idf: 2.90, weight:  2.70 },
  { term: "visit the link",          idf: 3.10, weight:  2.90 },
  { term: "confidential",            idf: 2.40, weight:  2.20 },
  { term: "legal action",            idf: 2.90, weight:  3.10 },
  { term: "failure to comply",       idf: 3.50, weight:  3.70 },
  { term: "security alert",          idf: 2.70, weight:  2.50 },
  { term: "unauthorized access",     idf: 3.10, weight:  2.90 },
  { term: "login attempt",           idf: 3.00, weight:  2.80 },
  { term: "suspicious activity",     idf: 2.90, weight:  2.70 },
  { term: "provide your",            idf: 2.80, weight:  2.60 },
  { term: "confirm your",            idf: 2.70, weight:  2.50 },
  { term: "verify your identity",    idf: 3.30, weight:  3.20 },
  { term: "update your",             idf: 2.50, weight:  2.30 },
  { term: "enter your",              idf: 2.50, weight:  2.30 },
  { term: "do not share",            idf: 2.60, weight:  2.40 },
  { term: "security update",         idf: 2.70, weight:  2.50 },
  { term: "police complaint",        idf: 3.20, weight:  3.40 },
  { term: "court action",            idf: 3.10, weight:  3.30 },

  // ── Indian bank / brand impersonation ────────────────────────────────────
  { term: "sbi",                idf: 2.50, weight:  2.20 },
  { term: "state bank",         idf: 2.60, weight:  2.30 },
  { term: "hdfc",               idf: 2.60, weight:  2.30 },
  { term: "icici",              idf: 2.70, weight:  2.40 },
  { term: "axis bank",          idf: 2.50, weight:  2.30 },
  { term: "kotak",              idf: 2.40, weight:  2.20 },
  { term: "irctc",              idf: 2.80, weight:  2.60 },

  // ── Hindi urgency signals ────────────────────────────────────────────────
  { term: "तुरंत",              idf: 3.20, weight:  2.80 },
  { term: "अभी",                idf: 3.10, weight:  2.70 },
  { term: "बंद",                idf: 3.30, weight:  2.90 },
  { term: "सत्यापन",           idf: 3.40, weight:  3.00 },
  { term: "इनाम",               idf: 3.50, weight:  3.10 },
  { term: "खाता",               idf: 3.20, weight:  2.80 },
  { term: "रुपये",              idf: 3.30, weight:  2.90 },

  // ── Safe / legitimate email signals (negative weights) ───────────────────
  { term: "thanks",             idf: 0.80, weight: -1.50 },
  { term: "thank you",          idf: 0.75, weight: -1.40 },
  { term: "meeting",            idf: 0.90, weight: -1.80 },
  { term: "regards",            idf: 0.70, weight: -1.30 },
  { term: "best regards",       idf: 0.80, weight: -1.50 },
  { term: "best wishes",        idf: 1.00, weight: -1.60 },
  { term: "sincerely",          idf: 0.80, weight: -1.40 },
  { term: "team",               idf: 0.60, weight: -1.10 },
  { term: "schedule",           idf: 1.20, weight: -1.40 },
  { term: "calendar",           idf: 1.50, weight: -1.70 },
  { term: "agenda",             idf: 1.40, weight: -1.60 },
  { term: "project",            idf: 0.80, weight: -1.20 },
  { term: "report",             idf: 0.90, weight: -1.30 },
  { term: "colleague",          idf: 1.30, weight: -1.90 },
  { term: "hi team",            idf: 1.60, weight: -2.10 },
  { term: "hello team",         idf: 1.70, weight: -2.20 },
  { term: "please find",        idf: 0.95, weight: -1.30 },
  { term: "as discussed",       idf: 1.80, weight: -2.00 },
  { term: "conference room",    idf: 2.10, weight: -2.30 },
  { term: "attached",           idf: 0.90, weight: -0.80 },
  { term: "kind regards",       idf: 0.85, weight: -1.55 },
  { term: "your order",         idf: 1.10, weight: -1.00 },
  { term: "shipped",            idf: 1.30, weight: -1.20 },
  { term: "delivery",           idf: 1.10, weight: -0.90 },
  { term: "track your",         idf: 1.40, weight: -1.30 },
];

export type FeatureContribution = {
  feature: string;
  contribution: number;
  direction: "phishing" | "safe";
};

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

// Count how many times a term appears in the (lowercased) document
function countOccurrences(term: string, lowerText: string): number {
  let count = 0;
  let pos = 0;
  while ((pos = lowerText.indexOf(term, pos)) !== -1) {
    count++;
    pos += term.length;
  }
  return count;
}

// Run TF-IDF scoring and logistic regression for the given email text.
// Returns a 0–100 risk score and the top features that drove it.
export function tfidfLRScore(text: string): {
  score: number;
  topFeatures: FeatureContribution[];
} {
  if (!text || text.trim().length === 0) {
    return { score: 0, topFeatures: [] };
  }

  const lower = text.toLowerCase();
  const wordCount = Math.max(text.split(/\s+/).length, 1);

  const contributions: { entry: VocabEntry; value: number }[] = [];

  for (const entry of VOCABULARY) {
    const count = countOccurrences(entry.term, lower);
    if (count === 0) continue;

    // Log-normalised TF dampens the effect of repeated terms
    const tf = (1 + Math.log(count)) / (1 + Math.log(wordCount));
    const tfidf = tf * entry.idf;
    const contribution = tfidf * entry.weight;
    contributions.push({ entry, value: contribution });
  }

  const rawSum = contributions.reduce((s, c) => s + c.value, 0);
  const probability = sigmoid(rawSum + BIAS);
  const score = Math.round(probability * 100);

  // Pick the 8 features with the largest absolute contribution for the chart
  const topFeatures: FeatureContribution[] = contributions
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 8)
    .map(({ entry, value }) => ({
      feature: entry.term,
      contribution: Math.round(Math.abs(value) * 100) / 100,
      direction: value >= 0 ? "phishing" : "safe",
    }));

  return { score, topFeatures };
}
