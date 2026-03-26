import { AnalyzeEmailResponse } from "@workspace/api-zod";
import type { AnalyzeResult, UrlAnalysis, DetectionReason, SuspiciousSpan } from "@workspace/api-zod";
import { tfidfLRScore, type FeatureContribution } from "./tfidfModel";
import { analyzeEmailHeaders, type HeaderAnalysis } from "./emailHeaderParser";

// ─── Language detection ───────────────────────────────────────────────────────
// We check for Devanagari (Hindi) and Telugu Unicode ranges.
// If both appear in the same email it's a mixed-language message.
function detectLanguage(text: string): string {
  const hasHindi = /[\u0900-\u097F]/.test(text);
  const hasTelugu = /[\u0C00-\u0C7F]/.test(text);
  if (hasHindi && hasTelugu) return "mixed";
  if (hasHindi) return "hi";
  if (hasTelugu) return "te";
  return "en";
}

// ─── Keyword lists ────────────────────────────────────────────────────────────
// These feed both the rule-based scorer and the highlighted span finder.

const URGENCY_WORDS = [
  "urgent", "urgently", "immediately", "expire", "expires", "expiring", "expired",
  "block", "blocked", "suspend", "suspended", "suspension", "terminate", "terminated",
  "verify", "verification", "click now", "act now", "action required", "limited time",
  "24 hours", "48 hours", "hours left", "deadline", "final notice", "last chance",
  "confirm now", "update now", "validate", "reactivate", "restore access",
  "account locked", "account blocked", "account suspended", "password expired",
  // Hindi urgency words
  "तुरंत", "तत्काल", "जल्दी", "अभी", "बंद", "निलंबित",
];

const FINANCIAL_SCAM_WORDS = [
  "prize", "winner", "won", "reward", "cash prize", "lottery", "jackpot",
  "congratulations", "selected", "lucky draw", "free money", "claim",
  "rs.", "rs ", "rupees", "lakh", "crore", "₹", "upi", "paytm", "phonepe",
  "gpay", "google pay", "bhim", "neft", "rtgs", "wallet", "cashback",
  "refund pending", "kyc", "know your customer", "pan card", "aadhaar",
  "bank account", "credit card", "debit card", "otp", "one time password",
  "transaction failed", "payment pending", "transfer",
  // Hindi financial words
  "इनाम", "जीत", "पैसे", "बधाई", "रुपये",
];

const SOCIAL_ENGINEERING_WORDS = [
  "dear customer", "dear user", "dear member", "dear account holder",
  "your account", "your profile", "login credentials", "password",
  "click here", "click the link", "visit the link", "follow the link",
  "do not share", "do not disclose", "confidential", "security alert",
  "unauthorized access", "suspicious activity", "login attempt",
  "confirm your identity", "verify your identity", "prove your identity",
  "provide your", "enter your", "submit your", "update your",
  "failure to comply", "legal action", "court action", "police complaint",
];

// Indian banks and payment services — used for impersonation detection
const INDIA_SPECIFIC_BANKS = [
  "sbi", "state bank", "hdfc", "icici", "axis bank", "punjab national",
  "pnb", "bank of baroda", "bob", "canara bank", "union bank",
  "indian bank", "uco bank", "kotak", "yes bank", "indusind",
  "rbl bank", "idfc", "federal bank", "karnataka bank",
];

const INDIA_SPECIFIC_SERVICES = [
  "paytm", "phonepe", "phone pe", "gpay", "google pay", "bhim upi",
  "amazon pay", "mobikwik", "freecharge", "airtel payments",
  "jio payments", "ippb", "india post",
  "irctc", "uidai", "aadhaar", "pan", "epfo", "income tax",
  "gst", "eway bill", "itr", "form 16",
];

// TLDs that are free/abused and show up constantly in phishing campaigns
const SUSPICIOUS_TLDS = [
  ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
  ".top", ".club", ".online", ".site", ".icu", ".work",
  ".loan", ".click", ".link", ".info", ".biz",
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
  "short.io", "rebrand.ly", "cutt.ly", "tiny.cc", "bl.ink",
  "clk.sh", "is.gd", "v.gd",
];

// Regex patterns for lookalike domains (e.g. "sbi-secure-login.xyz")
const LOOKALIKE_PATTERNS: [RegExp, string][] = [
  [/paypa[l1]|payp4l/i, "PayPal lookalike domain"],
  [/g00gle|g0ogle|gooogle/i, "Google lookalike domain"],
  [/amaz0n|am4zon|amazzon/i, "Amazon lookalike domain"],
  [/faceb00k|f4cebook|faceb0ok/i, "Facebook lookalike domain"],
  [/sb[i1]-|sb[i1]\.|sbi-online|sbi_online/i, "SBI lookalike domain"],
  [/hdf[c0]-|hdfcbank-/i, "HDFC lookalike domain"],
  [/icic[i1]-|icicibankk/i, "ICICI lookalike domain"],
  [/payt[m0]-|paytrn/i, "Paytm lookalike domain"],
  [/ph0nepe|phonep3/i, "PhonePe lookalike domain"],
  [/[a-z]+-secure-|secure-[a-z]+\./i, "Fake 'secure' domain pattern"],
  [/[a-z]+-update\./i, "Fake 'update' domain pattern"],
  [/[a-z]+-verify\./i, "Fake 'verify' domain pattern"],
  [/[a-z]+-alert\./i, "Fake 'alert' domain pattern"],
  [/[a-z]+-kyc\./i, "Fake 'KYC' domain pattern"],
  [/[a-z]+-reward\./i, "Fake 'reward' domain pattern"],
  [/[a-z]+-claim\./i, "Fake 'claim' domain pattern"],
];

// ─── URL helpers ──────────────────────────────────────────────────────────────

function extractUrls(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+/gi;
  return text.match(urlRegex) || [];
}

function extractDomain(url: string): string {
  try {
    const normalized = url.startsWith("www.") ? "http://" + url : url;
    const parsed = new URL(normalized);
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    // If URL parsing fails, pull the hostname out manually
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^/\s?#]+)/i);
    return match ? match[1].toLowerCase() : url;
  }
}

function analyzeUrl(url: string): UrlAnalysis {
  const domain = extractDomain(url);
  const flags: string[] = [];
  let score = 0;

  const tld = "." + domain.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    flags.push(`Suspicious TLD: ${tld}`);
    score += 30;
  }

  if (URL_SHORTENERS.some(s => domain.includes(s))) {
    flags.push("URL shortener detected");
    score += 25;
  }

  // Lookalike domains — check each pattern and stop at first match
  for (const [pattern, label] of LOOKALIKE_PATTERNS) {
    if (pattern.test(domain)) {
      flags.push(label);
      score += 40;
      break;
    }
  }

  if (domain.split(".").length > 3) {
    flags.push("Suspicious subdomain structure");
    score += 15;
  }

  if (/[0-9]/.test(domain.split(".")[0])) {
    flags.push("Domain contains numbers (suspicious)");
    score += 10;
  }

  if (url.length > 100) {
    flags.push("Unusually long URL");
    score += 10;
  }

  if (/token=|session=|verify=|otp=|password=|pin=/i.test(url)) {
    flags.push("Sensitive parameters in URL");
    score += 20;
  }

  if (/secure|login|verify|account|update|confirm|kyc|claim|reward/i.test(domain)) {
    flags.push("Suspicious keyword in domain name");
    score += 15;
  }

  return {
    url,
    domain,
    riskScore: Math.min(score, 100),
    flags,
    isSuspicious: score >= 30,
  };
}

// ─── Suspicious span finder ───────────────────────────────────────────────────
// Finds character positions of matched keywords and URLs so the frontend
// can highlight them in the original email text.

function findSuspiciousSpans(text: string, matchedTerms: string[]): SuspiciousSpan[] {
  const spans: SuspiciousSpan[] = [];
  const lowerText = text.toLowerCase();

  for (const term of matchedTerms) {
    const lowerTerm = term.toLowerCase();
    let idx = 0;
    while (idx < lowerText.length) {
      const pos = lowerText.indexOf(lowerTerm, idx);
      if (pos === -1) break;
      spans.push({
        start: pos,
        end: pos + term.length,
        text: text.slice(pos, pos + term.length),
        reason: `Suspicious term: "${term}"`,
      });
      idx = pos + 1;
    }
  }

  // Also mark every URL found in the email
  for (const url of extractUrls(text)) {
    const pos = text.indexOf(url);
    if (pos !== -1) {
      spans.push({ start: pos, end: pos + url.length, text: url, reason: "URL detected" });
    }
  }

  // Sort and merge overlapping spans so we don't get double-highlights
  spans.sort((a, b) => a.start - b.start);
  const merged: SuspiciousSpan[] = [];
  for (const span of spans) {
    if (merged.length === 0 || span.start > merged[merged.length - 1].end) {
      merged.push(span);
    } else {
      const last = merged[merged.length - 1];
      if (span.end > last.end) {
        last.end = span.end;
        last.text = text.slice(last.start, last.end);
        last.reason = last.reason + "; " + span.reason;
      }
    }
  }

  return merged;
}

// ─── Rule-based scorer ────────────────────────────────────────────────────────
// Pattern matching against known phishing indicators.
// Returns a score (0–100), the human-readable reasons, and all matched terms.

function computeRuleScore(text: string): {
  score: number;
  reasons: DetectionReason[];
  allTerms: string[];
} {
  const lower = text.toLowerCase();
  const reasons: DetectionReason[] = [];
  const allTerms: string[] = [];
  let total = 0;

  const urgencyHits = URGENCY_WORDS.filter(w => lower.includes(w));
  if (urgencyHits.length > 0) {
    allTerms.push(...urgencyHits);
    const sev = urgencyHits.length >= 3 ? "high" : urgencyHits.length >= 2 ? "medium" : "low";
    reasons.push({
      category: "urgency",
      description: `This email is trying to rush you into action. Words like "urgent", "blocked", or "verify now" are a common tactic used to prevent you from pausing to check whether the message is genuine.`,
      severity: sev,
      matchedTerms: urgencyHits.slice(0, 6),
    });
    total += Math.min(15 + (urgencyHits.length - 1) * 10, 45);
  }

  const financialHits = FINANCIAL_SCAM_WORDS.filter(w => lower.includes(w));
  if (financialHits.length > 0) {
    allTerms.push(...financialHits);
    const sev = financialHits.length >= 4 ? "high" : financialHits.length >= 2 ? "medium" : "low";
    reasons.push({
      category: "financial",
      description: `The email references money, bank accounts, or digital payments. Scammers use financial language to grab your attention and exploit concerns about your account or wallet.`,
      severity: sev,
      matchedTerms: financialHits.slice(0, 6),
    });
    total += Math.min(15 + (financialHits.length - 1) * 8, 35);
  }

  const socialHits = SOCIAL_ENGINEERING_WORDS.filter(w => lower.includes(w));
  if (socialHits.length > 0) {
    allTerms.push(...socialHits);
    reasons.push({
      category: "social_engineering",
      description: `This email is written to sound like it comes from someone you should trust. Phrases like "Dear Customer" and "click here" are used to make the message feel personal and authoritative.`,
      severity: socialHits.length >= 3 ? "high" : "medium",
      matchedTerms: socialHits.slice(0, 6),
    });
    total += Math.min(10 + (socialHits.length - 1) * 7, 30);
  }

  const bankHits = INDIA_SPECIFIC_BANKS.filter(b => lower.includes(b));
  const serviceHits = INDIA_SPECIFIC_SERVICES.filter(s => lower.includes(s));
  if (bankHits.length > 0 || serviceHits.length > 0) {
    const terms = [...bankHits, ...serviceHits];
    allTerms.push(...terms);
    // Only flag brand impersonation if there are other risk signals too
    if (total > 8) {
      reasons.push({
        category: "india_specific",
        description: `The sender appears to be impersonating a well-known Indian bank or payment platform. Scammers frequently clone real brands to appear legitimate — your actual bank will never ask for credentials over email.`,
        severity: "high",
        matchedTerms: terms.slice(0, 6),
      });
      total += 25;
    }
  }

  const hindiScamWords = ["तुरंत", "जल्दी", "अभी", "बंद", "इनाम", "बधाई", "रुपये", "पैसे", "खाता", "सत्यापन"];
  const hindiHits = hindiScamWords.filter(w => text.includes(w));
  if (hindiHits.length > 0) {
    allTerms.push(...hindiHits);
    reasons.push({
      category: "language",
      description: `This message contains Hindi words that commonly appear in regionally targeted phishing. Scammers use local language to make the email feel more familiar and trustworthy to Indian readers.`,
      severity: "medium",
      matchedTerms: hindiHits,
    });
    total += hindiHits.length * 8;
  }

  return {
    score: Math.min(total, 100),
    reasons,
    allTerms: [...new Set(allTerms)],
  };
}

// ─── Main export ──────────────────────────────────────────────────────────────

export function analyzeEmail(emailText: string): AnalyzeResult {
  // Empty input — return a neutral safe result
  if (!emailText || emailText.trim().length === 0) {
    return {
      riskScore: 0,
      classification: "safe",
      confidence: 1.0,
      detectedLanguage: "en",
      reasons: [],
      suspiciousSpans: [],
      urlAnalyses: [],
      safetyTips: ["Always verify sender email addresses before clicking any links."],
      warnings: [],
      mlScore: 0,
      ruleScore: 0,
      urlScore: 0,
      headerScore: 0,
      featureImportance: [],
    };
  }

  // Run all three subsystems in parallel (synchronously)
  const { score: mlScore, topFeatures } = tfidfLRScore(emailText);
  const headerAnalysis: HeaderAnalysis = analyzeEmailHeaders(emailText);
  const { score: ruleScore, reasons, allTerms } = computeRuleScore(emailText);

  // URL analysis — score is weighted max+avg to avoid one bad link dominating
  const urls = extractUrls(emailText);
  const urlAnalyses = urls.map(analyzeUrl);

  let urlScore = 0;
  if (urlAnalyses.length > 0) {
    const maxScore = Math.max(...urlAnalyses.map(u => u.riskScore));
    const avgScore = urlAnalyses.reduce((s, u) => s + u.riskScore, 0) / urlAnalyses.length;
    urlScore = Math.round(maxScore * 0.7 + avgScore * 0.3);
  }

  // Add URL-based reason if any link looks suspicious
  const suspiciousUrls = urlAnalyses.filter(u => u.isSuspicious);
  if (suspiciousUrls.length > 0) {
    const allFlags = suspiciousUrls.flatMap(u => u.flags);
    reasons.push({
      category: "url",
      description: suspiciousUrls.length === 1
        ? `We found a link in this email that looks suspicious. Clicking it may take you to a fake website designed to steal your information or credentials.`
        : `We found ${suspiciousUrls.length} links in this email that look suspicious. These may redirect to fake websites designed to steal information or install malware.`,
      severity: suspiciousUrls.some(u => u.riskScore >= 60) ? "high" : "medium",
      matchedTerms: [...new Set(allFlags)].slice(0, 5),
    });
  }

  // Add header-based reason if spoofing was detected
  const headerScore = headerAnalysis.headerScore;
  if (headerScore > 0 && headerAnalysis.issues.length > 0) {
    reasons.push({
      category: "header",
      description: headerAnalysis.issues[0],
      severity: headerScore >= 60 ? "high" : headerScore >= 30 ? "medium" : "low",
      matchedTerms: headerAnalysis.issues.slice(1, 4),
    });
  }

  // Fallback reason if nothing specific was caught (ML still had a signal)
  if (urls.length === 0 && reasons.length === 0) {
    reasons.push({
      category: "ml_score",
      description: mlScore > 30
        ? "Moderate phishing indicators in email content"
        : "No significant phishing indicators found",
      severity: mlScore > 60 ? "high" : mlScore > 30 ? "medium" : "low",
      matchedTerms: [],
    });
  }

  // Weighted combination: ML 25% + Rules 38% + URLs 22% + Headers 15%
  const baseScore = Math.round(mlScore * 0.25 + ruleScore * 0.38 + urlScore * 0.22 + headerScore * 0.15);

  // Bonus points when multiple high-risk signals appear together
  // (urgency + suspicious link is much worse than either alone)
  const hasUrgency = reasons.some(r => r.category === "urgency");
  const hasSuspiciousUrl = suspiciousUrls.length > 0;
  const hasFinancial = reasons.some(r => r.category === "financial");
  const hasImpersonation = reasons.some(r => r.category === "india_specific");

  let bonus = 0;
  if (hasUrgency && hasSuspiciousUrl) bonus += 20;
  if (hasSuspiciousUrl && hasFinancial) bonus += 20;
  if (hasImpersonation && hasUrgency) bonus += 15;
  if (hasUrgency && hasSuspiciousUrl && hasFinancial) bonus += 10;

  const finalScore = Math.min(baseScore + bonus, 100);

  // Classify and compute confidence
  let classification: "safe" | "suspicious" | "phishing";
  let confidence: number;

  if (finalScore >= 71) {
    classification = "phishing";
    confidence = 0.5 + finalScore / 200;
  } else if (finalScore >= 31) {
    classification = "suspicious";
    confidence = 0.5 + Math.abs(finalScore - 31) / 80;
  } else {
    classification = "safe";
    confidence = 0.5 + (31 - finalScore) / 62;
  }
  confidence = Math.min(Math.round(confidence * 100) / 100, 0.99);

  // User-facing warnings — only shown for risky emails
  const warnings: string[] = [];
  if (classification === "phishing") {
    warnings.push("Do not click any links or reply to this email. This appears to be a phishing attempt.");
    if (suspiciousUrls.length > 0) {
      warnings.push("The links in this email lead to suspicious domains — not the real websites they claim to be.");
    }
    warnings.push("If you think your account may actually be at risk, contact the organization directly using their official number or website.");
  } else if (classification === "suspicious") {
    warnings.push("This email has some unusual patterns. Verify that it is genuine before clicking any links or sharing any information.");
    warnings.push("If in doubt, contact the sender through a different channel — phone or official website — before acting.");
  }

  const safetyTips = [
    "Verify the sender's email address carefully — scammers use lookalike addresses",
    "Never share OTP, PIN, password, or Aadhaar/PAN details over email",
    "Your bank (SBI, HDFC, ICICI etc.) will NEVER ask for account details via email",
    "Call the official helpline to confirm any urgent bank/UPI requests",
    "Hover over links to see the real destination before clicking",
    "Enable 2-factor authentication on all financial accounts",
    "Report phishing emails to cybercrime.gov.in",
  ];

  const suspiciousSpans = findSuspiciousSpans(emailText, allTerms.slice(0, 30));
  const detectedLanguage = detectLanguage(emailText);

  const featureImportance = topFeatures.map((f: FeatureContribution) => ({
    feature: f.feature,
    contribution: f.contribution,
    direction: f.direction,
  }));

  return AnalyzeEmailResponse.parse({
    riskScore: finalScore,
    classification,
    confidence,
    detectedLanguage,
    reasons,
    suspiciousSpans,
    urlAnalyses,
    safetyTips,
    warnings,
    mlScore,
    ruleScore,
    urlScore,
    headerScore,
    featureImportance,
    headerAnalysis: headerAnalysis.hasHeaders ? {
      hasHeaders: true,
      senderEmail: headerAnalysis.senderEmail,
      senderDomain: headerAnalysis.senderDomain,
      displayName: headerAnalysis.displayName,
      replyToEmail: headerAnalysis.replyToEmail,
      replyToDomain: headerAnalysis.replyToDomain,
      mismatch: headerAnalysis.mismatch,
      spoofingRisk: headerAnalysis.spoofingRisk,
      issues: headerAnalysis.issues,
      headerScore: headerAnalysis.headerScore,
    } : undefined,
  });
}
