import { AnalyzeEmailResponse } from "@workspace/api-zod";
import type { AnalyzeResult, UrlAnalysis, DetectionReason, SuspiciousSpan } from "@workspace/api-zod";
import { tfidfLRScore, FeatureContribution } from "./tfidfModel";
import { analyzeEmailHeaders, HeaderAnalysis } from "./emailHeaderParser";

type UrlAnalysisType = UrlAnalysis;
type DetectionReasonType = DetectionReason;
type SuspiciousSpanType = SuspiciousSpan;

function detectLanguage(text: string): string {
  const devanagariRange = /[\u0900-\u097F]/;
  const teluguRange = /[\u0C00-\u0C7F]/;
  const hasHindi = devanagariRange.test(text);
  const hasTelugu = teluguRange.test(text);
  if (hasHindi && hasTelugu) return "mixed";
  if (hasHindi) return "hi";
  if (hasTelugu) return "te";
  return "en";
}

const URGENCY_WORDS = [
  "urgent", "urgently", "immediately", "expire", "expires", "expiring", "expired",
  "block", "blocked", "suspend", "suspended", "suspension", "terminate", "terminated",
  "verify", "verification", "click now", "act now", "action required", "limited time",
  "24 hours", "48 hours", "hours left", "deadline", "final notice", "last chance",
  "confirm now", "update now", "validate", "reactivate", "restore access",
  "account locked", "account blocked", "account suspended", "password expired",
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

function extractUrls(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+/gi;
  return text.match(urlRegex) || [];
}

function extractDomain(url: string): string {
  try {
    const u = url.startsWith("www.") ? "http://" + url : url;
    const parsed = new URL(u);
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^/\s?#]+)/i);
    return match ? match[1].toLowerCase() : url;
  }
}

function analyzeUrl(url: string): UrlAnalysisType {
  const domain = extractDomain(url);
  const flags: string[] = [];
  let score = 0;

  const tld = "." + domain.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    flags.push(`Suspicious TLD: ${tld}`);
    score += 30;
  }

  if (URL_SHORTENERS.some((s) => domain.includes(s))) {
    flags.push("URL shortener detected");
    score += 25;
  }

  for (const [pattern, label] of LOOKALIKE_PATTERNS) {
    if (pattern.test(domain)) {
      flags.push(label);
      score += 40;
      break;
    }
  }

  const domainParts = domain.split(".");
  if (domainParts.length > 3) {
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

  score = Math.min(score, 100);

  return {
    url,
    domain,
    riskScore: score,
    flags,
    isSuspicious: score >= 30,
  };
}

function findSuspiciousSpans(text: string, matchedTerms: string[]): SuspiciousSpanType[] {
  const spans: SuspiciousSpanType[] = [];
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

  const urls = extractUrls(text);
  for (const url of urls) {
    const pos = text.indexOf(url);
    if (pos !== -1) {
      spans.push({
        start: pos,
        end: pos + url.length,
        text: url,
        reason: "URL detected",
      });
    }
  }

  spans.sort((a, b) => a.start - b.start);
  const merged: SuspiciousSpanType[] = [];
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

function computeMLScore(text: string): number {
  const lowerText = text.toLowerCase();
  let score = 0;
  const wordCount = text.split(/\s+/).length;

  let urgencyHits = 0;
  for (const w of URGENCY_WORDS) {
    if (lowerText.includes(w)) urgencyHits++;
  }

  let financialHits = 0;
  for (const w of FINANCIAL_SCAM_WORDS) {
    if (lowerText.includes(w)) financialHits++;
  }

  let socialHits = 0;
  for (const w of SOCIAL_ENGINEERING_WORDS) {
    if (lowerText.includes(w)) socialHits++;
  }

  const urgencyRatio = urgencyHits / URGENCY_WORDS.length;
  const financialRatio = financialHits / FINANCIAL_SCAM_WORDS.length;
  const socialRatio = socialHits / SOCIAL_ENGINEERING_WORDS.length;

  score = urgencyRatio * 0.35 + financialRatio * 0.40 + socialRatio * 0.25;

  if (wordCount < 20 && (urgencyHits > 0 || financialHits > 0)) {
    score = Math.min(score * 1.3, 1.0);
  }

  const exclamationCount = (text.match(/!/g) || []).length;
  if (exclamationCount > 2) score = Math.min(score + 0.05 * exclamationCount, 1.0);

  const capsRatio = (text.match(/[A-Z]/g) || []).length / Math.max(text.length, 1);
  if (capsRatio > 0.3) score = Math.min(score + 0.1, 1.0);

  return Math.round(score * 100);
}

function computeRuleScore(text: string): { score: number; reasons: DetectionReasonType[]; allTerms: string[] } {
  const lowerText = text.toLowerCase();
  const reasons: DetectionReasonType[] = [];
  const allMatchedTerms: string[] = [];
  let totalScore = 0;

  const urgencyMatched = URGENCY_WORDS.filter((w) => lowerText.includes(w));
  if (urgencyMatched.length > 0) {
    allMatchedTerms.push(...urgencyMatched);
    const sev = urgencyMatched.length >= 3 ? "high" : urgencyMatched.length >= 2 ? "medium" : "low";
    reasons.push({
      category: "urgency",
      description: `This email is trying to rush you into action. Words like "urgent", "blocked", or "verify now" are a common tactic used to prevent you from pausing to check whether the message is genuine.`,
      severity: sev,
      matchedTerms: urgencyMatched.slice(0, 6),
    });
    totalScore += Math.min(15 + (urgencyMatched.length - 1) * 10, 45);
  }

  const financialMatched = FINANCIAL_SCAM_WORDS.filter((w) => lowerText.includes(w));
  if (financialMatched.length > 0) {
    allMatchedTerms.push(...financialMatched);
    const sev = financialMatched.length >= 4 ? "high" : financialMatched.length >= 2 ? "medium" : "low";
    reasons.push({
      category: "financial",
      description: `The email references money, bank accounts, or digital payments. Scammers use financial language to grab your attention and exploit concerns about your account or wallet.`,
      severity: sev,
      matchedTerms: financialMatched.slice(0, 6),
    });
    totalScore += Math.min(15 + (financialMatched.length - 1) * 8, 35);
  }

  const socialMatched = SOCIAL_ENGINEERING_WORDS.filter((w) => lowerText.includes(w));
  if (socialMatched.length > 0) {
    allMatchedTerms.push(...socialMatched);
    const sev = socialMatched.length >= 3 ? "high" : "medium";
    reasons.push({
      category: "social_engineering",
      description: `This email is written to sound like it comes from someone you should trust. Phrases like "Dear Customer" and "click here" are used to make the message feel personal and authoritative.`,
      severity: sev,
      matchedTerms: socialMatched.slice(0, 6),
    });
    totalScore += Math.min(10 + (socialMatched.length - 1) * 7, 30);
  }

  const bankMatched = INDIA_SPECIFIC_BANKS.filter((b) => lowerText.includes(b));
  const serviceMatched = INDIA_SPECIFIC_SERVICES.filter((s) => lowerText.includes(s));
  if (bankMatched.length > 0 || serviceMatched.length > 0) {
    const terms = [...bankMatched, ...serviceMatched];
    allMatchedTerms.push(...terms);
    if (totalScore > 8) {
      reasons.push({
        category: "india_specific",
        description: `The sender appears to be impersonating a well-known Indian bank or payment platform. Scammers frequently clone real brands to appear legitimate — your actual bank will never ask for credentials over email.`,
        severity: "high",
        matchedTerms: terms.slice(0, 6),
      });
      totalScore += 25;
    }
  }

  const hindiUrduPatterns = ["तुरंत", "जल्दी", "अभी", "बंद", "इनाम", "बधाई", "रुपये", "पैसे", "खाता", "सत्यापन"];
  const hindiMatched = hindiUrduPatterns.filter((w) => text.includes(w));
  if (hindiMatched.length > 0) {
    allMatchedTerms.push(...hindiMatched);
    reasons.push({
      category: "language",
      description: `This message contains Hindi words that commonly appear in regionally targeted phishing. Scammers use local language to make the email feel more familiar and trustworthy to Indian readers.`,
      severity: "medium",
      matchedTerms: hindiMatched,
    });
    totalScore += hindiMatched.length * 8;
  }

  return { score: Math.min(totalScore, 100), reasons, allTerms: [...new Set(allMatchedTerms)] };
}

export function analyzeEmail(emailText: string): AnalyzeResult {
  if (!emailText || emailText.trim().length === 0) {
    return {
      riskScore: 0,
      classification: "safe",
      confidence: 1.0,
      detectedLanguage: "english",
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

  const { score: mlScore, topFeatures } = tfidfLRScore(emailText);
  const headerAnalysis = analyzeEmailHeaders(emailText);
  const { score: ruleScore, reasons: ruleReasons, allTerms } = computeRuleScore(emailText);

  const urls = extractUrls(emailText);
  const urlAnalyses = urls.map(analyzeUrl);

  let urlScore = 0;
  if (urlAnalyses.length > 0) {
    const maxUrlScore = Math.max(...urlAnalyses.map((u) => u.riskScore));
    const avgUrlScore = urlAnalyses.reduce((s, u) => s + u.riskScore, 0) / urlAnalyses.length;
    urlScore = Math.round(maxUrlScore * 0.7 + avgUrlScore * 0.3);
  }

  const suspiciousUrls = urlAnalyses.filter((u) => u.isSuspicious);
  const allUrlFlags = suspiciousUrls.flatMap((u) => u.flags);

  if (suspiciousUrls.length > 0) {
    ruleReasons.push({
      category: "url",
      description: suspiciousUrls.length === 1
        ? `We found a link in this email that looks suspicious. Clicking it may take you to a fake website designed to steal your information or credentials.`
        : `We found ${suspiciousUrls.length} links in this email that look suspicious. These may redirect to fake websites designed to steal information or install malware.`,
      severity: suspiciousUrls.some((u) => u.riskScore >= 60) ? "high" : "medium",
      matchedTerms: [...new Set(allUrlFlags)].slice(0, 5),
    });
  }

  // Header-based detection reason
  const headerScore = headerAnalysis.headerScore;
  if (headerScore > 0 && headerAnalysis.issues.length > 0) {
    ruleReasons.push({
      category: "header",
      description: headerAnalysis.issues[0],
      severity: headerScore >= 60 ? "high" : headerScore >= 30 ? "medium" : "low",
      matchedTerms: headerAnalysis.issues.slice(1, 4),
    });
  }

  if (urls.length === 0 && ruleReasons.length === 0) {
    ruleReasons.push({
      category: "ml_score",
      description: mlScore > 30 ? "Moderate phishing indicators in email content" : "No significant phishing indicators found",
      severity: mlScore > 60 ? "high" : mlScore > 30 ? "medium" : "low",
      matchedTerms: [],
    });
  }

  const combinedScore = Math.round(
    mlScore * 0.25 + ruleScore * 0.38 + urlScore * 0.22 + headerScore * 0.15
  );

  // Combination boosters — multiple strong signals together are far more dangerous
  const hasUrgency = ruleReasons.some((r) => r.category === "urgency");
  const hasSuspiciousUrl = suspiciousUrls.length > 0;
  const hasFinancial = ruleReasons.some((r) => r.category === "financial");
  const hasImpersonation = ruleReasons.some((r) => r.category === "india_specific");

  let bonusScore = 0;
  if (hasUrgency && hasSuspiciousUrl) bonusScore += 20;
  if (hasSuspiciousUrl && hasFinancial) bonusScore += 20;
  if (hasImpersonation && hasUrgency) bonusScore += 15;
  if (hasUrgency && hasSuspiciousUrl && hasFinancial) bonusScore += 10;

  const finalScore = Math.min(combinedScore + bonusScore, 100);

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

  const warnings: string[] = [];
  if (classification === "phishing") {
    warnings.push("Do not click any links or reply to this email. This appears to be a phishing attempt.");
    if (suspiciousUrls.length > 0) warnings.push("The links in this email lead to suspicious domains — not the real websites they claim to be.");
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
    reasons: ruleReasons,
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
      hasHeaders: headerAnalysis.hasHeaders,
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
