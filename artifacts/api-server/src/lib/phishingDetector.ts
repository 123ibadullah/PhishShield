import { AnalyzeEmailResponse } from "@workspace/api-zod";
import type {
  AnalyzeResult,
  UrlAnalysis,
  DetectionReason,
  SuspiciousSpan,
} from "@workspace/api-zod";
import { hybridScore, type FeatureContribution } from "./transformerModel.js";
import { analyzeEmailHeaders, type HeaderAnalysis } from "./emailHeaderParser";

// ─── Modular Engine Imports ───────────────────────────────────────────────────
import { analyzeIntent } from "../engines/intentEngine";
import { analyzeTrust } from "../engines/trustEngine";
import { analyzeDomainIntel } from "../engines/domainEngine";
import { analyzeBehavior } from "../engines/behaviorEngine";
import { makeDecision } from "../engines/decisionEngine";
import { generateExplanation } from "../engines/explanationEngine";

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
  "urgent",
  "urgently",
  "immediately",
  "expire",
  "expires",
  "expiring",
  "expired",
  "block",
  "blocked",
  "suspend",
  "suspended",
  "suspension",
  "terminate",
  "terminated",
  "verify",
  "verification",
  "click now",
  "act now",
  "action required",
  "limited time",
  "24 hours",
  "48 hours",
  "hours left",
  "deadline",
  "final notice",
  "last chance",
  "confirm now",
  "update now",
  "validate",
  "reactivate",
  "restore access",
  "account locked",
  "account blocked",
  "account suspended",
  "password expired",
  // Hindi urgency words
  "तुरंत",
  "तत्काल",
  "जल्दी",
  "अभी",
  "बंद",
  "निलंबित",
];

const FINANCIAL_SCAM_WORDS = [
  "prize",
  "winner",
  "won",
  "reward",
  "cash prize",
  "lottery",
  "jackpot",
  "congratulations",
  "selected",
  "lucky draw",
  "free money",
  "claim",
  "rs.",
  "rs ",
  "rupees",
  "lakh",
  "crore",
  "₹",
  "upi",
  "paytm",
  "phonepe",
  "gpay",
  "google pay",
  "bhim",
  "neft",
  "rtgs",
  "wallet",
  "cashback",
  "refund pending",
  "kyc",
  "know your customer",
  "pan card",
  "aadhaar",
  "bank account",
  "credit card",
  "debit card",
  "otp",
  "one time password",
  "transaction failed",
  "payment pending",
  "transfer",
  // Hindi financial words
  "इनाम",
  "जीत",
  "पैसे",
  "बधाई",
  "रुपये",
];

const SOCIAL_ENGINEERING_WORDS = [
  "dear customer",
  "dear user",
  "dear member",
  "dear account holder",
  "your account",
  "your profile",
  "login credentials",
  "password",
  "click here",
  "click the link",
  "visit the link",
  "follow the link",
  "do not share",
  "do not disclose",
  "confidential",
  "security alert",
  "unauthorized access",
  "suspicious activity",
  "login attempt",
  "confirm your identity",
  "verify your identity",
  "prove your identity",
  "provide your",
  "enter your",
  "submit your",
  "update your",
  "failure to comply",
  "legal action",
  "court action",
  "police complaint",
];

// Indian banks and payment services — used for impersonation detection
const INDIA_SPECIFIC_BANKS = [
  "sbi",
  "state bank",
  "hdfc",
  "icici",
  "axis bank",
  "punjab national",
  "pnb",
  "bank of baroda",
  "bob",
  "canara bank",
  "union bank",
  "indian bank",
  "uco bank",
  "kotak",
  "yes bank",
  "indusind",
  "rbl bank",
  "idfc",
  "federal bank",
  "karnataka bank",
];

const INDIA_SPECIFIC_SERVICES = [
  "paytm",
  "phonepe",
  "phone pe",
  "gpay",
  "google pay",
  "bhim upi",
  "amazon pay",
  "mobikwik",
  "freecharge",
  "airtel payments",
  "jio payments",
  "ippb",
  "india post",
  "irctc",
  "uidai",
  "aadhaar",
  "pan",
  "epfo",
  "income tax",
  "gst",
  "eway bill",
  "itr",
  "form 16",
];

// TLDs that are free/abused and show up constantly in phishing campaigns
const SUSPICIOUS_TLDS = [
  ".xyz",
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".pw",
  ".top",
  ".club",
  ".online",
  ".site",
  ".icu",
  ".work",
  ".loan",
  ".click",
  ".link",
  ".info",
  ".biz",
];

const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "short.io",
  "rebrand.ly",
  "cutt.ly",
  "tiny.cc",
  "bl.ink",
  "clk.sh",
  "is.gd",
  "v.gd",
  "c.gle",
  "lnkd.in",
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
  const urlRegex =
    /https?:\/\/[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+/gi;
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

  if (URL_SHORTENERS.some((s) => domain.includes(s))) {
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

  if (
    /secure|login|verify|account|update|confirm|kyc|claim|reward/i.test(domain)
  ) {
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

function findSuspiciousSpans(
  text: string,
  matchedTerms: string[],
): SuspiciousSpan[] {
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
      spans.push({
        start: pos,
        end: pos + url.length,
        text: url,
        reason: "URL detected",
      });
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
  isSafeOtp: boolean;
  isSafeTransactional: boolean;
  isSoftTransaction: boolean;
  isNoLinkPhishing: boolean;
  isNoLinkSocialEngineering: boolean;
  isRewardScam: boolean;
  isSensitiveDataOverride: boolean;
  isShortScam: boolean;
  isPhoneScam: boolean;
  isCalmScam: boolean;
  isTrustedSafeLink: boolean;
  isAccountAlert: boolean;
  isHindiPhishing: boolean;
  isUrgencyPhishing: boolean;
} {
  const lower = text.toLowerCase();
  const reasons: DetectionReason[] = [];
  const allTerms: string[] = [];
  let total = 0;

  const hasLinks = extractUrls(text).length > 0;
  const hasStrongUrgency = /blocked|suspended|urgent|immediately|expire/i.test(
    lower,
  );

  // ─── 1. SAFE OTP DETECTION ───
  const hasOtpOrCode = /otp|verification code/i.test(lower);
  const hasSafeOtpPhrase = /do not share|don'?t share|never share|will never ask/i.test(lower);
  const hasTrustedLinks = extractUrls(text).every((u) =>
    /amazon\.(com|in|co\.uk|de|fr|ca|jp)|google\.com|c\.gle|cursor\.sh|\.cursor\.sh|flipkart\.com|netflix\.com|apple\.com|openai\.com|mandrillapp\.com|stripe\.com|hdfcbank\.com|icicibank\.com|axisbank\.com|sbi\.co\.in|paytm\.com|phonepe\.com|zomato\.com|swiggy\.in|cred\.club/i.test(u)
  );
  const hasActionWordsForOtp = /send|share|reply|provide|call/i.test(
    lower.replace(/do not share|don'?t share|never share/gi, ""),
  );
  const isSafeOtp =
    hasOtpOrCode && hasSafeOtpPhrase && (hasTrustedLinks || !hasLinks) && !hasActionWordsForOtp;

  // ─── 2. LEGIT TRANSACTIONAL / PROMO EMAIL ───
  const isPromoMarketing = /apply now|introducing|unveiling|get your|exclusive offer|claim benefit/i.test(lower);
  const isTransactional =
    /debited|credited|payment|txn|transaction alert|subscri(?:bed|ption)|your new plan|payment method|order (?:number|date|placed)|successfully (?:subscribed|signed up)/i.test(lower);

  const isSafeTransactional = (isTransactional || (isPromoMarketing && hasTrustedLinks)) && (hasTrustedLinks || !hasLinks) && !hasStrongUrgency;

  // ─── 3. SOFT URGENCY TRANSACTION ───
  const hasMildUrgency =
    /contact immediately|call support|contact cus|helpdesk|reach out/i.test(
      lower,
    );
  const hasStrongPhishingWords =
    /verify\b|blocked|suspended|password|otp|click here|login/i.test(lower);
  const isSoftTransaction =
    isTransactional && !hasLinks && hasMildUrgency && !hasStrongPhishingWords;

  // ─── 4. NO-LINK PHISHING BOOST ───
  const requestsSensitiveInfo = /otp|password|account details|pin\b|cvv/i.test(
    lower,
  );
  const isNoLinkPhishing =
    hasStrongUrgency && requestsSensitiveInfo && !hasLinks;

  // ─── 5. STRONG NO-LINK SOCIAL ENGINEERING ───
  const hasActionRequest = /call|contact|reply|send|share|\b\d{10}\b/i.test(
    lower,
  );
  const hasSensitiveIntent =
    /otp|password|bank|aadhaar|account|verify|salary|reward|credited|won/i.test(
      lower,
    );
  const hasSocialPressure =
    /urgent|immediately|suspended|blocked|to proceed|failure to act|limited slots/i.test(
      lower,
    );
  const isNoLinkSocialEngineering =
    !hasLinks && hasActionRequest && hasSensitiveIntent && hasSocialPressure;

  // ─── 6. REWARD / CASHBACK SCAM ───
  const hasRewardLure = /won|reward|cashback|congratulations|prize|offer/i.test(
    lower,
  );
  const hasRewardSensitiveRequest =
    /otp|bank|account number|aadhaar|bank details|account details|card details|personal details|send|reply/i.test(
      lower,
    );
  const isRewardScam = hasRewardLure && hasRewardSensitiveRequest;

  // ─── 7. UNIVERSAL SENSITIVE DATA OVERRIDE ───
  const safeLower = lower.replace(/do not share|don'?t share|never share|never disclose|will never ask/gi, "");
  const hasStrictActionIntent = /send|share|reply/i.test(safeLower);
  const hasRequestIntent = /send|share|reply|provide|request/i.test(safeLower);

  const isOtpScam =
    hasStrictActionIntent && /otp|verification code/i.test(safeLower);
  const isPasswordScam =
    hasStrictActionIntent && /password|pin\b|credentials/i.test(safeLower);
  const isBankScam =
    hasRequestIntent &&
    /bank details|account details|card details|aadhaar|pan\b|account number/i.test(
      safeLower,
    );

  const isSensitiveDataOverride = isOtpScam || isPasswordScam || isBankScam;

  // ─── 8. SHORT SCAM DETECTION ───
  const isShortScam = lower.length < 80 && isSensitiveDataOverride;

  // ─── 9. PHONE SCAM DETECTION ───
  const hasPhoneNumber = /\b\d{10}\b/.test(lower);
  const hasPhoneAction = /call|contact/i.test(lower);
  const hasAccountSecurityContext =
    /account|security|bank|aadhaar|pan\b|blocked|suspended|unauthorized/i.test(
      lower,
    );
  const hasPhoneSensitiveIntent =
    /otp|password|verify|restore|reactivate|kyc|blocked|suspended/i.test(lower);
  const isPhoneScam =
    hasPhoneNumber &&
    hasPhoneAction &&
    hasAccountSecurityContext &&
    hasPhoneSensitiveIntent;

  // ─── 10. CALM SCAM DETECTION ───
  const isCalmScam = !hasStrongUrgency && isSensitiveDataOverride;

  // ─── 11. TRUSTED DOMAIN WHITELIST BOOST ───
  const hasTrustedDomain = extractUrls(text).some((u) =>
    /icicibank\.com|hdfcbank\.com|sbi\.co\.in|amazon\.in|flipkart\.com|paytm\.com|phonepe\.com|google\.com/i.test(
      u,
    ),
  );
  const hasSensitiveData =
    /otp|password|pin\b|send|share|reply|provide|account number|aadhaar|pan\b/i.test(
      lower,
    );
  const hasNeutralTone = /view|access|track|check|download/i.test(lower);
  const isTrustedSafeLink =
    hasLinks && hasTrustedDomain && !hasSensitiveData && hasNeutralTone;

  // ─── 12. ACCOUNT ALERT DETECTION ───
  const hasAccountAlertPhrase =
    /unusual activity|suspicious activity|login attempt|security alert|account activity/i.test(
      lower,
    );
  const hasAlertSensitiveData = /otp|password|bank|aadhaar|send|share/i.test(
    lower,
  );
  const isAccountAlert =
    hasAccountAlertPhrase && !hasAlertSensitiveData && !hasLinks;

  // New Detection Hardening Flags
  const hasHindiUrgency = /बंद|तुरंत|अभी|सस्पेंड|रोक दिया/i.test(text);
  const hasHindiAction = /भेजें|सेंड|उत्तर दें|reply/i.test(text);
  const hasOtpOrSensitive = /otp|पासवर्ड|password|pin/i.test(lower);
  const isHindiPhishing =
    hasHindiUrgency && hasHindiAction && hasOtpOrSensitive;

  const hasStrongUrgencyWords =
    /urgent|immediately|now|asap|action required/i.test(lower);
  const hasVerifyIntent = /verify|confirm|update|secure account/i.test(lower);
  const isUrgencyPhishing = hasStrongUrgencyWords && hasVerifyIntent;

  // Track standard hits
  const urgencyHits = URGENCY_WORDS.filter((w) => lower.includes(w));
  if (urgencyHits.length > 0) {
    allTerms.push(...urgencyHits);
    const sev =
      urgencyHits.length >= 3
        ? "high"
        : urgencyHits.length >= 2
          ? "medium"
          : "low";
    reasons.push({
      category: "urgency",
      description: `This email is trying to rush you into action. Words like "urgent", "blocked", or "verify now" are a common tactic used to prevent you from pausing to check whether the message is genuine.`,
      severity: sev,
      matchedTerms: urgencyHits.slice(0, 6),
    });
    total += Math.min(15 + (urgencyHits.length - 1) * 10, 45);
  }

  const financialHits = FINANCIAL_SCAM_WORDS.filter((w) => lower.includes(w));
  if (financialHits.length > 0) {
    allTerms.push(...financialHits);
    const sev =
      financialHits.length >= 4
        ? "high"
        : financialHits.length >= 2
          ? "medium"
          : "low";
    reasons.push({
      category: "financial",
      description: `The email references money, bank accounts, or digital payments. Scammers use financial language to grab your attention and exploit concerns about your account or wallet.`,
      severity: sev,
      matchedTerms: financialHits.slice(0, 6),
    });
    total += Math.min(15 + (financialHits.length - 1) * 8, 35);
  }

  // FIX 1 & FIX 4: SOCIAL ENGINEERING STRICT MODE & CTA NORMALIZATION
  const socialHits = SOCIAL_ENGINEERING_WORDS.filter((w) => lower.includes(w));

  if (socialHits.length > 0) {
    const hasUrgencyAction =
      /immediately verify|account blocked|act now|verify now/i.test(lower);
    const hasAuthorityReq =
      /(bank|rbi|gov|income tax|police).*?(verify|provide|share|update)/i.test(
        lower,
      );
    const hasFear =
      /account suspended|legal action|court action|police complaint/i.test(
        lower,
      );

    const isInformationalAlert =
      /statement|newsletter|login notification/i.test(lower);
    const hasGenericCta =
      /apply now|get started|claim offer|claim reward/i.test(lower);

    // Only flag social engineering if strict urgency, requests, or fear apply, without being informational
    // If it's just a "click here" or "Apply now" (CTA), we ignore unless sensitive data override is active
    const isStrictSocialEngineering =
      hasUrgencyAction ||
      hasAuthorityReq ||
      hasFear ||
      (isSensitiveDataOverride && !hasGenericCta);

    if (isStrictSocialEngineering && !isInformationalAlert) {
      allTerms.push(...socialHits);
      reasons.push({
        category: "social_engineering",
        description: `This email uses high-pressure psychological tactics to build false authority, urgency, or fear. Scammers use this so you rush your decision without verifying.`,
        severity: socialHits.length >= 3 ? "high" : "medium",
        matchedTerms: socialHits.slice(0, 6),
      });
      total += Math.min(10 + (socialHits.length - 1) * 7, 30);
    }
  }

  const bankHits = INDIA_SPECIFIC_BANKS.filter((b) => lower.includes(b));
  const serviceHits = INDIA_SPECIFIC_SERVICES.filter((s) => lower.includes(s));
  if (bankHits.length > 0 || serviceHits.length > 0) {
    const terms = [...bankHits, ...serviceHits];
    allTerms.push(...terms);

    // Lower brand impersonation risk if it's a legit transactional or OTP mail or Trusted Link
    if (
      total > 8 &&
      !isSafeOtp &&
      !isSafeTransactional &&
      !isSoftTransaction &&
      !isTrustedSafeLink
    ) {
      reasons.push({
        category: "india_specific",
        description: `The sender appears to be impersonating a well-known Indian bank or payment platform. Scammers frequently clone real brands to appear legitimate — your actual bank will never ask for credentials over email.`,
        severity: "high",
        matchedTerms: terms.slice(0, 6),
      });
      total += 25;
    }
  }

  const hindiScamWords = [
    "तुरंत",
    "जल्दी",
    "अभी",
    "बंद",
    "इनाम",
    "बधाई",
    "रुपये",
    "पैसे",
    "खाता",
    "सत्यापन",
  ];
  const hindiHits = hindiScamWords.filter((w) => text.includes(w));
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

  const teluguScamWords = [
    "వెంటనే",
    "త్వరగా",
    "బ్లాక్",
    "నిలిపివేయబడింది",
    "బహుమతి",
    "రివార్డ్",
    "అభినందనలు",
    "రూపాయలు",
    "డబ్బు",
    "ఖాతా",
    "ధృవీకరణ",
  ];
  const teluguHits = teluguScamWords.filter((w) => text.includes(w));
  if (teluguHits.length > 0) {
    allTerms.push(...teluguHits);
    reasons.push({
      category: "language",
      description: `This message contains Telugu words that commonly appear in regionally targeted phishing. Scammers use local languages to make the email feel more familiar and trustworthy to Indian readers.`,
      severity: "medium",
      matchedTerms: teluguHits,
    });
    total += teluguHits.length * 8;
  }

  // ─── APPLY EDGE CASE ADJUSTMENTS ───
  if (isSafeOtp) {
    total = 0; // FORCE ruleScore = 0
    reasons.push({
      category: "ml_score",
      description: "Legitimate OTP notification (no action required).",
      severity: "low",
      matchedTerms: ["otp", "do not share"],
    });
  } else if (isSafeTransactional || isSoftTransaction) {
    total = Math.max(0, total - 40); // Reduce near 0
    reasons.push({
      category: "ml_score",
      description:
        "Appears to be a standard transactional alert or payment notification. No suspicious links or urgent actions were detected.",
      severity: "low",
      matchedTerms: ["transaction", "payment"],
    });
  } else if (
    isSensitiveDataOverride ||
    isShortScam ||
    isPhoneScam ||
    isCalmScam
  ) {
    total += 60; // Huge boost for direct sensitive requests
    reasons.push({
      category: "social_engineering",
      description:
        "Sensitive information requested — high-risk phishing. Legitimate organizations never ask you to send or reply with your credentials or OTPs in this manner.",
      severity: "high",
      matchedTerms: ["password/otp", "send/reply/call"],
    });
  } else if (isRewardScam) {
    total += 55; // Boost aggressively for reward scam
    reasons.push({
      category: "social_engineering",
      description:
        "High-risk reward scam. The sender claims you have won a prize or cashback but requests sensitive details or a direct reply without providing a verifiable link.",
      severity: "high",
      matchedTerms: ["prize", "bank details"],
    });
  } else if (isNoLinkSocialEngineering) {
    total += 55; // Boost aggressively for social engineering
    reasons.push({
      category: "social_engineering",
      description:
        "High-risk social engineering attack (no-link phishing). The sender is pressuring you to take action regarding sensitive information without providing verifiable links.",
      severity: "high",
      matchedTerms: ["action required", "sensitive intent"],
    });
  } else if (isNoLinkPhishing) {
    total += 50; // Boost aggressively
    reasons.push({
      category: "social_engineering",
      description:
        "Extremely suspicious no-link phishing attempt. The email uses high-pressure urgency to demand sensitive information directly.",
      severity: "high",
      matchedTerms: ["urgent", "password/otp"],
    });
  } else if (isAccountAlert) {
    total = Math.max(35, total); // Ensure base score supports suspicious classification
    reasons.push({
      category: "social_engineering",
      description:
        "Account activity alert — verify authenticity before taking action.",
      severity: "medium",
      matchedTerms: ["account alert"],
    });
  }

  return {
    score: Math.min(total, 100),
    reasons,
    allTerms: [...new Set(allTerms)],
    isSafeOtp,
    isSafeTransactional,
    isSoftTransaction,
    isNoLinkPhishing,
    isNoLinkSocialEngineering,
    isRewardScam,
    isSensitiveDataOverride,
    isShortScam,
    isPhoneScam,
    isCalmScam,
    isTrustedSafeLink,
    isAccountAlert,
    isHindiPhishing,
    isUrgencyPhishing,
  };
}

// ─── Main export ──────────────────────────────────────────────────────────────

export async function analyzeEmail(
  emailText: string,
  headersText?: string,
  id: string = "untracked",
): Promise<AnalyzeResult> {
  // Empty input — return a neutral safe result
  if (!emailText || emailText.trim().length === 0) {
    return {
      id,
      riskScore: 0,
      classification: "safe",
      confidence: 1.0,
      detectedLanguage: "en",
      reasons: [],
      suspiciousSpans: [],
      urlAnalyses: [],
      safetyTips: [
        "Always verify sender email addresses before clicking any links.",
      ],
      warnings: [],
      mlScore: 0,
      ruleScore: 0,
      urlScore: 0,
      headerScore: 0,
      featureImportance: [],
      attackType: "Safe / Informational",
      scamStory:
        "This is an empty scan. No threat analysis could be performed.",
    };
  }

  // Run all three subsystems
  const { score: mlScore, topFeatures } = await hybridScore(emailText);
  const headerAnalysis: HeaderAnalysis = analyzeEmailHeaders(
    headersText?.trim() ? headersText : emailText,
  );
  let {
    score: ruleScore,
    reasons,
    allTerms,
    isSafeOtp,
    isSafeTransactional,
    isSoftTransaction,
    isNoLinkPhishing,
    isNoLinkSocialEngineering,
    isRewardScam,
    isSensitiveDataOverride,
    isShortScam,
    isPhoneScam,
    isCalmScam,
    isTrustedSafeLink,
    isAccountAlert,
    isHindiPhishing,
    isUrgencyPhishing,
  } = computeRuleScore(emailText);

  // URL analysis — score is weighted max+avg to avoid one bad link dominating
  const urls = extractUrls(emailText);
  const urlAnalyses = urls.map(analyzeUrl);

  let urlScore = 0;
  if (urlAnalyses.length > 0) {
    const maxScore = Math.max(...urlAnalyses.map((u) => u.riskScore));
    const avgScore =
      urlAnalyses.reduce((s, u) => s + u.riskScore, 0) / urlAnalyses.length;
    urlScore = Math.round(maxScore * 0.7 + avgScore * 0.3);
  }

  const suspiciousUrls = urlAnalyses.filter((u) => u.isSuspicious);
  const headerScore = headerAnalysis.headerScore;

  // ═══════════════════════════════════════════════════════════════
  // MODULAR ENGINE PIPELINE
  // ═══════════════════════════════════════════════════════════════

  // 1. INTENT ENGINE — What does the email ask the user to do?
  const intent = analyzeIntent(emailText);

  // 2. TRUST ENGINE — Can we trust the sender?
  const trust = analyzeTrust(
    headerAnalysis.senderDomain || "",
    headerAnalysis.spoofingRisk || "none",
    headerAnalysis.hasHeaders,
    urlAnalyses.map((u) => u.domain),
  );

  // 3. DOMAIN INTELLIGENCE — Are the URLs dangerous?
  const domainIntel = analyzeDomainIntel(
    urlAnalyses.map((u) => ({
      domain: u.domain,
      fullUrl: u.url,
      isSuspicious: u.isSuspicious,
    })),
  );

  // 4. BEHAVIOR ENGINE — What signal combinations exist?
  const behavior = analyzeBehavior(emailText, intent, trust, domainIntel);

  // 5. DECISION ENGINE — Final classification
  const mlBaseScore = Math.round(
    mlScore * 0.4 + ruleScore * 0.3 + urlScore * 0.2 + headerScore * 0.1,
  );
  const decision = makeDecision(
    intent,
    trust,
    domainIntel,
    behavior,
    mlBaseScore,
  );

  // 6. EXPLANATION ENGINE — Human-readable output
  const explanation = generateExplanation(
    decision.classification,
    decision.attackType,
    intent,
    trust,
    domainIntel,
    behavior,
  );

  // ─── Map engine outputs to API response format ───
  const classification = decision.classification;
  const finalScore = decision.riskScore;
  const confidence = decision.confidence;
  reasons = explanation.reasons;

  const warnings = explanation.warnings;
  const safetyTips = explanation.safetyTips;

  const suspiciousSpans = findSuspiciousSpans(emailText, allTerms.slice(0, 30));
  const detectedLanguage = detectLanguage(emailText);

  const featureImportance = topFeatures.map((f: FeatureContribution) => ({
    feature: f.feature,
    contribution: f.contribution,
    direction: f.direction,
  }));

  // Map engine attack types to legacy API enum
  let attackType:
    | "Credential Harvesting"
    | "Reward Scam"
    | "Bank Impersonation"
    | "OTP Scam"
    | "Social Engineering"
    | "Safe / Informational"
    | "Account Alert / Social Engineering"
    | "Lookalike Domain Phishing" = "Safe / Informational";

  switch (decision.attackType) {
    case "Credential Theft":
      attackType = "Credential Harvesting";
      break;
    case "Brand Impersonation":
      attackType = "Bank Impersonation";
      break;
    case "Financial Scam":
      attackType = "Reward Scam";
      break;
    case "Link Phishing":
      attackType = "Credential Harvesting"; // or leave as Social Engineering
      break;
    case "Social Engineering":
      attackType = "Social Engineering";
      break;
    case "Safe / Informational":
      attackType = "Safe / Informational";
      break;
    case "Account Alert / Social Engineering":
      attackType = "Account Alert / Social Engineering";
      break;
    case "Lookalike Domain Phishing":
      attackType = "Lookalike Domain Phishing";
      break;
    case "OTP Scam":
      attackType = "OTP Scam";
      break;
  }

  // Scam story from explanation engine
  const scamStory = explanation.whatIsHappening;

  return AnalyzeEmailResponse.parse({
    id,
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
    headerAnalysis: headerAnalysis.hasHeaders
      ? {
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
      }
      : undefined,
    attackType,
    scamStory,
  });
}
