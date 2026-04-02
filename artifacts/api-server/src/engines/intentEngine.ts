/**
 * INTENT ENGINE — Core of PhishShield AI
 *
 * Determines WHAT the email is asking the user to do.
 * Keywords are support signals. Only user action intent decides.
 */

export type IntentType = "SAFE" | "ACTION_REQUIRED" | "DANGEROUS";

export interface IntentResult {
  intentType: IntentType;
  isUserAskedToAct: boolean;
  isSensitiveRequest: boolean;
  isInformational: boolean;
  hasAccountAlert: boolean;
  actionVerbs: string[];
  sensitiveTerms: string[];
  safeContextPhrases: string[];
}

// PhishShield's own boilerplate — strip this FIRST to prevent self-contamination
const PHISHSHIELD_BOILERPLATE =
  /what to do next.*?call the official helpline[^\n]*/gis;

// Safe disclaimer phrases — stripped before checking action words
const SAFE_DISCLAIMERS =
  /do not share|don'?t share|never share|will never ask|won'?t ask|ignore if not you|ignore this email|if this was not you|if not you|we will never|customer care will never|service will never|do not click|never disclose|never ask for|you requested to sign in|someone else might have typed|you received this email because/gi;

// Dangerous actions — commands to export/reveal data (Direct extraction)
const DANGEROUS_ACTION_PATTERNS = [
  { pattern: /\bsend(?:ing)?\s+(?:your|the|us|it)\b/i, verb: "send" },
  { pattern: /\breply(?:ing)?\s+(?:with|to)\b/i, verb: "reply" },
  // Hindi/Hinglish data export verbs
  { pattern: /\b(?:bhej(?:ein|o|iye)|batay?(?:ein|o|iye))\b/i, verb: "send" },
  { pattern: /\bshare\s+kar(?:ein|o|iye|na)\b/i, verb: "share" },
];

// Suspicious/Required actions — commands to navigate or perform a task
const SUSPICIOUS_ACTION_PATTERNS = [
  { pattern: /\bshar(?:e|ing)?\s+(?:your|the)\b/i, verb: "share" },
  { pattern: /\bshare\s+kar(?:ein|o|iye|na)\b/i, verb: "share" },
  { pattern: /\bprovid(?:e|ing)\s+(?:your|the)\b/i, verb: "provide" },
  { pattern: /\bclick(?:ing)?\s+(?:here|below|this|the)\b/i, verb: "click" },
  { pattern: /\blog(?:ging)?\s*-?\s*in\b/i, verb: "login" },
  { pattern: /\bsign(?:ing)?\s*-?\s*in\b/i, verb: "login" },
  { pattern: /\bvisit(?:ing)?\s+(?:the|our)\b/i, verb: "visit" },
  { pattern: /\bgo\s+to\s+(?:the|our)\b/i, verb: "visit" },
  { pattern: /\bcall(?:ing)?\s+(?:us|our|this)\b/i, verb: "call" },
  { pattern: /\bverify(?:ing)?\s+(?:now|your|account|immediately)\b/i, verb: "verify" },
  { pattern: /\bupdate(?:ing)?\s+(?:now|your|account|immediately)\b/i, verb: "update" },
  { pattern: /\bconfirm(?:ing)?\s+(?:now|your|identity|account)\b/i, verb: "confirm" },
  { pattern: /\benter(?:ing)?\s+(?:your|the)\b/i, verb: "enter" },
  { pattern: /\bforward(?:ing)?\s+(?:this|your)\b/i, verb: "forward" },
  { pattern: /\bact\s+now\b/i, verb: "act now" },
];

// Sensitive data terms — things an attacker wants
const SENSITIVE_TERMS = [
  { pattern: /\botp\b/i, term: "OTP" },
  { pattern: /\bpassword\b/i, term: "password" },
  { pattern: /\bpin\b/i, term: "PIN" },
  { pattern: /\baadhaar\b/i, term: "Aadhaar" },
  { pattern: /\bcredentials?\b/i, term: "credentials" },
  { pattern: /\bcvv\b/i, term: "CVV" },
  { pattern: /\bcard\s*number\b/i, term: "card number" },
  { pattern: /\baccount\s*number\b/i, term: "account number" },
  { pattern: /\bbank\s*details?\b/gi, term: "bank details" },
  { pattern: /\bsocial\s*security\b/gi, term: "SSN" },
  { pattern: /\bpan\s+(?:card|number)\b/gi, term: "PAN" },
];

// Safe context phrases — signs the email is informational
const SAFE_CONTEXT_PATTERNS = [
  { pattern: /do not share/i, phrase: "do not share" },
  { pattern: /never share/i, phrase: "never share" },
  { pattern: /don'?t share/i, phrase: "don't share" },
  { pattern: /will never ask/i, phrase: "will never ask" },
  { pattern: /ignore if not you/i, phrase: "ignore if not you" },
  { pattern: /ignore this email/i, phrase: "ignore this email" },
  { pattern: /if this was not you/i, phrase: "if this was not you" },
  { pattern: /this is (?:an? )?automated/i, phrase: "automated message" },
  { pattern: /do not reply/i, phrase: "do not reply" },
  { pattern: /you requested to sign in/i, phrase: "requested sign-in" },
  { pattern: /you received this email because/i, phrase: "standard notification" },
  { pattern: /you(?:'ve|'ve| have) successfully (?:subscribed|signed up|registered|created)/i, phrase: "confirmation" },
  { pattern: /subscription will (?:automatically )?renew/i, phrase: "subscription notice" },
  { pattern: /you can cancel at any time/i, phrase: "cancel anytime" },
  { pattern: /order (?:number|confirmation|placed|shipped)/i, phrase: "order confirmation" },
];

export function analyzeIntent(emailText: string): IntentResult {
  // 0. Strip PhishShield's own boilerplate to prevent self-contamination
  const cleanedText = emailText.replace(PHISHSHIELD_BOILERPLATE, " ");

  // 1. Remove zero-width obfuscation characters
  const deObfuscatedText = cleanedText.replace(/[\u200B-\u200D\uFEFF]/g, "");

  // 2. Normalize whitespace
  const textLower = deObfuscatedText.toLowerCase().replace(/\s+/g, " ");

  // Sanitize text: remove disclaimers that contain keywords like 'OTP', 'PIN', etc.
  const sanitizedText = textLower.replace(SAFE_DISCLAIMERS, " __SAFE__ ");

  // Detect action verbs (on sanitized text)
  const dangerousVerbs: string[] = [];
  for (const { pattern, verb } of DANGEROUS_ACTION_PATTERNS) {
    if (pattern.test(sanitizedText)) dangerousVerbs.push(verb);
  }

  const suspiciousVerbs: string[] = [];
  for (const { pattern, verb } of SUSPICIOUS_ACTION_PATTERNS) {
    if (pattern.test(sanitizedText)) suspiciousVerbs.push(verb);
  }

  // Detect sensitive terms (on SANITIZED text — so disclaimers don't pollute)
  const sensitiveTerms: string[] = [];
  for (const { pattern, term } of SENSITIVE_TERMS) {
    if (pattern.test(sanitizedText)) {
      sensitiveTerms.push(term);
    }
  }

  // --- ANTI-EVASION: Detect truly spaced-out words ---
  // Only trigger if the word exists in despaced form but NOT as a normal word in original text
  // This catches "p a s s w o r d" but NOT "password" in normal sentences
  const words = textLower.split(/\s+/);
  const normalWordsSet = new Set(words);

  // Check for spaced-out evasion: if single characters appear in sequence that form a keyword
  const checkSpacedEvasion = (keyword: string): boolean => {
    // Look for the keyword's characters appearing as individual letters separated by spaces
    // e.g., "p a s s w o r d" → individual chars in sequence
    const spacedPattern = keyword.split("").join("\\s+");
    const spacedRegex = new RegExp(spacedPattern, "i");
    return spacedRegex.test(textLower) && !normalWordsSet.has(keyword);
  };

  if (checkSpacedEvasion("password") && !sensitiveTerms.includes("password")) {
    sensitiveTerms.push("password");
  }
  if (checkSpacedEvasion("otp") && !sensitiveTerms.includes("OTP")) {
    sensitiveTerms.push("OTP");
  }
  if (checkSpacedEvasion("share") && !suspiciousVerbs.includes("share")) {
    suspiciousVerbs.push("share");
  }
  if (checkSpacedEvasion("send") && !dangerousVerbs.includes("send")) {
    dangerousVerbs.push("send");
  }

  // Compile final merged lists
  const actionVerbs = [...dangerousVerbs, ...suspiciousVerbs].filter(Boolean);

  // Detect safe context phrases (on original text)
  const safeContextPhrases: string[] = [];
  for (const { pattern, phrase } of SAFE_CONTEXT_PATTERNS) {
    if (pattern.test(textLower)) {
      safeContextPhrases.push(phrase);
    }
  }

  const isUserAskedToAct = actionVerbs.length > 0;
  // isSensitiveRequest = DANGEROUS verb (send/reply) + sensitive term
  const isSensitiveRequest = sensitiveTerms.length > 0 && dangerousVerbs.length > 0;
  const isInformational = safeContextPhrases.length > 0;

  // Specific check for account verification alerts — must NOT trigger on subscription/order receipts
  const isSubscriptionReceipt = /subscri(?:bed|ption|be)|order (?:number|confirmation|placed)|invoice|receipt/i.test(textLower);
  const hasAccountAlert = !isSubscriptionReceipt && /verify|check|review/i.test(textLower) && /account|activity|login/i.test(textLower);

  // Determine intent type
  let intentType: IntentType;

  if (isSensitiveRequest) {
    intentType = "DANGEROUS";
  } else if (isUserAskedToAct && !isInformational) {
    intentType = "ACTION_REQUIRED";
  } else {
    intentType = "SAFE";
  }

  return {
    intentType,
    isUserAskedToAct,
    isSensitiveRequest,
    isInformational,
    hasAccountAlert,
    actionVerbs,
    sensitiveTerms,
    safeContextPhrases,
  };
}
