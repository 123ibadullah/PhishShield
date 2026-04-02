/**
 * DOMAIN INTELLIGENCE ENGINE — URL & domain risk analysis
 *
 * Analyzes URLs for lookalike domains, suspicious patterns,
 * phishing keywords in domain names, and TLD risk.
 */

export type DomainRiskLevel = "safe" | "low" | "medium" | "high" | "critical";

export interface DomainIntelResult {
  riskLevel: DomainRiskLevel;
  riskScore: number; // 0–100
  hasAnyLink: boolean;
  hasSuspiciousLink: boolean;
  hasLookalikePatterns: boolean;
  hasPhishingKeywords: boolean;
  hasHighRiskTLD: boolean;
  findings: string[];
}

// Lookalike patterns — character substitutions attackers use
const LOOKALIKE_PATTERNS = [
  { pattern: /amaz[o0]n/i, brand: "Amazon" },
  { pattern: /g[o0]{2}gle/i, brand: "Google" },
  { pattern: /netfl[i1]x/i, brand: "Netflix" },
  { pattern: /payt[m][\-_]?secure/i, brand: "Paytm" },
  { pattern: /paypa[l1]/i, brand: "PayPal" },
  { pattern: /[i1]c[i1]c[i1]/i, brand: "ICICI" },
  { pattern: /h[d]fc[\-_]?bank/i, brand: "HDFC" },
  { pattern: /m[i1]crosoft/i, brand: "Microsoft" },
  { pattern: /fl[i1]pkart/i, brand: "Flipkart" },
  { pattern: /sb[i1][\-_]?on/i, brand: "SBI" },
];

// Phishing keywords in domain names
const DOMAIN_PHISHING_KEYWORDS = [
  "login",
  "signin",
  "verify",
  "update",
  "secure",
  "account",
  "confirm",
  "banking",
  "auth",
  "validate",
  "recover",
  "restore",
  "unlock",
  "alert",
  "notification",
];

// Suspicious URL path patterns
const SUSPICIOUS_PATH_PATTERNS = [
  /\/login\b/i,
  /\/verify\b/i,
  /\/update[\-_]?account/i,
  /\/secure[\-_]?login/i,
  /\/confirm[\-_]?identity/i,
  /\.php\?.*=(token|id|user|session)/i,
  /\/redirect\?/i,
];

const HIGH_RISK_TLDS = [
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".xyz",
  ".top",
  ".work",
  ".click",
  ".buzz",
  ".gq",
];

export function analyzeDomainIntel(
  urls: { domain: string; fullUrl: string; isSuspicious: boolean }[],
): DomainIntelResult {
  const findings: string[] = [];
  let riskScore = 0;
  let hasLookalikePatterns = false;
  let hasPhishingKeywords = false;
  let hasHighRiskTLD = false;
  let hasSuspiciousLink = false;

  if (urls.length === 0) {
    return {
      riskLevel: "safe",
      riskScore: 0,
      hasAnyLink: false,
      hasSuspiciousLink: false,
      hasLookalikePatterns: false,
      hasPhishingKeywords: false,
      hasHighRiskTLD: false,
      findings: ["No URLs found in email"],
    };
  }

  for (const url of urls) {
    const domainLower = url.domain.toLowerCase();
    const fullUrlLower = url.fullUrl.toLowerCase();

    // Check URL-level suspicious flag from existing analyzer
    if (url.isSuspicious) {
      hasSuspiciousLink = true;
      riskScore += 25;
      findings.push(`Suspicious URL detected: ${url.domain}`);
    }

    // Check lookalike patterns
    // Catch numeric substitutions (0->o, 1->i/l, 5->s, etc.)
    const normalizedDomain = domainLower
      .replace(/0/g, "o")
      .replace(/[1i|!]/g, "l")
      .replace(/5/g, "s")
      .replace(/3/g, "e")
      .replace(/4/g, "a")
      .replace(/8/g, "b")
      .replace(/_/g, "-");

    for (const { pattern, brand } of LOOKALIKE_PATTERNS) {
      const brandLower = brand.toLowerCase();
      
      // If normalized domain contains the brand, but the literal domain isn't exactly the brand's domain
      // e.g. "g00gle.com" normalized is "google.com"
      if (
        (pattern.test(domainLower) || normalizedDomain.includes(brandLower)) &&
        !domainLower.includes(brandLower + ".") &&
        domainLower !== brandLower + ".com" &&
        domainLower !== brandLower + ".in"
      ) {
        hasLookalikePatterns = true;
        riskScore += 50; // Boosted to ensure it hits PHISHING
        findings.push(
          `Adversarial lookalike domain detected for ${brand}: ${url.domain}`,
        );
      }
    }

    // Check for Auth Spoofing (e.g., http://google.com@attacker.com)
    // Legit URLs almost never use HTTP basic auth with a real domain name as the 'user'
    if (fullUrlLower.includes("@") && fullUrlLower.match(/https?:\/\/[^@]+@/)) {
      hasLookalikePatterns = true;
      riskScore += 50;
      findings.push(`URL Auth Spoofing detected: ${url.domain}`);
    }

    // Check for URL Shorteners
    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "cutt.ly", "is.gd", "v.gd"];
    const brandShorteners = ["c.gle", "lnkd.in"]; // Google, LinkedIn official
    
    if (shorteners.some(s => domainLower === s)) {
      hasSuspiciousLink = true;
      riskScore += 15;
      findings.push(`URL Shortener detected: ${url.domain}`);
    } else if (brandShorteners.some(s => domainLower === s)) {
      // Official brand shortener — only suspicious if sender doesn't match? 
      // For now, don't set hasSuspiciousLink = true to allow trusted sender override
      riskScore += 5; 
      findings.push(`Official brand shortener detected: ${url.domain}`);
    }

    // Check phishing keywords in domain
    for (const keyword of DOMAIN_PHISHING_KEYWORDS) {
      if (domainLower.includes(keyword)) {
        hasPhishingKeywords = true;
        riskScore += 15;
        findings.push(
          `Phishing keyword "${keyword}" found in domain: ${url.domain}`,
        );
        break; // One match per domain is enough
      }
    }

    // Check high-risk TLD
    if (HIGH_RISK_TLDS.some((tld) => domainLower.endsWith(tld))) {
      hasHighRiskTLD = true;
      riskScore += 25;
      findings.push(`High-risk TLD detected: ${url.domain}`);
    }

    // Check suspicious path patterns
    for (const pattern of SUSPICIOUS_PATH_PATTERNS) {
      if (pattern.test(fullUrlLower)) {
        riskScore += 10;
        findings.push(`Suspicious URL path pattern detected`);
        break;
      }
    }
  }

  // Clamp score
  riskScore = Math.min(100, riskScore);

  // Determine risk level
  let riskLevel: DomainRiskLevel;
  if (riskScore >= 70) riskLevel = "critical";
  else if (riskScore >= 50) riskLevel = "high";
  else if (riskScore >= 30) riskLevel = "medium";
  else if (riskScore >= 10) riskLevel = "low";
  else riskLevel = "safe";

  return {
    riskLevel,
    riskScore,
    hasAnyLink: urls.length > 0,
    hasSuspiciousLink:
      hasSuspiciousLink || hasLookalikePatterns || hasHighRiskTLD,
    hasLookalikePatterns,
    hasPhishingKeywords,
    hasHighRiskTLD,
    findings,
  };
}
