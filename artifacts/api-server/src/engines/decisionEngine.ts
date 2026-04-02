/**
 * DECISION ENGINE — Final classification pipeline
 *
 * Combines all engine outputs into a single deterministic verdict.
 * Priority-based: dangerous intent > structural forgery > informational > ML fallback
 */

import type { IntentResult } from "./intentEngine";
import type { TrustResult } from "./trustEngine";
import type { DomainIntelResult } from "./domainEngine";
import type { BehaviorResult } from "./behaviorEngine";

export type Classification = "safe" | "suspicious" | "phishing";
export type AttackType =
  | "Credential Theft"
  | "Brand Impersonation"
  | "Financial Scam"
  | "Link Phishing"
  | "Social Engineering"
  | "OTP Scam"
  | "Lookalike Domain Phishing"
  | "Account Alert / Social Engineering"
  | "Safe / Informational";

export interface DecisionResult {
  classification: Classification;
  riskScore: number;
  confidence: number;
  attackType: AttackType;
  decisionReason: string; // Which priority tier decided
}

export function makeDecision(
  intent: IntentResult,
  trust: TrustResult,
  domainIntel: DomainIntelResult,
  behavior: BehaviorResult,
  mlBaseScore: number,
): DecisionResult {
  let classification: Classification;
  let riskScore: number;
  let confidence: number;
  let attackType: AttackType = "Safe / Informational";
  let decisionReason: string;

  const dataExportVerbs = /send|reply|share|provide/i;
  const linkActionVerbs = /click|login|visit|access|go to|verify|update|confirm/i;

  // Only DIRECT data export counts as a sensitive request
  const hasDirectSensitiveRequest = intent.sensitiveTerms.length > 0 && intent.actionVerbs.some((v) => dataExportVerbs.test(v));

  // A malicious action is either a direct data export (send/reply with sensitive data)
  // OR a link-based action that points to a suspicious/lookalike URL.
  const hasMaliciousAction =
    hasDirectSensitiveRequest || 
    (intent.actionVerbs.some((v) => linkActionVerbs.test(v)) && 
     (domainIntel.hasSuspiciousLink || domainIntel.hasLookalikePatterns));

  // 1. SAFE OVERRIDE (Priority #1)
  // 1.1 Safe OTP / Security Override ("verify using code", "use this 123456")
  if (intent.sensitiveTerms.includes("OTP") || intent.safeContextPhrases.length > 0) {
    if (intent.isInformational && !hasMaliciousAction && !domainIntel.hasLookalikePatterns && !domainIntel.hasSuspiciousLink) {
      classification = "safe";
      riskScore = Math.min(20, mlBaseScore);
      confidence = 0.95;
      attackType = "Safe / Informational";
      decisionReason = "PRIORITY_1_SAFE_CONTEXT_OVERRIDE";
      return { classification, riskScore, confidence, attackType, decisionReason };
    }
  }

  // 1.2 Transactional Safe signals
  if (behavior.isTransactional && !hasMaliciousAction && !domainIntel.hasSuspiciousLink) {
    classification = "safe";
    riskScore = Math.min(20, mlBaseScore);
    confidence = 0.9;
    attackType = "Safe / Informational";
    decisionReason = "PRIORITY_1_SAFE_TRANSACTIONAL_OVERRIDE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 1.3 Trusted Sender Context (Fix 4: Trusted domains with no malicious commands)
  if (trust.isTrustedDomain && !hasMaliciousAction && !domainIntel.hasSuspiciousLink) {
    // If it's a known brand, it's safe if there's no dangerous command
    classification = "safe";
    riskScore = Math.min(20, mlBaseScore);
    confidence = 0.95;
    attackType = "Safe / Informational";
    decisionReason = "PRIORITY_1_TRUSTED_SENDER_OVERRIDE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 2. HARD PHISHING (Priority #2)
  // Phishing is only immediate if the sensitive request is DIRECT (send/reply) 
  // or combined with a malicious link (hasMaliciousAction)
  if (hasDirectSensitiveRequest || (intent.sensitiveTerms.length > 0 && hasMaliciousAction)) {
    classification = "phishing";
    riskScore = Math.max(80, Math.min(100, mlBaseScore + 40));
    confidence = 0.95;
    attackType = intent.sensitiveTerms.includes("OTP") ? "OTP Scam" : "Credential Theft";
    decisionReason = "PRIORITY_2_INTENT_DRIVEN_PHISHING";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 3. LINK / DOMAIN PHISHING (Priority #3)
  if (domainIntel.hasLookalikePatterns) {
    classification = "phishing";
    riskScore = Math.max(80, Math.min(100, mlBaseScore + 50));
    confidence = 0.95;
    attackType = "Lookalike Domain Phishing";
    decisionReason = "PRIORITY_3_LOOKALIKE_PHISHING";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  if (domainIntel.hasSuspiciousLink && (domainIntel.hasPhishingKeywords || behavior.behaviorRiskScore >= 30 || behavior.hasUrgency)) {
    classification = "phishing";
    riskScore = Math.max(75, Math.min(100, mlBaseScore + 35));
    confidence = 0.9;
    attackType = "Link Phishing";
    decisionReason = "PRIORITY_3_MALICIOUS_LINK";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 4. SPOOFING (Priority #4)
  if (trust.hasHeaderSpoof || trust.senderHasRiskyTLD) {
    classification = "phishing";
    riskScore = Math.max(80, Math.min(100, mlBaseScore + 45));
    confidence = 0.95;
    attackType = trust.hasHeaderSpoof ? "Brand Impersonation" : "Link Phishing";
    decisionReason = "PRIORITY_4_STRUCTURAL_FORGERY";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 5. ACCOUNT ALERT (Priority #5: SUSPICIOUS override for untrusted domains)
  if (intent.hasAccountAlert && !domainIntel.hasAnyLink && !intent.isSensitiveRequest) {
    classification = "suspicious";
    riskScore = Math.max(30, Math.min(50, mlBaseScore + 20));
    confidence = 0.85;
    attackType = "Account Alert / Social Engineering";
    decisionReason = "PRIORITY_5_SOS_ACCOUNT_ALERT";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 6. DEFAULT / FALLBACK
  if (domainIntel.hasSuspiciousLink || behavior.hasUrgency || behavior.behaviorRiskScore >= 25) {
    classification = "suspicious";
    riskScore = Math.max(31, Math.min(60, mlBaseScore + 15));
    confidence = 0.6;
    attackType = "Social Engineering";
    decisionReason = "PRIORITY_6_SUSPICIOUS_GENERAL";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  classification = "safe";
  riskScore = Math.min(25, mlBaseScore);
  confidence = 0.85;
  attackType = "Safe / Informational";
  decisionReason = "PRIORITY_7_DEFAULT_SAFE";

  return {
    classification,
    riskScore,
    confidence,
    attackType,
    decisionReason,
  };
}
