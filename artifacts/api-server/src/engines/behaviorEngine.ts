/**
 * BEHAVIOR ENGINE — Signal combination analysis
 *
 * Combines multiple signals to produce a behavioral risk score.
 * Single signals are weak. Combinations are strong.
 */

import type { IntentResult } from "./intentEngine";
import type { TrustResult } from "./trustEngine";
import type { DomainIntelResult } from "./domainEngine";

export interface BehaviorResult {
  behaviorRiskScore: number; // 0–100
  riskCombinations: string[]; // Human-readable combos detected
  hasUrgency: boolean;
  hasFinancialLure: boolean;
  hasBrandMention: boolean;
  isTransactional: boolean;
}

export function analyzeBehavior(
  emailText: string,
  intent: IntentResult,
  trust: TrustResult,
  domainIntel: DomainIntelResult,
): BehaviorResult {
  const textLower = emailText.toLowerCase();
  const despacedText = textLower.replace(/[\u200B-\u200D\uFEFF\s]/g, "");

  let behaviorRiskScore = 0;
  const riskCombinations: string[] = [];

  // --- Detect supporting signals ---
  const hasUrgency =
    /urgent|immediately|blocked|suspended|act now|expires? (soon|today|in \d)|within \d+ hours?|तुरंत|अभी|जल्दी|बंद|सस्पेंड|వెంటనే|త్వరగా|బ్లాక్|నిలిపివేయబడింది/i.test(textLower) ||
    despacedText.includes("urgent");
    
  const hasFinancialLure =
    (/win|reward|prize|cashback|gift|claim|lucky|selected|congratulations|इनाम|बधाई|रुपये|पैसे|బహుమతి|రివార్డ్|అభినందనలు|రూపాయలు|డబ్బు/i.test(textLower) || despacedText.includes("cashback")) &&
    !/debited|credited|payment|transaction|receipt/i.test(textLower);
    
  const hasBrandMention =
    /amazon|google|netflix|sbi|hdfc|icici|paypal|flipkart|paytm|phonepe|razorpay/i.test(textLower);
    
  const isTransactional =
    /debited|credited|order shipped|payment success|invoice|receipt|subscription renewed|subscri(?:bed|ption)|your new plan|payment method|order (?:number|date|placed|confirmation)|successfully (?:subscribed|signed up|registered)/i.test(textLower);


  // --- COMBINATION SCORING (the core of behavior analysis) ---

  // Behavioral signals like Urgency/Financial Bate are common in Phishing, 
  // but also in legit OTP/Sign-in emails. We only flag them if NOT from a trusted domain.
  if (!trust.isTrustedDomain) {
    // Urgency + Action Intent → HIGH RISK
    if (hasUrgency && intent.isUserAskedToAct) {
      behaviorRiskScore += 30;
      riskCombinations.push("Urgency combined with action request — classic pressure tactic");
    }

    // Financial lure + Action Intent → SCAM PATTERN
    if (hasFinancialLure && intent.isUserAskedToAct) {
      behaviorRiskScore += 30;
      riskCombinations.push("Financial bait combined with action request — reward scam pattern");
    }

    // Brand + Urgency + Action → IMPERSONATION ATTACK
    if (hasBrandMention && hasUrgency && intent.isUserAskedToAct) {
      behaviorRiskScore += 25;
      riskCombinations.push("Brand name + urgency + action — impersonation attack pattern");
    }

    // Untrusted TLD increases risk
    if (trust.senderHasRiskyTLD) {
      behaviorRiskScore += 20;
    }
  }

  // Sensitive request + Untrusted sender → HARD PHISHING
  if (intent.isSensitiveRequest && !trust.isTrustedDomain) {
    behaviorRiskScore += 35;
    riskCombinations.push("Credential request from untrusted sender — likely credential theft");
  }

  // Suspicious links + Action → LINK PHISHING
  if (domainIntel.hasSuspiciousLink && intent.isUserAskedToAct) {
    behaviorRiskScore += 30;
    riskCombinations.push("Suspicious links combined with action request — link phishing");
  }

  // Informational + No action → SAFE BEHAVIOR
  if (intent.isInformational && !intent.isUserAskedToAct) {
    behaviorRiskScore -= 30;
    riskCombinations.push(
      "Informational content with no action request — standard notification",
    );
  }

  // Transactional + No suspicious signals → SAFE BEHAVIOR
  if (
    isTransactional &&
    !intent.isUserAskedToAct &&
    !domainIntel.hasSuspiciousLink
  ) {
    behaviorRiskScore -= 20;
    riskCombinations.push(
      "Transaction receipt with no action request — standard receipt",
    );
  }

  // Trusted sender reduces risk
  if (trust.isTrustedDomain) {
    behaviorRiskScore -= 15;
  }

  // Untrusted TLD increases risk
  if (trust.senderHasRiskyTLD) {
    behaviorRiskScore += 20;
  }

  // Clamp
  behaviorRiskScore = Math.max(0, Math.min(100, behaviorRiskScore));

  return {
    behaviorRiskScore,
    riskCombinations,
    hasUrgency,
    hasFinancialLure,
    hasBrandMention,
    isTransactional,
  };
}
