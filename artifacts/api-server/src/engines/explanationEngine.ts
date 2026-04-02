/**
 * EXPLANATION ENGINE — Human-readable analysis output
 *
 * Generates structured explanations based ONLY on triggered signals.
 * Zero hallucination — if a signal didn't fire, no explanation for it.
 */

import type { IntentResult } from "./intentEngine";
import type { TrustResult } from "./trustEngine";
import type { DomainIntelResult } from "./domainEngine";
import type { BehaviorResult } from "./behaviorEngine";
import type { Classification, AttackType } from "./decisionEngine";

export interface ExplanationResult {
  summary: string; // One-line verdict
  whatIsHappening: string; // What the email is doing
  whyItIsRisky: string; // Why it's dangerous (or not)
  whatAttackerWants: string; // Attacker's goal
  whatUserShouldDo: string; // Actionable advice
  impact: ImpactPrediction;
  reasons: ExplanationReason[];
  warnings: string[];
  safetyTips: string[];
}

export type ReasonCategory =
  | "urgency"
  | "financial"
  | "social_engineering"
  | "url"
  | "domain"
  | "india_specific"
  | "ml_score"
  | "language"
  | "header"
  | "informational";

export interface ExplanationReason {
  category: ReasonCategory;
  description: string;
  severity: "low" | "medium" | "high";
  matchedTerms: string[];
}

export interface ImpactPrediction {
  accountTakeover: boolean;
  financialLoss: boolean;
  identityTheft: boolean;
  summary: string;
}

export function generateExplanation(
  classification: Classification,
  attackType: AttackType,
  intent: IntentResult,
  trust: TrustResult,
  domainIntel: DomainIntelResult,
  behavior: BehaviorResult,
): ExplanationResult {
  const reasons: ExplanationReason[] = [];
  const warnings: string[] = [];

  // ─── Build reasons ONLY from triggered signals ───
  if (classification !== "safe") {
    if (domainIntel.hasSuspiciousLink) {
      reasons.push({
        category: "url",
        description: "Suspicious or high-risk URLs detected in the email.",
        severity: "high",
        matchedTerms: ["suspicious link"],
      });
    }

    if (domainIntel.hasLookalikePatterns) {
      reasons.push({
        category: "url",
        description:
          "Domain name appears to be a fake lookalike of a trusted brand.",
        severity: "high",
        matchedTerms: ["lookalike domain"],
      });
    }

    if (behavior.hasFinancialLure) {
      reasons.push({
        category: "financial",
        description:
          "The message uses a financial lure like a prize or reward to bait you.",
        severity: "high",
        matchedTerms: ["financial lure"],
      });
    }

    if (behavior.hasUrgency) {
      reasons.push({
        category: "urgency",
        description:
          "The email creates pressure or urgency to force quick action.",
        severity: "medium",
        matchedTerms: ["urgency"],
      });
    }

    if (trust.hasHeaderSpoof || trust.senderHasRiskyTLD) {
      reasons.push({
        category: "header",
        description:
          "The sender identity is spoofed or uses a disposable high-risk domain.",
        severity: "high",
        matchedTerms: ["spoofed domain"],
      });
    }

    if (intent.isSensitiveRequest) {
      reasons.push({
        category: "social_engineering",
        description: `The email asks you to send or share sensitive credentials (${intent.sensitiveTerms.join(", ")}).`,
        severity: "high",
        matchedTerms: intent.sensitiveTerms,
      });
    }

    if (behavior.hasBrandMention && behavior.hasUrgency) {
      reasons.push({
        category: "india_specific",
        description:
          "A well-known brand name is used alongside urgency — possible impersonation.",
        severity: "high",
        matchedTerms: ["brand impersonation"],
      });
    }
  }

  // Default reason for safe emails
  if (reasons.length === 0) {
    if (classification === "safe") {
      reasons.push({
        category: "ml_score",
        description:
          "No threatening intent detected. This appears to be a standard communication.",
        severity: "low",
        matchedTerms: [],
      });
    } else {
      reasons.push({
        category: "ml_score",
        description:
          "General analysis inference detected potential risk patterns.",
        severity: "medium",
        matchedTerms: [],
      });
    }
  }

  // ─── Build user-facing warnings ───
  if (classification === "phishing") {
    warnings.push(
      "Do not click any links or reply to this email. This appears to be a phishing attempt.",
    );
    if (domainIntel.hasSuspiciousLink) {
      warnings.push(
        "The links in this email lead to suspicious domains — not the real websites they claim to be.",
      );
    }
    warnings.push(
      "If you think your account may actually be at risk, contact the organization directly using their official number or website.",
    );
  } else if (classification === "suspicious") {
    warnings.push(
      "This email has some unusual patterns. Verify that it is genuine before clicking any links.",
    );
    warnings.push(
      "If in doubt, contact the sender through a different channel — phone or official website.",
    );
  }

  // ─── Generate human-readable story ───
  const whatIsHappening = generateWhatIsHappening(
    classification,
    attackType,
    intent,
    behavior,
  );
  const whyItIsRisky = generateWhyRisky(
    classification,
    intent,
    trust,
    domainIntel,
    behavior,
  );
  const whatAttackerWants = generateAttackerGoal(
    classification,
    attackType,
    intent,
  );
  const whatUserShouldDo = generateUserAdvice(classification, attackType);
  const summary = generateSummary(classification, attackType);

  // ─── Impact prediction ───
  const impact = predictImpact(classification, attackType, intent);

  // ─── Safety tips ───
  const safetyTips = [
    "Verify the sender's email address carefully — scammers use lookalike addresses",
    "Never share OTP, PIN, password, or Aadhaar/PAN details over email",
    "Your bank will NEVER ask for account details via email",
    "Call the official helpline to confirm any urgent requests",
    "Hover over links to see the real destination before clicking",
    "Enable 2-factor authentication on all accounts",
    "Report phishing emails to cybercrime.gov.in",
  ];

  return {
    summary,
    whatIsHappening,
    whyItIsRisky,
    whatAttackerWants,
    whatUserShouldDo,
    impact,
    reasons,
    warnings,
    safetyTips,
  };
}

function generateSummary(
  classification: Classification,
  attackType: AttackType,
): string {
  if (classification === "safe")
    return "This email appears to be a legitimate communication with no threatening intent.";
  if (classification === "suspicious")
    return "This email has unusual patterns that warrant caution before taking any action.";
  if (attackType === "Credential Theft")
    return "⚠️ This email is attempting to steal your login credentials or sensitive information.";
  if (attackType === "Financial Scam")
    return "⚠️ This email uses financial bait to trick you into a scam.";
  if (attackType === "Brand Impersonation")
    return "⚠️ This email impersonates a trusted organization to deceive you.";
  if (attackType === "Link Phishing")
    return "⚠️ This email contains malicious links designed to steal your data.";
  return "⚠️ This email shows signs of a phishing or social engineering attack.";
}

function generateWhatIsHappening(
  classification: Classification,
  attackType: AttackType,
  intent: IntentResult,
  behavior: BehaviorResult,
): string {
  if (classification === "safe") {
    if (intent.sensitiveTerms.length > 0 && intent.isInformational) {
      return "This email is providing you with a security code or notification. It contains disclaimers telling you NOT to share this information.";
    }
    if (behavior.isTransactional) {
      return "This is a standard transaction receipt or notification about account activity.";
    }
    return "This appears to be a standard, non-threatening email communication.";
  }

  if (attackType === "Credential Theft") {
    return `This email is asking you to ${intent.actionVerbs.join("/")} your ${intent.sensitiveTerms.join(", ")}. This is a credential theft attempt.`;
  }
  if (attackType === "Financial Scam") {
    return "This email uses a financial reward or prize to bait you into providing personal information or making a payment.";
  }
  if (attackType === "Brand Impersonation") {
    return "Someone is pretending to be a trusted organization and creating urgency to trick you into acting quickly.";
  }
  if (attackType === "Link Phishing") {
    return "This email contains links that lead to fake or dangerous websites designed to harvest your credentials.";
  }
  return "This email uses social manipulation techniques to trick you into taking a harmful action.";
}

function generateWhyRisky(
  classification: Classification,
  intent: IntentResult,
  trust: TrustResult,
  domainIntel: DomainIntelResult,
  behavior: BehaviorResult,
): string {
  if (classification === "safe")
    return "No risk indicators detected. The email is informational and does not request any sensitive actions.";

  const riskFactors: string[] = [];
  if (intent.isSensitiveRequest)
    riskFactors.push("it asks for sensitive credentials");
  if (trust.hasHeaderSpoof) riskFactors.push("the sender identity is forged");
  if (trust.senderHasRiskyTLD)
    riskFactors.push("the sender uses a disposable domain");
  if (domainIntel.hasSuspiciousLink)
    riskFactors.push("it contains suspicious links");
  if (behavior.hasUrgency && intent.isUserAskedToAct)
    riskFactors.push("it uses urgency to pressure you");
  if (behavior.hasFinancialLure) riskFactors.push("it uses financial bait");

  if (riskFactors.length === 0)
    return "General analysis suggests potential risk patterns.";
  return `This is risky because ${riskFactors.join(", ")}.`;
}

function generateAttackerGoal(
  classification: Classification,
  attackType: AttackType,
  intent: IntentResult,
): string {
  if (classification === "safe")
    return "No attacker detected. This appears to be a legitimate sender.";
  if (attackType === "Credential Theft")
    return `The attacker wants your ${intent.sensitiveTerms.join(", ")} to gain unauthorized access to your accounts.`;
  if (attackType === "Financial Scam")
    return "The attacker wants to trick you into paying a fake fee or revealing financial details.";
  if (attackType === "Brand Impersonation")
    return "The attacker wants to exploit your trust in a well-known brand to extract personal information.";
  if (attackType === "Link Phishing")
    return "The attacker wants you to visit a fake website where your login credentials will be captured.";
  return "The attacker is using psychological manipulation to trick you into a harmful action.";
}

function generateUserAdvice(
  classification: Classification,
  attackType: AttackType,
): string {
  if (classification === "safe")
    return "No special action needed. This email appears safe.";
  if (classification === "suspicious")
    return "Exercise caution. Verify the sender through a separate channel before taking any action.";

  if (attackType === "Credential Theft")
    return "Do NOT send any credentials. Contact the organization directly through their official website or helpline.";
  if (attackType === "Financial Scam")
    return "Ignore the financial claim. No legitimate organization gives prizes via email without prior context.";
  if (attackType === "Link Phishing")
    return "Do NOT click any links. If concerned, go to the service directly by typing their URL in your browser.";
  return "Do not reply or click any links. Report this email as phishing.";
}

function predictImpact(
  classification: Classification,
  attackType: AttackType,
  intent: IntentResult,
): ImpactPrediction {
  if (classification === "safe") {
    return {
      accountTakeover: false,
      financialLoss: false,
      identityTheft: false,
      summary: "No harmful impact expected. This email is safe.",
    };
  }

  const accountTakeover =
    attackType === "Credential Theft" || attackType === "Link Phishing";
  const financialLoss =
    attackType === "Financial Scam" ||
    intent.sensitiveTerms.some((t) =>
      ["CVV", "card number", "bank details", "PIN"].includes(t),
    );
  const identityTheft = intent.sensitiveTerms.some((t) =>
    ["Aadhaar", "PAN", "SSN"].includes(t),
  );

  const impacts: string[] = [];
  if (accountTakeover) impacts.push("account takeover");
  if (financialLoss) impacts.push("financial loss");
  if (identityTheft) impacts.push("identity theft");

  return {
    accountTakeover,
    financialLoss,
    identityTheft,
    summary:
      impacts.length > 0
        ? `If you respond to this email, you risk: ${impacts.join(", ")}.`
        : "Potential social engineering impact — proceed with caution.",
  };
}
