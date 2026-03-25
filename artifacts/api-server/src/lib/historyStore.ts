import type { ScanHistoryItem } from "@workspace/api-zod";
import { randomUUID } from "crypto";

const MAX_HISTORY = 10;
const history: ScanHistoryItem[] = [];

export function addToHistory(params: {
  emailText: string;
  riskScore: number;
  classification: "safe" | "suspicious" | "phishing";
  detectedLanguage: string;
  urlCount: number;
  reasonCount: number;
}): void {
  const item: ScanHistoryItem = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    emailPreview: params.emailText.trim().slice(0, 80).replace(/\n/g, " "),
    riskScore: params.riskScore,
    classification: params.classification,
    detectedLanguage: params.detectedLanguage,
    urlCount: params.urlCount,
    reasonCount: params.reasonCount,
  };

  history.unshift(item);
  if (history.length > MAX_HISTORY) {
    history.length = MAX_HISTORY;
  }
}

export function getHistory(): ScanHistoryItem[] {
  return [...history];
}

export function clearHistory(): void {
  history.length = 0;
}

export function getSessionCounts(): {
  totalScans: number;
  phishingDetected: number;
  suspiciousDetected: number;
  safeDetected: number;
} {
  return {
    totalScans: history.length,
    phishingDetected: history.filter((h) => h.classification === "phishing").length,
    suspiciousDetected: history.filter((h) => h.classification === "suspicious").length,
    safeDetected: history.filter((h) => h.classification === "safe").length,
  };
}
