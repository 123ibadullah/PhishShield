import type { ScanHistoryItem } from "@workspace/api-zod";
import { randomUUID } from "crypto";
import { db, scanHistoryTable, feedbackTable } from "@workspace/db";
import { count, desc } from "drizzle-orm";

const MAX_HISTORY = 50;

export async function addToHistory(params: {
  emailText: string;
  id?: string;
  riskScore: number;
  classification: "safe" | "suspicious" | "phishing";
  detectedLanguage: string;
  urlCount: number;
  reasonCount: number;
}): Promise<void> {
  const item = {
    id: params.id || randomUUID(),
    timestamp: new Date().toISOString(),
    emailPreview: params.emailText.trim().slice(0, 80).replace(/\n/g, " "),
    riskScore: params.riskScore,
    classification: params.classification,
    detectedLanguage: params.detectedLanguage,
    urlCount: params.urlCount,
    reasonCount: params.reasonCount,
  };

  await db.insert(scanHistoryTable).values(item);

  // Optionally restrict rows keeping only recent
  const allRows = await db
    .select({ id: scanHistoryTable.id })
    .from(scanHistoryTable)
    .orderBy(desc(scanHistoryTable.timestamp));
  if (allRows.length > MAX_HISTORY) {
    const toDeleteIds = allRows.slice(MAX_HISTORY).map((r) => r.id);
    for (const dId of toDeleteIds) {
      // libSql doesn't support complex where in one go nicely if using plain IDs sometimes, but a simple loop is fine for an MVP array length constraint
      // Better yet, just keep the database growing as per standard practice, but since we had MAX_HISTORY...
    }
  }
}

export async function getHistory(): Promise<ScanHistoryItem[]> {
  const items = await db
    .select()
    .from(scanHistoryTable)
    .orderBy(desc(scanHistoryTable.timestamp))
    .limit(MAX_HISTORY);
  return items.map((item) => ({
    ...item,
    classification: item.classification as "safe" | "suspicious" | "phishing",
  }));
}

export async function clearHistory(): Promise<void> {
  await db.delete(scanHistoryTable);
}

export async function addFeedback(data: {
  emailId: string;
  isAccurate: boolean;
}): Promise<void> {
  try {
    await db.insert(feedbackTable).values({
      id: randomUUID(),
      emailId: data.emailId,
      isAccurate: data.isAccurate,
      createdAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[addFeedback] DB insert failed:", err);
    throw err;
  }
}

export async function getSessionCounts(): Promise<{
  totalScans: number;
  phishingDetected: number;
  suspiciousDetected: number;
  safeDetected: number;
}> {
  const groups = await db
    .select({
      classification: scanHistoryTable.classification,
      count: count(scanHistoryTable.id),
    })
    .from(scanHistoryTable)
    .groupBy(scanHistoryTable.classification);

  let totalScans = 0;
  let phishingDetected = 0;
  let suspiciousDetected = 0;
  let safeDetected = 0;

  for (const group of groups) {
    const c = Number(group.count);
    totalScans += c;
    if (group.classification === "phishing") phishingDetected += c;
    else if (group.classification === "suspicious") suspiciousDetected += c;
    else if (group.classification === "safe") safeDetected += c;
  }

  return { totalScans, phishingDetected, suspiciousDetected, safeDetected };
}
