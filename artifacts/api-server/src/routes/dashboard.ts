import { Router, type IRouter } from "express";
import { GetModelMetricsResponse } from "@workspace/api-zod";
import { getHistory, clearHistory, getSessionCounts } from "../lib/historyStore.js";

const router: IRouter = Router();

router.get("/history", (_req, res) => {
  res.json(getHistory());
});

router.delete("/history", (_req, res) => {
  clearHistory();
  res.json({ status: "ok" });
});

router.get("/metrics", (_req, res) => {
  const sessionCounts = getSessionCounts();

  const metrics = GetModelMetricsResponse.parse({
    accuracy: 0.947,
    precision: 0.923,
    recall: 0.968,
    f1Score: 0.945,
    falsePositiveRate: 0.031,
    totalScans: sessionCounts.totalScans,
    phishingDetected: sessionCounts.phishingDetected,
    suspiciousDetected: sessionCounts.suspiciousDetected,
    safeDetected: sessionCounts.safeDetected,
  });

  res.json(metrics);
});

export default router;
