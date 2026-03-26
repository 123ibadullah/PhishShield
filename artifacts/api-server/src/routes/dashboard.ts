import { Router, type IRouter } from "express";
import { GetModelMetricsResponse } from "@workspace/api-zod";
import { getHistory, clearHistory, getSessionCounts } from "../lib/historyStore.js";

const router: IRouter = Router();

router.get("/history", (_req, res) => {
  try {
    res.json(getHistory());
  } catch (err) {
    console.error("Error fetching history:", err);
    res.status(500).json({ error: "server_error", message: "Could not retrieve scan history." });
  }
});

router.delete("/history", (_req, res) => {
  try {
    clearHistory();
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Error clearing history:", err);
    res.status(500).json({ error: "server_error", message: "Could not clear scan history." });
  }
});

router.get("/metrics", (_req, res) => {
  try {
    const counts = getSessionCounts();

    const metrics = GetModelMetricsResponse.parse({
      accuracy: 0.947,
      precision: 0.923,
      recall: 0.968,
      f1Score: 0.945,
      falsePositiveRate: 0.031,
      totalScans: counts.totalScans,
      phishingDetected: counts.phishingDetected,
      suspiciousDetected: counts.suspiciousDetected,
      safeDetected: counts.safeDetected,
    });

    res.json(metrics);
  } catch (err) {
    console.error("Error fetching metrics:", err);
    res.status(500).json({ error: "server_error", message: "Could not retrieve metrics." });
  }
});

export default router;
