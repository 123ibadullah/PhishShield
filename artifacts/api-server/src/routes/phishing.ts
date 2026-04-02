import {
  Router,
  type IRouter,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import {
  AnalyzeEmailBody,
  SubmitFeedbackBody,
  GenerateReportBody,
  type AnalyzeResult,
} from "@workspace/api-zod";
import { analyzeEmail } from "../lib/phishingDetector.js";
import { cleanEmail } from "../lib/emailPreprocessor.js";
import { addToHistory, addFeedback } from "../lib/historyStore.js";
import { randomUUID } from "crypto";
import rateLimit from "express-rate-limit";
import {
  asyncHandler,
  ValidationError,
  AuthenticationError,
  InternalServerError
} from "../middlewares/errorHandler.js";
import { logger, phishingLogger } from "../lib/logger.js";

const router: IRouter = Router();

const MAX_EMAIL_LENGTH = 50_000;

// Rate limiter: Max 30 requests per minute
const analyzeLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // Limit each IP/API key to 30 requests per minute
  message: {
    error: "rate_limited",
    message: "Too many analysis requests, please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Authentication Middleware
const requireApiKey = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  const expectedKey = process.env.API_KEY || "dev-sandbox-key";

  if (
    !authHeader ||
    !authHeader.startsWith("Bearer ") ||
    authHeader.split(" ")[1] !== expectedKey
  ) {
    throw new AuthenticationError("Invalid or missing API key.");
  }

  next();
};

router.post("/analyze", analyzeLimiter, requireApiKey, asyncHandler(async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;

  // Validate request body
  const parsed = AnalyzeEmailBody.safeParse(req.body);
  if (!parsed.success) {
    throw new ValidationError("Invalid request body. Please provide emailText as a string.");
  }

  let { emailText, headers } = parsed.data;

  // Reject extremely massive inputs outright before regex mapping
  if (emailText && emailText.length > 500_000) {
    throw new ValidationError("Email length exceeds maximum safe hardware bounds (500k).");
  }

  // 1. Safe Processing pipeline
  const cleanOutput = cleanEmail(emailText);
  const safeText = cleanOutput.bodyText;
  const safeHeaders = headers || cleanOutput.rawHeaders || "";

  if (!safeText || safeText.trim().length === 0) {
    // Return a safe neutral fallback rather than crashing
    const scanId = randomUUID();
    phishingLogger.info("Empty email text after cleaning, returning safe fallback", { scanId }, correlationId);

    res.json({
      id: scanId,
      riskScore: 0,
      classification: "safe",
      confidence: 1.0,
      detectedLanguage: "en",
      reasons: [],
      suspiciousSpans: [],
      urlAnalyses: [],
      safetyTips: [
        "Message was blank or consisted entirely of removed base64 attachments.",
      ],
      warnings: [],
      mlScore: 0,
      ruleScore: 0,
      urlScore: 0,
      headerScore: 0,
      featureImportance: [],
      attackType: "Safe / Informational",
      scamStory:
        "No readable email text was found after stripping code attachments.",
    });
    return;
  }

  const scanId = randomUUID();
  phishingLogger.info("Starting email analysis", { scanId, textLength: safeText.length }, correlationId);

  let result: AnalyzeResult;
  try {
    result = await analyzeEmail(safeText, safeHeaders, scanId);

    // PERFORMANCE OPTIMIZATION:
    // In extremely rare edge-cases, mlScore or Final Score could be non-deterministic (NaN) due to tfidf divisions on empty tokens
    if (isNaN(result.riskScore)) result.riskScore = 0;
    if (!result.classification) result.classification = "safe";

    phishingLogger.info("Email analysis completed", {
      scanId,
      riskScore: result.riskScore,
      classification: result.classification,
      urlCount: result.urlAnalyses.length
    }, correlationId);
  } catch (engineError) {
    phishingLogger.error("analyzeEmail engine crashed", engineError as Error, { scanId }, correlationId);

    // Fallback valid response format
    result = {
      id: scanId,
      riskScore: 30, // Defaulting to slight risk since it broke the parser
      classification: "suspicious",
      confidence: 0,
      detectedLanguage: "en",
      reasons: [
        {
          category: "ml_score",
          description:
            "Email contains extremely complex or malformed structures that triggered analysis fallbacks.",
          severity: "low",
          matchedTerms: [],
        },
      ],
      suspiciousSpans: [],
      urlAnalyses: [],
      safetyTips: [
        "Always exercise caution with dynamically complex emails that are heavily encoded.",
      ],
      warnings: ["System Analysis Fallback triggered"],
      mlScore: 30,
      ruleScore: 0,
      urlScore: 0,
      headerScore: 0,
      featureImportance: [],
      attackType: "Social Engineering",
      scamStory:
        "This email was too complex or malformed for deep AI scanning. It has been marked suspicious by default. Please verify the sender manually.",
    };
  }

  // Send the response back immediately (Non-blocking performance)
  res.json(result);

  // Fire and forget: Persist to database async without making the user wait
  addToHistory({
    emailText,
    id: scanId,
    riskScore: result.riskScore,
    classification: result.classification,
    detectedLanguage: result.detectedLanguage,
    urlCount: result.urlAnalyses.length,
    reasonCount: result.reasons.length,
  }).catch((err) => {
    phishingLogger.error("History logging failed", err, { scanId }, correlationId);
  });
}));

router.post("/feedback", requireApiKey, asyncHandler(async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;

  const parsed = SubmitFeedbackBody.safeParse(req.body);
  if (!parsed.success) {
    throw new ValidationError("Invalid feedback payload. Expected { emailId, isAccurate }.");
  }

  const { emailId, isAccurate } = parsed.data;

  logger.info("Processing feedback", { emailId, isAccurate }, correlationId);

  await addFeedback({ emailId, isAccurate });

  res.json({ status: "ok" });
}));

router.post("/report", requireApiKey, asyncHandler(async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;

  const parsed = GenerateReportBody.safeParse(req.body);
  if (!parsed.success) {
    throw new ValidationError("Invalid report payload");
  }

  const result: any = parsed.data;

  logger.info("Generating report", {
    classification: result.classification,
    riskScore: result.riskScore
  }, correlationId);

  let reportText = `=== PHISHSHIELD AI DETAILED REPORT ===\n`;
  reportText += `Generated on: ${new Date().toISOString()}\n\n`;
  reportText += `VERDICT: ${result.classification.toUpperCase()}\n`;
  reportText += `RISK SCORE: ${result.riskScore}/100\n`;
  reportText += `CONFIDENCE: ${(result.confidence * 100).toFixed(1)}%\n\n`;

  if (result.reasons && result.reasons.length > 0) {
    reportText += `--- REASONS ---\n`;
    result.reasons.forEach((r: any) => {
      reportText += `[${r.severity.toUpperCase()}] ${r.category}: ${r.description}\n`;
      if (r.matchedTerms.length > 0)
        reportText += `Matches: ${r.matchedTerms.join(", ")}\n`;
    });
    reportText += "\n";
  }

  if (result.urlAnalyses && result.urlAnalyses.length > 0) {
    reportText += `--- LINKS DETECTED ---\n`;
    result.urlAnalyses.forEach((u: any) => {
      reportText += `URL: ${u.url}\n`;
      reportText += `Risk: ${u.isSuspicious ? "Suspicious" : "Safe"}\n`;
    });
    reportText += "\n";
  }

  res.setHeader(
    "Content-Disposition",
    "attachment; filename=phishshield-report.txt",
  );
  res.setHeader("Content-Type", "text/plain");
  res.send(reportText);
}));

export default router;
