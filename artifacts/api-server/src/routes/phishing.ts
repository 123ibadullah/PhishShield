import { Router, type IRouter } from "express";
import { AnalyzeEmailBody } from "@workspace/api-zod";
import { analyzeEmail } from "../lib/phishingDetector.js";
import { addToHistory } from "../lib/historyStore.js";

const router: IRouter = Router();

const MAX_EMAIL_LENGTH = 50_000;

router.post("/analyze", (req, res) => {
  try {
    const parsed = AnalyzeEmailBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: "validation_error",
        message: "Invalid request body. Please provide emailText as a string.",
      });
      return;
    }

    let { emailText } = parsed.data;

    if (!emailText || emailText.trim().length === 0) {
      res.status(400).json({
        error: "empty_input",
        message: "Email text cannot be empty.",
      });
      return;
    }

    // Trim silently rather than rejecting — very long emails are rare but shouldn't crash the server
    if (emailText.length > MAX_EMAIL_LENGTH) {
      emailText = emailText.slice(0, MAX_EMAIL_LENGTH);
    }

    const result = analyzeEmail(emailText);

    addToHistory({
      emailText,
      riskScore: result.riskScore,
      classification: result.classification,
      detectedLanguage: result.detectedLanguage,
      urlCount: result.urlAnalyses.length,
      reasonCount: result.reasons.length,
    });

    res.json(result);
  } catch (err) {
    console.error("Error analyzing email:", err);
    res.status(500).json({
      error: "analysis_failed",
      message: "An error occurred during analysis. Please try again.",
    });
  }
});

export default router;
