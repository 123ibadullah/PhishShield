import { Router, type IRouter } from "express";
import { AnalyzeEmailBody } from "@workspace/api-zod";
import { analyzeEmail } from "../lib/phishingDetector.js";

const router: IRouter = Router();

router.post("/analyze", (req, res) => {
  try {
    const parsed = AnalyzeEmailBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: "validation_error",
        message: "Invalid request body. Please provide emailText.",
      });
      return;
    }

    const { emailText } = parsed.data;

    if (!emailText || emailText.trim().length === 0) {
      res.status(400).json({
        error: "empty_input",
        message: "Email text cannot be empty.",
      });
      return;
    }

    if (emailText.length > 50000) {
      res.status(400).json({
        error: "input_too_long",
        message: "Email text is too long. Maximum 50,000 characters.",
      });
      return;
    }

    const result = analyzeEmail(emailText);
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
