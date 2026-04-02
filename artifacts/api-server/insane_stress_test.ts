import { analyzeEmail } from "./src/lib/phishingDetector";
import * as fs from 'fs';

const INSANE_TEST_CASES = [
  // =========================================================
  // CATEGORY 1: EVASION & OBFUSCATION (ADVERSARIAL ATTACKS)
  // =========================================================
  {
    name: "ZERO-WIDTH SPACES IN KEYWORDS",
    email: "Subject: Account Alert\n\nPlease verify your O\u200BT\u200BP immediately by sending it to us.",
    expected: "phishing" 
  },
  {
    name: "WEIRD CASING & SPACING",
    email: "Subject: U r g e n t\n\nP L E A S E  s h a r e  y o u r  p a s s w o r d  n o w.",
    expected: "phishing" 
  },
  {
    name: "URL AUTHORITY SPOOFING (USER@DOMAIN)",
    email: "Subject: Google Security Alert\n\nVerify your account: http://google.com-secure-login@attacker.xyz/login",
    expected: "phishing" 
  },
  {
    name: "HOMOGLYPH IN BODY (L0gIn)",
    email: "Subject: Verify Account\n\nYour account is blocked. Please l0gin to restore: http://secure-restore.net",
    expected: "phishing" 
  },
  {
    name: "REDIRECTION / SHORTENER",
    email: "Subject: KYC Pending\n\nUpdate your PAN immediately or your account will be blocked. Click here: https://bit.ly/3xYz12",
    expected: "phishing"
  },

  // =========================================================
  // CATEGORY 2: CONTEXT SMUGGLING
  // =========================================================
  {
    name: "MALICIOUS PAYLOAD WRAPPED IN SAFE DISCLAIMERS",
    email: "Subject: Action required\n\nTo keep your account active, please reply with your bank details. \n\nWe will never ask for your password. Do not share your OTP with anyone. Customer service will never call you.",
    expected: "phishing" 
  },
  {
    name: "TRUSTED DOMAIN + MALICIOUS LINK (COMPROMISED EMAIL)",
    email: "From: support@hdfcbank.com\nSubject: Important Update\n\nPlease click here to update your account: http://hdfc-update-portal.xyz",
    expected: "phishing" 
  },

  // =========================================================
  // CATEGORY 3: REAL-WORLD EDGE CASES (MUST BE SAFE)
  // =========================================================
  {
    name: "ZOMATO PROMO WITH EMOJIS (USER REPORTED)",
    email: "From: Zomato <noreply@mailers.zomato.com>\nSubject: ☕️☕️☕️☕️☕️☕️\n\nClick here to unsubscribe - unsubscribe here.",
    expected: "safe" 
  },
  {
    name: "LEGIT PASSWORD RESET (REQUESTED BY USER)",
    email: "From: Google <no-reply@accounts.google.com>\nSubject: Google Password Reset\n\nYou recently requested to reset your password. Click here to reset it: https://myaccount.google.com/reset. If you didn't request this, ignore this email.",
    expected: "safe" 
  },
  {
    name: "EMPTY EMAIL",
    email: "",
    expected: "safe" 
  },
  {
    name: "ONE WORD EMAIL",
    email: "Thanks.",
    expected: "safe"
  },
  {
    name: "MASSIVE OVERWHELMING TEXT (TOS UPDATE)",
    email: "Subject: Terms of Service Update\n\n" + "We have updated our terms. ".repeat(500) + "Please visit https://google.com/terms to read them.",
    expected: "safe"
  },

  // =========================================================
  // CATEGORY 4: REGIONAL / MULTI-LANGUAGE
  // =========================================================
  {
    name: "HINDI + ENGLISH URGENCY (HINGLISH)",
    email: "Subject: Account Blocked\n\nAapka SBI account suspend ho gaya hai. Turant apna PAN card update karein. Click here: http://sbi-kyc-verify.in",
    expected: "phishing"
  },
  {
    name: "PURE REGIONAL SCAM (TELUGU)",
    email: "Subject: బహుమతి గెలుచుకున్నారు\n\nమీరు ₹5000 రివార్డ్ గెలుచుకున్నారు. వెంటనే క్లిక్ చేయండి: http://free-money.xyz",
    expected: "phishing"
  }
];

async function runInsaneStressTest() {
  const results = [];
  let failures = 0;
  for (const test of INSANE_TEST_CASES) {
    try {
      const result = await analyzeEmail(test.email);
      const passed = result.classification === test.expected;
      if (!passed) failures++;
      results.push({
        testName: test.name,
        expected: test.expected,
        actual: result.classification,
        score: result.riskScore,
        passed,
        reasons: result.reasons.map((r:any) => r.category).join(', ')
      });
    } catch (e: any) {
      failures++;
      results.push({
        testName: test.name,
        error: e.message
      });
    }
  }

  const summary = { totalPass: INSANE_TEST_CASES.length - failures, totalFail: failures, results };
  fs.writeFileSync('stress_results.json', JSON.stringify(summary, null, 2), 'utf-8');
}

runInsaneStressTest();
