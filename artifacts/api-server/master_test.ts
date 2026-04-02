import { analyzeEmail } from "./src/lib/phishingDetector";
import * as fs from 'fs';

const MASTER_TEST_SUITE = [
  // =========================================================
  // CATEGORY A: REAL USER EMAILS (MUST BE SAFE — ZERO TOLERANCE)
  // =========================================================
  {
    name: "AMAZON OTP (REAL USER EMAIL)",
    email: "From: Amazon <account-update@amazon.com>\nSubject: Verify your new Amazon account\n\nTo verify your e-mail address, please use the following One Time Password (OTP): 960878. Don't share this OTP with anyone. Amazon takes your account security very seriously. Amazon Customer Service will never ask you to disclose or verify your Amazon password. Amazon.co.uk",
    expected: "safe"
  },
  {
    name: "CURSOR SIGN-IN (REAL USER EMAIL)",
    email: "From: Cursor <no-reply@cursor.sh>\nSubject: Sign in to Cursor\nmailed-by: em175.cursor.sh\nSigned by: cursor.sh\n\nSign in to Cursor. You requested to sign in to Cursor. Your one-time code is: 695651. This code expires in 10 minutes. If you didn't request to sign in to Cursor, you can safely ignore this email. Someone else might have typed your email address by mistake.",
    expected: "safe"
  },
  {
    name: "OPENAI CHATGPT SUBSCRIPTION (REAL USER EMAIL)",
    email: "From: OpenAI <noreply@tm.openai.com>\nreply-to: support@openai.com\nSubject: ChatGPT - Your new plan\nmailed-by: mandrillapp.com\nSigned by: tm.openai.com\n\nYou've successfully subscribed to ChatGPT Go. Your subscription will automatically renew monthly. You can cancel at any time. Manage your subscription. If you have any questions, please contact us through our help center. The OpenAI Team. Order number: sub_1SPcxeC6h1nxGoI3CTe8BlfN. Order date: Nov 03, 2025. ChatGPT Go Subscription ₹399.00. Tax: ₹0.00. Discount: -₹399.00. Total: ₹0.00. Payment method Visa-8363. By subscribing, you authorize us to charge you the subscription cost automatically, charged to the payment method provided until canceled. Learn how to cancel. OpenAI · 3180 18th St Ste 100 · San Francisco, CA 94110-2042 · USA. You received this email because you have an account with OpenAI.",
    expected: "safe"
  },
  {
    name: "OPENAI WITH PHISHSHIELD ADVICE APPENDED (SELF-CONTAMINATION TEST)",
    email: "From: OpenAI <noreply@tm.openai.com>\nSubject: ChatGPT - Your new plan\n\nYou've successfully subscribed to ChatGPT Go. Your subscription will automatically renew monthly. You can cancel at any time. Order number: sub_1SPcxeC6h1nxGoI3CTe8BlfN. Payment method Visa-8363. OpenAI · USA. You received this email because you have an account with OpenAI.\n\nWhat to do next\nVerify the sender's email address carefully — scammers use lookalike addresses\nNever share OTP, PIN, password, or Aadhaar/PAN details over email\nYour bank will NEVER ask for account details via email\nCall the official helpline to confirm any urgent requests",
    expected: "safe"
  },
  {
    name: "ZOMATO PROMO (REAL USER EMAIL)",
    email: "From: Zomato <noreply@mailers.zomato.com>\nSubject: ☕️☕️☕️☕️☕️☕️\nmailed-by: em9311.mailers.zomato.com\nSigned by: mailers.zomato.com\n\nClick here to unsubscribe - unsubscribe here.",
    expected: "safe"
  },
  {
    name: "GOOGLE SECURITY ALERT (REAL)",
    email: "From: Google <no-reply@accounts.google.com>\nSubject: Security alert\n\nYour Google Account was logged in to from a new device. If this was you, you can safely ignore this email.",
    expected: "safe"
  },
  {
    name: "LEGIT PASSWORD RESET (GOOGLE)",
    email: "From: Google <no-reply@accounts.google.com>\nSubject: Google Password Reset\n\nYou recently requested to reset your password. Click here to reset it: https://myaccount.google.com/reset. If you didn't request this, ignore this email.",
    expected: "safe"
  },
  {
    name: "SPOTIFY SUBSCRIPTION RECEIPT",
    email: "From: Spotify <no-reply@spotify.com>\nSubject: Your Spotify Premium receipt\n\nThanks for being a Premium subscriber! Your subscription renewed on Jan 15, 2026. Amount: ₹119. Payment method: Mastercard ending in 4521.",
    expected: "safe"
  },

  // =========================================================
  // CATEGORY B: REAL PHISHING (MUST BE CAUGHT — ZERO TOLERANCE)
  // =========================================================
  {
    name: "FAKE AMAZON (LOOKALIKE DOMAIN)",
    email: "From: Amazon <support@amaz0n-secure.net>\nSubject: Verify your account immediately\n\nSomeone tried to access your account. Please click here to verify now: http://amaz0n-verify.xyz/login",
    expected: "phishing"
  },
  {
    name: "OTP SCAM (SEND/REPLY REQUEST)",
    email: "Subject: Urgent: Verify SBI Account\n\nDear customer, to prevent account blocking, please reply to this email with the OTP sent to your phone immediately.",
    expected: "phishing"
  },
  {
    name: "REWARD SCAM",
    email: "Subject: Congratulations! You won ₹5000 cashback\n\nYou have been selected for a special HDFC cashback reward. Click here to claim: http://hdfc-rewards.xyz",
    expected: "phishing"
  },
  {
    name: "TRUSTED SENDER + MALICIOUS LINK",
    email: "From: support@hdfcbank.com\nSubject: Important Update\n\nPlease click here to update your account: http://hdfc-update-portal.xyz",
    expected: "phishing"
  },
  {
    name: "URL AUTHORITY SPOOFING",
    email: "Subject: Google Security Alert\n\nVerify your account: http://google.com-secure-login@attacker.xyz/login",
    expected: "phishing"
  },
  {
    name: "SHORTENER + URGENCY",
    email: "Subject: KYC Pending\n\nUpdate your PAN immediately or your account will be blocked. Click here: https://bit.ly/3xYz12",
    expected: "phishing"
  },
  {
    name: "CONTEXT SMUGGLING (DISCLAIMERS HIDING ATTACK)",
    email: "Subject: Action required\n\nTo keep your account active, please reply with your bank details.\n\nWe will never ask for your password. Do not share your OTP with anyone.",
    expected: "phishing"
  },
  {
    name: "HINGLISH SCAM",
    email: "Subject: Account Blocked\n\nAapka SBI account suspend ho gaya hai. Turant apna PAN card update karein. Click here: http://sbi-kyc-verify.in",
    expected: "phishing"
  },
  {
    name: "TELUGU REWARD SCAM",
    email: "Subject: బహుమతి గెలుచుకున్నారు\n\nమీరు ₹5000 రివార్డ్ గెలుచుకున్నారు. వెంటనే క్లిక్ చేయండి: http://free-money.xyz",
    expected: "phishing"
  },

  // =========================================================
  // CATEGORY C: ANTI-EVASION
  // =========================================================
  {
    name: "ZERO-WIDTH SPACES IN OTP",
    email: "Subject: Account Alert\n\nPlease verify your O\u200BT\u200BP immediately by sending it to us.",
    expected: "phishing"
  },
  {
    name: "SPACED OUT PASSWORD REQUEST",
    email: "Subject: U r g e n t\n\nP l e a s e s h a r e y o u r p a s s w o r d n o w.",
    expected: "phishing"
  },

  // =========================================================
  // CATEGORY D: EDGE CASES
  // =========================================================
  {
    name: "EMPTY EMAIL",
    email: "",
    expected: "safe"
  },
  {
    name: "ONE WORD",
    email: "Thanks.",
    expected: "safe"
  },
  {
    name: "MASSIVE TOS UPDATE",
    email: "Subject: Terms of Service Update\n\n" + "We have updated our terms. ".repeat(500) + "Visit https://google.com/terms.",
    expected: "safe"
  },

  // =========================================================
  // CATEGORY E: SUSPICIOUS (UNCERTAIN — WARN BUT DON'T ALARM)
  // =========================================================
  {
    name: "SUSPICIOUS ACCOUNT ALERT (NO LINKS, NO SENDER)",
    email: "Subject: Unusual activity detected\n\nWe noticed unusual activity on your account. Please verify your settings.",
    expected: "suspicious"
  },
];

async function runMasterSuite() {
  const results = [];
  let failures = 0;
  for (const test of MASTER_TEST_SUITE) {
    try {
      const result = await analyzeEmail(test.email);
      const passed = result.classification === test.expected;
      if (!passed) failures++;
      results.push({
        test: test.name,
        expected: test.expected,
        actual: result.classification,
        score: result.riskScore,
        passed,
        attackType: result.attackType,
        reasons: result.reasons.map((r:any) => r.category).join(', '),
        story: !passed ? result.scamStory : undefined
      });
    } catch (e: any) {
      failures++;
      results.push({ test: test.name, error: e.message });
    }
  }

  const summary = { totalTests: MASTER_TEST_SUITE.length, passed: MASTER_TEST_SUITE.length - failures, failed: failures, results };
  fs.writeFileSync('master_results.json', JSON.stringify(summary, null, 2), 'utf-8');
}

runMasterSuite();
