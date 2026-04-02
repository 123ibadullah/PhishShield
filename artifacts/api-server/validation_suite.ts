import { analyzeEmail } from "./src/lib/phishingDetector";

const TEST_CASES = [
  // 🟢 REAL AMAZON OTP EMAIL (User provided)
  {
    name: "USER PROVIDED: REAL AMAZON OTP",
    email: `from: Amazon <account-update@amazon.com>
to: mohdibadullah75@gmail.com
date: 12 Jan 2026, 22:03
subject: Verify your new Amazon account

Amazon
Verify your new Amazon account
To verify your e-mail address, please use the following One Time Password (OTP):

960878
 
Don't share this OTP with anyone. Amazon takes your account security very seriously. Amazon Customer Service will never ask you to disclose or verify your Amazon password, OTP, credit card, or banking account number. If you receive a suspicious e-mail with a link to update your account information, do not click on the link—instead, report the e-mail to Amazon for investigation.`,
    expectedClassification: "safe",
  },

  // 🟢 REAL CURSOR SIGN-IN EMAIL (User provided)
  {
    name: "USER PROVIDED: REAL CURSOR SIGN-IN",
    email: `from: Cursor <no-reply@cursor.sh>
to: mohdibadullah75@gmail.com
date: 19 Oct 2025, 10:56
subject: Sign in to Cursor

Sign in to Cursor
You requested to sign in to Cursor. Your one-time code is:
695651
This code expires in 10 minutes.
If you didn’t request to sign in to Cursor, you can safely ignore this email. Someone else might have typed your email address by mistake.`,
    expectedClassification: "safe",
  },

  // 🔴 INDIAN INCOME TAX REFUND SCAM (Adversarial)
  {
    name: "SCAM: INCOME TAX REFUND (India)",
    email: `Subject: INCOME TAX REFUND NOTIFICATION

Dear Taxpayer,
Our records indicate that you are eligible to receive a tax refund of ₹25,480. Please click the link below to verify your PAN details and claim your refund immediately.

http://incometax-gov-in.reclaim-refund.xyz/verify
Failure to claim within 24 hours will result in forfeiture.`,
    expectedClassification: "phishing",
  },

  // 🔴 BANK PHISHING (Adversarial)
  {
    name: "SCAM: HDFC BANK ACCOUNT BLOCKED",
    email: `Subject: Urgent - Your HDFC Bank account is on hold

We noticed an unauthorized login attempt from a new IP in Russia. For your safety, we have temporarily suspended your net banking. Please log in to http://hdfcbank-netbanking.tk/secure to reactivate your access.`,
    expectedClassification: "phishing",
  },

  // 🔴 SOCIAL ENGINEERING (No Link, vishing attempt)
  {
    name: "SCAM: RBL BANK CREDIT CARD ALERT",
    email: `Subject: Important Alert: Your credit card was used for ₹89,000 on Amazon

Dear customer, a transaction of ₹89,000 was flagged on your RBL Credit card. If you did not authorize this, please call our 24/7 fraud desk at +91-987-654-3210 immediately to provide your details and stop the payment.`,
    expectedClassification: "phishing",
  },

  // 🟢 TRANSACTIONAL NOTIFICATION (Safe)
  {
    name: "SAFE: NETFLIX PAYMENT SUCCESS",
    email: `Subject: Your Netflix receipt

Hi, your payment for the monthly plan was successful. Your next billing date is Nov 1st. You don't need to do anything. Enjoy watching.`,
    expectedClassification: "safe",
  }
];

async function runVerification() {
  console.log("🏁 STARTING PHISHSHIELD AI REAL-WORLD GLOBAL VALIDATION\n");
  let passed = 0;
  let failed = 0;

  for (const test of TEST_CASES) {
    try {
      const result = await analyzeEmail(test.email);
      const isMatch = result.classification === test.expectedClassification;

      if (isMatch) {
        console.log(`✅ PASS: ${test.name}`);
        console.log(`   [Classification: ${result.classification.toUpperCase()}] (Score: ${result.riskScore}) (Reason: ${result.attackType})\n`);
        passed++;
      } else {
        console.log(`❌ FAIL: ${test.name}`);
        console.log(`   - Expected: ${test.expectedClassification}`);
        console.log(`   - Received: ${result.classification}`);
        console.log(`   - Explanation: ${result.scamStory}\n`);
        failed++;
      }
    } catch (err) {
      console.log(`💥 ERROR in ${test.name}:`, err);
      failed++;
    }
  }

  console.log(`📊 FINAL REPORT: ${passed} Passed, ${failed} Failed`);
  if (failed === 0) {
    console.log("\n✨ SYSTEM FULLY VERIFIED ON REAL-WORLD SAMPLES & ADVERSARIAL VECTORS.");
  } else {
    console.log(`\n⚠️  ${failed} CRITICAL LOGIC MISMATHCES UNDETECTED.`);
  }
}

runVerification().catch(console.error);
