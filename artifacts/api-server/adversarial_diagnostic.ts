import { analyzeEmail } from "./src/lib/phishingDetector";

const ADVERSARIAL_CASES = [
  // 🟢 CRITICAL SAFE CASES (Must pass as SAFE)
  {
    name: "AMAZON.CO.UK REAL OTP",
    email: "From: Amazon <account-update@amazon.com>\nSubject: Verify your new Amazon account\n\nTo verify your e-mail address, please use the following One Time Password (OTP): 960878. Don't share this OTP with anyone. Amazon takes your account security very seriously. Amazon Customer Service will never ask you to disclose or verify your Amazon password. Amazon.co.uk",
    expected: "safe"
  },
  {
    name: "CURSOR EM175 REAL SIGN-IN",
    email: "From: Cursor <no-reply@cursor.sh>\nSubject: Sign in to Cursor\n\nYou requested to sign in to Cursor. em175.cursor.sh code: 695651. expire in 10 minutes.",
    expected: "safe"
  },
  {
    name: "GOOGLE REAL SECURITY ALERT",
    email: "From: Google <no-reply@accounts.google.com>\nSubject: Security alert\n\nYour Google Account was logged in to from a new device. If this was you, you can safely ignore this email. If not, secure your account.",
    expected: "safe"
  },

  // 🔴 CRITICAL PHISHING CASES (Must pass as PHISHING)
  {
    name: "FAKE AMAZON OTP (PHISHING)",
    email: "From: Amazon <support@amaz0n-secure.net>\nSubject: Verify your account immediately\n\nSomeone tried to access your account. Please click here to verify now: http://amaz0n-verify.xyz/login",
    expected: "phishing"
  },
  {
    name: "OTP SCAM (DIRECT REQUEST)",
    email: "Subject: Urgent: Verify SBI Account\n\nDear customer, to prevent account blocking, please reply to this email with the OTP sent to your phone immediately.",
    expected: "phishing"
  },
  {
    name: "REWARD SCAM (FINANCIAL LURE)",
    email: "Subject: Congratulations! You won ₹5000 cashback\n\nYou have been selected for a special HDFC cashback reward. Click here to claim: http://hdfc-rewards.xyz",
    expected: "phishing"
  },

  // 🟡 SUSPICIOUS CASES
  {
    name: "SUSPICIOUS ACCOUNT ALERT",
    email: "Subject: Unusual activity detected\n\nWe noticed unusual activity on your account. Please verify your settings.",
    expected: "suspicious"
  }
];

async function runAdversarialDiagnostic() {
  console.log("🚀 PHISHSHIELD AI — GLOBAL ADVERSARIAL DIAGNOSTIC SUITE\n");

  let failures = 0;
  for (const test of ADVERSARIAL_CASES) {
    const result = await analyzeEmail(test.email);
    const passed = result.classification === test.expected;

    if (passed) {
      console.log(`✅ PASS: ${test.name}`);
      console.log(`   - Class: ${result.classification.toUpperCase()} | Score: ${result.riskScore} | Type: ${result.attackType}\n`);
    } else {
      console.log(`❌ FAIL: ${test.name}`);
      console.log(`   - Expected: ${test.expected} | Got: ${result.classification}`);
      console.log(`   - Reasons: ${result.reasons.map(r => r.category).join(", ")}`);
      console.log(`   - Story: ${result.scamStory}\n`);
      failures++;
    }
  }

  console.log(`📊 FINAL DIAGNOSTIC: ${ADVERSARIAL_CASES.length - failures}/${ADVERSARIAL_CASES.length} Cases Correct.\n`);

  if (failures === 0) {
    console.log("✨ SYSTEM FULLY VERIFIED — ZERO FALSE POSITIVES DETECTED.");
  } else {
    console.log(`⚠️  SYSTEM FAILED ${failures} CRITICAL TESTS. FURTHER HEALING REQUIRED.`);
    process.exit(1);
  }
}

runAdversarialDiagnostic().catch(err => {
  console.error(err);
  process.exit(1);
});
