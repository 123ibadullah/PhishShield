import { analyzeEmail } from "./src/lib/phishingDetector";
import * as fs from 'fs';

/**
 * PHISHSHIELD AI — FINAL 50+ REAL-WORLD EXHAUSTIVE TEST SUITE
 * 
 * Categories:
 * A. Transactional Receipts (subscription, payment, order)
 * B. OTP / Sign-in / 2FA
 * C. Security Alerts (legit)
 * D. Marketing / Promo / Newsletter
 * E. Shipping / Delivery
 * F. Social Media Notifications
 * G. Phishing — Credential Theft
 * H. Phishing — Financial Scam / Reward
 * I. Phishing — Impersonation
 * J. Phishing — Link / Domain attacks
 * K. Phishing — India-specific (UPI/KYC/Banking)
 * L. Phishing — Multi-language (Hindi/Telugu)
 * M. Evasion / Adversarial
 * N. Edge Cases
 */

const EXHAUSTIVE_SUITE = [
  // ═══════════════════════════════════════════════════
  // A. TRANSACTIONAL RECEIPTS (ALL MUST BE SAFE)
  // ═══════════════════════════════════════════════════
  { name: "A1: OpenAI Subscription", email: "From: OpenAI <noreply@tm.openai.com>\nSubject: ChatGPT - Your new plan\n\nYou've successfully subscribed to ChatGPT Go. Your subscription will automatically renew monthly. You can cancel at any time. Order number: sub_1SPcxeC6h1nxGoI3CTe8BlfN. Payment method Visa-8363. Total: ₹0.00. You received this email because you have an account with OpenAI.", expected: "safe" },
  { name: "A2: Spotify Receipt", email: "From: Spotify <no-reply@spotify.com>\nSubject: Your Spotify Premium receipt\n\nThanks for being a Premium subscriber! Your subscription renewed on Jan 15, 2026. Amount: ₹119. Payment method: Mastercard ending in 4521.", expected: "safe" },
  { name: "A3: Netflix Invoice", email: "From: Netflix <info@mailer.netflix.com>\nSubject: Your payment was successful\n\nThank you for your payment. Your subscription has been renewed for another month. Amount charged: ₹649 to Visa ending in 1234.", expected: "safe" },
  { name: "A4: Uber Ride Receipt", email: "From: Uber <noreply@uber.com>\nSubject: Your ride receipt\n\nThanks for riding with Uber! Trip from Connaught Place to IGI Airport. Total: ₹485. Payment via UPI. Rate your driver.", expected: "safe" },
  { name: "A5: Swiggy Order", email: "From: Swiggy <noreply@swiggy.in>\nSubject: Order confirmed!\n\nYour order #SW12345 from Dominos has been placed. Estimated delivery: 35 mins. Total: ₹599. Payment via Paytm.", expected: "safe" },
  { name: "A6: Razorpay Payment", email: "From: Razorpay <noreply@razorpay.com>\nSubject: Payment receipt\n\nPayment of ₹2,499 received successfully. Transaction ID: pay_LmN0pQrStUv. Payment method: HDFC Debit Card.", expected: "safe" },
  { name: "A7: Zerodha Subscription", email: "From: Zerodha <noreply@zerodha.com>\nSubject: Your Console subscription\n\nYour Zerodha Console subscription has been renewed. Amount: ₹50/month. Deducted from your trading account.", expected: "safe" },

  // ═══════════════════════════════════════════════════
  // B. OTP / SIGN-IN / 2FA (ALL MUST BE SAFE)
  // ═══════════════════════════════════════════════════
  { name: "B1: Amazon OTP", email: "From: Amazon <account-update@amazon.com>\nSubject: Verify your new Amazon account\n\nTo verify your e-mail address, please use the following One Time Password (OTP): 960878. Don't share this OTP with anyone. Amazon Customer Service will never ask you to disclose or verify your Amazon password, OTP, credit card, or banking account number.", expected: "safe" },
  { name: "B2: Cursor Sign-in", email: "From: Cursor <no-reply@cursor.sh>\nSubject: Sign in to Cursor\n\nYou requested to sign in to Cursor. Your one-time code is: 695651. This code expires in 10 minutes. If you didn't request to sign in to Cursor, you can safely ignore this email.", expected: "safe" },
  { name: "B3: Google 2FA", email: "From: Google <no-reply@accounts.google.com>\nSubject: Your verification code\n\nYour Google verification code is 483921. Don't share this code. Google will never ask you for this code.", expected: "safe" },
  { name: "B4: Microsoft OTP", email: "From: Microsoft <account-security-noreply@accountprotection.microsoft.com>\nSubject: Microsoft account security code\n\nSecurity code: 7291. Use this code to verify your identity. If you didn't request this code, you can ignore this email.", expected: "safe" },
  { name: "B5: GitHub 2FA", email: "From: GitHub <noreply@github.com>\nSubject: Your GitHub verification code\n\nYour two-factor authentication code is 482916. This code expires in 10 minutes.", expected: "safe" },
  { name: "B6: LinkedIn OTP", email: "From: LinkedIn <security-noreply@linkedin.com>\nSubject: Your verification code\n\nHere's your verification code: 592014. This code expires in 15 minutes. If you didn't request this, ignore this email.", expected: "safe" },

  // ═══════════════════════════════════════════════════
  // C. SECURITY ALERTS (LEGIT — MUST BE SAFE)
  // ═══════════════════════════════════════════════════
  { name: "C1: Google New Device", email: "From: Google <no-reply@accounts.google.com>\nSubject: Security alert\n\nYour Google Account was just signed in to from a new Windows device. If this was you, you don't need to do anything. If not, we'll help you secure your account.", expected: "safe" },
  { name: "C2: Apple ID Login", email: "From: Apple <no-reply@email.apple.com>\nSubject: Your Apple ID was used to sign in\n\nYour Apple ID was used to sign in to iCloud via a web browser. Date: Jan 15, 2026. If this was you, you can disregard this email.", expected: "safe" },
  { name: "C3: Facebook Login Alert", email: "From: Facebook <security@facebookmail.com>\nSubject: New login to Facebook\n\nWe noticed a new login to your Facebook account. If this was you, you can ignore this email. Location: Mumbai, India. Device: Chrome on Windows.", expected: "safe" },

  // ═══════════════════════════════════════════════════
  // D. MARKETING / PROMO / NEWSLETTER (MUST BE SAFE)
  // ═══════════════════════════════════════════════════
  { name: "D1: Zomato Promo", email: "From: Zomato <noreply@mailers.zomato.com>\nSubject: ☕️☕️☕️☕️\n\nHungry? Order now and get 50% off on your first order! Use code WELCOME50. Click here to unsubscribe.", expected: "safe" },
  { name: "D2: Flipkart Sale", email: "From: Flipkart <do-not-reply@flipkart.com>\nSubject: Big Billion Days are here!\n\nShop the biggest sale of the year! Up to 80% off on electronics, fashion, and more. Sale starts midnight. Click to explore deals.", expected: "safe" },
  { name: "D3: Medium Newsletter", email: "From: Medium <noreply@medium.com>\nSubject: Daily Digest\n\nHere are today's top stories picked for you. 5 min read: How to build better habits. 3 min read: The future of AI. Unsubscribe from this email.", expected: "safe" },
  { name: "D4: CRED Cashback Promo", email: "From: CRED <noreply@cred.club>\nSubject: Pay your credit card bill & earn cashback\n\nPay your credit card bill on CRED and earn up to ₹500 cashback. Limited period offer. T&C apply.", expected: "safe" },
  { name: "D5: Google Pay Flex Promo", email: "From: Google Pay <googlepay-noreply@google.com>\nSubject: Say hello to Flex. A credit card by Google Pay\n\nBuilt on the RuPay network and issued in partnership with Axis Bank, Flex by Google Pay covers everything big and small. Every swipe earns you stars. Unlock welcome benefits worth ₹500. Apply now: https://c.gle/AEJ26qvY76wdyqCTVy0DJJbijwskZSw", expected: "safe" },

  // ═══════════════════════════════════════════════════
  // E. SHIPPING / DELIVERY (MUST BE SAFE)
  // ═══════════════════════════════════════════════════
  { name: "E1: Amazon Shipping", email: "From: Amazon <shipment-tracking@amazon.in>\nSubject: Your package is out for delivery\n\nYour order #402-1234567 is out for delivery. Expected by 8 PM today. Track your package on Amazon.", expected: "safe" },
  { name: "E2: Myntra Delivery", email: "From: Myntra <noreply@myntra.com>\nSubject: Your order has shipped!\n\nGreat news! Your order MYN-98765 has been shipped. Track your delivery. Expected delivery: Jan 20.", expected: "safe" },

  // ═══════════════════════════════════════════════════
  // F. SOCIAL MEDIA NOTIFICATIONS (MUST BE SAFE)
  // ═══════════════════════════════════════════════════
  { name: "F1: Twitter/X Notification", email: "From: X <notify@x.com>\nSubject: New follower\n\nYou have a new follower! @techguru started following you. See their profile.", expected: "safe" },
  { name: "F2: Instagram Like", email: "From: Instagram <no-reply@mail.instagram.com>\nSubject: techguy liked your photo\n\ntechguy liked your photo. See the post.", expected: "safe" },
  { name: "F3: Discord Server Invite", email: "From: Discord <noreply@discord.com>\nSubject: You've been invited to a server\n\nYou've been invited to join 'Dev Community'. Join server to start chatting.", expected: "safe" },

  // ═══════════════════════════════════════════════════
  // G. PHISHING — CREDENTIAL THEFT (MUST BE PHISHING)
  // ═══════════════════════════════════════════════════
  { name: "G1: Fake Login Page", email: "Subject: Your account has been compromised\n\nWe detected unauthorized access to your account. Click here immediately to verify: http://secure-login-verify.xyz/auth", expected: "phishing" },
  { name: "G2: Password Reset Scam", email: "Subject: Password Reset Required\n\nYour password has expired. Click to reset immediately or your account will be permanently deleted: http://account-recovery.tk/reset", expected: "phishing" },
  { name: "G3: OTP Harvest", email: "Subject: Urgent: Verify Your Account\n\nDear customer, reply to this email with the OTP sent to your phone to verify your identity and prevent account suspension.", expected: "phishing" },
  { name: "G4: Send Password Request", email: "Subject: IT Helpdesk\n\nDear employee, please send your current password so we can update your email server configuration. Reply urgently.", expected: "phishing" },

  // ═══════════════════════════════════════════════════
  // H. PHISHING — FINANCIAL SCAM / REWARD (MUST BE PHISHING)
  // ═══════════════════════════════════════════════════
  { name: "H1: Gift Card Scam", email: "Subject: Congratulations! You won ₹5000 Amazon Gift Card\n\nClaim your prize now! Click: http://amazon-gift-claim.xyz. Offer expires in 24 hours!", expected: "phishing" },
  { name: "H2: Lottery Scam", email: "Subject: You've Won $1,000,000!\n\nYou have been selected as the winner of our International Lottery. To claim, send your bank details and Aadhaar number to claims@lottery-win.tk", expected: "phishing" },
  { name: "H3: Tax Refund Scam", email: "Subject: Income Tax Refund\n\nYou are eligible for a tax refund of ₹15,000. Click here to verify your bank account: http://incometax-refund.xyz/verify", expected: "phishing" },

  // ═══════════════════════════════════════════════════
  // I. PHISHING — IMPERSONATION (MUST BE PHISHING)
  // ═══════════════════════════════════════════════════
  { name: "I1: Fake HDFC", email: "From: HDFC Bank <support@hdfc-secure.tk>\nSubject: Critical Alert\n\nYour HDFC account is blocked due to suspicious activity. Update your KYC immediately: http://hdfc-kyc-update.xyz", expected: "phishing" },
  { name: "I2: Fake SBI", email: "From: SBI <alert@sbi-net.ml>\nSubject: Account Suspended\n\nYour SBI account has been suspended. Click to reactivate: http://sbi-reactivate.ga/login", expected: "phishing" },
  { name: "I3: Fake PayPal", email: "From: PayPal <service@paypa1-secure.xyz>\nSubject: Unusual Activity\n\nWe noticed unusual activity in your PayPal account. Verify now: http://paypa1-verify.xyz", expected: "phishing" },

  // ═══════════════════════════════════════════════════
  // J. PHISHING — LINK / DOMAIN ATTACKS (MUST BE PHISHING)
  // ═══════════════════════════════════════════════════
  { name: "J1: URL Authority Spoof", email: "Subject: Verify Account\n\nClick to verify: http://accounts.google.com@evil-site.xyz/login", expected: "phishing" },
  { name: "J2: Shortener + Urgency", email: "Subject: Your account will be deleted\n\nAct now or lose access permanently. Verify: https://bit.ly/3abc123", expected: "phishing" },
  { name: "J3: Homoglyph Domain", email: "Subject: Amazon Order Issue\n\nThere's a problem with your recent order. Verify at http://amaz0n-orders.net/verify", expected: "phishing" },
  { name: "J4: Trusted Sender + Bad Link", email: "From: support@hdfcbank.com\nSubject: Important Update\n\nUpdate your details here: http://hdfc-portal-update.xyz/account", expected: "phishing" },

  // ═══════════════════════════════════════════════════
  // K. INDIA-SPECIFIC (UPI/KYC/BANKING)
  // ═══════════════════════════════════════════════════
  { name: "K1: Fake KYC", email: "Subject: Complete your KYC\n\nDear customer, your Paytm KYC is incomplete. Complete now or wallet will be blocked: http://paytm-kyc.tk/update", expected: "phishing" },
  { name: "K2: UPI Fraud", email: "Subject: UPI Payment Failed\n\nYour UPI payment of ₹5000 failed. To resolve, share your UPI PIN by replying to this email immediately.", expected: "phishing" },
  { name: "K3: Aadhaar Scam", email: "Subject: Aadhaar Update Required\n\nYour Aadhaar card needs to be updated urgently. Send your Aadhaar number and date of birth to avoid service disruption.", expected: "phishing" },
  { name: "K4: PAN Verification", email: "Subject: PAN Card Verification\n\nYour PAN card is not linked to your bank account. Click to link: http://pan-link-verify.xyz/update", expected: "phishing" },

  // ═══════════════════════════════════════════════════
  // L. MULTI-LANGUAGE (HINDI/TELUGU)
  // ═══════════════════════════════════════════════════
  { name: "L1: Hindi Banking Scam", email: "Subject: खाता बंद\n\nआपका SBI खाता तुरंत बंद हो जाएगा। अभी अपना KYC अपडेट करें: http://sbi-kyc.xyz", expected: "phishing" },
  { name: "L2: Hinglish OTP Scam", email: "Subject: Account Blocked\n\nAapka account suspend ho gaya hai. Turant apna OTP share karein neeche diye number pe: 9876543210", expected: "phishing" },
  { name: "L3: Telugu Reward", email: "Subject: బహుమతి\n\nమీరు ₹10000 రివార్డ్ గెలుచుకున్నారు! వెంటనే క్లిక్ చేయండి: http://free-money.xyz", expected: "phishing" },

  // ═══════════════════════════════════════════════════
  // M. EVASION / ADVERSARIAL
  // ═══════════════════════════════════════════════════
  { name: "M1: Zero-Width OTP", email: "Subject: Alert\n\nPlease verify your O\u200BT\u200BP immediately by sending it to us.", expected: "phishing" },
  { name: "M2: Spaced Password", email: "Subject: Urgent\n\nP l e a s e s h a r e y o u r p a s s w o r d n o w.", expected: "phishing" },
  { name: "M3: Disclaimers Hiding Attack", email: "Subject: Action required\n\nReply with your bank details to keep your account active.\n\nWe will never ask for your password. Do not share your OTP.", expected: "phishing" },
  { name: "M4: Self-Contamination Test", email: "From: OpenAI <noreply@tm.openai.com>\nSubject: Receipt\n\nYou subscribed to ChatGPT Plus. Total: ₹0.\n\nWhat to do next\nNever share OTP, PIN, password, or Aadhaar/PAN details over email\nCall the official helpline to confirm any urgent requests", expected: "safe" },

  // ═══════════════════════════════════════════════════
  // N. EDGE CASES
  // ═══════════════════════════════════════════════════
  { name: "N1: Empty", email: "", expected: "safe" },
  { name: "N2: Single Word", email: "Hello.", expected: "safe" },
  { name: "N3: Just Numbers", email: "123456789", expected: "safe" },
  { name: "N4: Just URL (safe)", email: "https://google.com", expected: "safe" },
  { name: "N5: Just URL (malicious)", email: "http://evil-site.xyz/login", expected: "phishing" },
  { name: "N6: Massive Email", email: "Subject: TOS\n\n" + "Updated terms apply. ".repeat(1000), expected: "safe" },

  // ═══════════════════════════════════════════════════
  // O. SUSPICIOUS ZONE (WARN BUT DON'T ALARM)
  // ═══════════════════════════════════════════════════
  { name: "O1: Vague Account Alert", email: "Subject: Unusual activity\n\nWe noticed unusual activity on your account. Please review your settings.", expected: "suspicious" },
];

async function runExhaustiveSuite() {
  const results: any[] = [];
  let pass = 0, fail = 0;

  for (const test of EXHAUSTIVE_SUITE) {
    try {
      const r = await analyzeEmail(test.email);
      const ok = r.classification === test.expected;
      if (ok) pass++; else fail++;
      results.push({
        test: test.name,
        expected: test.expected,
        actual: r.classification,
        score: r.riskScore,
        passed: ok,
        attackType: r.attackType,
        ...(ok ? {} : { reasons: r.reasons.map((x:any) => x.category).join(', '), story: r.scamStory })
      });
    } catch (e: any) {
      fail++;
      results.push({ test: test.name, error: e.message });
    }
  }

  const summary = { total: EXHAUSTIVE_SUITE.length, pass, fail, results };
  fs.writeFileSync('exhaustive_results.json', JSON.stringify(summary, null, 2), 'utf-8');
}

runExhaustiveSuite();
