/**
 * PHISHSHIELD AI — Gmail Integration
 * 
 * This code runs inside Google's servers as a Gmail Add-on.
 * It sends the current email body to your hardened API server.
 */

const API_SERVER_URL = "http://localhost:5000/api/analyze"; // Update to your production URL after deployment
const API_KEY = "dev-sandbox-key"; // Update with your secure API key

function buildAddOn(e) {
  var messageId = e.gmail.messageId;
  var accessToken = e.gmail.accessToken;
  
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var message = GmailApp.getMessageById(messageId);
  var bodyDecoded = message.getPlainBody();
  var subject = message.getSubject();
  var from = message.getFrom();

  // Call PhishShield Engine
  try {
    var options = {
      method: "post",
      contentType: "application/json",
      headers: { "Authorization": "Bearer " + API_KEY },
      payload: JSON.stringify({ 
        emailText: `From: ${from}\nSubject: ${subject}\n\n${bodyDecoded}` 
      }),
      muteHttpExceptions: true
    };

    var response = UrlFetchApp.fetch(API_SERVER_URL, options);
    var apiData = JSON.parse(response.getContentText());

    return createCardUI(apiData);
  } catch (error) {
    return createErrorCard("PhishShield AI could not reach the analysis server. Please check your connection.");
  }
}

function createCardUI(apiData) {
  var header = CardService.newCardHeader();
  var section = CardService.newCardSection();

  var riskEmoji = "✅";
  var riskStatus = "Safe Email";
  var headerColor = "#059669"; // Green

  if (apiData.classification === "phishing") {
    riskEmoji = "🚨";
    riskStatus = "PHISHING DETECTED";
    headerColor = "#DC2626"; // Red
  } else if (apiData.classification === "suspicious") {
    riskEmoji = "⚠️";
    riskStatus = "Suspicious Email";
    headerColor = "#D97706"; // Amber
  }

  header.setTitle(riskEmoji + " " + riskStatus);
  header.setSubtitle("PhishShield AI Risk Score: " + apiData.riskScore + "/100");

  // Summary of what is happening
  section.addWidget(CardService.newTextParagraph().setText(apiData.scamStory || "Analysis complete."));

  // Detected reasons
  if (apiData.reasons && apiData.reasons.length > 0) {
    section.addWidget(CardService.newTextParagraph().setText("<b>Why we flagged this:</b>"));
    apiData.reasons.forEach(function(r) {
      section.addWidget(CardService.newTextParagraph().setText("• " + r.description));
    });
  }

  // Safety Advice
  if (apiData.safetyTips && apiData.safetyTips.length > 0) {
    section.addWidget(CardService.newTextParagraph().setText("<b>Safety Advice:</b>"));
    section.addWidget(CardService.newTextParagraph().setText(apiData.safetyTips[0]));
  }

  var card = CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();

  return card;
}

function createErrorCard(message) {
  var header = CardService.newCardHeader().setTitle("❌ Connection Error");
  var section = CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(message));
  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}
