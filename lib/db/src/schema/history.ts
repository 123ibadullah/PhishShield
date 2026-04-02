import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";

export const scanHistoryTable = sqliteTable("scan_history", {
  id: text("id").primaryKey(),
  timestamp: text("timestamp").notNull(),
  emailPreview: text("email_preview").notNull(),
  riskScore: integer("risk_score").notNull(),
  classification: text("classification").notNull(),
  detectedLanguage: text("detected_language").notNull(),
  urlCount: integer("url_count").notNull(),
  reasonCount: integer("reason_count").notNull(),
});

export const insertScanHistorySchema = createInsertSchema(scanHistoryTable);
export const selectScanHistorySchema = createSelectSchema(scanHistoryTable);

export const feedbackTable = sqliteTable("feedback", {
  id: text("id").primaryKey(),
  emailId: text("email_id").notNull(),
  isAccurate: integer("is_accurate", { mode: "boolean" }).notNull(),
  createdAt: text("created_at").notNull(),
});

export const insertFeedbackSchema = createInsertSchema(feedbackTable);
export const selectFeedbackSchema = createSelectSchema(feedbackTable);
