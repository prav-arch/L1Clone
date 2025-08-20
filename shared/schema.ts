import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, decimal, boolean, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const anomalies = pgTable("anomalies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  timestamp: timestamp("timestamp").notNull().default(sql`now()`),
  type: text("type").notNull(), // 'fronthaul', 'ue_event', 'mac_address', 'protocol'
  description: text("description").notNull(),
  severity: text("severity").notNull(), // 'high', 'medium', 'low'
  source_file: text("source_file").notNull(),
  packet_number: integer("packet_number").default(1),
  mac_address: text("mac_address"),
  ue_id: text("ue_id"),
  details: jsonb("details"), // Additional structured data
  status: text("status").notNull().default('open'), // 'open', 'investigating', 'resolved'
  recommendation: text("recommendation"),
});

export const processed_files = pgTable("processed_files", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  filename: text("filename").notNull(),
  file_type: text("file_type").notNull(), // 'pcap', 'log'
  file_size: integer("file_size").notNull(),
  upload_date: timestamp("upload_date").notNull().default(sql`now()`),
  processing_status: text("processing_status").notNull().default('pending'), // 'pending', 'processing', 'completed', 'failed'
  anomalies_found: integer("anomalies_found").default(0),
  processing_time: integer("processing_time"), // in milliseconds
  error_message: text("error_message"),
});

export const sessions = pgTable("sessions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  session_id: text("session_id").notNull().unique(),
  start_time: timestamp("start_time").notNull(),
  end_time: timestamp("end_time"),
  packets_analyzed: integer("packets_analyzed").default(0),
  anomalies_detected: integer("anomalies_detected").default(0),
  source_file: text("source_file").notNull(),
});

export const metrics = pgTable("metrics", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  metric_name: text("metric_name").notNull(),
  metric_value: decimal("metric_value").notNull(),
  timestamp: timestamp("timestamp").notNull().default(sql`now()`),
  category: text("category").notNull(), // 'anomalies', 'sessions', 'files', 'performance'
});

// Insert schemas
export const insertAnomalySchema = createInsertSchema(anomalies).omit({
  id: true,
  timestamp: true,
});

export const insertProcessedFileSchema = createInsertSchema(processed_files).omit({
  id: true,
  upload_date: true,
});

export const insertSessionSchema = createInsertSchema(sessions).omit({
  id: true,
});

export const insertMetricSchema = createInsertSchema(metrics).omit({
  id: true,
  timestamp: true,
});

// Types
export type Anomaly = typeof anomalies.$inferSelect & {
  // Additional fields for LLM compatibility
  anomaly_type?: string;
  confidence_score?: number;
  detection_algorithm?: string;
  context_data?: string;
};
export type InsertAnomaly = z.infer<typeof insertAnomalySchema>;

export type ProcessedFile = typeof processed_files.$inferSelect;
export type InsertProcessedFile = z.infer<typeof insertProcessedFileSchema>;

export type Session = typeof sessions.$inferSelect;
export type InsertSession = z.infer<typeof insertSessionSchema>;

export type Metric = typeof metrics.$inferSelect;
export type InsertMetric = z.infer<typeof insertMetricSchema>;

// API Response types
export type DashboardMetrics = {
  totalAnomalies: number;
  sessionsAnalyzed: number;
  detectionRate: number;
  filesProcessed: number;
};

export type DashboardMetricsWithChanges = DashboardMetrics & {
  totalAnomaliesChange: number;
  sessionsAnalyzedChange: number;
  detectionRateChange: number;
  filesProcessedChange: number;
};

export type AnomalyTrend = {
  date: string;
  count: number;
};

export type AnomalyTypeBreakdown = {
  type: string;
  count: number;
  percentage: number;
};