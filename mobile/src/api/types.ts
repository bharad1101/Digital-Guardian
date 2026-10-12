export type ThreatLevel =
  | "SAFE"
  | "LOW_RISK"
  | "SUSPICIOUS"
  | "HIGH_RISK"
  | "CRITICAL";

export interface User {
  id: number;
  name: string;
  email: string;
  guardian_mode: boolean;
  created_at: string | null;
}

export interface UserSettings {
  notifications_enabled: boolean;
  save_history: boolean;
  retention_days: number;
}

export interface Indicator {
  type?: string;
  detail?: string;
  [key: string]: unknown;
}

export interface Payload {
  type: string;
  value: string;
  url: string | null;
}

export interface AnalysisResult {
  success: boolean;
  analysis_id?: string;
  input_type: string;
  channel: string;
  content: string;
  risk_score: number;
  rule_score: number;
  threat_level: ThreatLevel;
  threat_level_label: string;
  threat_type: string | null;
  scam_category: string | null;
  ml_prediction: string;
  ml_spam_probability: number;
  ml_available: boolean;
  indicators: string[];
  recommendations: string[];
  manipulation: Indicator[];
  evidence: Indicator[];
  explanation: string | null;
  uncertainty: string | null;
  payload?: Payload | null;
  created_at: string | null;
  saved?: boolean;
  scan_id?: number;
}

export interface ScanSummary {
  id: number;
  analysis_id: string;
  input_type: string;
  channel: string;
  content: string;
  risk_score: number;
  threat_level: ThreatLevel;
  threat_type: string | null;
  scam_category: string | null;
  created_at: string | null;
}

export interface DashboardSummary {
  total_scans: number;
  average_risk: number;
  guardian_score: number;
  level_counts: Record<string, number>;
  high_risk_count: number;
  most_common_channel: string | null;
  most_common_category: string | null;
  conclusion: string;
  recent: ScanSummary[];
}

export interface HistoryPage {
  items: ScanSummary[];
  page: number;
  pages: number;
  total: number;
}

export interface Capabilities {
  ml_model: boolean;
  ocr: boolean;
  server_qr_decode: boolean;
  remote_url_inspection: boolean;
}
