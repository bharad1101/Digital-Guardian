import type { AnalysisResult, ScanSummary } from "../api/types";

export type AuthStackParamList = {
  Login: undefined;
  Register: undefined;
};

export type MainTabParamList = {
  Dashboard: undefined;
  Scan: undefined;
  Lens: undefined;
  History: undefined;
  Settings: undefined;
};

export type RootStackParamList = {
  Tabs: undefined;
  Result: { result: AnalysisResult };
  ScanDetail: { scan: ScanSummary };
  ReceiveShare: { text?: string; url?: string } | undefined;
  Privacy: undefined;
};
