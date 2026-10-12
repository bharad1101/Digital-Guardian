export const colors = {
  bg: "#070b18",
  surface: "#0f1730",
  surfaceAlt: "#141d3a",
  border: "#22305a",
  text: "#e8edf7",
  muted: "#93a1c4",
  primary: "#3b82f6",
  primaryDark: "#1d4ed8",
  accent: "#22d3ee",
  safe: "#22c55e",
  low: "#84cc16",
  suspicious: "#f59e0b",
  high: "#f97316",
  critical: "#ef4444",
  danger: "#ef4444",
  white: "#ffffff",
};

export const levelColor: Record<string, string> = {
  SAFE: colors.safe,
  LOW_RISK: colors.low,
  SUSPICIOUS: colors.suspicious,
  HIGH_RISK: colors.high,
  CRITICAL: colors.critical,
};

export function levelLabel(level: string): string {
  return (
    {
      SAFE: "Safe",
      LOW_RISK: "Low Risk",
      SUSPICIOUS: "Suspicious",
      HIGH_RISK: "High Risk",
      CRITICAL: "Critical",
    }[level] || level || "Unknown"
  );
}

export const spacing = (n: number) => n * 8;
export const radius = { sm: 8, md: 12, lg: 18 };
