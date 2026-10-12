import React from "react";
import { Linking, Pressable, StyleSheet, Text, View } from "react-native";

import { colors, levelColor, levelLabel, radius, spacing } from "../theme";
import type { AnalysisResult } from "../api/types";
import { Card, Muted, SectionTitle } from "./ui";

export function RiskBadge({ level, score }: { level: string; score?: number }) {
  const color = levelColor[level] || colors.muted;
  return (
    <View style={{ flexDirection: "row", alignItems: "center" }}>
      <View style={[styles.badge, { borderColor: color }]}>
        <Text style={[styles.badgeText, { color }]}>{levelLabel(level)}</Text>
      </View>
      {score !== undefined ? (
        <Text style={styles.score}>{score}/100</Text>
      ) : null}
    </View>
  );
}

export function ResultView({ result }: { result: AnalysisResult }) {
  const color = levelColor[result.threat_level] || colors.muted;
  return (
    <View>
      <Card>
        <View style={styles.ring}>
          <Text style={[styles.ringScore, { color }]}>{result.risk_score}</Text>
          <Text style={styles.ringLabel}>risk score</Text>
        </View>
        <RiskBadge level={result.threat_level} />
        {result.threat_type ? (
          <Text style={styles.threatType}>{result.threat_type}</Text>
        ) : null}
        {result.content ? (
          <Muted numberOfLines={4} style={{ marginTop: spacing(1) }}>
            {result.content}
          </Muted>
        ) : null}
      </Card>

      {result.explanation ? (
        <Card>
          <SectionTitle>What this means</SectionTitle>
          <Text style={styles.body}>{result.explanation}</Text>
        </Card>
      ) : null}

      {result.indicators.length > 0 ? (
        <Card>
          <SectionTitle>Indicators</SectionTitle>
          {result.indicators.map((item, i) => (
            <View key={i} style={styles.bulletRow}>
              <Text style={[styles.bullet, { color: colors.high }]}>•</Text>
              <Text style={styles.body}>{item}</Text>
            </View>
          ))}
        </Card>
      ) : null}

      {result.recommendations.length > 0 ? (
        <Card>
          <SectionTitle>Recommended actions</SectionTitle>
          {result.recommendations.map((item, i) => (
            <View key={i} style={styles.bulletRow}>
              <Text style={[styles.bullet, { color: colors.safe }]}>✓</Text>
              <Text style={styles.body}>{item}</Text>
            </View>
          ))}
        </Card>
      ) : null}

      <Card>
        <SectionTitle>Classifier</SectionTitle>
        <Muted>
          {result.ml_available
            ? `Prediction: ${result.ml_prediction} (${(
                (result.ml_spam_probability || 0) * 100
              ).toFixed(1)}% spam probability)`
            : "The machine-learning classifier is not available on the server. Results are based on rules only."}
        </Muted>
      </Card>

      {result.payload?.url ? (
        <Card>
          <SectionTitle>QR destination</SectionTitle>
          <Muted style={{ marginBottom: spacing(1) }}>{result.payload.url}</Muted>
          <Pressable
            style={[
              styles.openBtn,
              { backgroundColor: result.risk_score >= 40 ? colors.danger : colors.primary },
            ]}
            onPress={() => Linking.openURL(result.payload!.url as string)}
          >
            <Text style={styles.openBtnText}>
              {result.risk_score >= 40 ? "Open anyway (risky)" : "Open destination"}
            </Text>
          </Pressable>
          <Muted style={{ marginTop: spacing(0.5) }}>
            Links are never opened automatically.
          </Muted>
        </Card>
      ) : null}

      {result.uncertainty ? (
        <Card>
          <Muted>{result.uncertainty}</Muted>
        </Card>
      ) : null}

      {result.saved === false ? (
        <Muted style={{ textAlign: "center", marginBottom: spacing(2) }}>
          This result was not saved to your history.
        </Muted>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    borderWidth: 1,
    borderRadius: radius.sm,
    paddingHorizontal: spacing(1),
    paddingVertical: spacing(0.5),
  },
  badgeText: {
    fontSize: 13,
    fontWeight: "700",
  },
  score: {
    color: colors.muted,
    marginLeft: spacing(1),
    fontSize: 13,
    fontWeight: "600",
  },
  ring: {
    alignItems: "center",
    marginBottom: spacing(1.5),
  },
  ringScore: {
    fontSize: 46,
    fontWeight: "800",
  },
  ringLabel: {
    color: colors.muted,
    fontSize: 13,
    textTransform: "uppercase",
    letterSpacing: 1,
  },
  threatType: {
    color: colors.text,
    fontSize: 16,
    fontWeight: "700",
    marginTop: spacing(1),
  },
  body: {
    color: colors.text,
    fontSize: 15,
    lineHeight: 21,
    flex: 1,
  },
  bulletRow: {
    flexDirection: "row",
    marginBottom: spacing(0.75),
  },
  bullet: {
    fontSize: 15,
    marginRight: spacing(1),
    fontWeight: "700",
  },
  openBtn: {
    borderRadius: radius.md,
    paddingVertical: spacing(1.25),
    alignItems: "center",
  },
  openBtnText: {
    color: colors.white,
    fontWeight: "700",
  },
});
