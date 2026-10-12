import React, { useEffect, useState } from "react";
import {
  Alert,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import { useAuth } from "../auth/AuthContext";
import * as api from "../api/client";
import type { AnalysisResult } from "../api/types";
import { ResultView } from "../components/ResultView";
import { Button, Card, Muted } from "../components/ui";
import { colors, spacing } from "../theme";
import type { RootStackParamList } from "../navigation/types";
import { summaryText } from "./ResultScreen";

type Props = NativeStackScreenProps<RootStackParamList, "ScanDetail">;

/**
 * Reconstruct a full result view from a stored scan by fetching the detail
 * endpoint (which returns the complete stored analysis). Falls back to the
 * summary passed through navigation if the detail call fails.
 */
export default function ScanDetailScreen({ navigation, route }: Props) {
  const { token } = useAuth();
  const { scan } = route.params;
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      if (!token) return;
      try {
        const full = await api.getScan(token, scan.id);
        if (active) {
          setResult({
            ...(full as unknown as AnalysisResult),
            success: true,
            threat_level_label: full.threat_level,
            content: full.content,
            rule_score: 0,
            ml_prediction: "UNKNOWN",
            ml_spam_probability: 0,
            ml_available: false,
            indicators: [],
            recommendations: [],
            manipulation: [],
            evidence: [],
            explanation: null,
            uncertainty:
              "This is a stored analysis result. Automated analysis is advisory and not a guarantee of safety.",
          });
        }
      } catch (err: any) {
        if (active) setError(err.message || "Could not load this scan.");
      }
    })();
    return () => {
      active = false;
    };
  }, [token, scan.id]);

  function confirmDelete() {
    if (!token) return;
    Alert.alert("Delete scan", "Remove this scan from your history?", [
      { text: "Cancel", style: "cancel" },
      {
        text: "Delete",
        style: "destructive",
        onPress: async () => {
          try {
            await api.deleteScan(token, scan.id);
            navigation.goBack();
          } catch (err: any) {
            Alert.alert("Delete failed", err.message || "Please try again.");
          }
        },
      },
    ]);
  }

  return (
    <ScrollView style={styles.flex} contentContainerStyle={styles.container}>
      {result ? (
        <ResultView result={result} />
      ) : (
        <Card>
          <Text style={styles.title}>
            {scan.input_type.toUpperCase()} · {scan.channel}
          </Text>
          <Muted>{scan.content}</Muted>
          <Text style={styles.score}>
            Risk {scan.risk_score}/100 · {scan.threat_level}
          </Text>
          {scan.threat_type ? <Muted>{scan.threat_type}</Muted> : null}
          {error ? <Text style={{ color: colors.danger, marginTop: spacing(1) }}>{error}</Text> : null}
        </Card>
      )}

      {result ? (
        <Muted style={styles.summary}>{summaryText(result)}</Muted>
      ) : null}

      <Button title="Delete this scan" variant="danger" onPress={confirmDelete} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: colors.bg },
  container: { padding: spacing(2) },
  title: { color: colors.text, fontWeight: "800", marginBottom: spacing(0.5) },
  score: { color: colors.text, fontWeight: "700", marginTop: spacing(1) },
  summary: {
    fontSize: 12,
    lineHeight: 18,
    backgroundColor: colors.surface,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 12,
    padding: spacing(1.5),
    marginBottom: spacing(2),
  },
});
