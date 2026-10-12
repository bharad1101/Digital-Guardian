import React from "react";
import { ScrollView, Share, StyleSheet, Text } from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";
import * as Clipboard from "expo-clipboard";

import { ResultView } from "../components/ResultView";
import { Button, Muted } from "../components/ui";
import { colors, spacing } from "../theme";
import type { RootStackParamList } from "../navigation/types";
import type { AnalysisResult } from "../api/types";

type Props = NativeStackScreenProps<RootStackParamList, "Result">;

export function summaryText(result: AnalysisResult): string {
  const lines = [
    "Digital Guardian analysis",
    `Risk: ${result.risk_score}/100 (${result.threat_level_label})`,
  ];
  if (result.threat_type) lines.push(`Type: ${result.threat_type}`);
  if (result.indicators?.length) {
    lines.push("Indicators:");
    result.indicators.forEach((i) => lines.push(`- ${i}`));
  }
  if (result.recommendations?.length) {
    lines.push("Recommended actions:");
    result.recommendations.forEach((r) => lines.push(`- ${r}`));
  }
  lines.push(
    "Advisory only: automated analysis is not a guarantee of safety. Verify independently.",
  );
  return lines.join("\n");
}

export default function ResultScreen({ navigation, route }: Props) {
  const { result } = route.params;

  async function copySummary() {
    await Clipboard.setStringAsync(summaryText(result));
  }

  async function shareSummary() {
    try {
      await Share.share({ message: summaryText(result) });
    } catch {
      // user dismissed
    }
  }

  return (
    <ScrollView style={styles.flex} contentContainerStyle={styles.container}>
      <ResultView result={result} />

      <Button title="Copy summary" variant="ghost" onPress={copySummary} />
      <Button title="Share summary" variant="ghost" onPress={shareSummary} />
      <Button title="Analyse another item" onPress={() => navigation.navigate("Tabs")} />

      <Text style={styles.footnote}>
        Digital Guardian never opens links or files automatically. Results are
        advisory and cannot detect every threat.
      </Text>
      <Muted style={{ textAlign: "center" }}>
        {result.analysis_id ? `ID ${result.analysis_id.slice(0, 12)}` : ""}
      </Muted>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: colors.bg },
  container: { padding: spacing(2) },
  footnote: {
    color: colors.muted,
    fontSize: 12,
    textAlign: "center",
    marginTop: spacing(2),
    marginBottom: spacing(1),
  },
});
