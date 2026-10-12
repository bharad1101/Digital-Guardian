import React, { useCallback, useState } from "react";
import {
  RefreshControl,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { useFocusEffect } from "@react-navigation/native";

import { useAuth } from "../auth/AuthContext";
import * as api from "../api/client";
import type { DashboardSummary } from "../api/types";
import { Card, Muted, SectionTitle } from "../components/ui";
import { RiskBadge } from "../components/ResultView";
import { colors, spacing } from "../theme";

export default function DashboardScreen() {
  const { token, user } = useAuth();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      setSummary(await api.getDashboard(token));
    } catch (err: any) {
      setError(err.message || "Could not load dashboard.");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useFocusEffect(
    useCallback(() => {
      load();
    }, [load]),
  );

  return (
    <ScrollView
      style={styles.flex}
      contentContainerStyle={styles.container}
      refreshControl={<RefreshControl refreshing={loading} onRefresh={load} tintColor={colors.text} />}
    >
      <Text style={styles.hello}>Hello, {user?.name ?? "there"}</Text>
      <Muted>Your personal threat overview</Muted>

      {error ? (
        <Card>
          <Text style={{ color: colors.danger }}>{error}</Text>
        </Card>
      ) : null}

      {summary ? (
        <>
          <Card style={styles.statsRow}>
            <View style={styles.stat}>
              <Text style={styles.statValue}>{summary.total_scans}</Text>
              <Muted>Analysed</Muted>
            </View>
            <View style={styles.stat}>
              <Text style={styles.statValue}>{summary.average_risk}</Text>
              <Muted>Avg risk</Muted>
            </View>
            <View style={styles.stat}>
              <Text style={[styles.statValue, { color: colors.safe }]}>
                {summary.guardian_score}
              </Text>
              <Muted>Guardian</Muted>
            </View>
          </Card>

          <Card>
            <SectionTitle>Assessment</SectionTitle>
            <Text style={styles.conclusion}>{summary.conclusion}</Text>
          </Card>

          <Card>
            <SectionTitle>Recent activity</SectionTitle>
            {summary.recent.length === 0 ? (
              <Muted>No scans yet. Use the Scan tab to analyse content.</Muted>
            ) : (
              summary.recent.map((scan) => (
                <View key={scan.id} style={styles.recentRow}>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.recentTitle} numberOfLines={1}>
                      {scan.input_type.toUpperCase()} · {scan.channel}
                    </Text>
                    <Muted numberOfLines={1}>{scan.content}</Muted>
                  </View>
                  <RiskBadge level={scan.threat_level} score={scan.risk_score} />
                </View>
              ))
            )}
          </Card>
        </>
      ) : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: colors.bg },
  container: { padding: spacing(2) },
  hello: { color: colors.text, fontSize: 24, fontWeight: "800" },
  statsRow: { flexDirection: "row", justifyContent: "space-around" },
  stat: { alignItems: "center" },
  statValue: { color: colors.text, fontSize: 26, fontWeight: "800" },
  conclusion: { color: colors.text, fontSize: 15, lineHeight: 21 },
  recentRow: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: spacing(1),
    borderTopWidth: 1,
    borderTopColor: colors.border,
  },
  recentTitle: { color: colors.text, fontWeight: "700", marginBottom: 2 },
});
