import React, { useEffect, useRef, useState } from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import { useAuth } from "../auth/AuthContext";
import * as api from "../api/client";
import { Button, Card, Muted } from "../components/ui";
import { colors, spacing } from "../theme";
import type { RootStackParamList } from "../navigation/types";

type Props = NativeStackScreenProps<RootStackParamList, "ReceiveShare">;

const URL_RE = /^https?:\/\/[^\s]+$/i;

/**
 * Entry point for shared content delivered through a deep link
 * (digitalguardian://share?text=... or ?url=...). It analyses the content
 * and pushes the standard result screen. If the shared payload is missing it
 * offers to open the Scan tab manually.
 */
export default function ReceiveShareScreen({ navigation, route }: Props) {
  const { token } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const ran = useRef(false);

  const text = route.params?.text?.trim();
  const url = route.params?.url?.trim();
  const content = url || text || "";
  const isUrl = url ? true : URL_RE.test(content);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;

    if (!content) {
      setLoading(false);
      return;
    }

    (async () => {
      try {
        const result = isUrl
          ? await api.analyzeUrl(token, content)
          : await api.analyzeText(token, content, "Shared");
        navigation.replace("Result", { result });
      } catch (err: any) {
        setError(err.message || "Could not analyse the shared content.");
      } finally {
        setLoading(false);
      }
    })();
  }, [content, isUrl, token, navigation]);

  return (
    <View style={styles.container}>
      {loading ? (
        <>
          <ActivityIndicator color={colors.primary} size="large" />
          <Muted style={{ marginTop: spacing(2) }}>Analysing shared content…</Muted>
        </>
      ) : (
        <Card>
          <Text style={styles.title}>
            {error ? "Analysis failed" : "Nothing to analyse"}
          </Text>
          <Muted>
            {error || "No text or link was included in the share request."}
          </Muted>
          <View style={{ height: spacing(1.5) }} />
          <Button
            title="Open the scanner"
            onPress={() => navigation.replace("Tabs")}
            variant="ghost"
          />
        </Card>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.bg,
    alignItems: "center",
    justifyContent: "center",
    padding: spacing(3),
  },
  title: { color: colors.text, fontWeight: "800", fontSize: 18, marginBottom: spacing(1) },
});
