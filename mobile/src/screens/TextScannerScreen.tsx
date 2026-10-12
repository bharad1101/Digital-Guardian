import React, { useState } from "react";
import {
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import * as Clipboard from "expo-clipboard";

import { useAuth } from "../auth/AuthContext";
import * as api from "../api/client";
import { Button, Card, Field, Muted, SectionTitle } from "../components/ui";
import { colors, spacing } from "../theme";
import type { RootStackParamList } from "../navigation/types";

type Props = NativeStackScreenProps<RootStackParamList>;

export default function TextScannerScreen({ navigation }: Props) {
  const { token } = useAuth();
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function pasteFromClipboard() {
    setError(null);
    try {
      const value = await Clipboard.getStringAsync();
      if (!value) {
        setError("Your clipboard is empty or hasn't been shared with the app.");
        return;
      }
      setText(value);
    } catch {
      setError("Clipboard access is unavailable. Please paste manually.");
    }
  }

  async function run(kind: "text" | "url") {
    setError(null);
    const value = kind === "text" ? text : url;
    if (!value.trim()) {
      setError(kind === "text" ? "Enter a message to analyse." : "Enter a URL to analyse.");
      return;
    }
    setLoading(true);
    try {
      const result =
        kind === "text"
          ? await api.analyzeText(token, value.trim())
          : await api.analyzeUrl(token, value.trim());
      navigation.navigate("Result", { result });
    } catch (err: any) {
      setError(err.message || "Analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <KeyboardAvoidingView
      style={styles.flex}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <ScrollView contentContainerStyle={styles.container} keyboardShouldPersistTaps="handled">
        <Text style={styles.title}>Analyse content</Text>
        <Muted style={{ marginBottom: spacing(2) }}>
          Paste any suspicious message or link. Nothing is sent anywhere except your own
          Digital Guardian server.
        </Muted>

        {error ? (
          <Card>
            <Text style={{ color: colors.danger }}>{error}</Text>
          </Card>
        ) : null}

        <Card>
          <SectionTitle>Message text</SectionTitle>
          <Field
            value={text}
            onChangeText={setText}
            placeholder="Paste the SMS, WhatsApp or email text here"
            multiline
            numberOfLines={6}
            style={{ minHeight: 130, textAlignVertical: "top" }}
          />
          <View style={styles.buttonRow}>
            <View style={{ flex: 1 }}>
              <Button title="Analyse message" onPress={() => run("text")} loading={loading} />
            </View>
            <View style={{ width: spacing(1) }} />
            <View style={{ flex: 1 }}>
              <Button title="Paste from clipboard" variant="ghost" onPress={pasteFromClipboard} />
            </View>
          </View>
          <Button title="Clear" variant="ghost" onPress={() => setText("")} />
        </Card>

        <Card>
          <SectionTitle>Web link</SectionTitle>
          <Field
            value={url}
            onChangeText={setUrl}
            placeholder="https://example.com/login"
            autoCapitalize="none"
            keyboardType="url"
          />
          <Button title="Analyse link" onPress={() => run("url")} variant="ghost" />
        </Card>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: colors.bg },
  container: { padding: spacing(2) },
  title: { color: colors.text, fontSize: 24, fontWeight: "800" },
  buttonRow: { flexDirection: "row", alignItems: "stretch" },
});
