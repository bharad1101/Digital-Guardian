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

import { useAuth } from "../auth/AuthContext";
import { Button, Field, Muted, styles as ui } from "../components/ui";
import { colors, spacing } from "../theme";
import type { AuthStackParamList } from "../navigation/types";

type Props = NativeStackScreenProps<AuthStackParamList, "Login">;

export default function LoginScreen({ navigation }: Props) {
  const { signIn } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit() {
    setError(null);
    setLoading(true);
    try {
      await signIn(email.trim(), password);
    } catch (err: any) {
      setError(err.message || "Login failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <KeyboardAvoidingView
      style={styles.flex}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <ScrollView contentContainerStyle={styles.container}>
        <View style={styles.header}>
          <Text style={styles.brand}>Digital Guardian</Text>
          <Muted>Sign in to analyse messages, links and QR codes.</Muted>
        </View>

        {error ? (
          <View style={styles.error}>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        ) : null}

        <Field
          label="Email"
          value={email}
          onChangeText={setEmail}
          autoCapitalize="none"
          keyboardType="email-address"
          autoComplete="email"
          placeholder="you@example.com"
        />
        <Field
          label="Password"
          value={password}
          onChangeText={setPassword}
          secureTextEntry
          placeholder="Your password"
        />

        <Button title="Sign in" onPress={submit} loading={loading} />

        <View style={styles.footer}>
          <Muted>New to Digital Guardian?</Muted>
          <Text style={styles.link} onPress={() => navigation.navigate("Register")}>
            {" "}
            Create an account
          </Text>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: colors.bg },
  container: { padding: spacing(3), justifyContent: "center", flexGrow: 1 },
  header: { marginBottom: spacing(3) },
  brand: { color: colors.text, fontSize: 28, fontWeight: "800", marginBottom: spacing(0.5) },
  error: {
    backgroundColor: "rgba(239,68,68,0.12)",
    borderColor: colors.danger,
    borderWidth: 1,
    borderRadius: 12,
    padding: spacing(1.5),
    marginBottom: spacing(2),
  },
  errorText: { color: colors.danger },
  footer: {
    flexDirection: "row",
    justifyContent: "center",
    marginTop: spacing(2),
    flexWrap: "wrap",
  },
  link: { color: colors.primary, fontWeight: "700" },
});
