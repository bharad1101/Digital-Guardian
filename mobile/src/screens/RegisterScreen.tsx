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
import { Button, Field, Muted } from "../components/ui";
import { colors, spacing } from "../theme";
import type { AuthStackParamList } from "../navigation/types";

type Props = NativeStackScreenProps<AuthStackParamList, "Register">;

export default function RegisterScreen({ navigation }: Props) {
  const { signUp } = useAuth();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit() {
    setError(null);
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setLoading(true);
    try {
      await signUp(name.trim(), email.trim(), password);
    } catch (err: any) {
      setError(err.message || "Registration failed.");
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
          <Text style={styles.brand}>Create account</Text>
          <Muted>Passwords must be at least 8 characters with a letter and a number.</Muted>
        </View>

        {error ? (
          <View style={styles.error}>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        ) : null}

        <Field label="Name" value={name} onChangeText={setName} placeholder="Your name" />
        <Field
          label="Email"
          value={email}
          onChangeText={setEmail}
          autoCapitalize="none"
          keyboardType="email-address"
          placeholder="you@example.com"
        />
        <Field
          label="Password"
          value={password}
          onChangeText={setPassword}
          secureTextEntry
          placeholder="Create a password"
        />
        <Field
          label="Confirm password"
          value={confirm}
          onChangeText={setConfirm}
          secureTextEntry
          placeholder="Repeat your password"
        />

        <Button title="Create account" onPress={submit} loading={loading} />

        <View style={styles.footer}>
          <Muted>Already registered?</Muted>
          <Text style={styles.link} onPress={() => navigation.navigate("Login")}>
            {" "}
            Sign in
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
  brand: { color: colors.text, fontSize: 26, fontWeight: "800", marginBottom: spacing(0.5) },
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
