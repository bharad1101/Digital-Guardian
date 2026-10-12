import React, { useEffect, useState } from "react";
import {
  Alert,
  Linking,
  Platform,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  View,
} from "react-native";
import { useNavigation } from "@react-navigation/native";

import { useAuth } from "../auth/AuthContext";
import * as api from "../api/client";
import { Button, Card, Field, Muted, SectionTitle } from "../components/ui";
import { colors, spacing } from "../theme";

export default function SettingsScreen() {
  const { token, user, settings, signOut, setSettings, setUser } = useAuth();
  const navigation = useNavigation<any>();

  const [name, setName] = useState(user?.name ?? "");
  const [notifications, setNotifications] = useState(settings?.notifications_enabled ?? true);
  const [saveHistory, setSaveHistory] = useState(settings?.save_history ?? true);
  const [guardian, setGuardian] = useState(user?.guardian_mode ?? true);
  const [baseUrl, setBaseUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getBaseUrl().then(setBaseUrl);
  }, []);

  useEffect(() => {
    if (settings) {
      setNotifications(settings.notifications_enabled);
      setSaveHistory(settings.save_history);
    }
    if (user) {
      setName(user.name);
      setGuardian(user.guardian_mode);
    }
  }, [settings, user]);

  async function saveProfile() {
    if (!token) return;
    setSaving(true);
    setMessage(null);
    setError(null);
    try {
      const res = await api.updateSettings(token, {
        name: name.trim(),
        notifications_enabled: notifications,
        save_history: saveHistory,
        guardian_mode: guardian,
      });
      setSettings(res.settings);
      setUser(res.user);
      setMessage("Settings saved.");
    } catch (err: any) {
      setError(err.message || "Could not save settings.");
    } finally {
      setSaving(false);
    }
  }

  async function saveServer() {
    setMessage(null);
    setError(null);
    await api.setBaseUrl(baseUrl);
    try {
      await api.health();
      setMessage("Server address saved and reachable.");
    } catch (err: any) {
      setError(err.message || "Saved, but the server could not be reached.");
    }
  }

  async function deleteAllHistory() {
    if (!token) return;
    Alert.alert("Delete all history", "Delete every saved scan? This cannot be undone.", [
      { text: "Cancel", style: "cancel" },
      {
        text: "Delete all",
        style: "destructive",
        onPress: async () => {
          try {
            const res = await api.deleteAllHistory(token);
            setMessage(`Deleted ${res.deleted} scan(s).`);
          } catch (err: any) {
            setError(err.message || "Delete failed.");
          }
        },
      },
    ]);
  }

  function confirmSignOut() {
    Alert.alert("Sign out", "Sign out of Digital Guardian?", [
      { text: "Cancel", style: "cancel" },
      { text: "Sign out", style: "destructive", onPress: () => signOut() },
    ]);
  }

  return (
    <ScrollView style={styles.flex} contentContainerStyle={styles.container}>
      <Text style={styles.title}>Settings</Text>

      {message ? (
        <Card>
          <Text style={{ color: colors.safe }}>{message}</Text>
        </Card>
      ) : null}
      {error ? (
        <Card>
          <Text style={{ color: colors.danger }}>{error}</Text>
        </Card>
      ) : null}

      <Card>
        <SectionTitle>Account</SectionTitle>
        <Field label="Display name" value={name} onChangeText={setName} />
        <Muted>{user?.email}</Muted>
      </Card>

      <Card>
        <SectionTitle>Privacy</SectionTitle>
        <View style={styles.switchRow}>
          <View style={{ flex: 1 }}>
            <Text style={styles.switchLabel}>Save scan history</Text>
            <Muted>Store each analysis result so you can review it later.</Muted>
          </View>
          <Switch value={saveHistory} onValueChange={setSaveHistory} />
        </View>

        <View style={styles.switchRow}>
          <View style={{ flex: 1 }}>
            <Text style={styles.switchLabel}>Notifications</Text>
            <Muted>Allow alerts about completed analyses and Guardian events.</Muted>
          </View>
          <Switch value={notifications} onValueChange={setNotifications} />
        </View>

        <View style={styles.switchRow}>
          <View style={{ flex: 1 }}>
            <Text style={styles.switchLabel}>Guardian mode</Text>
            <Muted>
              Enables user-initiated analysis shortcuts. It does not run covert
              background monitoring (Android restricts background work).
            </Muted>
          </View>
          <Switch value={guardian} onValueChange={setGuardian} />
        </View>
      </Card>

      <Card>
        <SectionTitle>Server</SectionTitle>
        <Muted style={{ marginBottom: spacing(1) }}>
          {Platform.OS === "android"
            ? "Android emulator reaches your computer at 10.0.2.2. On a physical phone use your computer's LAN IP, e.g. http://192.168.1.20:5000."
            : "On a physical device use your computer's LAN IP, e.g. http://192.168.1.20:5000 (localhost refers to the phone itself)."}
        </Muted>
        <Field
          value={baseUrl}
          onChangeText={setBaseUrl}
          autoCapitalize="none"
          keyboardType="url"
          placeholder="http://192.168.1.20:5000"
        />
        <Button title="Save server address" variant="ghost" onPress={saveServer} />
      </Card>

      <Card>
        <SectionTitle>Data</SectionTitle>
        <Button title="Delete all scan history" variant="danger" onPress={deleteAllHistory} />
      </Card>

      <Card>
        <SectionTitle>About</SectionTitle>
        <Muted>
          Digital Guardian analyses messages, links and QR codes and explains the
          risks. Results are advisory only and are not a guarantee of safety.
          Links and files are never opened or executed automatically.
        </Muted>
        <Muted style={{ marginTop: spacing(1) }}>
          <Text
            style={styles.link}
            onPress={() => navigation.navigate("Privacy")}
          >
            Privacy &amp; security information
          </Text>
        </Muted>
      </Card>

      <Button title="Sign out" variant="ghost" onPress={confirmSignOut} />
      <Text style={styles.version}>Digital Guardian 1.0.0</Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: colors.bg },
  container: { padding: spacing(2) },
  title: { color: colors.text, fontSize: 24, fontWeight: "800", marginBottom: spacing(1) },
  switchRow: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: spacing(1.5),
  },
  switchLabel: { color: colors.text, fontWeight: "600", marginBottom: 2 },
  link: { color: colors.primary, fontWeight: "700" },
  version: {
    color: colors.muted,
    fontSize: 12,
    textAlign: "center",
    marginTop: spacing(2),
  },
});
