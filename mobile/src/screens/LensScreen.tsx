import React, { useRef, useState } from "react";
import {
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { CameraView, useCameraPermissions } from "expo-camera";
import * as ImagePicker from "expo-image-picker";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import { useAuth } from "../auth/AuthContext";
import * as api from "../api/client";
import { Button, Card, Field, Muted, SectionTitle } from "../components/ui";
import { colors, radius, spacing } from "../theme";
import type { RootStackParamList } from "../navigation/types";

type Props = NativeStackScreenProps<RootStackParamList>;

export default function LensScreen({ navigation }: Props) {
  const { token } = useAuth();
  const [permission, requestPermission] = useCameraPermissions();
  const [scanning, setScanning] = useState(false);
  const [manual, setManual] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const handled = useRef(false);

  async function analyzePayload(payload: string) {
    setError(null);
    if (!payload.trim()) {
      setError("Enter or scan a QR payload first.");
      return;
    }
    setLoading(true);
    try {
      const result = await api.analyzeQr(token, payload.trim());
      navigation.navigate("Result", { result });
    } catch (err: any) {
      setError(err.message || "Analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  function onBarcodeScanned({ data }: { data: string }) {
    if (handled.current) return;
    handled.current = true;
    setScanning(false);
    analyzePayload(data).finally(() => {
      setTimeout(() => {
        handled.current = false;
      }, 1500);
    });
  }

  async function scanFromGallery() {
    setError(null);
    const perm = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (!perm.granted) {
      setError("Photo library permission is required to analyse an image.");
      return;
    }
    const picked = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ["images"],
      quality: 1,
    });
    if (picked.canceled || !picked.assets?.length) return;
    const asset = picked.assets[0];
    setLoading(true);
    try {
      const result = await api.analyzeImage(token, {
        uri: asset.uri,
        name: asset.fileName || "image.jpg",
        type: asset.mimeType || "image/jpeg",
      });
      navigation.navigate("Result", { result });
    } catch (err: any) {
      setError(err.message || "Could not analyse the image.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>Guardian Lens</Text>
      <Muted style={{ marginBottom: spacing(2) }}>
        Point the camera at a QR code, upload a screenshot, or paste a payload.
      </Muted>

      {error ? (
        <Card>
          <Text style={{ color: colors.danger }}>{error}</Text>
        </Card>
      ) : null}

      <Card>
        <SectionTitle>Camera scanner</SectionTitle>
        {!permission ? (
          <Muted>Checking camera permission…</Muted>
        ) : !permission.granted ? (
          <View>
            <Muted style={{ marginBottom: spacing(1) }}>
              Camera access is needed to scan QR codes.
            </Muted>
            <Button title="Grant camera permission" onPress={requestPermission} />
          </View>
        ) : scanning ? (
          <View>
            <View style={styles.cameraWrap}>
              <CameraView
                style={styles.camera}
                facing="back"
                barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
                onBarcodeScanned={onBarcodeScanned}
              />
            </View>
            <Button title="Stop camera" variant="ghost" onPress={() => setScanning(false)} />
          </View>
        ) : (
          <Button title="Start camera" onPress={() => setScanning(true)} />
        )}
      </Card>

      <Card>
        <SectionTitle>From a screenshot</SectionTitle>
        <Muted style={{ marginBottom: spacing(1) }}>
          Choose an image; any QR code or text found in it will be analysed.
        </Muted>
        <Button
          title="Choose image"
          variant="ghost"
          onPress={scanFromGallery}
          loading={loading}
        />
      </Card>

      <Card>
        <SectionTitle>Paste a payload</SectionTitle>
        <Field
          value={manual}
          onChangeText={setManual}
          placeholder="http://… or WIFI:T:WPA;S:…"
          autoCapitalize="none"
          multiline
        />
        <Button title="Analyse payload" onPress={() => analyzePayload(manual)} loading={loading} />
      </Card>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: spacing(2), backgroundColor: colors.bg, flexGrow: 1 },
  title: { color: colors.text, fontSize: 24, fontWeight: "800" },
  cameraWrap: {
    height: 280,
    borderRadius: radius.md,
    overflow: "hidden",
    marginBottom: spacing(1.5),
    borderWidth: 1,
    borderColor: colors.border,
  },
  camera: { flex: 1 },
});
