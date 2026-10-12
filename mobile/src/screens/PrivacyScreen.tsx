import React from "react";
import { ScrollView, StyleSheet, Text } from "react-native";

import { Card, SectionTitle } from "../components/ui";
import { colors, spacing } from "../theme";

const SECTIONS: { title: string; body: string }[] = [
  {
    title: "What is sent to the server",
    body:
      "Only the content you explicitly submit is sent to your Digital Guardian server: the text or link you paste, a QR payload you scan, or an image you choose to analyse. Images are processed in memory and are not written to disk by default.",
  },
  {
    title: "What is stored",
    body:
      "When history saving is enabled, the server stores the submitted text (up to a limit), the risk result and indicator metadata. Uploaded images are not stored. You can delete individual scans or all history at any time.",
  },
  {
    title: "Clipboard and sharing",
    body:
      "Digital Guardian never reads your clipboard in the background. Clipboard content is only read when you tap a paste action, and shared content is only analysed when you open it in the app.",
  },
  {
    title: "Background behaviour",
    body:
      "Digital Guardian does not secretly monitor other apps, read notifications, or capture your screen. Android restricts background work; analysis happens when you start it. Real background monitoring is not provided.",
  },
  {
    title: "Accuracy and limits",
    body:
      "Assessments are advisory and cannot detect every scam. A low risk score is not a guarantee of safety. Links and files are never opened or executed automatically, and you should verify important requests through an official channel you look up yourself.",
  },
];

export default function PrivacyScreen() {
  return (
    <ScrollView style={styles.flex} contentContainerStyle={styles.container}>
      <Text style={styles.title}>Privacy &amp; security</Text>
      {SECTIONS.map((section) => (
        <Card key={section.title}>
          <SectionTitle>{section.title}</SectionTitle>
          <Text style={styles.body}>{section.body}</Text>
        </Card>
      ))}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: colors.bg },
  container: { padding: spacing(2) },
  title: { color: colors.text, fontSize: 24, fontWeight: "800", marginBottom: spacing(1) },
  body: { color: colors.text, fontSize: 15, lineHeight: 21 },
});
