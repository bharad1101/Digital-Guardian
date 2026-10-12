import React, { useCallback, useState } from "react";
import {
  Alert,
  FlatList,
  Pressable,
  RefreshControl,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { useFocusEffect } from "@react-navigation/native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import { useAuth } from "../auth/AuthContext";
import * as api from "../api/client";
import type { ScanSummary } from "../api/types";
import { RiskBadge } from "../components/ResultView";
import { Button, Card, Muted } from "../components/ui";
import { colors, spacing } from "../theme";
import type { RootStackParamList } from "../navigation/types";

type Props = NativeStackScreenProps<RootStackParamList>;

const FILTERS = ["all", "text", "url", "qr", "image"] as const;
type Filter = (typeof FILTERS)[number];

export default function HistoryScreen({ navigation }: Props) {
  const { token } = useAuth();
  const [items, setItems] = useState<ScanSummary[]>([]);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState<Filter>("all");
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (pageToLoad: number, append: boolean, activeFilter: Filter) => {
      if (!token) return;
      setLoading(!append);
      setLoadingMore(append);
      setError(null);
      try {
        const result = await api.getHistory(token, {
          page: pageToLoad,
          type: activeFilter === "all" ? undefined : activeFilter,
        });
        setItems((prev) => (append ? [...prev, ...result.items] : result.items));
        setPage(result.page);
        setPages(result.pages);
        setTotal(result.total);
      } catch (err: any) {
        setError(err.message || "Could not load history.");
      } finally {
        setLoading(false);
        setLoadingMore(false);
      }
    },
    [token],
  );

  useFocusEffect(
    useCallback(() => {
      load(1, false, filter);
    }, [load, filter]),
  );

  function changeFilter(next: Filter) {
    setFilter(next);
    setItems([]);
  }

  async function removeOne(id: number) {
    if (!token) return;
    try {
      await api.deleteScan(token, id);
      setItems((prev) => prev.filter((s) => s.id !== id));
      setTotal((t) => Math.max(0, t - 1));
    } catch (err: any) {
      Alert.alert("Delete failed", err.message || "Please try again.");
    }
  }

  function confirmRemoveOne(id: number) {
    Alert.alert("Delete scan", "Remove this scan from your history?", [
      { text: "Cancel", style: "cancel" },
      { text: "Delete", style: "destructive", onPress: () => removeOne(id) },
    ]);
  }

  function confirmDeleteAll() {
    if (!token) return;
    Alert.alert("Delete all history", "Delete every saved scan? This cannot be undone.", [
      { text: "Cancel", style: "cancel" },
      {
        text: "Delete all",
        style: "destructive",
        onPress: async () => {
          try {
            await api.deleteAllHistory(token);
            setItems([]);
            setTotal(0);
            setPages(1);
          } catch (err: any) {
            Alert.alert("Delete failed", err.message || "Please try again.");
          }
        },
      },
    ]);
  }

  const renderItem = ({ item }: { item: ScanSummary }) => (
    <Pressable onPress={() => navigation.navigate("ScanDetail", { scan: item })}>
      <Card>
        <View style={styles.row}>
          <View style={{ flex: 1 }}>
            <Text style={styles.type}>
              {item.input_type.toUpperCase()} · {item.channel}
            </Text>
            <Muted numberOfLines={2}>{item.content}</Muted>
            <Text style={styles.date}>{item.created_at ?? ""}</Text>
          </View>
          <RiskBadge level={item.threat_level} score={item.risk_score} />
        </View>
        <Pressable onPress={() => confirmRemoveOne(item.id)} style={styles.deleteBtn}>
          <Text style={styles.deleteText}>Delete</Text>
        </Pressable>
      </Card>
    </Pressable>
  );

  return (
    <View style={styles.flex}>
      <View style={styles.filters}>
        {FILTERS.map((f) => (
          <Pressable
            key={f}
            onPress={() => changeFilter(f)}
            style={[styles.chip, filter === f && styles.chipActive]}
          >
            <Text style={[styles.chipText, filter === f && styles.chipTextActive]}>
              {f}
            </Text>
          </Pressable>
        ))}
      </View>

      {total > 0 ? (
        <View style={styles.headerRow}>
          <Muted>{total} saved scan{total === 1 ? "" : "s"}</Muted>
          <Pressable onPress={confirmDeleteAll}>
            <Text style={styles.deleteAll}>Delete all</Text>
          </Pressable>
        </View>
      ) : null}

      {error ? (
        <Card>
          <Text style={{ color: colors.danger }}>{error}</Text>
        </Card>
      ) : null}

      <FlatList
        data={items}
        keyExtractor={(item) => String(item.id)}
        renderItem={renderItem}
        contentContainerStyle={styles.list}
        refreshControl={
          <RefreshControl
            refreshing={loading}
            onRefresh={() => load(1, false, filter)}
            tintColor={colors.text}
          />
        }
        ListEmptyComponent={
          loading ? null : (
            <Card>
              <Muted>No scans yet. Use the Scan or Lens tab to analyse content.</Muted>
            </Card>
          )
        }
        onEndReachedThreshold={0.4}
        onEndReached={() => {
          if (page < pages && !loadingMore) load(page + 1, true, filter);
        }}
        ListFooterComponent={
          loadingMore ? <Muted style={{ textAlign: "center" }}>Loading…</Muted> : null
        }
      />
    </View>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: colors.bg },
  filters: {
    flexDirection: "row",
    flexWrap: "wrap",
    paddingHorizontal: spacing(2),
    paddingTop: spacing(2),
    gap: spacing(0.5),
  },
  chip: {
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 999,
    paddingHorizontal: spacing(1.5),
    paddingVertical: spacing(0.6),
    marginRight: spacing(0.5),
    marginBottom: spacing(0.5),
  },
  chipActive: { backgroundColor: colors.primary, borderColor: colors.primary },
  chipText: { color: colors.muted, fontSize: 13, textTransform: "capitalize" },
  chipTextActive: { color: colors.white, fontWeight: "700" },
  headerRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingHorizontal: spacing(2),
    paddingVertical: spacing(1),
  },
  deleteAll: { color: colors.danger, fontWeight: "700" },
  list: { padding: spacing(2), paddingTop: spacing(0.5) },
  row: { flexDirection: "row", alignItems: "flex-start" },
  type: { color: colors.text, fontWeight: "700", marginBottom: 2 },
  date: { color: colors.muted, fontSize: 12, marginTop: 4 },
  deleteBtn: {
    marginTop: spacing(1),
    alignSelf: "flex-start",
    paddingVertical: spacing(0.5),
  },
  deleteText: { color: colors.danger, fontSize: 13, fontWeight: "600" },
});
