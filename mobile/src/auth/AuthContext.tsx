import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import * as SecureStore from "expo-secure-store";

import * as api from "../api/client";
import type { User, UserSettings } from "../api/types";

const TOKEN_KEY = "dg_auth_token";

interface AuthState {
  ready: boolean;
  token: string | null;
  user: User | null;
  settings: UserSettings | null;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (name: string, email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  refresh: () => Promise<void>;
  setSettings: (settings: UserSettings) => void;
  setUser: (user: User) => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [settings, setSettings] = useState<UserSettings | null>(null);

  const persist = useCallback(async (newToken: string | null) => {
    if (newToken) {
      await SecureStore.setItemAsync(TOKEN_KEY, newToken);
    } else {
      await SecureStore.deleteItemAsync(TOKEN_KEY);
    }
    setToken(newToken);
  }, []);

  const refresh = useCallback(async () => {
    const stored = await SecureStore.getItemAsync(TOKEN_KEY);
    if (!stored) {
      setToken(null);
      setUser(null);
      setSettings(null);
      return;
    }
    try {
      const res = await api.me(stored);
      setToken(stored);
      setUser(res.user);
      setSettings(res.settings);
    } catch {
      // Stored token is invalid / revoked.
      await persist(null);
      setUser(null);
      setSettings(null);
    }
  }, [persist]);

  useEffect(() => {
    (async () => {
      await refresh();
      setReady(true);
    })();
  }, [refresh]);

  const signIn = useCallback(
    async (email: string, password: string) => {
      const res = await api.login(email, password);
      setUser(res.user);
      setSettings(res.settings);
      await persist(res.token);
    },
    [persist],
  );

  const signUp = useCallback(
    async (name: string, email: string, password: string) => {
      const res = await api.register(name, email, password);
      setUser(res.user);
      setSettings(res.settings);
      await persist(res.token);
    },
    [persist],
  );

  const signOut = useCallback(async () => {
    const current = token ?? (await SecureStore.getItemAsync(TOKEN_KEY));
    if (current) {
      try {
        await api.logout(current);
      } catch {
        // Ignore network errors on logout.
      }
    }
    await persist(null);
    setUser(null);
    setSettings(null);
  }, [token, persist]);

  const value = useMemo<AuthState>(
    () => ({
      ready,
      token,
      user,
      settings,
      signIn,
      signUp,
      signOut,
      refresh,
      setSettings,
      setUser,
    }),
    [ready, token, user, settings, signIn, signUp, signOut, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
