import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";

import type {
  AnalysisResult,
  Capabilities,
  DashboardSummary,
  HistoryPage,
  ScanSummary,
  User,
  UserSettings,
} from "./types";

const BASE_URL_KEY = "dg_api_base_url";

function defaultBaseUrl(): string {
  const extra = (Constants.expoConfig?.extra ?? {}) as { apiBaseUrl?: string };
  return (extra.apiBaseUrl ?? "http://10.0.2.2:5000").replace(/\/+$/, "");
}

let cachedBaseUrl: string | null = null;

export async function getBaseUrl(): Promise<string> {
  if (cachedBaseUrl) return cachedBaseUrl;
  const stored = await SecureStore.getItemAsync(BASE_URL_KEY);
  cachedBaseUrl = stored && stored.trim() ? stored.replace(/\/+$/, "") : defaultBaseUrl();
  return cachedBaseUrl;
}

export async function setBaseUrl(url: string): Promise<void> {
  const clean = url.trim().replace(/\/+$/, "");
  cachedBaseUrl = clean || defaultBaseUrl();
  if (clean) {
    await SecureStore.setItemAsync(BASE_URL_KEY, clean);
  } else {
    await SecureStore.deleteItemAsync(BASE_URL_KEY);
  }
}

export class ApiError extends Error {
  status: number;
  code?: string;
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

interface RequestOptions {
  method?: string;
  token?: string | null;
  body?: unknown;
  form?: FormData;
  query?: Record<string, string | number | undefined>;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const base = await getBaseUrl();
  let url = base + path;
  if (options.query) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(options.query)) {
      if (value !== undefined && value !== null && value !== "") {
        params.append(key, String(value));
      }
    }
    const qs = params.toString();
    if (qs) url += "?" + qs;
  }

  const headers: Record<string, string> = { Accept: "application/json" };
  let body: BodyInit | undefined;
  if (options.form) {
    body = options.form;
  } else if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  if (options.token) {
    headers["Authorization"] = "Bearer " + options.token;
  }

  let response: Response;
  try {
    response = await fetch(url, { method: options.method ?? "GET", headers, body });
  } catch (err) {
    throw new ApiError(
      "Could not reach the Digital Guardian server. Check the server address in Settings and that your device is online.",
      0,
      "network_error",
    );
  }

  const text = await response.text();
  let data: any = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    const message =
      (data && (data.error || data.message)) ||
      `Request failed (${response.status}).`;
    throw new ApiError(message, response.status, data?.code);
  }
  return (data ?? {}) as T;
}

// ------------------------------------------------------------------ meta

export async function health() {
  return request<{ success: boolean; status: string }>("/api/v1/health");
}

export async function capabilities() {
  const res = await request<{ success: boolean; capabilities: Capabilities }>(
    "/api/v1/capabilities",
  );
  return res.capabilities;
}

// ------------------------------------------------------------------ auth

export async function register(name: string, email: string, password: string) {
  return request<{ token: string; user: User; settings: UserSettings }>(
    "/api/v1/auth/register",
    { method: "POST", body: { name, email, password } },
  );
}

export async function login(email: string, password: string) {
  return request<{ token: string; user: User; settings: UserSettings }>(
    "/api/v1/auth/login",
    { method: "POST", body: { email, password } },
  );
}

export async function me(token: string) {
  return request<{ user: User; settings: UserSettings }>("/api/v1/auth/me", { token });
}

export async function logout(token: string) {
  return request<{ success: boolean }>("/api/v1/auth/logout", { method: "POST", token });
}

// -------------------------------------------------------------- analysis

export async function analyzeText(token: string | null, text: string, channel = "Message") {
  return request<AnalysisResult>("/api/v1/analyze/text", {
    method: "POST",
    token,
    body: { text, channel },
  });
}

export async function analyzeUrl(token: string | null, url: string) {
  return request<AnalysisResult>("/api/v1/analyze/url", {
    method: "POST",
    token,
    body: { url },
  });
}

export async function analyzeQr(token: string | null, payload: string) {
  return request<AnalysisResult>("/api/v1/analyze/qr", {
    method: "POST",
    token,
    body: { payload },
  });
}

export async function analyzeImage(
  token: string | null,
  image: { uri: string; name: string; type: string },
  qrPayload?: string,
) {
  const form = new FormData();
  // React Native multipart file object.
  form.append("image", image as any);
  if (qrPayload) form.append("qr_payload", qrPayload);
  return request<AnalysisResult>("/api/v1/analyze/image", {
    method: "POST",
    token,
    form,
  });
}

// --------------------------------------------------------------- history

export async function getHistory(
  token: string,
  params: { page?: number; type?: string; q?: string; level?: string; sort?: string } = {},
): Promise<HistoryPage> {
  return request<HistoryPage>("/api/v1/history", {
    token,
    query: {
      page: params.page,
      type: params.type,
      q: params.q,
      level: params.level,
      sort: params.sort,
    },
  });
}

export async function getScan(token: string, id: number): Promise<ScanSummary> {
  const res = await request<{ scan: ScanSummary }>(`/api/v1/history/${id}`, { token });
  return res.scan;
}

export async function deleteScan(token: string, id: number) {
  return request<{ success: boolean }>(`/api/v1/history/${id}`, {
    method: "DELETE",
    token,
  });
}

export async function deleteAllHistory(token: string) {
  return request<{ success: boolean; deleted: number }>("/api/v1/history", {
    method: "DELETE",
    token,
  });
}

// ------------------------------------------------------- dashboard / settings

export async function getDashboard(token: string): Promise<DashboardSummary> {
  const res = await request<{ summary: DashboardSummary }>("/api/v1/dashboard/summary", {
    token,
  });
  return res.summary;
}

export async function getSettings(token: string) {
  return request<{ user: User; settings: UserSettings }>("/api/v1/settings", { token });
}

export async function updateSettings(
  token: string,
  patch: Partial<UserSettings> & { name?: string; guardian_mode?: boolean },
) {
  return request<{ user: User; settings: UserSettings }>("/api/v1/settings", {
    method: "PATCH",
    token,
    body: patch,
  });
}
