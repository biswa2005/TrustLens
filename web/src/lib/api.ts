import { config } from "./config";

const base = () => config.scanApiUrl || "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${base()}${path}`;
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`Request failed: ${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

export const api = {
  health: () => request<Record<string, unknown>>("/health"),
  meta: () => request<Record<string, unknown>>("/api/v1/meta"),

  analyzeMessage: (message: string, language = "auto") =>
    request<{ investigation_id: string; module: string; report: Record<string, unknown> }>(
      "/api/v1/messages/analyze",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, language }),
      },
    ),

  analyzeUrl: (url: string, skipThirdPartyReputation = false) =>
    request<Record<string, unknown>>("/api/v1/analyse/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, skip_third_party_reputation: skipThirdPartyReputation }),
    }),

  listInvestigations: (limit = 20, module?: string) =>
    request<Record<string, unknown>[]>(
      `/api/v1/investigations?limit=${limit}${module ? `&module=${module}` : ""}`,
    ),

  getInvestigation: (id: string) => request<Record<string, unknown>>(`/api/v1/investigations/${id}`),

  verifyInvestigation: (id: string) =>
    request<Record<string, unknown>>(`/api/v1/investigations/${id}/verify`, { method: "POST" }),

  analyzeQr: (file: File, caption?: string, language = "auto") => {
    const fd = new FormData();
    fd.append("image", file);
    if (caption) fd.append("caption", caption);
    fd.append("language", language);
    return request<{ investigation_id: string; report: Record<string, unknown> }>(
      "/api/v1/qr/analyze",
      { method: "POST", body: fd },
    );
  },

  analyzeVisual: (file: File, brandHint?: string, claimedUrl?: string, language = "auto") => {
    const fd = new FormData();
    fd.append("image", file);
    if (brandHint) fd.append("brand_hint", brandHint);
    if (claimedUrl) fd.append("claimed_url", claimedUrl);
    fd.append("language", language);
    return request<{ investigation_id: string; report: Record<string, unknown> }>(
      "/api/v1/visual/analyze",
      { method: "POST", body: fd },
    );
  },

  analyzeEmail: (file: File, language = "auto") => {
    const fd = new FormData();
    fd.append("eml", file);
    fd.append("language", language);
    return request<{ investigation_id: string; report: Record<string, unknown> }>(
      "/api/v1/email/analyze",
      { method: "POST", body: fd },
    );
  },

  createThreatReport: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/v1/threat-reports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
};