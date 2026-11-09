import { config } from "./config";
import { api } from "./api";
import type { RiskLevel } from "./risk";

export type ScanMode = "url" | "message";
export type Severity = "info" | "low" | "medium" | "high";
export type CheckStatus = "pass" | "warn" | "fail" | "not-checked";

export interface Indicator {
  id: string;
  label: string;
  detail: string;
  severity: Severity;
  evidence?: string[];
}

export interface Check {
  label: string;
  status: CheckStatus;
  value: string;
}

export interface ScanReport {
  mode: ScanMode;
  /** `local-heuristic` reports never contain external intelligence. */
  source: "local-heuristic" | "live";
  target: string;
  level: RiskLevel;
  score: number | null;
  scoreLabel: string;
  summary: string;
  indicators: Indicator[];
  checks: Check[];
  recommendation: { title: string; steps: string[] };
  analyzedAt: string;
}

export const SCAN_STEPS: Record<"local" | "live", Record<ScanMode, string[]>> = {
  local: {
    url: [
      "Normalising input",
      "Structural URL inspection",
      "Impersonation & look-alike checks",
      "Compiling report",
    ],
    message: [
      "Normalising message",
      "Social-engineering pattern matching",
      "Embedded link inspection",
      "Compiling report",
    ],
  },
  live: {
    url: [
      "Submitting to TrustLens backend",
      "Passive DNS, TLS & header inspection",
      "Threat intelligence correlation",
      "Compiling report",
    ],
    message: [
      "Submitting to TrustLens backend",
      "Contextual NLP analysis",
      "Link & sender correlation",
      "Compiling report",
    ],
  },
};

// ---------- Validation ----------

export function validateUrlInput(
  raw: string,
): { ok: true; url: URL } | { ok: false; error: string } {
  const value = raw.trim();
  if (!value) return { ok: false, error: "Enter a URL or domain to investigate." };
  if (value.length > 2048)
    return { ok: false, error: "That URL is too long to analyse (2,048 characters max)." };
  if (/\s/.test(value))
    return { ok: false, error: "URLs cannot contain spaces. Check what you pasted." };
  const withScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return { ok: false, error: "That does not look like a valid URL or domain." };
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    return { ok: false, error: "Only http and https addresses can be analysed." };
  }
  const host = url.hostname;
  if (!host.includes(".") && !isIPv4(host)) {
    return { ok: false, error: "Include a full domain, for example example.com." };
  }
  return { ok: true, url };
}

export function validateMessageInput(raw: string): { ok: true } | { ok: false; error: string } {
  const value = raw.trim();
  if (!value) return { ok: false, error: "Paste the message you want to analyse." };
  if (value.length < 20)
    return {
      ok: false,
      error: "Add a little more of the message (at least 20 characters) for a meaningful analysis.",
    };
  if (value.length > 5000) return { ok: false, error: "Messages are limited to 5,000 characters." };
  return { ok: true };
}

// ---------- Service ----------

const VERDICT_TO_LEVEL: Record<string, RiskLevel> = {
  benign: "low",
  suspicious: "suspicious",
  likely_malicious: "high",
  malicious: "malicious",
  inconclusive: "inconclusive",
};

export async function runScan(
  mode: ScanMode,
  input: string,
  signal?: AbortSignal,
): Promise<ScanReport> {
  if (config.scanApiUrl) {
    try {
      if (mode === "url") {
        const data = await api.analyzeUrl(input.trim());
        return adaptUrlReport(data, input);
      }
      const { report } = await api.analyzeMessage(input.trim());
      return adaptMessageReport(report, input);
    } catch (err) {
      // fall back to local heuristics if the backend is unreachable
      if ((err as Error)?.name === "AbortError") throw err;
    }
  }
  return mode === "url" ? analyzeUrlLocally(input) : analyzeMessageLocally(input);
}

function adaptUrlReport(data: Record<string, any>, input: string): ScanReport {
  const indicators: Indicator[] = (data.signals ?? []).map((s: any) => ({
    id: String(s.id ?? s.label ?? "signal"),
    label: String(s.label ?? s.id ?? "Signal"),
    detail: String(s.detail ?? ""),
    severity: String(s.severity ?? "low").toLowerCase() as Severity,
    evidence: Array.isArray(s.evidence_ids) ? s.evidence_ids : undefined,
  }));
  const score = Number.isFinite(data.reputation_score) ? data.reputation_score : indicators.reduce((a, i) => a + 0, 0);
  const verdict = String(data.verdict ?? "inconclusive");
  const level = VERDICT_TO_LEVEL[verdict] ?? "inconclusive";
  const ssl = data.ssl ?? {};
  const dns = data.dns ?? {};
  const checks: Check[] = [
    { label: "Registrable domain", status: "pass", value: String(data.registered_domain || data.domain || "") },
    { label: "Transport scheme", status: data.scheme === "https" ? "pass" : "warn", value: data.scheme === "https" ? "HTTPS requested" : "HTTP (unencrypted)" },
    { label: "TLS certificate", status: ssl.valid ? "pass" : ssl.inspected ? "warn" : "not-checked", value: ssl.valid ? "Valid certificate" : ssl.error ?? (ssl.inspected ? "Invalid / not trusted" : "Not inspected") },
    { label: "DNS resolution", status: (dns.a ?? []).length ? "pass" : "warn", value: (dns.a ?? []).join(", ") || "No A records" },
    { label: "Redirect chain", status: (data.redirects ?? []).length ? "warn" : "pass", value: (data.redirects ?? []).length ? `${data.redirects.length} redirect(s)` : "None" },
    { label: "Domain age", status: "pass", value: data.domain_age_days != null ? `${data.domain_age_days} days` : "Unknown" },
    ...((data.threat_intel ?? []).slice(0, 5).map((ti: any) => ({
      label: `Threat intel: ${ti.source}`,
      status: ti.status === "malicious" ? "fail" : ti.status === "suspicious" ? "warn" : ti.status === "clean" ? "pass" : "not-checked",
      value: `${ti.status}${ti.positives != null ? ` (${ti.positives}/${ti.total ?? "?"})` : ""}`,
    })) as Check[]),
  ];
  return {
    mode: "url",
    source: "live",
    target: String(data.final_url || data.normalized_url || data.url || input),
    level,
    score: Number.isFinite(score) ? score : null,
    scoreLabel: "Reputation score",
    summary: `${data.verdict ?? "inconclusive"}: ${indicators.length} signal(s) raised. Final destination: ${data.final_url || data.normalized_url || data.url || input}.`,
    indicators,
    checks,
    recommendation: recommendationForLevel(level),
    analyzedAt: new Date().toISOString(),
  };
}

function adaptMessageReport(report: Record<string, any>, input: string): ScanReport {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const indicators: Indicator[] = findings.map((f: any) => ({
    id: String(f.id ?? f.title ?? "finding"),
    label: String(f.title ?? f.id ?? "Finding"),
    detail: String(f.description ?? ""),
    severity: (["critical", "high", "medium", "low", "info"].includes(String(f.severity ?? "").toLowerCase())
      ? String(f.severity).toLowerCase()
      : "medium") as Severity,
    evidence: Array.isArray(f.evidence_ids) ? f.evidence_ids : undefined,
  }));
  const risk = report.risk ?? {};
  const verdict = String(risk.verdict ?? report.verdict ?? "inconclusive");
  const level = VERDICT_TO_LEVEL[verdict] ?? "inconclusive";
  const score = Number.isFinite(risk.score) ? risk.score : Number.isFinite(report.risk_score) ? report.risk_score : null;
  const recs = Array.isArray(report.recommendations) ? report.recommendations : [];
  const firstRec = recs[0] ?? {};
  const recommendation = {
    title: String(firstRec.title ?? (level === "malicious" ? "Block and avoid" : "Review carefully")),
    steps: recs.length
      ? recs.map((r: any) => String(r.detail ?? r.title ?? "")).filter(Boolean)
      : [String(firstRec.detail ?? "Verify through an official channel.")],
  };
  return {
    mode: "message",
    source: "live",
    target: input.length > 160 ? `${input.slice(0, 157)}…` : input,
    score,
    scoreLabel: "Risk score",
    level,
    summary: String(risk.summary || report.executive_summary || report.technical_summary || "Live analysis completed."),
    indicators,
    checks: [
      { label: "Findings", status: indicators.length ? "warn" : "pass", value: `${indicators.length} raised` },
      { label: "Evidence items", status: "pass", value: String((report.evidence ?? []).length) },
      { label: "Confidence", status: "pass", value: `${Math.round((report.confidence ?? risk.confidence ?? 0) * 100)}%` },
      { label: "Verdict", status: level === "malicious" || level === "high" ? "fail" : level === "suspicious" ? "warn" : "pass", value: verdict },
    ],
    recommendation,
    analyzedAt: new Date().toISOString(),
  };
}

function recommendationForLevel(level: RiskLevel): ScanReport["recommendation"] {
  switch (level) {
    case "malicious":
      return { title: "Block and avoid", steps: ["Do not open, reply or enter any information.", "Change affected passwords and enable 2FA if interacted.", "Report to the impersonated organisation."] };
    case "high":
      return { title: "Do not interact", steps: ["Do not enter credentials, codes or payment details.", "Reach the organisation via its official site/app.", "Report the link/message to your provider."] };
    case "suspicious":
      return { title: "Verify before you proceed", steps: ["Confirm via an independent known channel.", "Check the exact domain before signing in.", "Re-run after connecting live intelligence."] };
    case "low":
      return { title: "Proceed with normal caution", steps: ["Keep verifying unexpected requests for sensitive data."] };
    default:
      return { title: "Treat as unverified", steps: ["Inconclusive is not a safe verdict.", "Avoid sharing sensitive data until trust is established.", "Verify the source through an official channel."] };
  }
}

// ---------- Local heuristics (operate only on the submitted text) ----------

const BRANDS: Record<string, string[]> = {
  paypal: ["paypal.com"],
  apple: ["apple.com", "icloud.com"],
  microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com"],
  google: ["google.com", "gmail.com"],
  amazon: ["amazon.com"],
  netflix: ["netflix.com"],
  facebook: ["facebook.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
  coinbase: ["coinbase.com"],
  binance: ["binance.com"],
  metamask: ["metamask.io"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  usps: ["usps.com"],
};
const SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "cutt.ly",
  "rb.gy",
  "buff.ly",
  "shorturl.at",
  "t.ly",
];
const ABUSED_TLDS = [
  "zip",
  "mov",
  "xyz",
  "top",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "click",
  "country",
  "work",
  "support",
  "rest",
  "cam",
  "icu",
  "buzz",
];
const LURE_TERMS = [
  "login",
  "signin",
  "sign-in",
  "verify",
  "verification",
  "secure",
  "account",
  "update",
  "wallet",
  "confirm",
  "unlock",
  "recover",
  "billing",
  "suspended",
  "claim",
  "airdrop",
];

const SEVERITY_WEIGHT: Record<Severity, number> = { info: 0, low: 6, medium: 14, high: 26 };

function isIPv4(host: string) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function levenshtein(a: string, b: string) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
  return dp[a.length][b.length];
}

function registrableDomain(host: string) {
  const labels = host.split(".");
  return labels.slice(-2).join(".");
}

function urlIndicators(url: URL, rawInput: string): Indicator[] {
  const out: Indicator[] = [];
  const host = url.hostname.toLowerCase();
  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  const regDomain = registrableDomain(host);
  const full = url.href.toLowerCase();

  if (isIPv4(host))
    out.push({
      id: "ip-host",
      label: "Raw IP address used as host",
      detail:
        "Legitimate services almost always use a domain name. Bare IP hosts are common in throwaway phishing infrastructure.",
      severity: "high",
      evidence: [host],
    });
  if (host.includes("xn--"))
    out.push({
      id: "punycode",
      label: "Internationalised (punycode) domain",
      detail:
        "Punycode can render characters that look identical to Latin letters — a known homograph impersonation technique.",
      severity: "high",
      evidence: [host],
    });
  if (url.username || /@/.test(rawInput.replace(/^[a-z]+:\/\//i, "").split("/")[0]))
    out.push({
      id: "userinfo",
      label: "Credentials embedded before the host",
      detail:
        "Text before “@” in a URL is ignored by browsers and is often used to disguise the real destination.",
      severity: "high",
      evidence: [url.username || "@"],
    });
  if (url.protocol === "http:" && /^http:\/\//i.test(rawInput.trim()))
    out.push({
      id: "http",
      label: "Unencrypted HTTP scheme",
      detail: "Traffic to this address would not be protected by TLS.",
      severity: "medium",
      evidence: ["http://"],
    });
  if (labels.length >= 5)
    out.push({
      id: "subdomains",
      label: "Deep subdomain nesting",
      detail:
        "Stacking many subdomains can push the real registrable domain out of view on mobile screens.",
      severity: "medium",
      evidence: [host],
    });
  if ((host.match(/-/g) ?? []).length >= 3)
    out.push({
      id: "hyphens",
      label: "Heavily hyphenated hostname",
      detail: "Multiple hyphens are characteristic of keyword-stuffed look-alike domains.",
      severity: "medium",
      evidence: [host],
    });
  if (ABUSED_TLDS.includes(tld))
    out.push({
      id: "tld",
      label: `Top-level domain “.${tld}”`,
      detail:
        "This TLD is disproportionately represented in public abuse reports. On its own it proves nothing.",
      severity: "low",
      evidence: [`.${tld}`],
    });
  if (SHORTENERS.includes(regDomain) || SHORTENERS.includes(host))
    out.push({
      id: "shortener",
      label: "Link shortener hides destination",
      detail:
        "The final destination cannot be seen without following the redirect, which requires backend inspection.",
      severity: "medium",
      evidence: [host],
    });
  if (url.port && !["80", "443"].includes(url.port))
    out.push({
      id: "port",
      label: "Non-standard port",
      detail: "Consumer-facing services rarely run on custom ports.",
      severity: "low",
      evidence: [`:${url.port}`],
    });
  if ((full.match(/%[0-9a-f]{2}/g) ?? []).length > 5)
    out.push({
      id: "encoding",
      label: "Excessive URL encoding",
      detail: "Heavy percent-encoding can be used to obscure parameters or payloads.",
      severity: "low",
    });
  if (full.length > 140)
    out.push({
      id: "length",
      label: "Unusually long URL",
      detail: "Very long URLs can hide the meaningful part of the address.",
      severity: "low",
      evidence: [`${full.length} characters`],
    });

  const lures = LURE_TERMS.filter(
    (t) => host.includes(t) || url.pathname.toLowerCase().includes(t),
  );
  if (lures.length)
    out.push({
      id: "lure",
      label: "Credential-lure keywords",
      detail: "Words associated with account verification or recovery appear in the address.",
      severity: lures.length >= 2 ? "medium" : "low",
      evidence: lures.slice(0, 4),
    });

  const tokens = host.split(/[.-]/).filter(Boolean);
  const lookalike = (t: string) =>
    t.replace(/[01345]/g, (d) => ({ "0": "o", "1": "l", "3": "e", "4": "a", "5": "s" })[d] ?? d);
  for (const [brand, official] of Object.entries(BRANDS)) {
    const isOfficial = official.some((d) => host === d || host.endsWith(`.${d}`));
    if (isOfficial) continue;
    const substituted = tokens.find((t) => t !== brand && lookalike(t).includes(brand));
    const nearMiss =
      brand.length >= 5
        ? tokens.find(
            (t) =>
              t !== brand &&
              Math.abs(t.length - brand.length) <= 1 &&
              levenshtein(lookalike(t), brand) === 1,
          )
        : undefined;
    if (substituted || nearMiss) {
      const token = (substituted ?? nearMiss)!;
      out.push({
        id: `typo-${brand}`,
        label: `Possible look-alike of “${brand}”`,
        detail: `“${token}” imitates ${brand} using substituted or altered characters, and the site is not hosted on ${official.join(" or ")}.`,
        severity: "high",
        evidence: [token, official[0]],
      });
      break;
    }
    if (tokens.some((t) => t.includes(brand))) {
      out.push({
        id: `brand-${brand}`,
        label: `Brand name “${brand}” on an unofficial domain`,
        detail: `The address references ${brand} but is not hosted on ${official.join(" or ")}.`,
        severity: "high",
        evidence: [host],
      });
      break;
    }
  }
  return out;
}

function scoreOf(indicators: Indicator[]) {
  return Math.min(
    100,
    indicators.reduce((sum, i) => sum + SEVERITY_WEIGHT[i.severity], 0),
  );
}

function levelFromLocalScore(
  score: number,
  highThreshold: number,
  suspiciousThreshold: number,
): RiskLevel {
  // Local heuristics can never confirm maliciousness, nor establish that something is safe.
  if (score >= highThreshold) return "high";
  if (score >= suspiciousThreshold) return "suspicious";
  return "inconclusive";
}

const NOT_CHECKED = "Requires the live analysis backend";

export function analyzeUrlLocally(input: string): ScanReport {
  const parsed = validateUrlInput(input);
  if (!parsed.ok) throw new Error(parsed.error);
  const { url } = parsed;
  const indicators = urlIndicators(url, input);
  const score = scoreOf(indicators);
  // Impersonating a known brand is a strong signal on its own (see the High Risk definition).
  const impersonation = indicators.some((i) => /^(typo|brand)-/.test(i.id) || i.id === "punycode");
  const level: RiskLevel = impersonation ? "high" : levelFromLocalScore(score, 45, 14);
  const shortened = indicators.some((i) => i.id === "shortener");

  return {
    mode: "url",
    source: "local-heuristic",
    target: url.href,
    level,
    score,
    scoreLabel: "Structural signal score",
    summary:
      level === "inconclusive"
        ? indicators.length
          ? "Only minor structural signals were found in the address itself. Reputation, certificate and content were not verified, so trust cannot be established."
          : "No structural red flags were found in the address itself. Reputation, certificate and content were not verified, so trust cannot be established."
        : `The address itself shows ${indicators.length} warning sign${indicators.length === 1 ? "" : "s"}. These are drawn only from the URL’s structure; no live intelligence was queried.`,
    indicators,
    checks: [
      { label: "Registrable domain", status: "pass", value: registrableDomain(url.hostname) },
      {
        label: "Transport scheme",
        status: url.protocol === "https:" ? "pass" : "warn",
        value: url.protocol === "https:" ? "HTTPS requested" : "HTTP (unencrypted)",
      },
      { label: "Domain reputation", status: "not-checked", value: NOT_CHECKED },
      { label: "TLS certificate", status: "not-checked", value: NOT_CHECKED },
      {
        label: "Redirect chain",
        status: "not-checked",
        value: shortened ? "Shortened link — destination unresolved" : NOT_CHECKED,
      },
    ],
    recommendation: recommendationFor(level),
    analyzedAt: new Date().toISOString(),
  };
}

const MESSAGE_PATTERNS: {
  id: string;
  label: string;
  detail: string;
  severity: Severity;
  terms: RegExp;
}[] = [
  {
    id: "urgency",
    label: "Urgency or time pressure",
    detail: "Creates pressure to act before thinking — a core social-engineering tactic.",
    severity: "medium",
    terms:
      /\b(urgent(?:ly)?|immediately|act now|right away|within \d+ ?(?:hours?|hrs?|minutes?)|last chance|final (?:notice|warning)|expires? (?:today|soon)|today only|asap)\b/gi,
  },
  {
    id: "credentials",
    label: "Request for credentials or secrets",
    detail:
      "Legitimate organisations do not ask for passwords, one-time codes or recovery phrases by message.",
    severity: "high",
    terms:
      /\b(password|passcode|one[- ]time (?:code|password)|otp|verification code|pin(?: code)?|seed phrase|recovery phrase|private key|cvv|security code|login details|ssn|social security)\b/gi,
  },
  {
    id: "threat",
    label: "Threat or fear of loss",
    detail: "Threatens account closure, legal action or penalties to provoke a reaction.",
    severity: "medium",
    terms:
      /\b(suspend(?:ed)?|locked|blocked|deactivat(?:ed|ion)|legal action|arrest|penalt(?:y|ies)|unauthori[sz]ed (?:access|login|transaction)|unusual activity|will be (?:closed|terminated))\b/gi,
  },
  {
    id: "reward",
    label: "Too-good-to-be-true reward",
    detail: "Promises prizes, refunds or returns to lure engagement.",
    severity: "medium",
    terms:
      /\b(you(?:'ve| have)? won|winner|prize|lottery|gift ?card|refund|cashback|reward|bonus|airdrop|double your|guaranteed (?:return|profit))\b/gi,
  },
  {
    id: "payment",
    label: "Unusual payment request",
    detail: "Asks for payment through hard-to-reverse channels or unexpected fees.",
    severity: "high",
    terms:
      /\b(wire transfer|bitcoin|btc|usdt|crypto(?:currency)? (?:wallet|payment)|pay (?:a )?(?:small )?fee|processing fee|customs fee|western union|moneygram|pay now)\b/gi,
  },
  {
    id: "impersonation",
    label: "Claims to be a trusted organisation",
    detail:
      "References banks, delivery services, authorities or support teams — verify through an official channel.",
    severity: "low",
    terms:
      /\b(bank|irs|hmrc|tax office|customs|delivery|parcel|package|courier|dhl|fedex|usps|ups|amazon|paypal|apple|microsoft|netflix|support team|security team|help ?desk)\b/gi,
  },
  {
    id: "channel",
    label: "Moves conversation to another channel",
    detail: "Pushing to WhatsApp, Telegram or a personal number avoids platform protections.",
    severity: "low",
    terms:
      /\b(whatsapp me|message me on|contact (?:me|us) on (?:whatsapp|telegram)|telegram|text me at|call this number)\b/gi,
  },
  {
    id: "greeting",
    label: "Generic greeting",
    detail: "Mass phishing rarely uses your real name.",
    severity: "low",
    terms: /\b(dear (?:customer|user|client|member|account holder|valued customer|sir\/madam))\b/gi,
  },
  {
    id: "click",
    label: "Call to click or verify",
    detail: "Directs you to a link to “verify”, “confirm” or “update” details.",
    severity: "medium",
    terms:
      /\b(click (?:here|the link|below)|verify your|confirm your|update your (?:details|information|account|payment)|log ?in (?:here|now|to))\b/gi,
  },
];

export function analyzeMessageLocally(input: string): ScanReport {
  const text = input.trim();
  const indicators: Indicator[] = [];
  for (const p of MESSAGE_PATTERNS) {
    const matches = [...new Set((text.match(p.terms) ?? []).map((m) => m.toLowerCase()))];
    if (matches.length)
      indicators.push({
        id: p.id,
        label: p.label,
        detail: p.detail,
        severity: p.severity,
        evidence: matches.slice(0, 5),
      });
  }

  const links = [
    ...new Set(
      text.match(
        /\b(?:https?:\/\/|www\.)[^\s<>"')]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|xyz|top|info|ly|me|app|link|zip|click|support)\b(?:\/[^\s]*)?/gi,
      ) ?? [],
    ),
  ].slice(0, 5);
  let worstLink: { href: string; count: number; high: boolean } | null = null;
  for (const link of links) {
    const parsed = validateUrlInput(link);
    if (!parsed.ok) continue;
    const linkIndicators = urlIndicators(parsed.url, link);
    const high = linkIndicators.some((i) => i.severity === "high");
    if (!worstLink || linkIndicators.length > worstLink.count)
      worstLink = { href: parsed.url.hostname, count: linkIndicators.length, high };
  }
  if (links.length) {
    indicators.push({
      id: "links",
      label:
        worstLink && worstLink.count
          ? "Embedded link with structural warning signs"
          : "Contains embedded link",
      detail:
        worstLink && worstLink.count
          ? `The link to ${worstLink.href} shows ${worstLink.count} structural warning sign${worstLink.count === 1 ? "" : "s"}. Scan it separately in URL mode for details.`
          : "Links in unsolicited messages should be opened only after verifying the sender.",
      severity: worstLink?.high ? "high" : worstLink && worstLink.count ? "medium" : "low",
      evidence: links.slice(0, 3),
    });
  }

  // Patterns are much more telling in combination than individually.
  const combo = ["urgency", "credentials", "threat", "payment", "click"].filter((id) =>
    indicators.some((i) => i.id === id),
  ).length;
  const score = Math.min(100, scoreOf(indicators) + (combo >= 3 ? 12 : 0));
  const level = levelFromLocalScore(score, 55, 22);

  return {
    mode: "message",
    source: "local-heuristic",
    target: text.length > 160 ? `${text.slice(0, 157)}…` : text,
    level,
    score,
    scoreLabel: "Pattern signal score",
    summary:
      level === "inconclusive"
        ? "No strong social-engineering patterns were matched by local rules. This does not mean the message is safe — contextual AI analysis and sender verification were not performed."
        : `Matched ${indicators.length} social-engineering pattern${indicators.length === 1 ? "" : "s"} in the text you provided. Evidence below is quoted directly from the message.`,
    indicators,
    checks: [
      {
        label: "Patterns matched",
        status: indicators.length ? "warn" : "pass",
        value: `${indicators.length} of ${MESSAGE_PATTERNS.length + 1} rule groups`,
      },
      {
        label: "Embedded links",
        status: links.length ? "warn" : "pass",
        value: links.length ? `${links.length} found` : "None found",
      },
      { label: "Contextual AI interpretation", status: "not-checked", value: NOT_CHECKED },
      {
        label: "Link reputation",
        status: "not-checked",
        value: links.length ? NOT_CHECKED : "No links to check",
      },
      {
        label: "Sender verification",
        status: "not-checked",
        value: "Sender metadata is not available from pasted text",
      },
    ],
    recommendation: recommendationFor(level),
    analyzedAt: new Date().toISOString(),
  };
}

function recommendationFor(level: RiskLevel): ScanReport["recommendation"] {
  switch (level) {
    case "malicious":
      return {
        title: "Block and avoid",
        steps: [
          "Do not open, reply or enter any information.",
          "If you already interacted, change affected passwords and enable 2FA.",
          "Report the incident to the impersonated organisation.",
        ],
      };
    case "high":
      return {
        title: "Do not interact",
        steps: [
          "Do not enter credentials, codes or payment details.",
          "Reach the organisation through its official website or app instead.",
          "Report the message or link to your provider.",
        ],
      };
    case "suspicious":
      return {
        title: "Verify before you proceed",
        steps: [
          "Confirm the request through an independent, known channel.",
          "Check the exact domain carefully before signing in anywhere.",
          "Run a live scan once the analysis backend is connected.",
        ],
      };
    case "low":
      return {
        title: "Proceed with normal caution",
        steps: ["Keep verifying unexpected requests for sensitive data."],
      };
    default:
      return {
        title: "Treat as unverified",
        steps: [
          "Inconclusive is not a safe verdict.",
          "Avoid sharing sensitive data until trust is established.",
          "Verify the source through an official channel.",
        ],
      };
  }
}
