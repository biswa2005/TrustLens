export type RiskLevel = "low" | "suspicious" | "high" | "malicious" | "inconclusive";

export interface RiskDefinition {
  level: RiskLevel;
  label: string;
  short: string;
  color: string;
  description: string;
  example: string;
  action: string;
  basis: string;
}

export const RISK_LEVELS: RiskDefinition[] = [
  {
    level: "low",
    label: "Low Risk",
    short: "Low",
    color: "#00E6A0",
    description:
      "Multiple independent signals agree that the target behaves as expected. No reputation hits, valid TLS and no deceptive patterns were observed.",
    example:
      "Long-established domain, valid certificate chain, clean reputation across all queried sources.",
    action: "Proceed with normal caution. Low risk is never a guarantee of safety.",
    basis: "Requires positive evidence from live intelligence sources.",
  },
  {
    level: "suspicious",
    label: "Suspicious",
    short: "Suspicious",
    color: "#FFD24A",
    description:
      "Some signals deviate from what a legitimate service would normally present. Not enough to call it harmful, but enough to slow down.",
    example:
      "Recently registered domain using credential-related keywords such as “verify” or “account”.",
    action: "Verify the sender or destination through an independent channel before interacting.",
    basis: "One or more moderate indicators without corroborating reputation hits.",
  },
  {
    level: "high",
    label: "High Risk",
    short: "High",
    color: "#FF8A3D",
    description:
      "Several strong indicators point to deceptive intent, such as impersonation, obfuscation or credential harvesting patterns.",
    example:
      "Look-alike domain one character away from a major brand, served over a fresh certificate.",
    action:
      "Do not enter credentials or payment details. Report it to the impersonated organisation.",
    basis: "Multiple strong indicators, but no confirmed threat-intelligence match.",
  },
  {
    level: "malicious",
    label: "Confirmed Malicious",
    short: "Malicious",
    color: "#FF4269",
    description:
      "The target matches a known threat in one or more trusted intelligence feeds. This verdict is reserved for corroborated evidence only.",
    example:
      "URL listed by an established blocklist as an active phishing or malware distribution endpoint.",
    action:
      "Block and avoid. If you already interacted, change credentials and contact your provider.",
    basis: "Requires a corroborated match in a trusted threat-intelligence source.",
  },
  {
    level: "inconclusive",
    label: "Inconclusive",
    short: "Inconclusive",
    color: "#8B95A7",
    description:
      "There was not enough evidence to classify the target either way. Inconclusive is not a safe verdict — it means TrustLens could not verify trust.",
    example:
      "Sources unreachable, the site blocked inspection, or only surface-level signals were available.",
    action: "Treat as unverified. Avoid sharing sensitive data until trust can be established.",
    basis: "Insufficient or unavailable evidence. Never interpreted as safe.",
  },
];

export const RISK_BY_LEVEL = Object.fromEntries(RISK_LEVELS.map((r) => [r.level, r])) as Record<
  RiskLevel,
  RiskDefinition
>;
