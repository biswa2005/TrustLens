import { useState } from "react";
import { motion } from "motion/react";
import {
  AlertTriangle,
  Check,
  CircleDashed,
  Copy,
  FlaskConical,
  Radio,
  RotateCcw,
  ShieldAlert,
  X,
} from "lucide-react";
import type { CheckStatus, ScanReport, Severity } from "@/lib/scanner";
import { RISK_BY_LEVEL } from "@/lib/risk";
import { RiskDial } from "./RiskDial";

const SEVERITY: Record<Severity, { label: string; color: string }> = {
  high: { label: "High", color: "#FF4269" },
  medium: { label: "Medium", color: "#FF8A3D" },
  low: { label: "Low", color: "#FFD24A" },
  info: { label: "Info", color: "#8B95A7" },
};

const CHECK_ICON: Record<CheckStatus, { Icon: typeof Check; color: string }> = {
  pass: { Icon: Check, color: "#00E6A0" },
  warn: { Icon: AlertTriangle, color: "#FFB547" },
  fail: { Icon: X, color: "#FF4269" },
  "not-checked": { Icon: CircleDashed, color: "#66748A" },
};

const item = {
  hidden: { opacity: 0, y: 12 },
  show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] as const } },
};

export function ScanReportView({ report, onReset }: { report: ScanReport; onReset: () => void }) {
  const risk = RISK_BY_LEVEL[report.level];
  const [copied, setCopied] = useState(false);
  const isLocal = report.source === "local-heuristic";

  async function copy() {
    const lines = [
      `TrustLens report (${isLocal ? "local heuristic preview — no live intelligence queried" : "live analysis"})`,
      `Target: ${report.target}`,
      `Classification: ${risk.label}${report.score != null ? ` · ${report.scoreLabel} ${report.score}/100` : ""}`,
      `Summary: ${report.summary}`,
      "",
      "Indicators:",
      ...(report.indicators.length
        ? report.indicators.map(
            (i) =>
              `- [${i.severity}] ${i.label}${i.evidence?.length ? ` — ${i.evidence.join(", ")}` : ""}`,
          )
        : ["- None"]),
      "",
      "Checks:",
      ...report.checks.map((c) => `- ${c.label}: ${c.value}`),
      "",
      `Recommended: ${report.recommendation.title}`,
      `Analyzed: ${new Date(report.analyzedAt).toLocaleString()}`,
    ];
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  return (
    <motion.div
      initial="hidden"
      animate="show"
      variants={{ show: { transition: { staggerChildren: 0.07 } } }}
      className="space-y-5"
      aria-live="polite"
    >
      <motion.div
        variants={item}
        className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-[13.5px] leading-relaxed ${
          isLocal
            ? "border-violet/30 bg-violet/[0.07] text-[#cbbcff]"
            : "border-cyan/30 bg-cyan/[0.06] text-cyan"
        }`}
      >
        {isLocal ? (
          <FlaskConical className="mt-0.5 size-4 shrink-0" />
        ) : (
          <Radio className="mt-0.5 size-4 shrink-0" />
        )}
        <p>
          {isLocal ? (
            <>
              <strong className="font-semibold text-white">Preview analysis.</strong> These results
              come only from rules applied to the text you submitted, in your browser. No
              threat-intelligence feeds, DNS, TLS or reputation sources were queried.
            </>
          ) : (
            <>
              <strong className="font-semibold text-white">Live analysis</strong> returned by the
              configured TrustLens backend.
            </>
          )}
        </p>
      </motion.div>

      <motion.div
        variants={item}
        className="grid gap-6 rounded-2xl border border-white/10 bg-black/30 p-5 md:grid-cols-[auto_1fr] md:items-center md:p-7"
      >
        <RiskDial level={report.level} score={report.score} label={report.scoreLabel} />
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <span
              className="inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-[12px] font-semibold tracking-[0.1em] uppercase"
              style={{
                color: risk.color,
                borderColor: `${risk.color}55`,
                background: `${risk.color}14`,
              }}
            >
              <span className="size-1.5 rounded-full" style={{ background: risk.color }} />
              {risk.label}
            </span>
            <span className="font-mono text-[12px] text-fg-3">
              {new Date(report.analyzedAt).toLocaleTimeString()}
            </span>
          </div>
          <p className="mt-3 truncate font-mono text-[13.5px] text-fg-2" title={report.target}>
            {report.target}
          </p>
          <p className="mt-3 text-[15.5px] leading-relaxed text-white/85">{report.summary}</p>
          {report.level === "inconclusive" && (
            <p className="mt-3 inline-flex items-center gap-2 text-[13px] text-fg-2">
              <ShieldAlert className="size-4 text-neutral" /> Inconclusive is not a safe verdict.
            </p>
          )}
        </div>
      </motion.div>

      <div className="grid gap-5 lg:grid-cols-[1.25fr_1fr] lg:items-start">
        <motion.section
          variants={item}
          className="rounded-2xl border border-white/10 bg-black/20 p-5 md:p-6"
          aria-labelledby="indicators-title"
        >
          <div className="flex items-center justify-between">
            <h3 id="indicators-title" className="text-[15px] font-semibold text-white">
              Threat indicators
            </h3>
            <span className="font-mono text-[12px] text-fg-3">
              {report.indicators.length} found
            </span>
          </div>
          {report.indicators.length === 0 ? (
            <p className="mt-4 rounded-xl border border-dashed border-white/10 p-4 text-[14px] leading-relaxed text-fg-2">
              No indicators were matched by the checks that ran. Checks that require live data are
              listed separately and were not performed.
            </p>
          ) : (
            <ul className="mt-4 divide-y divide-white/[0.06]">
              {report.indicators.map((ind) => {
                const sev = SEVERITY[ind.severity];
                return (
                  <li key={ind.id} className="py-3.5 first:pt-0 last:pb-0">
                    <div className="flex items-start gap-3">
                      <span
                        className="mt-[7px] size-2 shrink-0 rounded-full"
                        style={{ background: sev.color, boxShadow: `0 0 8px ${sev.color}` }}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                          <p className="text-[14.5px] font-medium text-white">{ind.label}</p>
                          <span
                            className="font-mono text-[11px] tracking-wider uppercase"
                            style={{ color: sev.color }}
                          >
                            {sev.label}
                          </span>
                        </div>
                        <p className="mt-1 text-[13.5px] leading-relaxed text-fg-2">{ind.detail}</p>
                        {ind.evidence && ind.evidence.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {ind.evidence.map((e) => (
                              <code
                                key={e}
                                className="max-w-full truncate rounded-md border border-white/10 bg-white/[0.04] px-2 py-0.5 font-mono text-[12px] text-white/80"
                              >
                                {e}
                              </code>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </motion.section>

        <div className="space-y-5">
          <motion.section
            variants={item}
            className="rounded-2xl border border-white/10 bg-black/20 p-5 md:p-6"
            aria-labelledby="checks-title"
          >
            <h3 id="checks-title" className="text-[15px] font-semibold text-white">
              Evidence &amp; checks
            </h3>
            <dl className="mt-4 space-y-3">
              {report.checks.map((c) => {
                const { Icon, color } = CHECK_ICON[c.status];
                return (
                  <div key={c.label} className="flex items-start gap-3">
                    <Icon className="mt-0.5 size-4 shrink-0" style={{ color }} aria-hidden />
                    <div className="min-w-0">
                      <dt className="text-[13.5px] text-white">{c.label}</dt>
                      <dd
                        className={`text-[13px] ${c.status === "not-checked" ? "text-fg-3" : "font-mono text-fg-2"} break-words`}
                      >
                        {c.value}
                      </dd>
                    </div>
                  </div>
                );
              })}
            </dl>
          </motion.section>

          <motion.section
            variants={item}
            className="rounded-2xl border p-5 md:p-6"
            style={{
              borderColor: `${risk.color}33`,
              background: `linear-gradient(160deg, ${risk.color}12, transparent 70%)`,
            }}
            aria-labelledby="action-title"
          >
            <p className="font-mono text-[11px] tracking-[0.12em] text-fg-3">
              RECOMMENDED NEXT ACTION
            </p>
            <h3
              id="action-title"
              className="mt-2 text-[18px] font-bold tracking-[-0.02em] text-white"
            >
              {report.recommendation.title}
            </h3>
            <ul className="mt-3 space-y-2">
              {report.recommendation.steps.map((s) => (
                <li key={s} className="flex gap-2.5 text-[13.5px] leading-relaxed text-fg-2">
                  <span className="mt-[9px] h-px w-3 shrink-0" style={{ background: risk.color }} />
                  {s}
                </li>
              ))}
            </ul>
          </motion.section>
        </div>
      </div>

      <motion.div variants={item} className="flex flex-wrap items-center justify-end gap-3 pt-1">
        <button
          type="button"
          onClick={copy}
          className="inline-flex h-10 items-center gap-2 rounded-full border border-white/12 px-4 text-[14px] text-fg-2 transition hover:border-white/25 hover:text-white"
        >
          {copied ? <Check className="size-4 text-safe" /> : <Copy className="size-4" />}
          {copied ? "Copied" : "Copy report"}
        </button>
        <button
          type="button"
          onClick={onReset}
          className="inline-flex h-10 items-center gap-2 rounded-full bg-white px-5 text-[14px] font-semibold text-[#07090e] transition hover:bg-[#e9f6ff]"
        >
          <RotateCcw className="size-4" /> New scan
        </button>
      </motion.div>
    </motion.div>
  );
}
