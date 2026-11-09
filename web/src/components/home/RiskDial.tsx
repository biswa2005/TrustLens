import { motion } from "motion/react";
import { RISK_BY_LEVEL, type RiskLevel } from "@/lib/risk";

/** Ring gauge for a 0–100 score. When no score is available, renders an open, dashed ring. */
export function RiskDial({
  level,
  score,
  label,
}: {
  level: RiskLevel;
  score: number | null;
  label: string;
}) {
  const risk = RISK_BY_LEVEL[level];
  const r = 52;
  const c = 2 * Math.PI * r;
  const pct = score == null ? 0 : Math.max(score, 3) / 100;
  return (
    <div className="relative grid size-[156px] shrink-0 place-items-center">
      <svg viewBox="0 0 128 128" className="absolute inset-0 -rotate-90" aria-hidden>
        <circle
          cx="64"
          cy="64"
          r={r}
          fill="none"
          stroke="rgba(148,163,184,0.12)"
          strokeWidth="8"
          strokeDasharray={score == null ? "3 6" : undefined}
        />
        {score != null && (
          <motion.circle
            cx="64"
            cy="64"
            r={r}
            fill="none"
            stroke={risk.color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={c}
            initial={{ strokeDashoffset: c }}
            animate={{ strokeDashoffset: c * (1 - pct) }}
            transition={{ duration: 1.2, ease: [0.22, 1, 0.36, 1], delay: 0.15 }}
            style={{ filter: `drop-shadow(0 0 8px ${risk.color}66)` }}
          />
        )}
      </svg>
      <div className="text-center">
        <div className="text-[40px] leading-none font-extrabold tracking-[-0.04em] text-white tabular-nums">
          {score ?? "—"}
        </div>
        <div className="mt-1.5 max-w-[96px] font-mono text-[10px] leading-tight tracking-[0.08em] text-fg-3 uppercase">
          {label}
        </div>
      </div>
    </div>
  );
}
