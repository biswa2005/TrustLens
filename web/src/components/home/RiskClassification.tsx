import { useState, type KeyboardEvent } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  CircleCheck,
  CircleHelp,
  OctagonAlert,
  ShieldAlert,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { Reveal } from "@/components/ui/Reveal";
import { RISK_LEVELS, type RiskLevel } from "@/lib/risk";

const ICONS: Record<RiskLevel, LucideIcon> = {
  low: CircleCheck,
  suspicious: TriangleAlert,
  high: ShieldAlert,
  malicious: OctagonAlert,
  inconclusive: CircleHelp,
};

const SCALE = RISK_LEVELS.filter((r) => r.level !== "inconclusive");
const INCONCLUSIVE = RISK_LEVELS.find((r) => r.level === "inconclusive")!;

export function RiskClassification() {
  const [selected, setSelected] = useState<RiskLevel>("suspicious");
  const current = RISK_LEVELS.find((r) => r.level === selected)!;
  const order = RISK_LEVELS.map((r) => r.level);

  function onKey(e: KeyboardEvent) {
    if (!["ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp"].includes(e.key)) return;
    e.preventDefault();
    const dir = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : -1;
    const next = order[(order.indexOf(selected) + dir + order.length) % order.length];
    setSelected(next);
    document.getElementById(`risk-tab-${next}`)?.focus();
  }

  // Rendered via a plain function (not a nested component) so buttons keep identity and focus.
  function renderSegment(level: (typeof RISK_LEVELS)[number], className = "") {
    const Icon = ICONS[level.level];
    const active = selected === level.level;
    const isInc = level.level === "inconclusive";
    return (
      <button
        key={level.level}
        id={`risk-tab-${level.level}`}
        role="tab"
        aria-selected={active}
        aria-controls="risk-panel"
        tabIndex={active ? 0 : -1}
        onClick={() => setSelected(level.level)}
        onKeyDown={onKey}
        className={`group relative flex min-h-[112px] flex-col justify-between overflow-hidden rounded-[14px] border p-4 text-left transition duration-300 ${
          active ? "bg-white/[0.04]" : "border-white/[0.08] bg-black/20 hover:border-white/20"
        } ${className}`}
        style={{
          borderColor: active ? `${level.color}80` : undefined,
          backgroundImage: isInc
            ? "repeating-linear-gradient(135deg, rgba(139,149,167,0.07) 0 6px, transparent 6px 12px)"
            : undefined,
        }}
      >
        <span
          className="absolute inset-x-0 top-0 h-[3px] transition-opacity"
          style={{ background: level.color, opacity: active ? 1 : 0.45 }}
        />
        <Icon className="size-5" style={{ color: level.color }} aria-hidden />
        <span>
          <span
            className="block font-mono text-[11px] tracking-[0.12em] uppercase"
            style={{ color: active ? level.color : "#9AA7BA" }}
          >
            {level.label}
          </span>
        </span>
      </button>
    );
  }

  const Icon = ICONS[current.level];

  return (
    <section aria-labelledby="risk-title" className="relative px-5 py-16 md:px-8 md:py-20">
      <div className="mx-auto max-w-[1264px]">
        <div className="grid gap-12 lg:grid-cols-[0.9fr_1.4fr] lg:gap-20">
          <div className="lg:sticky lg:top-32 lg:self-start">
            <SectionHeading
              id="risk-title"
              align="left"
              eyebrow="RISK CLASSIFICATION STANDARD"
              dot="#FFD24A"
              title="Know the Risk Before You Proceed."
              description="Five verdicts, each tied to an explicit evidence threshold. A confirmed malicious verdict needs corroborated intelligence — and an inconclusive result is never presented as safe."
            />
          </div>

          <Reveal delay={0.1}>
            <div
              role="tablist"
              aria-label="Risk classifications"
              className="grid grid-cols-2 gap-3 sm:grid-cols-[1fr_1fr_1fr_1fr_auto_1fr]"
            >
              {SCALE.map((r) => renderSegment(r))}
              <div
                className="hidden w-px self-stretch bg-[linear-gradient(180deg,transparent,rgba(148,163,184,0.3),transparent)] sm:block"
                aria-hidden
              />
              {renderSegment(INCONCLUSIVE, "col-span-2 sm:col-span-1")}
            </div>

            <div className="mt-4 flex items-center gap-3 px-1 font-mono text-[10.5px] tracking-[0.12em] text-fg-3">
              <span>LESS EVIDENCE OF HARM</span>
              <span className="h-px flex-1 bg-[linear-gradient(90deg,#00E6A0,#FFD24A,#FF8A3D,#FF4269)] opacity-60" />
              <span>CORROBORATED HARM</span>
              <span className="hidden sm:inline">·</span>
              <span className="hidden sm:inline">OFF-SCALE: UNVERIFIED</span>
            </div>

            <div
              id="risk-panel"
              role="tabpanel"
              aria-labelledby={`risk-tab-${current.level}`}
              className="relative mt-8 overflow-hidden rounded-[18px] border border-white/[0.08] bg-[linear-gradient(180deg,#0f1520,#0a0e16)]"
            >
              <div
                className="pointer-events-none absolute -top-32 -right-24 size-72 rounded-full blur-3xl transition-colors duration-500"
                style={{ background: `${current.color}22` }}
                aria-hidden
              />
              <AnimatePresence mode="wait">
                <motion.div
                  key={current.level}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                  transition={{ duration: 0.3 }}
                  className="relative p-6 md:p-9"
                >
                  <div className="flex items-center gap-4">
                    <span
                      className="grid size-12 place-items-center rounded-[14px] border"
                      style={{
                        borderColor: `${current.color}55`,
                        background: `${current.color}14`,
                        color: current.color,
                      }}
                    >
                      <Icon className="size-6" aria-hidden />
                    </span>
                    <div>
                      <h3 className="text-[26px] font-bold tracking-[-0.03em] text-white">
                        {current.label}
                      </h3>
                      <p className="font-mono text-[12px] text-fg-3">{current.basis}</p>
                    </div>
                  </div>
                  <p className="mt-6 max-w-2xl text-[16px] leading-[1.7] text-white/80">
                    {current.description}
                  </p>
                  <dl className="mt-8 grid gap-4 md:grid-cols-2">
                    <div className="rounded-xl border border-white/[0.07] bg-black/30 p-4">
                      <dt className="font-mono text-[11px] tracking-[0.12em] text-fg-3">
                        EXAMPLE CONDITION
                      </dt>
                      <dd className="mt-2 text-[14.5px] leading-relaxed text-fg-2">
                        {current.example}
                      </dd>
                    </div>
                    <div className="rounded-xl border border-white/[0.07] bg-black/30 p-4">
                      <dt className="font-mono text-[11px] tracking-[0.12em] text-fg-3">
                        RECOMMENDED RESPONSE
                      </dt>
                      <dd className="mt-2 text-[14.5px] leading-relaxed text-fg-2">
                        {current.action}
                      </dd>
                    </div>
                  </dl>
                </motion.div>
              </AnimatePresence>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
