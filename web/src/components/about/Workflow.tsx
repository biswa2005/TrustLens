import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { BrainCircuit, FileText, Link2, Radar, Send, type LucideIcon } from "lucide-react";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { Reveal } from "@/components/ui/Reveal";

const STEPS: {
  n: string;
  title: string;
  body: string;
  Icon: LucideIcon;
  output: string;
  color: string;
}[] = [
  {
    n: "01",
    title: "Submit",
    body: "Submit a suspicious URL, domain or message for investigation.",
    Icon: Send,
    output: "url · domain · text",
    color: "#00D5F2",
  },
  {
    n: "02",
    title: "Investigate",
    body: "Retrieve passive technical indicators, domain information and TLS certificate details.",
    Icon: Radar,
    output: "dns · tls · headers",
    color: "#2fb4f7",
  },
  {
    n: "03",
    title: "AI Analysis",
    body: "Apply contextual NLP analysis, threat pattern matching and evidence correlation.",
    Icon: BrainCircuit,
    output: "patterns · context",
    color: "#9166FF",
  },
  {
    n: "04",
    title: "Risk Assessment",
    body: "Generate a structured security report with risk classification, supporting evidence and recommended actions.",
    Icon: FileText,
    output: "verdict · evidence",
    color: "#3985FF",
  },
  {
    n: "05",
    title: "Web3 Register",
    body: "Create a cryptographic commitment to selected incident information for transparent verification.",
    Icon: Link2,
    output: "sha-256 hash",
    color: "#00E6A0",
  },
];

export function Workflow() {
  const [active, setActive] = useState(0);
  const [paused, setPaused] = useState(false);
  const reduce = useReducedMotion();

  useEffect(() => {
    if (paused || reduce) return;
    const t = setInterval(() => setActive((a) => (a + 1) % STEPS.length), 2600);
    return () => clearInterval(t);
  }, [paused, reduce]);

  const progress = active / (STEPS.length - 1);

  return (
    <section
      id="workflow"
      aria-labelledby="workflow-title"
      className="relative isolate scroll-mt-20 overflow-hidden px-5 py-16 md:px-8 md:py-20"
    >
      <div
        className="pointer-events-none absolute inset-0 -z-10 hairline-grid opacity-50 [mask-image:radial-gradient(50%_60%_at_50%_50%,black,transparent)]"
        aria-hidden
      />
      <div className="mx-auto max-w-[1264px]">
        <SectionHeading
          id="workflow-title"
          eyebrow="THE INVESTIGATION WORKFLOW"
          title={
            <>
              Five steps from doubt <span className="text-tide">to evidence.</span>
            </>
          }
          description="Every TrustLens report follows the same transparent pipeline, so you can see exactly how a verdict was reached."
        />

        <Reveal delay={0.1}>
          <ol
            className="relative mt-20"
            onMouseEnter={() => setPaused(true)}
            onMouseLeave={() => setPaused(false)}
            onFocus={() => setPaused(true)}
            onBlur={() => setPaused(false)}
          >
            {/* horizontal rail (desktop) */}
            <div
              className="absolute top-7 right-[10%] left-[10%] hidden h-px bg-white/10 lg:block"
              aria-hidden
            >
              <motion.div
                className="h-full origin-left bg-[linear-gradient(90deg,#00D5F2,#9166FF,#3985FF,#00E6A0)]"
                animate={{ scaleX: progress }}
                transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
              />
            </div>
            {/* vertical rail (mobile) */}
            <div className="absolute top-7 bottom-7 left-7 w-px bg-white/10 lg:hidden" aria-hidden>
              <motion.div
                className="w-full origin-top bg-[linear-gradient(180deg,#00D5F2,#9166FF,#3985FF,#00E6A0)]"
                style={{ height: "100%" }}
                animate={{ scaleY: progress }}
                transition={{ duration: 0.8 }}
              />
            </div>

            <div className="grid gap-10 lg:grid-cols-5 lg:gap-6">
              {STEPS.map((s, i) => {
                const isActive = i === active;
                const reached = i <= active;
                return (
                  <li key={s.n} className="relative">
                    <button
                      type="button"
                      onClick={() => setActive(i)}
                      onMouseEnter={() => setActive(i)}
                      aria-current={isActive ? "step" : undefined}
                      className="group flex w-full gap-5 text-left lg:flex-col lg:items-center lg:gap-0 lg:text-center"
                    >
                      <span className="relative grid size-14 shrink-0 place-items-center">
                        <span
                          className="absolute inset-0 rounded-full border bg-[#0a0e16] transition-all duration-500"
                          style={{
                            borderColor: reached ? `${s.color}aa` : "rgba(148,163,184,0.18)",
                            boxShadow: isActive
                              ? `0 0 0 6px ${s.color}14, 0 0 30px ${s.color}55`
                              : "none",
                          }}
                        />
                        <s.Icon
                          className="relative size-[22px] transition-colors duration-500"
                          style={{ color: reached ? s.color : "#66748A" }}
                          strokeWidth={1.8}
                          aria-hidden
                        />
                      </span>
                      <span className="flex-1 lg:mt-7">
                        <span
                          className="block font-mono text-[11.5px] tracking-[0.14em] transition-colors"
                          style={{ color: isActive ? s.color : "#66748A" }}
                        >
                          STEP {s.n}
                        </span>
                        <span
                          className={`mt-2 block text-[21px] font-bold tracking-[-0.03em] transition-colors ${isActive ? "text-white" : "text-white/70"}`}
                        >
                          {s.title}
                        </span>
                        <span className="mt-2 block text-[14.5px] leading-[1.6] text-fg-2 lg:mx-auto lg:max-w-[220px]">
                          {s.body}
                        </span>
                        <span
                          className="mt-4 inline-block rounded-md border px-2 py-1 font-mono text-[11px] whitespace-nowrap transition-all duration-500"
                          style={{
                            borderColor: isActive ? `${s.color}55` : "rgba(148,163,184,0.12)",
                            color: isActive ? s.color : "#66748A",
                            background: isActive ? `${s.color}10` : "transparent",
                          }}
                        >
                          {i === 0 ? "in →" : "out →"} {s.output}
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </div>
          </ol>
        </Reveal>
      </div>
    </section>
  );
}
