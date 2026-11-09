import { Brain, FileSearch, Fingerprint } from "lucide-react";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { Reveal } from "@/components/ui/Reveal";

const PILLARS = [
  {
    n: "01",
    title: "Intelligence",
    body: "AI-powered analysis that helps uncover suspicious digital patterns.",
    Icon: Brain,
    color: "#9166FF",
    tags: ["NLP", "Pattern recognition", "Anomalies"],
  },
  {
    n: "02",
    title: "Transparency",
    body: "Evidence-based security assessments rather than unexplained verdicts.",
    Icon: FileSearch,
    color: "#00D5F2",
    tags: ["Evidence", "Explainable", "Reproducible"],
  },
  {
    n: "03",
    title: "Verifiability",
    body: "Cryptographic provenance that supports transparent incident verification.",
    Icon: Fingerprint,
    color: "#3985FF",
    tags: ["SHA-256", "EVM", "Timestamped"],
  },
];

export function Mission() {
  return (
    <section aria-labelledby="mission-title" className="px-5 py-16 md:px-8 md:py-20">
      <div className="mx-auto max-w-[1264px]">
        <div className="grid gap-8 lg:grid-cols-2 lg:items-end">
          <SectionHeading
            id="mission-title"
            align="left"
            eyebrow="OUR MISSION"
            title="Making Digital Trust Measurable."
          />
          <Reveal delay={0.1}>
            <p className="max-w-lg text-[17px] leading-[1.7] text-fg-2 lg:ml-auto">
              Trust online is usually a feeling. We want it to be a measurement — built from
              observable signals, explained in plain language, and verifiable by anyone.
            </p>
          </Reveal>
        </div>

        <div className="mt-16 grid gap-px overflow-hidden rounded-[20px] border border-white/[0.08] bg-white/[0.08] md:grid-cols-3">
          {PILLARS.map((p, i) => (
            <Reveal
              key={p.title}
              delay={i * 0.1}
              className="group relative bg-[#0a0e16] p-8 transition-colors duration-300 hover:bg-[#0d131d] md:p-10"
            >
              <span
                className="absolute inset-x-0 top-0 h-px origin-left scale-x-0 transition-transform duration-500 group-hover:scale-x-100"
                style={{ background: p.color }}
                aria-hidden
              />
              <div className="flex items-start justify-between">
                <span
                  className="grid size-12 place-items-center rounded-[14px] border border-white/10 bg-white/[0.03]"
                  style={{ color: p.color }}
                >
                  <p.Icon className="size-[22px]" strokeWidth={1.7} aria-hidden />
                </span>
                <span className="text-[56px] leading-none font-extrabold tracking-[-0.06em] text-white/[0.06]">
                  {p.n}
                </span>
              </div>
              <h3
                className="mt-10 font-mono text-[13px] tracking-[0.16em]"
                style={{ color: p.color }}
              >
                {p.title.toUpperCase()}
              </h3>
              <p className="mt-3 text-[22px] leading-[1.3] font-semibold tracking-[-0.025em] text-white">
                {p.body}
              </p>
              <ul className="mt-8 flex flex-wrap gap-2">
                {p.tags.map((t) => (
                  <li
                    key={t}
                    className="rounded-full border border-white/10 px-2.5 py-1 text-[12px] text-fg-2"
                  >
                    {t}
                  </li>
                ))}
              </ul>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
