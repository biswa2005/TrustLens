import { Reveal } from "@/components/ui/Reveal";

const METRICS = [
  {
    tag: "01 / INSPECTION",
    title: "Passive Inspection",
    body: "Non-intrusive security analysis.",
    color: "#00D5F2",
  },
  {
    tag: "02 / VELOCITY",
    title: "Fast Analysis",
    body: "Efficient multi-signal investigation.",
    color: "#3985FF",
  },
  {
    tag: "03 / PROVENANCE",
    title: "Web3 Verifiable",
    body: "Cryptographic incident commitments.",
    color: "#9166FF",
  },
  {
    tag: "04 / CORRELATION",
    title: "Multi-Source Intelligence",
    body: "Correlated threat intelligence signals.",
    color: "#00E6A0",
  },
];

export function Telemetry() {
  return (
    <section aria-label="Platform telemetry" className="relative z-10 px-5 md:px-8">
      <div className="relative mx-auto max-w-[1264px]">
        <span
          className="pointer-events-none absolute inset-x-0 bottom-0 h-px bg-[linear-gradient(90deg,transparent,rgba(148,163,184,0.16)_20%,rgba(148,163,184,0.16)_80%,transparent)]"
          aria-hidden
        />
        <ul className="grid sm:grid-cols-2 lg:grid-cols-4">
          {METRICS.map((m, i) => (
            <Reveal
              as="li"
              key={m.title}
              delay={i * 0.08}
              className={`group relative px-2 py-9 sm:px-8 lg:py-11 ${i > 0 ? "border-t border-white/[0.08] sm:border-t-0" : ""} ${
                i % 2 === 1 ? "sm:border-l sm:border-white/[0.08]" : ""
              } ${i >= 2 ? "sm:border-t sm:border-white/[0.08] lg:border-t-0" : ""} ${i === 2 ? "lg:border-l lg:border-white/[0.08]" : ""}`}
            >
              <span
                className="absolute top-0 left-0 h-px w-0 transition-all duration-500 group-hover:w-full sm:left-8 group-hover:sm:w-[calc(100%-4rem)]"
                style={{ background: m.color }}
                aria-hidden
              />
              <p className="flex items-center gap-2 font-mono text-[11.5px] tracking-[0.12em] text-fg-3">
                <span
                  className="size-1.5 rounded-full animate-pulse-dot"
                  style={{ background: m.color, color: m.color }}
                />
                {m.tag}
              </p>
              <p className="mt-6 text-[28px] leading-[1.05] font-bold tracking-[-0.04em] text-white md:text-[32px]">
                {m.title}
              </p>
              <p className="mt-3 text-[15px] text-fg-2">{m.body}</p>
            </Reveal>
          ))}
        </ul>
      </div>
    </section>
  );
}
