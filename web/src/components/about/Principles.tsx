import { EyeOff, FileSearch, Network, ScanEye, ServerCog, type LucideIcon } from "lucide-react";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { Reveal } from "@/components/ui/Reveal";

const PRINCIPLES: { title: string; body: string; Icon: LucideIcon; tag: string }[] = [
  {
    title: "Passive-First Inspection",
    body: "Analyze publicly observable information without attempting intrusive attacks.",
    Icon: ScanEye,
    tag: "NO ACTIVE PROBING",
  },
  {
    title: "Privacy-Conscious Processing",
    body: "Do not request passwords or unnecessary sensitive information. Minimize collection and retention of submitted data.",
    Icon: EyeOff,
    tag: "DATA MINIMISATION",
  },
  {
    title: "SSRF-Aware Architecture",
    body: "Security inspection must be handled through appropriately protected backend infrastructure, with protections against private IP access, malicious redirects and internal service exposure.",
    Icon: ServerCog,
    tag: "PRIVATE RANGES BLOCKED",
  },
  {
    title: "Transparent Assessments",
    body: "Provide understandable explanations and supporting evidence for security classifications.",
    Icon: FileSearch,
    tag: "EVIDENCE ATTACHED",
  },
  {
    title: "Responsible Threat Sharing",
    body: "Share cryptographic incident commitments without unnecessarily exposing private user content.",
    Icon: Network,
    tag: "HASHES, NOT CONTENT",
  },
];

export function Principles() {
  return (
    <section
      id="principles"
      aria-labelledby="principles-title"
      className="relative isolate scroll-mt-20 px-5 py-16 md:px-8 md:py-20"
    >
      <div
        className="pointer-events-none absolute top-1/3 left-0 -z-10 h-[500px] w-[45%] bg-[radial-gradient(closest-side,rgba(0,230,160,0.08),transparent)] blur-3xl"
        aria-hidden
      />
      <div className="mx-auto grid max-w-[1264px] gap-14 lg:grid-cols-[0.85fr_1.15fr] lg:gap-20">
        <div className="lg:sticky lg:top-32 lg:self-start">
          <SectionHeading
            id="principles-title"
            align="left"
            eyebrow="SECURITY, PRIVACY & ETHICS"
            dot="#00E6A0"
            title="Security Must Be Responsible by Design."
            description="The tools that investigate threats must never become one. These principles govern how TrustLens inspects, processes and shares information."
          />
        </div>
        <ol className="border-t border-white/[0.08]">
          {PRINCIPLES.map((p, i) => (
            <Reveal
              as="li"
              key={p.title}
              delay={i * 0.05}
              className="group grid grid-cols-[auto_1fr] gap-x-5 gap-y-2 border-b border-white/[0.08] py-8 md:grid-cols-[56px_auto_1fr] md:gap-x-6"
            >
              <span className="hidden pt-1 font-mono text-[12px] text-fg-3 md:block">0{i + 1}</span>
              <span className="grid size-11 place-items-center rounded-[12px] border border-white/10 bg-white/[0.03] text-safe transition-colors group-hover:border-safe/40">
                <p.Icon className="size-5" strokeWidth={1.8} aria-hidden />
              </span>
              <div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <h3 className="text-[20px] font-bold tracking-[-0.025em] text-white">
                    {p.title}
                  </h3>
                  <span className="rounded-full border border-safe/25 bg-safe/[0.06] px-2 py-0.5 font-mono text-[10px] tracking-[0.1em] text-safe">
                    {p.tag}
                  </span>
                </div>
                <p className="mt-2 max-w-xl text-[15px] leading-[1.7] text-fg-2">{p.body}</p>
              </div>
            </Reveal>
          ))}
        </ol>
      </div>
    </section>
  );
}
