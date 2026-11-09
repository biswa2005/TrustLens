import {
  Blocks,
  BrainCircuit,
  Globe2,
  Radar,
  ServerCog,
  ShieldCheck,
  Monitor,
  Link2,
  type LucideIcon,
} from "lucide-react";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { Reveal } from "@/components/ui/Reveal";
import { isLiveScanConfigured, isRegistryConfigured } from "@/lib/config";

const CATEGORIES: {
  title: string;
  Icon: LucideIcon;
  color: string;
  items: { name: string; mark: string }[];
  configured: boolean;
}[] = [
  {
    title: "AI & NLP",
    Icon: BrainCircuit,
    color: "#9166FF",
    items: [
      { name: "LLM-based analysis", mark: "LLM" },
      { name: "Contextual message interpretation", mark: "CTX" },
      { name: "Pattern recognition", mark: "PTN" },
      { name: "Anomaly detection", mark: "ANM" },
    ],
    configured: isLiveScanConfigured,
  },
  {
    title: "Threat Intelligence",
    Icon: Radar,
    color: "#00D5F2",
    items: [
      { name: "Google Safe Browsing", mark: "GSB" },
      { name: "URLhaus", mark: "UH" },
      { name: "VirusTotal", mark: "VT" },
      { name: "crt.sh", mark: "CRT" },
    ],
    configured: isLiveScanConfigured,
  },
  {
    title: "Web Security",
    Icon: ShieldCheck,
    color: "#3985FF",
    items: [
      { name: "OpenSSL", mark: "SSL" },
      { name: "DNS analysis", mark: "DNS" },
      { name: "HTTP security headers", mark: "HDR" },
      { name: "TLS certificate validation", mark: "TLS" },
    ],
    configured: isLiveScanConfigured,
  },
  {
    title: "Web3 & Cryptography",
    Icon: Blocks,
    color: "#00E6A0",
    items: [
      { name: "EVM smart contracts", mark: "EVM" },
      { name: "Cryptographic hashing", mark: "#" },
      { name: "On-chain incident commitments", mark: "TX" },
      { name: "Decentralized verification", mark: "DV" },
    ],
    configured: isRegistryConfigured,
  },
];

const FLOW: { label: string; sub: string; Icon: LucideIcon }[] = [
  { label: "Client", sub: "Browser", Icon: Monitor },
  { label: "Protected backend", sub: "SSRF guard", Icon: ServerCog },
  { label: "Intelligence", sub: "Feeds · DNS · TLS", Icon: Globe2 },
  { label: "Report", sub: "Evidence", Icon: ShieldCheck },
  { label: "Registry", sub: "Commitment", Icon: Link2 },
];

export function TechArchitecture() {
  return (
    <section
      id="architecture"
      aria-labelledby="architecture-title"
      className="scroll-mt-20 px-5 py-16 md:px-8 md:py-20"
    >
      <div className="mx-auto max-w-[1264px]">
        <SectionHeading
          id="architecture-title"
          eyebrow="TECHNOLOGY ARCHITECTURE"
          title={
            <>
              Built on Intelligence. <span className="text-tide">Secured by Transparency.</span>
            </>
          }
          description="The services below make up TrustLens’ intended analysis stack. Each is labelled with its connection status in this build."
        />

        <Reveal delay={0.1} className="mx-auto mt-14 max-w-[1000px]">
          <ol
            className="flex items-center gap-2 overflow-x-auto pb-2 [scrollbar-width:none]"
            aria-label="Request flow"
          >
            {FLOW.map((f, i) => (
              <li key={f.label} className="flex flex-1 items-center gap-2">
                <div className="flex min-w-[132px] flex-1 items-center gap-3 rounded-xl border border-white/[0.08] bg-white/[0.02] px-3 py-2.5">
                  <f.Icon className="size-4 shrink-0 text-cyan" aria-hidden />
                  <div className="min-w-0">
                    <p className="truncate text-[13px] font-medium text-white">{f.label}</p>
                    <p className="truncate font-mono text-[10.5px] text-fg-3">{f.sub}</p>
                  </div>
                </div>
                {i < FLOW.length - 1 && (
                  <span
                    className="h-px w-4 shrink-0 bg-[linear-gradient(90deg,rgba(0,213,242,0.6),rgba(57,133,255,0.3))]"
                    aria-hidden
                  />
                )}
              </li>
            ))}
          </ol>
        </Reveal>

        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {CATEGORIES.map((cat, i) => (
            <Reveal key={cat.title} delay={i * 0.08} className="h-full">
              <article className="flex h-full flex-col rounded-[18px] border border-white/[0.08] bg-[linear-gradient(180deg,#0f1520,#0a0e16)] p-6">
                <div className="flex items-center justify-between">
                  <span
                    className="grid size-10 place-items-center rounded-[12px] border border-white/10 bg-white/[0.03]"
                    style={{ color: cat.color }}
                  >
                    <cat.Icon className="size-5" strokeWidth={1.8} aria-hidden />
                  </span>
                  <span className="font-mono text-[11px] text-fg-3">0{i + 1}</span>
                </div>
                <h3 className="mt-6 text-[19px] font-bold tracking-[-0.025em] text-white">
                  {cat.title}
                </h3>
                <ul className="mt-5 flex-1 space-y-2.5">
                  {cat.items.map((it) => (
                    <li
                      key={it.name}
                      className="flex items-center gap-3 rounded-[10px] border border-white/[0.06] bg-black/25 px-2.5 py-2"
                    >
                      <span
                        className="grid h-7 min-w-9 place-items-center rounded-md px-1.5 font-mono text-[10px] font-semibold tracking-wide"
                        style={{
                          color: cat.color,
                          background: `${cat.color}14`,
                          border: `1px solid ${cat.color}33`,
                        }}
                      >
                        {it.mark}
                      </span>
                      <span className="text-[13.5px] text-white/85">{it.name}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-5 flex items-center gap-2 border-t border-white/[0.06] pt-4 font-mono text-[11px] tracking-[0.06em]">
                  <span
                    className={`size-1.5 rounded-full ${cat.configured ? "bg-safe" : "bg-amber"}`}
                  />
                  <span className={cat.configured ? "text-safe" : "text-amber"}>
                    {cat.configured
                      ? "Delegated to configured backend"
                      : "Planned · not connected in this build"}
                  </span>
                </p>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
