import { useState } from "react";
import { ArrowRight, Fingerprint, Clock, Eye } from "lucide-react";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { Reveal } from "@/components/ui/Reveal";
import { config, isRegistryConfigured } from "@/lib/config";
import { RegistryDialog } from "./RegistryDialog";

const SAMPLE_ENTRIES = [
  {
    id: "TL-0481",
    hash: "0x7c1e…a91d",
    time: "08 Nov · 09:14",
    net: "Arbitrum",
    kind: "Phishing domain",
  },
  {
    id: "TL-0480",
    hash: "0x3f9a…c21e",
    time: "08 Nov · 08:52",
    net: "Arbitrum",
    kind: "Scam message",
  },
  {
    id: "TL-0479",
    hash: "0xb06d…4e7f",
    time: "07 Nov · 22:31",
    net: "Ethereum",
    kind: "Look-alike TLS",
  },
  {
    id: "TL-0478",
    hash: "0x91ac…08b3",
    time: "07 Nov · 19:05",
    net: "Arbitrum",
    kind: "Credential lure",
  },
];

const FACTS = [
  {
    Icon: Fingerprint,
    title: "Hash, Not Content",
    body: "Store only encrypted fingerprints of selected incident data, not the original reports.",
  },
  {
    Icon: Clock,
    title: "Tamper-Proof Timeline",
    body: "Record timestamps on the blockchain to make changes easy to detect.",
  },
  {
    Icon: Eye,
    title: "Public Verification",
    body: "Allow anyone with the original report to verify its authenticity independently.",
  },
];

function ChainBackdrop() {
  return (
    <svg
      className="pointer-events-none absolute inset-0 -z-10 h-full w-full opacity-[0.35]"
      aria-hidden
    >
      <defs>
        <pattern
          id="registry-hex"
          width="64"
          height="74"
          patternUnits="userSpaceOnUse"
          patternTransform="scale(1.1)"
        >
          <path
            d="M32 2 62 19v36L32 72 2 55V19Z"
            fill="none"
            stroke="rgba(57,133,255,0.12)"
            strokeWidth="1"
          />
        </pattern>
        <radialGradient id="registry-fade" cx="70%" cy="50%" r="60%">
          <stop offset="0" stopColor="white" />
          <stop offset="1" stopColor="white" stopOpacity="0" />
        </radialGradient>
        <mask id="registry-mask">
          <rect width="100%" height="100%" fill="url(#registry-fade)" />
        </mask>
      </defs>
      <rect width="100%" height="100%" fill="url(#registry-hex)" mask="url(#registry-mask)" />
    </svg>
  );
}

export function TrustRegistry() {
  const [open, setOpen] = useState(false);
  return (
    <section
      id="registry"
      aria-labelledby="registry-title"
      className="relative isolate scroll-mt-20 overflow-hidden px-5 py-16 md:px-8 md:py-20"
    >
      <div
        className="absolute inset-0 -z-20 bg-[linear-gradient(180deg,#080B12,#0a0d1a_40%,#080B12)]"
        aria-hidden
      />
      <div
        className="pointer-events-none absolute top-1/2 right-[-10%] -z-10 h-[700px] w-[60%] -translate-y-1/2 bg-[radial-gradient(closest-side,rgba(145,102,255,0.16),rgba(57,133,255,0.08)_50%,transparent)] blur-2xl"
        aria-hidden
      />
      <ChainBackdrop />

      <div className="mx-auto grid max-w-[1264px] items-center gap-14 lg:grid-cols-[0.95fr_1.25fr] lg:gap-16">
        <div>
          <SectionHeading
            id="registry-title"
            align="left"
            eyebrow="TRUST REGISTRY"
            dot="#9166FF"
            title={
              <>
                Trust Should Be <span className="text-tide">Verifiable.</span>
              </>
            }
            description="Move beyond isolated threat reports with transparent, verifiable records that build digital trust."
          />
          <Reveal delay={0.1}>
            <ul className="mt-10 space-y-5">
              {FACTS.map(({ Icon, title, body }) => (
                <li key={title} className="flex gap-4">
                  <span className="grid size-10 shrink-0 place-items-center rounded-[12px] border border-white/10 bg-white/[0.03] text-violet">
                    <Icon className="size-[18px]" strokeWidth={1.8} aria-hidden />
                  </span>
                  <div>
                    <p className="text-[15.5px] font-semibold text-white">{title}</p>
                    <p className="mt-0.5 text-[14.5px] leading-relaxed text-fg-2">{body}</p>
                  </div>
                </li>
              ))}
            </ul>
            <button
              type="button"
              onClick={() => setOpen(true)}
              className="group mt-10 inline-flex h-12 items-center gap-2 rounded-full bg-white px-6 text-[15px] font-semibold text-[#07090e] shadow-[0_10px_30px_-12px_rgba(255,255,255,0.55)] transition hover:bg-[#efe9ff] hover:shadow-[0_14px_40px_-12px_rgba(145,102,255,0.6)]"
            >
              Explore Threat Registry
              <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
            </button>
          </Reveal>
        </div>

        <Reveal delay={0.15}>
          <div className="relative overflow-hidden rounded-[20px] border border-white/10 bg-[#0a0f18]/90 shadow-[0_40px_100px_-40px_rgba(0,0,0,0.9)] backdrop-blur-xl">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] px-5 py-4">
              <div className="flex items-center gap-3">
                <span className="flex gap-1.5" aria-hidden>
                  <span className="size-2.5 rounded-full bg-white/10" />
                  <span className="size-2.5 rounded-full bg-white/10" />
                  <span className="size-2.5 rounded-full bg-white/10" />
                </span>
                <p className="font-mono text-[12px] tracking-[0.08em] text-fg-2">
                  registry / incident-commitments
                </p>
              </div>
              <span className="rounded-full border border-amber/40 bg-amber/10 px-2.5 py-1 font-mono text-[10.5px] font-semibold tracking-[0.12em] text-amber">
                SAMPLE DATA
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[600px] text-left whitespace-nowrap">
                <caption className="sr-only">
                  Illustrative sample registry entries — not on-chain records
                </caption>
                <thead>
                  <tr className="font-mono text-[10.5px] tracking-[0.12em] text-fg-3">
                    <th scope="col" className="px-5 py-3 font-normal">
                      INCIDENT ID
                    </th>
                    <th scope="col" className="px-3 py-3 font-normal">
                      COMMITMENT HASH
                    </th>
                    <th scope="col" className="px-3 py-3 font-normal">
                      TIMESTAMP (UTC)
                    </th>
                    <th scope="col" className="px-3 py-3 font-normal">
                      NETWORK
                    </th>
                    <th scope="col" className="px-5 py-3 font-normal">
                      STATUS
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {SAMPLE_ENTRIES.map((e) => (
                    <tr
                      key={e.id}
                      className="border-t border-white/[0.05] transition-colors hover:bg-white/[0.02]"
                    >
                      <td className="px-5 py-4">
                        <p className="font-mono text-[12.5px] text-white">{e.id}</p>
                        <p className="mt-0.5 text-[12px] text-fg-3">{e.kind}</p>
                      </td>
                      <td className="px-3 py-4 font-mono text-[12.5px] text-cyan/90">{e.hash}</td>
                      <td className="px-3 py-4 font-mono text-[12px] text-fg-2">{e.time}</td>
                      <td className="px-3 py-4 text-[13px] text-fg-2">{e.net}</td>
                      <td className="px-5 py-4">
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 px-2.5 py-1 font-mono text-[10.5px] tracking-wider text-fg-2">
                          <span className="size-1.5 rounded-full bg-fg-3" />
                          SAMPLE · NOT ON-CHAIN
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex flex-col gap-2 border-t border-white/[0.07] bg-black/20 px-5 py-4 text-[12.5px] text-fg-3 sm:flex-row sm:items-center sm:justify-between">
              <p>Entries are illustrative and do not correspond to on-chain transactions.</p>
              <p className="font-mono">
                Network:{" "}
                <span className={isRegistryConfigured ? "text-white" : "text-amber"}>
                  {config.registry.network ?? "not configured"}
                </span>
              </p>
            </div>
          </div>
        </Reveal>
      </div>
      <RegistryDialog open={open} onClose={() => setOpen(false)} />
    </section>
  );
}
