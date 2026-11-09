import { useRef, type MouseEvent, type ReactNode } from "react";
import { Blocks, Brain, Globe, Lock, Network, ShieldCheck, type LucideIcon } from "lucide-react";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { Reveal } from "@/components/ui/Reveal";

function DomainPreview() {
  const rows = [
    { d: "paypa1-secure.com", r: "High", c: "#FF8A3D", w: "86%" },
    { d: "login-examp1e.net", r: "Suspicious", c: "#FFD24A", w: "54%" },
    { d: "example.com", r: "Low", c: "#00E6A0", w: "12%" },
  ];
  return (
    <div className="space-y-2.5">
      {rows.map((row) => (
        <div key={row.d} className="rounded-lg border border-white/[0.07] bg-black/30 px-3 py-2.5">
          <div className="flex items-center justify-between gap-2">
            <span className="truncate font-mono text-[12px] text-white/85">{row.d}</span>
            <span
              className="font-mono text-[10.5px] tracking-wider uppercase"
              style={{ color: row.c }}
            >
              {row.r}
            </span>
          </div>
          <div className="mt-2 h-1 rounded-full bg-white/[0.06]">
            <div className="h-full rounded-full" style={{ width: row.w, background: row.c }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function CertificatePreview() {
  const chain = [
    { n: "Root CA", s: "Trusted store" },
    { n: "Intermediate CA", s: "Signature valid" },
    { n: "*.example.com", s: "Valid · 64 days left" },
  ];
  return (
    <div className="relative pl-5">
      <div className="absolute top-3 bottom-3 left-[7px] w-px bg-[linear-gradient(180deg,#00D5F2,#3985FF)]" />
      <div className="space-y-2">
        {chain.map((c) => (
          <div
            key={c.n}
            className="relative flex items-center justify-between rounded-lg border border-white/[0.07] bg-black/30 px-3 py-2"
          >
            <span className="absolute top-1/2 -left-[17px] size-2.5 -translate-y-1/2 rounded-full border-2 border-[#0b1019] bg-cyan" />
            <span className="font-mono text-[12px] text-white/85">{c.n}</span>
            <span className="text-[11px] text-safe">{c.s}</span>
          </div>
        ))}
      </div>
      <p className="mt-2.5 font-mono text-[10.5px] tracking-wider text-fg-3">CT LOG · PRESENT</p>
    </div>
  );
}

function ClassificationPreview() {
  const bars = [
    { l: "Urgency", v: 82 },
    { l: "Impersonation", v: 64 },
    { l: "Credential lure", v: 71 },
  ];
  return (
    <div>
      <p className="rounded-lg border border-white/[0.07] bg-black/30 px-3 py-2.5 text-[12.5px] leading-relaxed text-white/75">
        “<mark className="rounded bg-violet/25 px-0.5 text-[#d9ceff]">Urgent</mark>:{" "}
        <mark className="rounded bg-violet/25 px-0.5 text-[#d9ceff]">verify your account</mark>{" "}
        within 24h to avoid suspension…”
      </p>
      <div className="mt-3 space-y-2">
        {bars.map((b) => (
          <div key={b.l} className="grid grid-cols-[96px_1fr_32px] items-center gap-2">
            <span className="text-[11.5px] text-fg-2">{b.l}</span>
            <div className="h-1 rounded-full bg-white/[0.06]">
              <div
                className="h-full rounded-full bg-[linear-gradient(90deg,#9166FF,#3985FF)]"
                style={{ width: `${b.v}%` }}
              />
            </div>
            <span className="text-right font-mono text-[11px] text-fg-2">{b.v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function NetworkPreview() {
  const nodes = [
    { x: 50, y: 50, r: 7, c: "#FF4269", l: "campaign" },
    { x: 18, y: 26, r: 4.5, c: "#00D5F2", l: "domain" },
    { x: 84, y: 22, r: 4.5, c: "#00D5F2", l: "domain" },
    { x: 14, y: 78, r: 4.5, c: "#3985FF", l: "ip" },
    { x: 80, y: 80, r: 4.5, c: "#9166FF", l: "cert" },
    { x: 50, y: 12, r: 3.5, c: "#3985FF", l: "" },
  ];
  return (
    <svg viewBox="0 0 100 92" className="h-[150px] w-full" aria-hidden>
      {nodes.slice(1).map((n, i) => (
        <line
          key={i}
          x1="50"
          y1="50"
          x2={n.x}
          y2={n.y}
          stroke="rgba(0,213,242,0.45)"
          strokeWidth="0.5"
          strokeDasharray="2 2"
          className="animate-dash"
        />
      ))}
      <line x1="18" y1="26" x2="50" y2="12" stroke="rgba(148,163,184,0.2)" strokeWidth="0.4" />
      <line x1="84" y1="22" x2="50" y2="12" stroke="rgba(148,163,184,0.2)" strokeWidth="0.4" />
      <line x1="14" y1="78" x2="80" y2="80" stroke="rgba(148,163,184,0.15)" strokeWidth="0.4" />
      {nodes.map((n, i) => (
        <g key={i}>
          <circle cx={n.x} cy={n.y} r={n.r * 2} fill={n.c} opacity="0.12" />
          <circle cx={n.x} cy={n.y} r={n.r} fill="#0b1019" stroke={n.c} strokeWidth="1" />
          {n.l && (
            <text
              x={n.x}
              y={n.y + n.r + 6}
              textAnchor="middle"
              fontSize="4.2"
              fill="#9AA7BA"
              fontFamily="JetBrains Mono, monospace"
            >
              {n.l}
            </text>
          )}
        </g>
      ))}
    </svg>
  );
}

function AuditPreview() {
  const rows = [
    { k: "Strict-Transport-Security", ok: true },
    { k: "Content-Security-Policy", ok: true },
    { k: "X-Frame-Options", ok: false },
    { k: "Referrer-Policy", ok: true },
  ];
  return (
    <ul className="divide-y divide-white/[0.06] rounded-lg border border-white/[0.07] bg-black/30">
      {rows.map((r) => (
        <li key={r.k} className="flex items-center justify-between px-3 py-2">
          <span className="font-mono text-[11.5px] text-white/80">{r.k}</span>
          <span
            className={`font-mono text-[10.5px] tracking-wider ${r.ok ? "text-safe" : "text-amber"}`}
          >
            {r.ok ? "PRESENT" : "MISSING"}
          </span>
        </li>
      ))}
    </ul>
  );
}

function ChainPreview() {
  const blocks = ["#1042", "#1043", "#1044"];
  return (
    <div>
      <div className="flex items-center">
        {blocks.map((b, i) => (
          <div key={b} className="flex flex-1 items-center">
            <div
              className={`flex-1 rounded-lg border px-2.5 py-2 ${i === 2 ? "border-cyan/50 bg-cyan/[0.07]" : "border-white/[0.08] bg-black/30"}`}
            >
              <p className="font-mono text-[10px] text-fg-3">BLOCK</p>
              <p className="font-mono text-[12px] text-white/85">{b}</p>
            </div>
            {i < blocks.length - 1 && <span className="h-px w-3 bg-cyan/50" />}
          </div>
        ))}
      </div>
      <div className="mt-3 rounded-lg border border-white/[0.07] bg-black/30 px-3 py-2.5">
        <p className="font-mono text-[10px] tracking-wider text-fg-3">COMMITMENT · SHA-256</p>
        <p className="mt-1 truncate font-mono text-[12px] text-cyan">0x7c1e…sample…a91d</p>
      </div>
    </div>
  );
}

const CARDS: {
  n: string;
  title: string;
  body: string;
  Icon: LucideIcon;
  accent: string;
  visual: ReactNode;
}[] = [
  {
    n: "01",
    title: "URL & Domain Intelligence",
    body: "Detect phishing websites, fake domains, suspicious redirects, and domain risks.",
    Icon: Globe,
    accent: "#00D5F2",
    visual: <DomainPreview />,
  },
  {
    n: "02",
    title: "TLS & Web Trust Inspection",
    body: "Check SSL/TLS certificates, trust chains, expiry dates, and certificate issues.",
    Icon: ShieldCheck,
    accent: "#3985FF",
    visual: <CertificatePreview />,
  },
  {
    n: "03",
    title: "AI Social Engineering Analysis",
    body: "Identify phishing messages, fake urgency, impersonation, and manipulative language.",
    Icon: Brain,
    accent: "#9166FF",
    visual: <ClassificationPreview />,
  },
  {
    n: "04",
    title: "Cross-Incident Threat Correlation",
    body: "Connect domains, IPs, and certificates to uncover related threats and campaigns.",
    Icon: Network,
    accent: "#00D5F2",
    visual: <NetworkPreview />,
  },
  {
    n: "05",
    title: "Non-Intrusive Security Audit",
    body: "Review security headers, HTTPS settings, HSTS, CSP, and website security risks.",
    Icon: Lock,
    accent: "#3985FF",
    visual: <AuditPreview />,
  },
  {
    n: "06",
    title: "Web3 On-Chain Threat Registry",
    body: "Securely verify threat reports using tamper-proof hashes on EVM networks.",
    Icon: Blocks,
    accent: "#9166FF",
    visual: <ChainPreview />,
  },
];

function CapabilityCard({ card }: { card: (typeof CARDS)[number] }) {
  const ref = useRef<HTMLElement>(null);
  function onMove(e: MouseEvent) {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - rect.left}px`);
    el.style.setProperty("--my", `${e.clientY - rect.top}px`);
  }
  return (
    <article
      ref={ref}
      onMouseMove={onMove}
      className="group relative flex h-full flex-col overflow-hidden rounded-[18px] border border-white/[0.08] bg-[linear-gradient(180deg,#0f1520,#0a0e16)] p-6 transition duration-300 hover:-translate-y-1 hover:border-white/[0.16] hover:shadow-[0_30px_60px_-30px_rgba(0,0,0,0.9)]"
    >
      <div
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{
          background: `radial-gradient(360px circle at var(--mx, 50%) var(--my, 0%), ${card.accent}14, transparent 60%)`,
        }}
        aria-hidden
      />
      <div className="relative min-h-[178px]">{card.visual}</div>
      <div className="relative mt-6 flex items-center gap-3 border-t border-white/[0.07] pt-5">
        <span
          className="grid size-9 place-items-center rounded-[10px] border border-white/10 bg-white/[0.03]"
          style={{ color: card.accent }}
        >
          <card.Icon className="size-[18px]" strokeWidth={1.8} aria-hidden />
        </span>
        <span className="font-mono text-[11.5px] tracking-[0.12em] text-fg-3">{card.n}</span>
      </div>
      <h3 className="relative mt-4 text-[20px] leading-tight font-bold tracking-[-0.025em] text-white">
        {card.title}
      </h3>
      <p className="relative mt-2.5 text-[14.5px] leading-[1.6] text-fg-2">{card.body}</p>
    </article>
  );
}

export function Capabilities() {
  return (
    <section
      id="features"
      aria-labelledby="features-title"
      className="relative isolate scroll-mt-20 px-5 pt-6 pb-16 md:px-8 md:pt-8 md:pb-20"
    >
      <div
        className="pointer-events-none absolute top-40 left-0 -z-10 h-[500px] w-[40%] bg-[radial-gradient(closest-side,rgba(180,105,50,0.12),transparent)] blur-3xl"
        aria-hidden
      />
      <div
        className="pointer-events-none absolute right-0 bottom-20 -z-10 h-[500px] w-[40%] bg-[radial-gradient(closest-side,rgba(57,133,255,0.12),transparent)] blur-3xl"
        aria-hidden
      />
      <div className="mx-auto max-w-[1264px]">
        <SectionHeading
          id="features-title"
          eyebrow="CORE CAPABILITIES"
          title={
            <>
              Beyond Detection. <span className="text-tide">Into Digital Trust.</span>
            </>
          }
          description="A unified intelligence platform designed to uncover deceptive infrastructure, analyze suspicious interactions and provide transparent security insights."
        />
        <div className="mt-16 grid gap-4 md:grid-cols-2 lg:grid-cols-3 lg:gap-5">
          {CARDS.map((card, i) => (
            <Reveal key={card.n} delay={(i % 3) * 0.08} className="h-full">
              <CapabilityCard card={card} />
            </Reveal>
          ))}
        </div>
        <p className="mt-6 text-center font-mono text-[11.5px] tracking-[0.1em] text-fg-3">
          INTERFACE PREVIEWS ARE ILLUSTRATIVE AND DO NOT REPRESENT LIVE DATA
        </p>
      </div>
    </section>
  );
}
