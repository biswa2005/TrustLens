import { motion } from "motion/react";
import { Eyebrow } from "@/components/ui/Eyebrow";
import { Stars } from "@/components/ui/Stars";

const ease = [0.22, 1, 0.36, 1] as const;
const SHIELD = "M200 28 338 82v108c0 88-58 160-138 194C120 350 62 278 62 190V82L200 28Z";

function ShieldMotif() {
  const nodes = [
    { x: 40, y: 120, l: "Intelligence", c: "#9166FF" },
    { x: 366, y: 96, l: "Evidence", c: "#00D5F2" },
    { x: 370, y: 318, l: "Provenance", c: "#3985FF" },
    { x: 30, y: 300, l: "Transparency", c: "#00E6A0" },
  ];
  return (
    <div className="relative mx-auto aspect-square w-full max-w-[520px]">
      <div
        className="absolute inset-[12%] rounded-full bg-[radial-gradient(closest-side,rgba(0,213,242,0.22),rgba(57,133,255,0.08)_60%,transparent)] blur-xl"
        aria-hidden
      />
      <svg
        viewBox="0 0 400 420"
        className="relative h-full w-full"
        role="img"
        aria-label="Abstract TrustLens shield surrounded by connected trust signals"
      >
        <defs>
          <linearGradient
            id="about-shield"
            x1="60"
            y1="20"
            x2="340"
            y2="390"
            gradientUnits="userSpaceOnUse"
          >
            <stop stopColor="#7EF0F5" />
            <stop offset="0.5" stopColor="#00D5F2" />
            <stop offset="1" stopColor="#3985FF" />
          </linearGradient>
          <linearGradient id="about-scan" x1="0" y1="0" x2="0" y2="1">
            <stop stopColor="#00D5F2" stopOpacity="0" />
            <stop offset="0.92" stopColor="#00D5F2" stopOpacity="0.22" />
            <stop offset="1" stopColor="#00D5F2" stopOpacity="0" />
          </linearGradient>
          <clipPath id="about-clip">
            <path d={SHIELD} />
          </clipPath>
        </defs>

        <circle
          cx="200"
          cy="210"
          r="186"
          fill="none"
          stroke="rgba(148,163,184,0.12)"
          strokeDasharray="2 6"
        />
        <circle cx="200" cy="210" r="150" fill="none" stroke="rgba(148,163,184,0.08)" />

        {nodes.map((n) => (
          <line
            key={n.l}
            x1="200"
            y1="210"
            x2={n.x}
            y2={n.y}
            stroke="rgba(0,213,242,0.3)"
            strokeWidth="1"
            strokeDasharray="3 5"
            className="animate-dash"
          />
        ))}

        <path d={SHIELD} fill="rgba(10,16,26,0.9)" stroke="url(#about-shield)" strokeWidth="2" />
        <g transform="translate(200 210) scale(0.74) translate(-200 -210)">
          <path d={SHIELD} fill="none" stroke="rgba(0,213,242,0.35)" strokeWidth="1.5" />
        </g>
        <g transform="translate(200 210) scale(0.48) translate(-200 -210)">
          <path
            d={SHIELD}
            fill="rgba(0,213,242,0.06)"
            stroke="rgba(0,213,242,0.5)"
            strokeWidth="2"
          />
        </g>

        <g clipPath="url(#about-clip)">
          <g opacity="0.5">
            {Array.from({ length: 9 }, (_, i) => (
              <line
                key={i}
                x1={60 + i * 35}
                y1="20"
                x2={60 + i * 35}
                y2="400"
                stroke="rgba(148,163,184,0.06)"
              />
            ))}
          </g>
          <motion.g
            initial={{ y: 0 }}
            animate={{ y: [0, 330, 0] }}
            transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }}
          >
            <rect x="40" width="320" height="70" fill="url(#about-scan)" />
            <line
              x1="40"
              x2="360"
              y1="65"
              y2="65"
              stroke="#00D5F2"
              strokeOpacity="0.55"
              strokeWidth="1"
            />
          </motion.g>
        </g>

        <circle cx="194" cy="200" r="30" fill="none" stroke="#F5F7FC" strokeWidth="5" />
        <path d="m216 222 22 22" stroke="#F5F7FC" strokeWidth="5" strokeLinecap="round" />
        <circle cx="194" cy="200" r="9" fill="url(#about-shield)" />

        {nodes.map((n, i) => (
          <g key={n.l}>
            <circle
              cx={n.x}
              cy={n.y}
              r="14"
              fill={n.c}
              opacity="0.14"
              className="animate-pulse"
              style={{ animationDelay: `${i * 0.6}s` }}
            />
            <circle cx={n.x} cy={n.y} r="5" fill="#0b1019" stroke={n.c} strokeWidth="2" />
          </g>
        ))}
      </svg>
      {nodes.map((n) => (
        <span
          key={n.l}
          className="absolute -translate-x-1/2 rounded-full border border-white/10 bg-black/60 px-2.5 py-1 font-mono text-[10.5px] tracking-[0.08em] whitespace-nowrap text-white/75 backdrop-blur-md"
          style={{ left: `${(n.x / 400) * 100}%`, top: `calc(${(n.y / 420) * 100}% + 14px)` }}
        >
          {n.l.toUpperCase()}
        </span>
      ))}
    </div>
  );
}

export function AboutHero() {
  return (
    <section aria-labelledby="about-title" className="relative isolate overflow-hidden">
      <div className="absolute inset-0 -z-10 bg-[#07080c]" aria-hidden>
        <div className="absolute top-[-30%] right-[-10%] h-[110%] w-[60%] animate-drift-slow drift-layer rounded-full bg-[radial-gradient(closest-side,rgba(57,120,200,0.55),transparent)]" />
        <div className="absolute bottom-[-40%] left-[-15%] h-[90%] w-[45%] animate-drift drift-layer rounded-full bg-[radial-gradient(closest-side,rgba(190,110,50,0.35),transparent)]" />
        <div className="absolute inset-0 hairline-grid opacity-40 [mask-image:radial-gradient(60%_60%_at_70%_45%,black,transparent)]" />
        <div className="absolute inset-x-0 bottom-0 h-40 bg-[linear-gradient(180deg,transparent,#080B12)]" />
        <Stars count={50} seed={5} />
        <div className="grain" />
      </div>

      <div className="mx-auto grid max-w-[1264px] items-center gap-12 px-5 pt-16 pb-12 md:px-8 md:pt-24 lg:grid-cols-[1.1fr_0.9fr] lg:pb-16">
        <div>
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, ease }}
          >
            <Eyebrow>ABOUT TRUSTLENS</Eyebrow>
          </motion.div>
          <motion.h1
            id="about-title"
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, delay: 0.1, ease }}
            className="mt-7 text-[clamp(2.75rem,7vw,5.75rem)] leading-[0.95] font-extrabold tracking-[-0.055em] text-white text-balance"
          >
            Restoring Trust to the <span className="text-tide">Open Web.</span>
          </motion.h1>
          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, delay: 0.2, ease }}
            className="mt-8 max-w-xl text-[20px] leading-[1.5] font-medium tracking-[-0.01em] text-white/85 md:text-[22px]"
          >
            Combining Artificial Intelligence, Web Security and Cryptographic Provenance to help
            eliminate digital deception.
          </motion.p>
          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, delay: 0.3, ease }}
            className="mt-6 max-w-xl border-l border-cyan/40 pl-5 text-[16px] leading-[1.75] text-fg-2"
          >
            The modern web is increasingly vulnerable to phishing websites, impersonated portals,
            fraudulent messages and compromised digital trust signals. TrustLens brings intelligent
            investigation, explainable risk assessment and verifiable security insights together in
            one unified platform.
          </motion.p>
        </div>
        <motion.div
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 1.1, delay: 0.2, ease }}
        >
          <ShieldMotif />
        </motion.div>
      </div>
    </section>
  );
}
