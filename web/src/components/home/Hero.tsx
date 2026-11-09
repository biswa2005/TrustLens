import { Link } from "react-router";
import { motion } from "motion/react";
import { ArrowRight, Play } from "lucide-react";
import { PillLink } from "@/components/ui/Pill";
import { Stars } from "@/components/ui/Stars";

const ease = [0.22, 1, 0.36, 1] as const;
const rise = (delay: number) => ({
  initial: { opacity: 0, y: 18 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.9, delay, ease },
});

/** Atmospheric light: warm amber from the left, cool blue from the right, darkness at the centre. */
function Atmosphere() {
  return (
    <div className="absolute inset-0 -z-10 overflow-hidden bg-[#07080c]" aria-hidden>
      {/* Small screens: rounder gradients so the light doesn't collapse into vertical streaks */}
      <div className="absolute inset-0 lg:hidden bg-[radial-gradient(90%_45%_at_0%_45%,rgba(196,112,48,0.85),transparent_70%),radial-gradient(90%_50%_at_100%_55%,rgba(66,120,190,0.85),transparent_70%),radial-gradient(80%_30%_at_40%_0%,rgba(120,82,72,0.5),transparent_70%),radial-gradient(80%_30%_at_100%_0%,rgba(110,170,225,0.5),transparent_70%)]" />
      <div className="absolute inset-0 hidden animate-drift drift-layer lg:block">
        <div className="absolute top-[-10%] left-[-12%] h-[130%] w-[46%] bg-[radial-gradient(closest-side,rgba(196,112,48,0.95),rgba(150,80,35,0.55)_45%,transparent)]" />
        <div className="absolute top-[-30%] left-[18%] h-[70%] w-[36%] rounded-full bg-[radial-gradient(closest-side,rgba(120,82,72,0.6),transparent)]" />
        <div className="absolute bottom-[-25%] left-[-6%] h-[60%] w-[34%] rounded-full bg-[radial-gradient(closest-side,rgba(205,128,58,0.75),transparent)]" />
      </div>
      <div className="absolute inset-0 hidden animate-drift-slow drift-layer lg:block">
        <div className="absolute top-[-15%] right-[-14%] h-[135%] w-[44%] bg-[radial-gradient(closest-side,rgba(66,120,190,0.95),rgba(40,82,150,0.5)_50%,transparent)]" />
        <div className="absolute top-[-30%] right-[2%] h-[60%] w-[30%] rounded-full bg-[radial-gradient(closest-side,rgba(110,170,225,0.65),transparent)]" />
        <div className="absolute top-[-35%] left-[42%] h-[70%] w-[36%] rounded-full bg-[radial-gradient(closest-side,rgba(40,72,125,0.6),transparent)]" />
        <div className="absolute right-[6%] bottom-[-20%] h-[55%] w-[30%] rounded-full bg-[radial-gradient(closest-side,rgba(70,125,190,0.7),transparent)]" />
      </div>
      {/* soft vertical light leaks */}
      <div className="absolute top-[-20%] left-[18%] hidden lg:block h-[110%] w-[14%] bg-[radial-gradient(closest-side,rgba(150,90,60,0.28),transparent)]" />
      <div className="absolute top-[-20%] right-[14%] hidden lg:block h-[110%] w-[14%] bg-[radial-gradient(closest-side,rgba(90,140,200,0.3),transparent)]" />
      {/* the dark centre that frames the copy */}
      <div className="absolute top-[18%] left-1/2 h-[90%] w-[80%] -translate-x-1/2 lg:w-[52%] rounded-full bg-[radial-gradient(closest-side,rgba(6,7,11,0.92),rgba(6,7,11,0.55)_55%,transparent)]" />
      <div className="absolute inset-x-0 bottom-0 h-72 bg-[linear-gradient(180deg,transparent,rgba(8,11,18,0.75)_55%,#080B12)]" />
      <Stars count={80} seed={11} />
      <div className="grain" />
    </div>
  );
}

function SignalOrbs() {
  const orbs = [
    "radial-gradient(circle at 32% 28%, #8fb8ff, #2a5bd7 55%, #142b6b)",
    "radial-gradient(circle at 32% 28%, #9ff3e2, #3aa59a 55%, #16504d)",
    "radial-gradient(circle at 32% 28%, #8ee9ff, #2c8fc4 55%, #0f3c5e)",
    "radial-gradient(circle at 32% 28%, #b9a8ff, #5d4fc4 55%, #26205e)",
  ];
  return (
    <span className="flex -space-x-2.5" aria-hidden>
      {orbs.map((bg, i) => (
        <span
          key={i}
          className="size-[30px] rounded-full ring-2 ring-[#0a0b10]"
          style={{ background: bg }}
        />
      ))}
    </span>
  );
}

export function Hero() {
  return (
    <section aria-labelledby="hero-title" className="relative isolate overflow-hidden">
      <Atmosphere />
      <div className="mx-auto flex min-h-[calc(100svh-108px)] max-w-[1264px] flex-col items-center justify-center px-5 pt-16 pb-14 text-center md:px-8 md:pt-16 md:pb-10">
        <motion.div {...rise(0.05)}>
          <Link
            to={{ pathname: "/about" }}
            className="group inline-flex items-center gap-2.5 rounded-full border border-white/10 bg-black/45 px-3.5 py-[7px] font-mono text-[10px] tracking-[0.06em] whitespace-nowrap text-white/70 backdrop-blur-md transition hover:border-white/20 hover:text-white sm:px-4 sm:text-[12.5px] sm:tracking-[0.1em]"
          >
            <span className="size-1.5 rounded-full bg-[#7ef0e0] shadow-[0_0_10px_#7ef0e0]" />
            AI-POWERED DIGITAL TRUST INTELLIGENCE
            <span
              className="text-white/40 transition-transform group-hover:translate-x-0.5"
              aria-hidden
            >
              →
            </span>
          </Link>
        </motion.div>

        <motion.h1
          id="hero-title"
          {...rise(0.15)}
          className="mt-7 max-w-[1240px] text-[clamp(2.5rem,6.4vw,5.3rem)] leading-[1] font-extrabold tracking-[-0.05em] text-[#f4f5f8] text-balance"
        >
          AI-Powered Threat Detection{" "}
          <span className="hidden md:inline">
            <br />
          </span>
          &amp; Digital Trust <span className="text-tide">Intelligence.</span>
        </motion.h1>

        <motion.p
          {...rise(0.28)}
          className="mt-7 max-w-[720px] text-[17px] leading-[1.6] text-white/60 text-pretty md:text-[19px]"
        >
          Instantly analyze suspicious URLs, TLS certificates and digital messages with AI-powered
          threat intelligence, passive security inspection and verifiable digital provenance.
        </motion.p>

        <motion.div {...rise(0.38)} className="mt-9 flex flex-col items-center gap-3.5 sm:flex-row">
          <PillLink
            to={{ pathname: "/", hash: "#scanner" }}
            arrow
            className="h-[46px] px-6 font-medium"
          >
            Start Security Scan
          </PillLink>
          <PillLink
            to={{ pathname: "/", hash: "#features" }}
            variant="dark"
            className="h-[46px] px-6"
          >
            Explore Platform
          </PillLink>
        </motion.div>

        <motion.div
          {...rise(0.48)}
          className="mt-10 flex flex-col items-center gap-3 sm:flex-row sm:gap-3.5"
        >
          <SignalOrbs />
          <p className="text-[15px] text-white/60">
            <span className="font-semibold text-white">Passive-first</span> inspection ·
            multi-source intelligence · privacy-conscious
          </p>
        </motion.div>

        <motion.div {...rise(0.58)} className="mt-10">
          <Link
            to={{ pathname: "/about", hash: "#video" }}
            className="group flex items-center gap-3.5 rounded-full border border-[#3d6fa8]/60 bg-[#0b111c]/70 py-2.5 pr-6 pl-3 text-left backdrop-blur-md transition hover:border-[#5d9be0]/80 hover:bg-[#0e1626]/80"
          >
            <span className="grid size-[38px] place-items-center rounded-full bg-[linear-gradient(135deg,#7ef0f5,#3a8bff)] shadow-[0_0_24px_rgba(63,195,240,0.45)]">
              <Play className="ml-0.5 size-3.5 fill-[#06121a] text-[#06121a]" aria-hidden />
            </span>
            <span className="flex flex-col">
              <span className="text-[15.5px] leading-tight font-semibold text-white">
                Why TrustLens?
              </span>
              <span className="text-[13px] text-white/55">How it works · 2 min 15 sec</span>
            </span>
            <ArrowRight
              className="ml-4 size-4 text-white/50 transition-transform group-hover:translate-x-1"
              aria-hidden
            />
          </Link>
        </motion.div>
      </div>
    </section>
  );
}
