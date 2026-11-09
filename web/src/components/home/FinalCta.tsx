import { PillLink } from "@/components/ui/Pill";
import { Reveal } from "@/components/ui/Reveal";
import { Stars } from "@/components/ui/Stars";

export function NetworkPattern({ className = "" }: { className?: string }) {
  const pts = [
    [8, 30],
    [20, 62],
    [32, 22],
    [44, 70],
    [56, 36],
    [68, 76],
    [78, 28],
    [90, 60],
    [14, 88],
    [62, 10],
    [96, 20],
    [38, 48],
    [84, 90],
  ];
  const links = [
    [0, 2],
    [0, 1],
    [1, 3],
    [2, 4],
    [3, 4],
    [4, 6],
    [5, 7],
    [6, 7],
    [3, 5],
    [1, 8],
    [4, 9],
    [6, 10],
    [2, 11],
    [11, 4],
    [7, 12],
    [5, 12],
  ];
  return (
    <svg
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      className={`pointer-events-none absolute inset-0 h-full w-full ${className}`}
      aria-hidden
    >
      {links.map(([a, b], i) => (
        <line
          key={i}
          x1={pts[a][0]}
          y1={pts[a][1]}
          x2={pts[b][0]}
          y2={pts[b][1]}
          stroke="rgba(255,255,255,0.18)"
          strokeWidth="0.12"
          vectorEffect="non-scaling-stroke"
        />
      ))}
      {pts.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r="0.35" fill="rgba(255,255,255,0.7)" />
      ))}
    </svg>
  );
}

export function FinalCta() {
  return (
    <section aria-labelledby="final-cta-title" className="px-5 pb-16 md:px-8 md:pb-20">
      <Reveal className="relative isolate mx-auto max-w-[1264px] overflow-hidden rounded-[28px] border border-white/10">
        <div className="absolute inset-0 -z-10 bg-[#061423]" aria-hidden />
        <div className="absolute inset-0 -z-10 animate-drift drift-layer" aria-hidden>
          <div className="absolute -top-1/3 -left-[10%] h-[120%] w-[60%] rounded-full bg-[radial-gradient(closest-side,rgba(0,213,242,0.6),transparent)]" />
          <div className="absolute -right-[10%] -bottom-1/3 h-[120%] w-[65%] rounded-full bg-[radial-gradient(closest-side,rgba(57,133,255,0.75),transparent)]" />
          <div className="absolute top-[20%] left-[35%] h-[70%] w-[35%] rounded-full bg-[radial-gradient(closest-side,rgba(6,12,24,0.75),transparent)]" />
        </div>
        <NetworkPattern className="-z-10 opacity-60" />
        <Stars count={30} seed={41} className="-z-10" />
        <div className="grain -z-10" />
        <div className="flex flex-col items-center px-6 py-20 text-center md:py-28">
          <p className="font-mono text-[12px] tracking-[0.16em] text-white/70">
            DON&apos;T TRUST. VERIFY.
          </p>
          <h2
            id="final-cta-title"
            className="mt-5 max-w-4xl text-[clamp(2.25rem,5.4vw,4.5rem)] leading-[1] font-extrabold tracking-[-0.05em] text-white text-balance"
          >
            Don&apos;t Just Detect Threats. Build Digital Trust.
          </h2>
          <p className="mt-6 max-w-xl text-[17px] leading-relaxed text-white/75 md:text-[18px]">
            Investigate suspicious content, uncover hidden risks and contribute to a more
            transparent digital ecosystem.
          </p>
          <div className="mt-10 flex flex-col gap-3.5 sm:flex-row">
            <PillLink to={{ pathname: "/", hash: "#scanner" }} arrow>
              Start Investigating
            </PillLink>
            <PillLink to="/about" variant="dark">
              Learn How It Works
            </PillLink>
          </div>
        </div>
      </Reveal>
    </section>
  );
}
