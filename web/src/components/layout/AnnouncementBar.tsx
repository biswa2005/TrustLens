import { Link } from "react-router";

export function AnnouncementBar() {
  return (
    <div className="relative z-50 bg-[linear-gradient(90deg,#8ff0e4_0%,#5fd6f0_35%,#4aa8ff_70%,#3a7dff_100%)] text-[#06121a]">
      <div className="mx-auto flex h-[42px] max-w-[1264px] items-center justify-center gap-3 px-4 text-[13px] sm:gap-4">
        <span className="hidden size-1.5 rounded-full bg-[#06121a]/60 sm:block" aria-hidden />
        <span className="font-mono tracking-[0.1em]">DON&apos;T TRUST. VERIFY.</span>
        <span className="hidden font-mono text-[#06121a]/55 line-through md:inline">guesswork</span>
        <span className="hidden font-semibold tracking-[-0.01em] md:inline">
          Evidence-based threat analysis
        </span>
        <span className="hidden text-[#06121a]/50 lg:inline" aria-hidden>
          —
        </span>
        <span className="hidden font-mono text-[#06121a]/70 lg:inline">preview build</span>
        <Link
          to={{ pathname: "/", hash: "#scanner" }}
          className="inline-flex h-[26px] items-center gap-1 rounded-full bg-[#06121a] px-3 text-[12.5px] font-semibold text-[#8ff0e4] transition hover:bg-black"
        >
          Try it <span aria-hidden>→</span>
        </Link>
      </div>
    </div>
  );
}
