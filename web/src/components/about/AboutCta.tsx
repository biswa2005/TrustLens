import { PillLink } from "@/components/ui/Pill";
import { Reveal } from "@/components/ui/Reveal";
import { Stars } from "@/components/ui/Stars";
import { LogoMark } from "@/components/ui/Logo";

export function AboutCta() {
  return (
    <section
      aria-labelledby="about-cta-title"
      className="relative isolate overflow-hidden px-5 py-20 md:px-8 md:py-24"
    >
      <div className="absolute inset-0 -z-10" aria-hidden>
        <div className="absolute bottom-[-50%] left-1/2 h-[120%] w-[90%] -translate-x-1/2 rounded-[50%] bg-[radial-gradient(closest-side,rgba(57,133,255,0.45),rgba(0,213,242,0.15)_50%,transparent)] blur-2xl" />
        <div className="absolute bottom-[-30%] left-[-10%] h-[80%] w-[40%] rounded-full bg-[radial-gradient(closest-side,rgba(190,110,50,0.3),transparent)] blur-3xl" />
        <Stars count={40} seed={99} />
        <div className="grain" />
      </div>
      <Reveal className="mx-auto flex max-w-3xl flex-col items-center text-center">
        <span className="grid size-16 place-items-center rounded-[18px] border border-white/15 bg-black/60 shadow-[0_0_40px_rgba(0,213,242,0.25)]">
          <LogoMark className="size-8" />
        </span>
        <h2
          id="about-cta-title"
          className="mt-8 text-[clamp(2.4rem,6vw,4.75rem)] leading-[0.98] font-extrabold tracking-[-0.05em] text-white text-balance"
        >
          Help Build a More <span className="text-tide">Trustworthy Web.</span>
        </h2>
        <p className="mt-6 text-[18px] text-white/65">
          Every verified signal brings us closer to a safer digital environment.
        </p>
        <PillLink to={{ pathname: "/", hash: "#scanner" }} arrow className="mt-10">
          Start Your Investigation
        </PillLink>
      </Reveal>
    </section>
  );
}
