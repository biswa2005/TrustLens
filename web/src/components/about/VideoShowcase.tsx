import { useRef, useState } from "react";
import { Maximize, Play, Settings, Volume2 } from "lucide-react";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { Reveal } from "@/components/ui/Reveal";
import { LogoMark } from "@/components/ui/Logo";
import { NetworkPattern } from "@/components/home/FinalCta";
import { config } from "@/lib/config";

export function VideoShowcase() {
  const videoUrl = config.howItWorksVideoUrl;
  const [playing, setPlaying] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);

  function play() {
    if (!videoUrl) return;
    setPlaying(true);
    requestAnimationFrame(() => videoRef.current?.play().catch(() => {}));
  }

  return (
    <section
      id="video"
      aria-labelledby="video-title"
      className="scroll-mt-20 px-5 py-16 md:px-8 md:py-20"
    >
      <div className="mx-auto max-w-[1264px]">
        <SectionHeading
          id="video-title"
          eyebrow="HOW IT WORKS"
          title="See an investigation, end to end."
          description="A guided walkthrough of how TrustLens turns a suspicious link or message into an explainable, verifiable report."
        />

        <Reveal delay={0.1} className="relative mx-auto mt-14 max-w-[1080px]">
          <div
            className="pointer-events-none absolute -inset-10 -z-10 rounded-[40px] bg-[radial-gradient(closest-side,rgba(0,213,242,0.16),transparent)] blur-2xl"
            aria-hidden
          />
          <div className="relative aspect-video overflow-hidden rounded-[20px] border border-cyan/30 bg-[#05080e] shadow-[0_50px_120px_-40px_rgba(0,0,0,0.95)]">
            {playing && videoUrl ? (
              <video
                ref={videoRef}
                src={videoUrl}
                controls
                playsInline
                className="h-full w-full object-cover"
                aria-label="Watch TrustLens in Action"
              />
            ) : (
              <>
                <div className="absolute inset-0" aria-hidden>
                  <div className="absolute top-[-30%] left-[-10%] h-[90%] w-[55%] rounded-full bg-[radial-gradient(closest-side,rgba(190,110,50,0.35),transparent)] blur-2xl" />
                  <div className="absolute right-[-10%] bottom-[-30%] h-[100%] w-[60%] rounded-full bg-[radial-gradient(closest-side,rgba(57,133,255,0.4),transparent)] blur-2xl" />
                  <NetworkPattern className="opacity-40" />
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 opacity-[0.07]">
                    <LogoMark className="size-[340px]" />
                  </div>
                  <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(5,8,14,0.2),rgba(5,8,14,0.85))]" />
                  <div className="grain" />
                </div>

                <div className="absolute top-4 left-4 flex items-center gap-2 md:top-6 md:left-6">
                  <span className="rounded-md border border-white/15 bg-black/50 px-2 py-1 font-mono text-[11px] text-white/80 backdrop-blur">
                    02:15
                  </span>
                  {!videoUrl && (
                    <span className="rounded-md border border-amber/40 bg-amber/10 px-2 py-1 font-mono text-[10.5px] tracking-[0.1em] text-amber backdrop-blur">
                      VIDEO COMING SOON
                    </span>
                  )}
                </div>

                <div className="absolute inset-0 grid place-items-center">
                  <button
                    type="button"
                    onClick={play}
                    disabled={!videoUrl}
                    aria-label={
                      videoUrl ? "Play video: Watch TrustLens in Action" : "Video not yet available"
                    }
                    className="group relative grid size-20 place-items-center rounded-full bg-[linear-gradient(135deg,#7ef0f5,#3a8bff)] shadow-[0_0_60px_rgba(0,213,242,0.45)] transition enabled:hover:scale-105 disabled:cursor-not-allowed disabled:opacity-60 md:size-24"
                  >
                    <span
                      className="absolute inset-0 animate-ping rounded-full bg-cyan/20 group-disabled:hidden"
                      aria-hidden
                    />
                    <Play
                      className="ml-1 size-7 fill-[#06121a] text-[#06121a] md:size-8"
                      aria-hidden
                    />
                  </button>
                </div>

                <div className="absolute inset-x-0 bottom-0 p-4 md:p-7">
                  <h3 className="text-[22px] font-bold tracking-[-0.03em] text-white md:text-[34px]">
                    Watch TrustLens in Action
                  </h3>
                  <p className="mt-1 hidden text-[14px] text-white/60 sm:block">
                    {videoUrl
                      ? "From submission to verifiable report in five steps."
                      : "This walkthrough is in production. Placeholder shown until the video is published."}
                  </p>
                  <div className="mt-4 flex items-center gap-4 text-white/50" aria-hidden>
                    <Play className="size-4" />
                    <div className="h-1 flex-1 rounded-full bg-white/15">
                      <div className="h-full w-0 rounded-full bg-cyan" />
                    </div>
                    <span className="font-mono text-[11px]">00:00 / 02:15</span>
                    <Volume2 className="hidden size-4 sm:block" />
                    <Settings className="hidden size-4 sm:block" />
                    <Maximize className="size-4" />
                  </div>
                </div>
              </>
            )}
          </div>
        </Reveal>
      </div>
    </section>
  );
}
