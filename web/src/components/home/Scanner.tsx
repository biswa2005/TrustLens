import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { useSearchParams } from "react-router";
import { AnimatePresence, motion } from "motion/react";
import {
  AlertCircle,
  ArrowRight,
  Check,
  Globe,
  LoaderCircle,
  MessageSquareWarning,
  X,
} from "lucide-react";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { Reveal } from "@/components/ui/Reveal";
import { isLiveScanConfigured } from "@/lib/config";
import {
  SCAN_STEPS,
  runScan,
  validateMessageInput,
  validateUrlInput,
  type ScanMode,
  type ScanReport,
} from "@/lib/scanner";
import { ScanReportView } from "./ScanReportView";

const TABS: { id: ScanMode; label: string; short: string; Icon: typeof Globe }[] = [
  { id: "url", label: "Check URL / Domain", short: "URL / Domain", Icon: Globe },
  {
    id: "message",
    label: "Analyze Scam Message",
    short: "Scam Message",
    Icon: MessageSquareWarning,
  },
];

const EXAMPLES: Record<ScanMode, string[]> = {
  url: ["paypa1-account-verify.xyz/login", "http://192.168.4.20:8080/secure", "bit.ly/3xample"],
  message: [
    "URGENT: Your bank account has been suspended due to unusual activity. Verify your account within 24 hours at secure-bank-verify.top or it will be closed. Reply with your one-time code.",
    "Hi! Just confirming our meeting tomorrow at 10am at the usual place. Let me know if the time still works for you.",
  ],
};

type Phase = "idle" | "scanning" | "done" | "failed";
const STEP_MS = 650;

function wait(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      clearTimeout(t);
      reject(new DOMException("Aborted", "AbortError"));
    });
  });
}

function ScanProgress({ steps, current }: { steps: string[]; current: number }) {
  const pct = Math.min(100, ((current + 0.5) / steps.length) * 100);
  return (
    <div
      className="grid items-center gap-10 py-6 md:grid-cols-[220px_1fr] md:py-10"
      role="status"
      aria-live="polite"
    >
      <div className="relative mx-auto grid size-[200px] place-items-center">
        <div className="absolute inset-0 rounded-full border border-cyan/15" />
        <div className="absolute inset-[22%] rounded-full border border-cyan/15" />
        <div className="absolute inset-[44%] rounded-full border border-cyan/25 bg-cyan/10" />
        <div className="absolute inset-0 animate-sweep rounded-full bg-[conic-gradient(from_0deg,transparent_0deg,rgba(0,213,242,0.32)_50deg,transparent_60deg)]" />
        <div className="absolute inset-x-0 top-1/2 h-px bg-cyan/10" />
        <div className="absolute inset-y-0 left-1/2 w-px bg-cyan/10" />
        {[
          [24, 30],
          [70, 22],
          [78, 66],
          [32, 74],
        ].map(([x, y], i) => (
          <span
            key={i}
            className="absolute size-1.5 rounded-full bg-cyan shadow-[0_0_10px_#00D5F2] transition-opacity duration-500"
            style={{ left: `${x}%`, top: `${y}%`, opacity: i <= current ? 1 : 0.15 }}
          />
        ))}
        <span className="relative font-mono text-[13px] font-semibold text-cyan tabular-nums">
          {Math.round(pct)}%
        </span>
      </div>
      <div>
        <p className="font-mono text-[12px] tracking-[0.12em] text-fg-3">ANALYSIS IN PROGRESS</p>
        <div className="mt-3 h-1 overflow-hidden rounded-full bg-white/[0.06]">
          <motion.div
            className="h-full rounded-full bg-[linear-gradient(90deg,#00D5F2,#3985FF)]"
            animate={{ width: `${pct}%` }}
            transition={{ duration: 0.5 }}
          />
        </div>
        <ol className="mt-6 space-y-3.5">
          {steps.map((step, i) => {
            const done = i < current;
            const active = i === current;
            return (
              <li
                key={step}
                className={`flex items-center gap-3 text-[15px] transition-colors ${done ? "text-white/80" : active ? "text-white" : "text-fg-3"}`}
              >
                <span
                  className={`grid size-6 place-items-center rounded-full border text-[11px] ${
                    done
                      ? "border-safe/50 bg-safe/15 text-safe"
                      : active
                        ? "border-cyan/60 text-cyan"
                        : "border-white/10"
                  }`}
                >
                  {done ? (
                    <Check className="size-3.5" />
                  ) : active ? (
                    <LoaderCircle className="size-3.5 animate-spin" />
                  ) : (
                    i + 1
                  )}
                </span>
                {step}
              </li>
            );
          })}
        </ol>
      </div>
    </div>
  );
}

export function Scanner() {
  const [searchParams] = useSearchParams();
  const [mode, setMode] = useState<ScanMode>(
    searchParams.get("mode") === "message" ? "message" : "url",
  );
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [step, setStep] = useState(0);
  const [report, setReport] = useState<ScanReport | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const urlRef = useRef<HTMLInputElement>(null);
  const messageRef = useRef<HTMLTextAreaElement>(null);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const steps = SCAN_STEPS[isLiveScanConfigured ? "live" : "local"][mode];

  useEffect(() => {
    const m = searchParams.get("mode");
    if ((m === "url" || m === "message") && phase !== "scanning") switchMode(m);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  useEffect(() => () => abortRef.current?.abort(), []);

  function switchMode(next: ScanMode) {
    setMode(next);
    setError(null);
    if (phase !== "scanning") {
      setPhase("idle");
      setReport(null);
    }
  }

  function onTabKey(e: KeyboardEvent, index: number) {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    e.preventDefault();
    const next = (index + (e.key === "ArrowRight" ? 1 : -1) + TABS.length) % TABS.length;
    switchMode(TABS[next].id);
    tabRefs.current[next]?.focus();
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const input = mode === "url" ? url : message;
    const validation = mode === "url" ? validateUrlInput(input) : validateMessageInput(input);
    if (!validation.ok) {
      setError(validation.error);
      (mode === "url" ? urlRef.current : messageRef.current)?.focus();
      return;
    }
    setError(null);
    setPhase("scanning");
    setStep(0);
    setReport(null);
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const scanPromise = runScan(mode, input.trim(), controller.signal);
      scanPromise.catch(() => {}); // handled below; avoids an unhandled rejection while steps animate
      for (let i = 0; i < steps.length - 1; i++) {
        await wait(STEP_MS, controller.signal);
        setStep(i + 1);
      }
      const result = await scanPromise;
      await wait(STEP_MS * 0.7, controller.signal);
      setReport(result);
      setPhase("done");
    } catch (err) {
      if ((err as Error).name === "AbortError") return;
      setError((err as Error).message || "The analysis could not be completed.");
      setPhase("failed");
    }
  }

  function reset() {
    setPhase("idle");
    setReport(null);
    setStep(0);
    requestAnimationFrame(() => (mode === "url" ? urlRef.current : messageRef.current)?.focus());
  }

  const scanning = phase === "scanning";
  const errorId = "scanner-error";

  return (
    <section
      id="scanner"
      aria-labelledby="scanner-title"
      className="relative isolate scroll-mt-20 px-5 pt-16 pb-6 md:px-8 md:pt-20 md:pb-8"
    >
      <div
        className="pointer-events-none absolute inset-x-0 -top-40 -z-10 h-[760px] bg-[radial-gradient(55%_50%_at_50%_45%,rgba(57,133,255,0.13),transparent_72%)]"
        aria-hidden
      />
      <div className="mx-auto max-w-[1264px]">
        <SectionHeading
          id="scanner-title"
          eyebrow="THREAT SCANNER"
          title={
            <>
              One Scan. A Clearer <span className="text-tide">Picture of Trust.</span>
            </>
          }
          description="Investigate a suspicious website or message and uncover the signals behind its digital reputation."
        />

        <Reveal delay={0.1} className="relative mx-auto mt-14 max-w-[980px]">
          <div
            className="pointer-events-none absolute -inset-px rounded-[22px] bg-[linear-gradient(140deg,rgba(0,213,242,0.45),rgba(57,133,255,0.1)_30%,transparent_55%,rgba(145,102,255,0.25))] opacity-70"
            aria-hidden
          />
          <div className="relative overflow-hidden rounded-[22px] bg-[#0a0f18]/95 shadow-[0_40px_120px_-40px_rgba(0,0,0,0.9)]">
            <div
              className="pointer-events-none absolute inset-0 hairline-grid opacity-40 [mask-image:linear-gradient(180deg,black,transparent_60%)]"
              aria-hidden
            />

            <div className="relative flex flex-col gap-4 border-b border-white/[0.07] px-4 py-4 sm:flex-row sm:items-center sm:justify-between md:px-6">
              <div
                role="tablist"
                aria-label="Scanner mode"
                className="grid grid-cols-2 gap-1 rounded-full border border-white/10 bg-black/40 p-1"
              >
                {TABS.map((tab, i) => {
                  const selected = mode === tab.id;
                  return (
                    <button
                      key={tab.id}
                      ref={(el) => {
                        tabRefs.current[i] = el;
                      }}
                      role="tab"
                      id={`tab-${tab.id}`}
                      aria-selected={selected}
                      aria-controls="scanner-panel"
                      tabIndex={selected ? 0 : -1}
                      disabled={scanning}
                      onKeyDown={(e) => onTabKey(e, i)}
                      onClick={() => switchMode(tab.id)}
                      className={`relative flex h-10 items-center justify-center gap-2 rounded-full px-4 text-[14px] font-medium transition-colors disabled:cursor-not-allowed ${
                        selected ? "text-[#07090e]" : "text-fg-2 hover:text-white"
                      }`}
                    >
                      {selected && (
                        <motion.span
                          layoutId="scanner-tab"
                          className="absolute inset-0 rounded-full bg-white"
                          transition={{ type: "spring", stiffness: 420, damping: 36 }}
                        />
                      )}
                      <tab.Icon className="relative size-4" aria-hidden />
                      <span className="relative hidden sm:inline">{tab.label}</span>
                      <span className="relative sm:hidden">{tab.short}</span>
                    </button>
                  );
                })}
              </div>
              <span className="inline-flex items-center gap-2 self-start font-mono text-[11.5px] tracking-[0.08em] text-fg-3 sm:self-auto">
                <span
                  className={`size-1.5 rounded-full animate-pulse-dot ${isLiveScanConfigured ? "bg-safe text-safe" : "bg-violet text-violet"}`}
                />
                {isLiveScanConfigured ? "LIVE BACKEND" : "PREVIEW MODE · LOCAL HEURISTICS"}
              </span>
            </div>

            <div
              id="scanner-panel"
              role="tabpanel"
              aria-labelledby={`tab-${mode}`}
              className="relative p-4 md:p-7"
            >
              <AnimatePresence mode="wait" initial={false}>
                {phase === "scanning" ? (
                  <motion.div
                    key="scanning"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                  >
                    <ScanProgress steps={steps} current={step} />
                  </motion.div>
                ) : phase === "done" && report ? (
                  <motion.div
                    key="report"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                  >
                    <ScanReportView report={report} onReset={reset} />
                  </motion.div>
                ) : (
                  <motion.form
                    key={`form-${mode}`}
                    onSubmit={onSubmit}
                    noValidate
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.25 }}
                  >
                    {mode === "url" ? (
                      <div className="flex flex-col gap-3 md:flex-row">
                        <label htmlFor="scan-url" className="sr-only">
                          URL or domain
                        </label>
                        <div
                          className={`group flex h-16 flex-1 items-center gap-3 rounded-2xl border bg-black/40 pr-2 pl-5 transition focus-within:border-cyan/60 focus-within:shadow-[0_0_0_4px_rgba(0,213,242,0.08)] ${
                            error ? "border-crimson/60" : "border-white/12"
                          }`}
                        >
                          <Globe
                            className="size-5 shrink-0 text-fg-3 transition group-focus-within:text-cyan"
                            aria-hidden
                          />
                          <input
                            ref={urlRef}
                            id="scan-url"
                            type="text"
                            inputMode="url"
                            autoComplete="off"
                            autoCapitalize="off"
                            spellCheck={false}
                            value={url}
                            onChange={(e) => {
                              setUrl(e.target.value);
                              if (error) setError(null);
                            }}
                            placeholder="Paste a suspicious URL or domain to investigate..."
                            aria-invalid={Boolean(error)}
                            aria-describedby={error ? errorId : "scan-hint"}
                            className="h-full min-w-0 flex-1 bg-transparent font-mono text-[15px] text-white placeholder:font-sans placeholder:text-fg-3 focus:outline-none"
                          />
                          {url && (
                            <button
                              type="button"
                              onClick={() => {
                                setUrl("");
                                setError(null);
                                urlRef.current?.focus();
                              }}
                              className="grid size-9 place-items-center rounded-full text-fg-3 transition hover:bg-white/5 hover:text-white"
                              aria-label="Clear input"
                            >
                              <X className="size-4" />
                            </button>
                          )}
                        </div>
                        <button
                          type="submit"
                          className="group inline-flex h-16 items-center justify-center gap-2 rounded-2xl bg-white px-7 text-[15.5px] font-semibold text-[#07090e] transition hover:bg-[#e9f6ff] hover:shadow-[0_14px_40px_-14px_rgba(0,213,242,0.6)] active:scale-[0.99]"
                        >
                          Analyze Threat
                          <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
                        </button>
                      </div>
                    ) : (
                      <div>
                        <label htmlFor="scan-message" className="sr-only">
                          Suspicious message
                        </label>
                        <div
                          className={`relative rounded-2xl border bg-black/40 transition focus-within:border-cyan/60 focus-within:shadow-[0_0_0_4px_rgba(0,213,242,0.08)] ${error ? "border-crimson/60" : "border-white/12"}`}
                        >
                          <textarea
                            ref={messageRef}
                            id="scan-message"
                            rows={6}
                            maxLength={5000}
                            value={message}
                            onChange={(e) => {
                              setMessage(e.target.value);
                              if (error) setError(null);
                            }}
                            placeholder="Paste a suspicious SMS, email, WhatsApp message or social media message..."
                            aria-invalid={Boolean(error)}
                            aria-describedby={error ? errorId : "scan-hint"}
                            className="block w-full resize-y rounded-2xl bg-transparent px-5 pt-5 pb-12 text-[15.5px] leading-relaxed text-white placeholder:text-fg-3 focus:outline-none"
                          />
                          <div className="absolute right-3 bottom-3 left-5 flex items-center justify-between">
                            <span className="font-mono text-[11.5px] text-fg-3 tabular-nums">
                              {message.length.toLocaleString()} / 5,000
                            </span>
                            {message && (
                              <button
                                type="button"
                                onClick={() => {
                                  setMessage("");
                                  setError(null);
                                  messageRef.current?.focus();
                                }}
                                className="inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-[12.5px] text-fg-3 transition hover:bg-white/5 hover:text-white"
                              >
                                <X className="size-3.5" /> Clear
                              </button>
                            )}
                          </div>
                        </div>
                        <div className="mt-3 flex justify-end">
                          <button
                            type="submit"
                            className="group inline-flex h-14 w-full items-center justify-center gap-2 rounded-2xl bg-white px-7 text-[15.5px] font-semibold text-[#07090e] transition hover:bg-[#e9f6ff] hover:shadow-[0_14px_40px_-14px_rgba(0,213,242,0.6)] sm:w-auto"
                          >
                            Analyze Message
                            <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
                          </button>
                        </div>
                      </div>
                    )}

                    <div className="mt-4 min-h-6">
                      {error ? (
                        <p
                          id={errorId}
                          role="alert"
                          className="flex items-center gap-2 text-[14px] text-crimson"
                        >
                          <AlertCircle className="size-4 shrink-0" /> {error}
                        </p>
                      ) : (
                        <p id="scan-hint" className="text-[13.5px] text-fg-3">
                          TrustLens never asks for passwords. Don’t paste personal credentials or
                          private data.
                        </p>
                      )}
                    </div>

                    <div className="mt-6 flex flex-wrap items-center gap-2 border-t border-white/[0.06] pt-5">
                      <span className="mr-1 font-mono text-[11.5px] tracking-[0.1em] text-fg-3">
                        TRY AN EXAMPLE INPUT
                      </span>
                      {EXAMPLES[mode].map((ex, i) => (
                        <button
                          key={ex}
                          type="button"
                          onClick={() => {
                            setError(null);
                            if (mode === "url") setUrl(ex);
                            else setMessage(ex);
                          }}
                          className="max-w-full truncate rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 font-mono text-[12px] text-fg-2 transition hover:border-cyan/40 hover:text-white"
                        >
                          {mode === "url"
                            ? ex
                            : i === 0
                              ? "Bank “suspension” SMS"
                              : "Ordinary meeting reminder"}
                        </button>
                      ))}
                    </div>
                  </motion.form>
                )}
              </AnimatePresence>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
