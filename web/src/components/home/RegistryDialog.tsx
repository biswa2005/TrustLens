import { useEffect, useRef, useState, type FormEvent } from "react";
import { Check, Copy, Hash, Info, LoaderCircle, X } from "lucide-react";
import { config, isRegistryConfigured } from "@/lib/config";
import { sha256Hex } from "@/lib/crypto";

/** Registry status plus a local, real SHA-256 commitment generator. Nothing is published. */
export function RegistryDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [text, setText] = useState("");
  const [hash, setHash] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!text.trim())
      return setError("Enter incident details to hash, for example a domain and date.");
    setError(null);
    setBusy(true);
    try {
      setHash(await sha256Hex(text.trim()));
    } catch {
      setError("Hashing is unavailable in this browser context.");
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    if (!hash) return;
    await navigator.clipboard.writeText(hash).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => e.target === ref.current && onClose()}
      aria-labelledby="registry-dialog-title"
      className="m-auto w-[min(640px,calc(100vw-2rem))] max-h-[calc(100svh-2rem)] overflow-y-auto rounded-[20px] border border-white/10 bg-[#0a0f18] p-0 text-fg shadow-[0_40px_120px_-30px_rgba(0,0,0,0.9)]"
    >
      <div className="p-6 md:p-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-[11px] tracking-[0.14em] text-fg-3">TRUST REGISTRY</p>
            <h2
              id="registry-dialog-title"
              className="mt-2 text-[26px] font-bold tracking-[-0.03em] text-white"
            >
              Explore the Threat Registry
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="grid size-9 place-items-center rounded-full border border-white/10 text-fg-2 hover:text-white"
            aria-label="Close dialog"
          >
            <X className="size-4" />
          </button>
        </div>

        <dl className="mt-6 grid gap-2 sm:grid-cols-2">
          <div className="rounded-xl border border-white/[0.07] bg-black/30 p-3.5">
            <dt className="font-mono text-[11px] tracking-[0.1em] text-fg-3">NETWORK</dt>
            <dd
              className={`mt-1 text-[14px] ${config.registry.network ? "text-white" : "text-amber"}`}
            >
              {config.registry.network ?? "Not configured"}
            </dd>
          </div>
          <div className="rounded-xl border border-white/[0.07] bg-black/30 p-3.5">
            <dt className="font-mono text-[11px] tracking-[0.1em] text-fg-3">CONTRACT</dt>
            <dd
              className={`mt-1 truncate font-mono text-[13px] ${config.registry.contractAddress ? "text-white" : "text-amber"}`}
            >
              {config.registry.contractAddress ?? "Not deployed / not configured"}
            </dd>
          </div>
        </dl>

        {!isRegistryConfigured ? (
          <p className="mt-4 flex gap-2.5 rounded-xl border border-amber/25 bg-amber/[0.06] p-3.5 text-[13.5px] leading-relaxed text-[#ffd79a]">
            <Info className="mt-0.5 size-4 shrink-0" />
            The on-chain registry isn’t connected in this build, so there are no verified records to
            browse yet. You can still see how a commitment is formed below.
          </p>
        ) : (
          config.registry.explorerUrl && (
            <a
              href={config.registry.explorerUrl}
              target="_blank"
              rel="noreferrer"
              className="mt-4 inline-flex text-[14px] text-cyan hover:underline"
            >
              View contract on block explorer →
            </a>
          )
        )}

        <form onSubmit={onSubmit} className="mt-8" noValidate>
          <label htmlFor="commitment-input" className="text-[15px] font-semibold text-white">
            Compute an incident commitment
          </label>
          <p className="mt-1 text-[13.5px] leading-relaxed text-fg-2">
            A commitment is a SHA-256 fingerprint of selected incident details. Publishing only the
            hash lets anyone later verify a report without exposing private content. Hashing runs in
            your browser; nothing is sent or published.
          </p>
          <textarea
            id="commitment-input"
            rows={3}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setHash(null);
            }}
            placeholder="e.g. phishing | paypa1-account-verify.xyz | 2026-11-08"
            className="mt-4 w-full resize-y rounded-xl border border-white/12 bg-black/40 p-4 font-mono text-[13.5px] text-white placeholder:text-fg-3 focus:border-cyan/60 focus:outline-none"
            aria-invalid={Boolean(error)}
            aria-describedby={error ? "commitment-error" : undefined}
          />
          {error && (
            <p id="commitment-error" role="alert" className="mt-2 text-[13px] text-crimson">
              {error}
            </p>
          )}
          <button
            type="submit"
            disabled={busy}
            className="mt-3 inline-flex h-11 items-center gap-2 rounded-full bg-white px-5 text-[14px] font-semibold text-[#07090e] transition hover:bg-[#e9f6ff] disabled:opacity-60"
          >
            {busy ? <LoaderCircle className="size-4 animate-spin" /> : <Hash className="size-4" />}
            Generate SHA-256 commitment
          </button>
        </form>

        {hash && (
          <div className="mt-5 rounded-xl border border-cyan/25 bg-cyan/[0.05] p-4" role="status">
            <div className="flex items-center justify-between gap-3">
              <p className="font-mono text-[11px] tracking-[0.12em] text-fg-3">
                LOCAL COMMITMENT · NOT PUBLISHED
              </p>
              <button
                type="button"
                onClick={copy}
                className="inline-flex items-center gap-1.5 text-[12.5px] text-fg-2 hover:text-white"
              >
                {copied ? <Check className="size-3.5 text-safe" /> : <Copy className="size-3.5" />}{" "}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <p className="mt-2 font-mono text-[13px] leading-relaxed break-all text-cyan">{hash}</p>
          </div>
        )}
      </div>
    </dialog>
  );
}
