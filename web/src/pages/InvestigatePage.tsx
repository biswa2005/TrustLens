import { useRef, useState } from "react";
import { FileText, Image as ImageIcon, Link, Mail, MessageSquareWarning, QrCode, Loader2, CheckCircle2, ShieldAlert } from "lucide-react";
import { isLiveScanConfigured } from "@/lib/config";
import { api } from "@/lib/api";

const TABS = [
  { id: "url", label: "URL / Domain", Icon: Link },
  { id: "message", label: "Scam Message", Icon: MessageSquareWarning },
  { id: "qr", label: "QR Code", Icon: QrCode },
  { id: "visual", label: "Screenshot", Icon: ImageIcon },
  { id: "email", label: "Email (.eml)", Icon: Mail },
] as const;

type Tab = (typeof TABS)[number]["id"];

export default function InvestigatePage() {
  const [tab, setTab] = useState<Tab>("url");
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [caption, setCaption] = useState("");
  const [brandHint, setBrandHint] = useState("");
  const [claimedUrl, setClaimedUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<unknown>(null);

  async function run() {
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      let data: unknown;
      switch (tab) {
        case "url":
          data = await api.analyzeUrl(url.trim());
          break;
        case "message":
          data = await api.analyzeMessage(message.trim());
          break;
        case "qr":
          if (!file) throw new Error("Choose a QR image to analyze.");
          data = await api.analyzeQr(file, caption.trim() || undefined);
          break;
        case "visual":
          if (!file) throw new Error("Choose a screenshot to analyze.");
          data = await api.analyzeVisual(file, brandHint.trim() || undefined, claimedUrl.trim() || undefined);
          break;
        case "email":
          if (!file) throw new Error("Choose an .eml file to analyze.");
          data = await api.analyzeEmail(file);
          break;
      }
      setResult(data);
    } catch (e) {
      setError((e as Error).message || "Analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6 px-5 py-12 md:px-8">
      <h1 className="text-2xl font-bold text-white">Investigation Console</h1>
      <p className="text-sm text-fg-2">
        Direct access to every TrustLens backend module: URL reputation, message NLP, QR semantics, screenshot impersonation detection, and BEC/email forensics.
      </p>
      {!isLiveScanConfigured ? (
        <div className="flex items-center gap-2 rounded-lg border border-violet/30 bg-violet/[0.07] px-3 py-2 text-sm text-[#cbbcff]">
          <ShieldAlert className="size-4" /> Backend not configured — set VITE_TRUSTLENS_API_URL for live results.
        </div>
      ) : (
        <div className="flex items-center gap-2 rounded-lg border border-cyan/30 bg-cyan/[0.06] px-3 py-2 text-sm text-cyan">
          <CheckCircle2 className="size-4" /> Live backend connected.
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => {
              setTab(t.id);
              setResult(null);
              setError(null);
              setFile(null);
            }}
            className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm transition ${
              tab === t.id ? "border-white/40 bg-white text-[#07090e]" : "border-white/10 text-fg-2 hover:text-white"
            }`}
          >
            <t.Icon className="size-4" /> {t.label}
          </button>
        ))}
      </div>

      <div className="space-y-4 rounded-2xl border border-white/10 bg-black/30 p-5">
        {(tab === "url" || tab === "message") && tab === "url" ? (
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/path"
            className="w-full rounded-xl border border-white/12 bg-black/40 px-4 py-3 font-mono text-sm text-white outline-none focus:border-cyan/60"
          />
        ) : null}
        {(tab === "url" || tab === "message") && tab === "message" ? (
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            rows={6}
            placeholder="Paste suspicious SMS/email/social message…"
            className="w-full rounded-xl border border-white/12 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-cyan/60"
          />
        ) : null}
        {tab === "qr" ? (
          <>
            <input ref={fileRef} type="file" accept="image/*" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm text-fg-2" />
            <input value={caption} onChange={(e) => setCaption(e.target.value)} placeholder="Caption or visible claim (optional)" className="w-full rounded-xl border border-white/12 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-cyan/60" />
          </>
        ) : null}
        {tab === "visual" ? (
          <>
            <input ref={fileRef} type="file" accept="image/*" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm text-fg-2" />
            <input value={brandHint} onChange={(e) => setBrandHint(e.target.value)} placeholder="Brand hint (optional)" className="w-full rounded-xl border border-white/12 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-cyan/60" />
            <input value={claimedUrl} onChange={(e) => setClaimedUrl(e.target.value)} placeholder="Claimed URL (optional)" className="w-full rounded-xl border border-white/12 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-cyan/60" />
          </>
        ) : null}
        {tab === "email" ? (
          <input ref={fileRef} type="file" accept=".eml,message/rfc822" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm text-fg-2" />
        ) : null}

        <button
          type="button"
          disabled={loading}
          onClick={run}
          className="inline-flex items-center gap-2 rounded-xl bg-white px-6 py-3 text-sm font-semibold text-[#07090e] transition hover:bg-[#e9f6ff] disabled:opacity-60"
        >
          {loading ? <Loader2 className="size-4 animate-spin" /> : null}
          Run investigation
        </button>
        {error ? <p className="text-sm text-red-400">{error}</p> : null}
      </div>

      {result ? (
        <div className="rounded-2xl border border-white/10 bg-black/20 p-5">
          <h2 className="mb-3 text-lg font-semibold text-white">Backend response</h2>
          <pre className="max-h-[500px] overflow-auto rounded-xl bg-black/40 p-4 text-xs text-white/80">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      ) : null}
    </div>
  );
}
