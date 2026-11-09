import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type Item = {
  id?: string;
  module?: string;
  verdict?: string;
  risk_score?: number | null;
  created_at?: string;
};

export default function InvestigationsPage() {
  const [items, setItems] = useState<Item[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [verify, setVerify] = useState<Record<string, string>>({});

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const data = (await api.listInvestigations(50)) as Item[];
      setItems(Array.isArray(data) ? data : []);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function verifyOne(id?: string) {
    if (!id) return;
    try {
      const result = await api.verifyInvestigation(id);
      setVerify((v) => ({ ...v, [id]: JSON.stringify(result) }));
    } catch (e) {
      setVerify((v) => ({ ...v, [id]: (e as Error).message }));
    }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6 px-5 py-12 md:px-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Investigation History</h1>
        <button type="button" onClick={load} className="rounded-full border border-white/12 px-4 py-2 text-sm text-fg-2 hover:text-white">
          Refresh
        </button>
      </div>
      {loading ? <p className="text-fg-2">Loading…</p> : null}
      {error ? <p className="text-red-400">{error}</p> : null}
      <div className="overflow-x-auto rounded-2xl border border-white/10">
        <table className="w-full text-sm text-white/80">
          <thead className="bg-black/40 text-left text-fg-2">
            <tr>
              <th className="p-3">ID</th>
              <th className="p-3">Module</th>
              <th className="p-3">Verdict</th>
              <th className="p-3">Score</th>
              <th className="p-3">Created</th>
              <th className="p-3">Chain</th>
            </tr>
          </thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={it.id ?? i} className="border-t border-white/[0.06]">
                <td className="p-3 font-mono text-xs break-all">{it.id}</td>
                <td className="p-3">{it.module}</td>
                <td className="p-3">{it.verdict}</td>
                <td className="p-3">{it.risk_score ?? "—"}</td>
                <td className="p-3 font-mono text-xs">{it.created_at ? new Date(it.created_at).toLocaleString() : "—"}</td>
                <td className="p-3">
                  <button type="button" onClick={() => verifyOne(it.id)} className="rounded-full border border-white/12 px-3 py-1 text-xs hover:text-white">
                    Verify
                  </button>
                  {it.id && verify[it.id] ? <pre className="mt-2 max-w-xs overflow-auto text-xs text-fg-3">{verify[it.id]}</pre> : null}
                </td>
              </tr>
            ))}
            {!loading && !items.length ? (
              <tr><td colSpan={6} className="p-4 text-center text-fg-3">No investigations yet.</td></tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}
