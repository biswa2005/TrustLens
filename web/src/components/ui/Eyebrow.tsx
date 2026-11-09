import type { ReactNode } from "react";

export function Eyebrow({
  children,
  dot = "#00D5F2",
  className = "",
}: {
  children: ReactNode;
  dot?: string;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-2.5 rounded-full border border-white/10 bg-black/40 px-3.5 py-1.5 font-mono text-[12px] tracking-[0.12em] text-white/70 backdrop-blur-md ${className}`}
    >
      <span
        className="size-1.5 rounded-full"
        style={{ background: dot, boxShadow: `0 0 10px ${dot}` }}
      />
      {children}
    </span>
  );
}
