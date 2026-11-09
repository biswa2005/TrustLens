import { useId } from "react";

export function LogoMark({ className = "size-5" }: { className?: string }) {
  const id = useId();
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="4" y1="3" x2="20" y2="21" gradientUnits="userSpaceOnUse">
          <stop stopColor="#7EF0F5" />
          <stop offset="0.5" stopColor="#00D5F2" />
          <stop offset="1" stopColor="#3985FF" />
        </linearGradient>
      </defs>
      <path
        d="M12 2.6 19.4 5.4v5.9c0 4.6-3.1 8.4-7.4 10.1-4.3-1.7-7.4-5.5-7.4-10.1V5.4L12 2.6Z"
        stroke={`url(#${id})`}
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <circle cx="11.4" cy="10.6" r="3.2" stroke="#F5F7FC" strokeWidth="1.6" />
      <path d="m13.8 13 2.3 2.3" stroke="#F5F7FC" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="11.4" cy="10.6" r="1" fill={`url(#${id})`} />
    </svg>
  );
}

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <span className="grid size-9 place-items-center rounded-[10px] border border-white/15 bg-black shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
        <LogoMark />
      </span>
      {!compact && (
        <span className="text-[19px] font-bold tracking-[-0.03em] text-white">
          Trust<span className="text-white/55">Lens</span>
        </span>
      )}
    </span>
  );
}
