import { useMemo } from "react";

function seeded(seed: number) {
  let s = seed;
  return () => {
    s = (s * 16807) % 2147483647;
    return (s - 1) / 2147483646;
  };
}

/** Deterministic scattered pinpoints of light, as in a night sky. */
export function Stars({
  count = 70,
  seed = 7,
  className = "",
}: {
  count?: number;
  seed?: number;
  className?: string;
}) {
  const stars = useMemo(() => {
    const rand = seeded(seed);
    return Array.from({ length: count }, () => ({
      left: rand() * 100,
      top: rand() * 100,
      size: rand() > 0.85 ? 2.2 : rand() > 0.5 ? 1.6 : 1.1,
      opacity: 0.25 + rand() * 0.6,
    }));
  }, [count, seed]);
  return (
    <div className={`pointer-events-none absolute inset-0 ${className}`} aria-hidden>
      {stars.map((s, i) => (
        <span
          key={i}
          className="absolute rounded-full bg-white"
          style={{
            left: `${s.left}%`,
            top: `${s.top}%`,
            width: s.size,
            height: s.size,
            opacity: s.opacity,
          }}
        />
      ))}
    </div>
  );
}
