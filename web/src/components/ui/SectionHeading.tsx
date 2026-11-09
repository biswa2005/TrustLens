import type { ReactNode } from "react";
import { Eyebrow } from "./Eyebrow";
import { Reveal } from "./Reveal";

export function SectionHeading({
  eyebrow,
  title,
  description,
  align = "center",
  dot,
  id,
}: {
  eyebrow?: string;
  title: ReactNode;
  description?: ReactNode;
  align?: "center" | "left";
  dot?: string;
  id?: string;
}) {
  const centered = align === "center";
  return (
    <Reveal
      className={`flex flex-col gap-5 ${centered ? "mx-auto max-w-3xl items-center text-center" : "max-w-2xl items-start"}`}
    >
      {eyebrow && <Eyebrow dot={dot}>{eyebrow}</Eyebrow>}
      <h2
        id={id}
        className="text-[clamp(2.25rem,4.6vw,3.75rem)] font-extrabold leading-[1.02] tracking-[-0.045em] text-balance text-fg"
      >
        {title}
      </h2>
      {description && (
        <p className="max-w-2xl text-[17px] leading-[1.65] text-fg-2 text-pretty md:text-[18px]">
          {description}
        </p>
      )}
    </Reveal>
  );
}
