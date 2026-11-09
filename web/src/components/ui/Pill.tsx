import type { ComponentProps, ReactNode } from "react";
import { Link, type To } from "react-router";
import { ArrowRight } from "lucide-react";

type Variant = "light" | "dark";
type Size = "sm" | "md";

const base =
  "group relative inline-flex shrink-0 items-center justify-center gap-2 rounded-full font-semibold tracking-[-0.01em] transition duration-200 ease-out disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]";
const variants: Record<Variant, string> = {
  light:
    "bg-white text-[#07090e] shadow-[0_10px_30px_-12px_rgba(255,255,255,0.55)] hover:bg-[#e9f6ff] hover:shadow-[0_14px_40px_-12px_rgba(0,213,242,0.55)]",
  dark: "border border-white/15 bg-black/45 text-white backdrop-blur-md hover:border-white/30 hover:bg-white/[0.06]",
};
const sizes: Record<Size, string> = {
  sm: "h-10 px-4 text-[14px]",
  md: "h-12 px-6 text-[15px]",
};

interface CommonProps {
  variant?: Variant;
  size?: Size;
  arrow?: boolean;
  children: ReactNode;
  className?: string;
}

function Inner({ children, arrow }: { children: ReactNode; arrow?: boolean }) {
  return (
    <>
      {children}
      {arrow && (
        <ArrowRight
          className="size-4 transition-transform duration-200 group-hover:translate-x-0.5"
          strokeWidth={2.2}
          aria-hidden
        />
      )}
    </>
  );
}

export function PillLink({
  to,
  variant = "light",
  size = "md",
  arrow,
  children,
  className = "",
}: CommonProps & { to: To }) {
  return (
    <Link to={to} className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}>
      <Inner arrow={arrow}>{children}</Inner>
    </Link>
  );
}

export function PillButton({
  variant = "light",
  size = "md",
  arrow,
  children,
  className = "",
  ...rest
}: CommonProps & Omit<ComponentProps<"button">, "children" | "className">) {
  return (
    <button
      type="button"
      {...rest}
      className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}
    >
      <Inner arrow={arrow}>{children}</Inner>
    </button>
  );
}
