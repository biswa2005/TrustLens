import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router";
import { AnimatePresence, motion } from "motion/react";
import { Menu, X } from "lucide-react";
import { Logo } from "@/components/ui/Logo";
import { PillLink } from "@/components/ui/Pill";

const NAV = [
  { label: "Scanner", to: { pathname: "/", hash: "#scanner" }, id: "scanner" },
  { label: "Features", to: { pathname: "/", hash: "#features" }, id: "features" },
  {
    label: "Trust Registry",
    to: { pathname: "/", hash: "#registry" },
    id: "registry",
    badge: "WEB3",
  },
  { label: "About Us", to: { pathname: "/about" }, id: "about" },
] as const;

function useActiveSection(enabled: boolean) {
  const [active, setActive] = useState<string | null>(null);
  useEffect(() => {
    if (!enabled) return setActive(null);
    const ids = ["scanner", "features", "registry"];
    const visible = new Map<string, boolean>();
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => visible.set(e.target.id, e.isIntersecting));
        setActive(ids.find((id) => visible.get(id)) ?? null);
      },
      { rootMargin: "-45% 0px -50% 0px" },
    );
    const t = setTimeout(
      () =>
        ids.forEach((id) => {
          const el = document.getElementById(id);
          if (el) observer.observe(el);
        }),
      50,
    );
    return () => {
      clearTimeout(t);
      observer.disconnect();
    };
  }, [enabled]);
  return active;
}

export function Header() {
  const location = useLocation();
  const isHome = location.pathname === "/";
  const activeSection = useActiveSection(isHome);
  const active = isHome ? activeSection : location.pathname.startsWith("/about") ? "about" : null;
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 48);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => setOpen(false), [location.key]);

  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [open]);

  return (
    <header
      className={`sticky top-0 z-40 border-b transition-[background-color,border-color,backdrop-filter] duration-300 ${
        scrolled || open
          ? "border-white/10 bg-black/80 backdrop-blur-xl"
          : "border-white/[0.06] bg-black"
      }`}
    >
      <div className="mx-auto flex h-[66px] max-w-[1264px] items-center justify-between gap-6 px-5 md:px-8">
        <Link to="/" aria-label="TrustLens home" className="rounded-xl">
          <Logo />
        </Link>

        <nav aria-label="Primary" className="hidden items-center gap-1 lg:flex">
          {NAV.map((item) => {
            const isActive = active === item.id;
            return (
              <Link
                key={item.id}
                to={item.to}
                aria-current={isActive ? "page" : undefined}
                className={`relative inline-flex h-10 items-center gap-2 rounded-full px-4 text-[15px] transition-colors duration-200 ${
                  isActive ? "text-white" : "text-white/65 hover:text-white"
                }`}
              >
                {item.label}
                {"badge" in item && (
                  <span className="rounded-[5px] border border-amber/60 bg-amber/10 px-1.5 py-px font-mono text-[9.5px] font-semibold tracking-[0.08em] text-amber">
                    {item.badge}
                  </span>
                )}
                {isActive && (
                  <motion.span
                    layoutId="nav-active"
                    className="absolute inset-x-4 -bottom-[13px] h-px bg-[linear-gradient(90deg,transparent,#00D5F2,transparent)]"
                    transition={{ type: "spring", stiffness: 400, damping: 34 }}
                  />
                )}
              </Link>
            );
          })}
        </nav>

        <div className="hidden items-center gap-2 lg:flex">
          <PillLink
            to={{ pathname: "/", hash: "#scanner" }}
            size="sm"
            className="h-[38px] px-4 text-[15px] font-medium"
          >
            Live Scan
          </PillLink>
        </div>

        <button
          type="button"
          className="grid size-10 place-items-center rounded-full border border-white/12 text-white lg:hidden"
          aria-label={open ? "Close menu" : "Open menu"}
          aria-expanded={open}
          aria-controls="mobile-menu"
          onClick={() => setOpen((o) => !o)}
        >
          {open ? <X className="size-5" /> : <Menu className="size-5" />}
        </button>
      </div>

      <AnimatePresence>
        {open && (
          <motion.nav
            id="mobile-menu"
            aria-label="Mobile"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "calc(100svh - 66px)" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-y-auto border-t border-white/10 bg-black/95 lg:hidden"
          >
            <ul className="mx-auto flex max-w-[1264px] flex-col px-5 pt-4">
              {NAV.map((item, i) => (
                <motion.li
                  key={item.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.05 * i + 0.05 }}
                >
                  <Link
                    to={item.to}
                    className={`flex items-center justify-between border-b border-white/[0.07] py-4 text-[22px] font-semibold tracking-[-0.02em] ${
                      active === item.id ? "text-white" : "text-white/70"
                    }`}
                  >
                    <span className="flex items-center gap-3">
                      {item.label}
                      {"badge" in item && (
                        <span className="rounded-[5px] border border-amber/60 bg-amber/10 px-1.5 py-px font-mono text-[10px] text-amber">
                          {item.badge}
                        </span>
                      )}
                    </span>
                    <span aria-hidden className="text-white/30">
                      →
                    </span>
                  </Link>
                </motion.li>
              ))}
            </ul>
            <div className="mx-auto flex max-w-[1264px] flex-col gap-3 px-5 py-8">
              <PillLink to={{ pathname: "/", hash: "#scanner" }} className="w-full" arrow>
                Live Scan
              </PillLink>
            </div>
          </motion.nav>
        )}
      </AnimatePresence>
    </header>
  );
}
