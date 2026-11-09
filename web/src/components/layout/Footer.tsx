import { Link, type To } from "react-router";
import { Logo } from "@/components/ui/Logo";
import { Stars } from "@/components/ui/Stars";
import { DiscordIcon, GitHubIcon, TelegramIcon, XIcon } from "@/components/ui/SocialIcons";
import { config, isLiveScanConfigured, isRegistryConfigured } from "@/lib/config";

type FooterLink = { label: string; to?: To; href?: string };

const COLUMNS: { title: string; links: FooterLink[] }[] = [
  {
    title: "Product",
    links: [
      { label: "URL Scanner", to: { pathname: "/", search: "?mode=url", hash: "#scanner" } },
      { label: "Scam Inspector", to: { pathname: "/", search: "?mode=message", hash: "#scanner" } },
      { label: "TLS Auditor", to: { pathname: "/", hash: "#features" } },
      { label: "Threat Registry", to: { pathname: "/", hash: "#registry" } },
      { label: "API Access", to: { pathname: "/about", hash: "#architecture" } },
    ],
  },
  {
    title: "Security & Ethics",
    links: [
      { label: "Passive Scan Policy", to: { pathname: "/about", hash: "#principles" } },
      { label: "Data Privacy", to: { pathname: "/about", hash: "#principles" } },
      { label: "SSRF Protection", to: { pathname: "/about", hash: "#principles" } },
      { label: "System Status", to: { hash: "#system-status" } },
    ],
  },
  {
    title: "Developers & Web3",
    links: [
      { label: "Smart Contracts", to: { pathname: "/about", hash: "#architecture" } },
      { label: "GitHub Repository", href: config.links.github },
      { label: "Documentation", to: { pathname: "/about", hash: "#workflow" } },
      { label: "Verified Audits" },
    ],
  },
  {
    title: "Legal",
    links: [
      { label: "Terms of Service" },
      { label: "Privacy Policy" },
      { label: "Responsible Disclosure" },
    ],
  },
];

const SOCIALS = [
  { label: "GitHub", href: config.links.github, Icon: GitHubIcon },
  { label: "X / Twitter", href: config.links.x, Icon: XIcon },
  { label: "Discord", href: config.links.discord, Icon: DiscordIcon },
  { label: "Telegram", href: config.links.telegram, Icon: TelegramIcon },
];

const linkClass = "text-[14.5px] text-fg-2 transition-colors hover:text-white";

function FooterItem({ link }: { link: FooterLink }) {
  if (link.to)
    return (
      <Link to={link.to} className={linkClass}>
        {link.label}
      </Link>
    );
  if (link.href)
    return (
      <a href={link.href} target="_blank" rel="noreferrer" className={linkClass}>
        {link.label}
      </a>
    );
  return (
    <span className="inline-flex items-center gap-2 text-[14.5px] text-fg-3" aria-disabled="true">
      {link.label}
      <span className="rounded border border-white/10 px-1.5 py-px font-mono text-[10px] tracking-wider text-fg-3">
        SOON
      </span>
    </span>
  );
}

export function Footer() {
  return (
    <footer className="relative isolate overflow-hidden border-t border-white/[0.07] bg-[#05070b]">
      <Stars count={40} seed={23} className="opacity-50" />
      <div
        className="pointer-events-none absolute -bottom-40 left-1/2 h-80 w-[80%] -translate-x-1/2 rounded-full bg-[#1d3b66]/30 blur-[120px]"
        aria-hidden
      />
      <div className="relative mx-auto max-w-[1264px] px-5 pt-20 pb-10 md:px-8">
        <div className="flex flex-col gap-8 md:flex-row md:items-end md:justify-between">
          <div>
            <Logo />
            <p className="mt-6 max-w-sm text-[17px] leading-relaxed text-fg-2">
              <span className="text-white">TrustLens</span> — AI-Powered Web Threat Detection
              &amp; Digital Trust Intelligence.
            </p>
          </div>
          <p className="font-mono text-[13px] tracking-[0.14em] text-fg-3">
            DON&apos;T TRUST. VERIFY.
          </p>
        </div>

        <div className="mt-16 grid grid-cols-2 gap-x-6 gap-y-10 border-t border-white/[0.07] pt-12 md:grid-cols-4">
          {COLUMNS.map((col) => (
            <div key={col.title}>
              <h4 className="font-mono text-[12px] tracking-[0.14em] text-fg-3 uppercase">
                {col.title}
              </h4>
              <ul className="mt-5 space-y-3">
                {col.links.map((l) => (
                  <li key={l.label}>
                    <FooterItem link={l} />
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="mt-14 flex flex-col gap-6 border-t border-white/[0.07] pt-8 lg:flex-row lg:items-center lg:justify-between">
          <p className="text-[13.5px] text-fg-3">
            © {new Date().getFullYear()} TrustLens. All rights reserved.
          </p>

          <ul className="flex items-center gap-2">
            {SOCIALS.map(({ label, href, Icon }) => (
              <li key={label}>
                {href ? (
                  <a
                    href={href}
                    target="_blank"
                    rel="noreferrer"
                    aria-label={label}
                    className="grid size-9 place-items-center rounded-full border border-white/10 text-fg-2 transition hover:border-white/25 hover:text-white"
                  >
                    <Icon className="size-4" />
                  </a>
                ) : (
                  <span
                    title={`${label} link not configured yet`}
                    aria-label={`${label} (not configured yet)`}
                    className="grid size-9 place-items-center rounded-full border border-white/[0.06] text-fg-3/60"
                  >
                    <Icon className="size-4" />
                  </span>
                )}
              </li>
            ))}
          </ul>

          <div
            id="system-status"
            className="flex flex-col gap-2 font-mono text-[12px] sm:flex-row sm:items-center sm:gap-5"
          >
            <span className="inline-flex items-center gap-2 text-fg-2">
              <span
                className={`size-2 rounded-full ${isLiveScanConfigured ? "bg-safe text-safe" : "bg-amber text-amber"} animate-pulse-dot`}
                aria-hidden
              />
              {isLiveScanConfigured
                ? "Analysis backend configured"
                : "Preview mode · live services not connected"}
            </span>
            <span className="inline-flex items-center gap-2 text-fg-3">
              <span className="size-2 rounded-full bg-fg-3" aria-hidden />
              Network:{" "}
              {isRegistryConfigured
                ? config.registry.network
                : "Arbitrum / Ethereum — not configured"}
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}
