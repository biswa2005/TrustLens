const env = import.meta.env;

function clean(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim().replace(/\/+$/, "") : undefined;
}

/** Public, build-time configuration. Secrets never belong here. */
export const config = {
  scanApiUrl: clean(env.VITE_TRUSTLENS_API_URL),
  howItWorksVideoUrl: clean(env.VITE_HOW_IT_WORKS_VIDEO_URL),
  registry: {
    network: clean(env.VITE_REGISTRY_NETWORK),
    contractAddress: clean(env.VITE_REGISTRY_CONTRACT_ADDRESS),
    explorerUrl: clean(env.VITE_REGISTRY_EXPLORER_URL),
  },
  links: {
    github: clean(env.VITE_GITHUB_URL),
    x: clean(env.VITE_X_URL),
    discord: clean(env.VITE_DISCORD_URL),
    telegram: clean(env.VITE_TELEGRAM_URL),
  },
};

export const isLiveScanConfigured = Boolean(config.scanApiUrl);
export const isRegistryConfigured = Boolean(
  config.registry.network && config.registry.contractAddress,
);
