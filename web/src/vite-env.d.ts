/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_TRUSTLENS_API_URL?: string;
  readonly VITE_HOW_IT_WORKS_VIDEO_URL?: string;
  readonly VITE_REGISTRY_NETWORK?: string;
  readonly VITE_REGISTRY_CONTRACT_ADDRESS?: string;
  readonly VITE_REGISTRY_EXPLORER_URL?: string;
  readonly VITE_GITHUB_URL?: string;
  readonly VITE_X_URL?: string;
  readonly VITE_DISCORD_URL?: string;
  readonly VITE_TELEGRAM_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
