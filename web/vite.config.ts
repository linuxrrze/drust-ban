import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// `npm run dev` proxies the API to a local controller (self-signed
// internal CA, hence secure: false - development only).
const controller = process.env.DF2B_CONTROLLER ?? 'https://127.0.0.1:7444';

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: 'dist',
    // no inline scripts: the controller's CSP allows script-src 'self' only
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    cssCodeSplit: false,
  },
  server: {
    proxy: { '/api': { target: controller, secure: false, changeOrigin: true } },
  },
});
