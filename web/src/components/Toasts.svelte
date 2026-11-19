<script lang="ts">
  import { toasts } from '../lib/toast.svelte';
</script>

<div class="toasts" role="status" aria-live="polite">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}">{t.text}</div>
  {/each}
</div>

<style>
  .toasts {
    position: fixed; right: 16px; bottom: 16px; z-index: 50;
    display: grid; gap: 8px; max-width: min(420px, calc(100vw - 32px));
  }
  .toast {
    background: var(--text); color: var(--surface);
    border-radius: 10px; padding: 10px 14px; font-weight: 500;
    box-shadow: 0 8px 24px rgb(0 0 0 / 0.2);
  }
  .toast.error { background: var(--bad); color: #fff; }
</style>
