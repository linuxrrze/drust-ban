<script lang="ts">
  import { ApiError, post } from '../lib/api';
  import { dateTime } from '../lib/format';
  import Dialog from './Dialog.svelte';

  let { open = $bindable(false) }: { open: boolean } = $props();

  let group = $state('default');
  let ttl = $state('1h');
  let error = $state('');
  let busy = $state(false);
  let result = $state<{ token: string; group: string; expires_at: string } | null>(null);
  let copied = $state(false);

  $effect(() => {
    if (open) {
      result = null;
      error = '';
      copied = false;
    }
  });

  async function submit() {
    if (result) {
      open = false;
      return;
    }
    busy = true;
    error = '';
    try {
      result = await post('/enroll-tokens', { group: group.trim(), ttl });
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copy() {
    if (!result) return;
    await navigator.clipboard.writeText(result.token);
    copied = true;
  }
</script>

<Dialog bind:open title="Enroll an agent" onsubmit={submit}>
  {#if !result}
    <label class="field">
      Group
      <input bind:value={group} required pattern="[A-Za-z0-9._\-]+" />
      <span class="hint">Bans can be limited to a group.</span>
    </label>
    <label class="field">
      Token valid for
      <select bind:value={ttl}>
        <option value="15m">15 minutes</option>
        <option value="1h">1 hour</option>
        <option value="24h">24 hours</option>
        <option value="7d">7 days</option>
      </select>
    </label>
    {#if error}<div class="error-box">{error}</div>{/if}
    <div class="actions">
      <button type="button" onclick={() => (open = false)}>Cancel</button>
      <button type="submit" class="primary" disabled={busy}>Create token</button>
    </div>
  {:else}
    <p class="muted">
      One-time token for group <strong>{result.group}</strong>, valid until
      {dateTime(result.expires_at)}. It is shown only once. On the agent host:
    </p>
    <code class="token">DF2B_ENROLL_TOKEN={result.token} df2b-agent</code>
    <p class="faint small">
      The token also pins the controller's CA, so the agent cannot be tricked into enrolling with
      another server.
    </p>
    <div class="actions">
      <button type="button" onclick={copy}>{copied ? 'Copied' : 'Copy token'}</button>
      <button type="submit" class="primary">Done</button>
    </div>
  {/if}
</Dialog>

<style>
  p { margin: 0; }
  .token {
    display: block; padding: 10px 12px; border-radius: 8px;
    background: var(--surface-2); word-break: break-all; user-select: all;
  }
</style>
