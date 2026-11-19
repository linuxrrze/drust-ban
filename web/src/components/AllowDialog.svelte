<script lang="ts">
  import { ApiError, post } from '../lib/api';
  import { notify } from '../lib/toast.svelte';
  import { dateTime } from '../lib/format';
  import Dialog from './Dialog.svelte';

  let {
    open = $bindable(false),
    initialNet = '',
    ondone,
  }: { open: boolean; initialNet?: string; ondone?: () => void } = $props();

  let net = $state('');
  let comment = $state('');
  let unban = $state(true);
  let ttl = $state('never');
  let error = $state('');
  let busy = $state(false);

  $effect(() => {
    if (open) {
      net = initialNet;
      comment = '';
      unban = true;
      ttl = 'never';
      error = '';
    }
  });

  async function submit() {
    busy = true;
    error = '';
    try {
      const r = await post<{ net: string; unbanned: number; expires_at: string | null }>('/allowlist', {
        net: net.trim(),
        comment: comment.trim(),
        unban,
        ttl,
      });
      const until = r.expires_at ? ` until ${dateTime(r.expires_at)}` : '';
      notify(`${r.net} allowlisted${until}${r.unbanned ? `; ${r.unbanned} active ban(s) lifted` : ''}`);
      open = false;
      ondone?.();
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open title="Add to the allowlist" onsubmit={submit}>
  <label class="field">
    Address or network
    <input class="mono" bind:value={net} required placeholder="192.0.2.0/24 or 2001:db8:5::/48" />
    <span class="hint">At most /8 (IPv4) or /16 (IPv6). Never banned centrally from now on.</span>
  </label>
  <label class="field">
    Comment <span class="hint">who or what this is</span>
    <input bind:value={comment} maxlength="200" placeholder="e.g. monitoring, partner VPN" />
  </label>
  <label class="field">
    Keep
    <select bind:value={ttl}>
      <option value="never">permanently</option>
      <option value="1h">for 1 hour</option>
      <option value="24h">for 24 hours</option>
      <option value="7d">for 7 days</option>
      <option value="30d">for 30 days</option>
    </select>
  </label>
  <label class="check">
    <input type="checkbox" bind:checked={unban} />
    Lift active bans that overlap this network
  </label>
  {#if error}<div class="error-box">{error}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" class="primary" disabled={busy}>Add</button>
  </div>
</Dialog>

<style>
  .check { display: flex; gap: 8px; align-items: center; font-size: 13px; }
</style>
