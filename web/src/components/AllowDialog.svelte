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

  const isAsn = $derived(/^\s*as\d+\s*$/i.test(net));

  async function submit() {
    busy = true;
    error = '';
    try {
      const r = await post<{ net?: string; asn?: number; networks?: number; unbanned: number; expires_at?: string | null }>(
        '/allowlist',
        isAsn
          ? { net: net.trim().toUpperCase(), comment: comment.trim(), unban }
          : { net: net.trim(), comment: comment.trim(), unban, ttl },
      );
      const lifted = r.unbanned ? `; ${r.unbanned} active ban(s) lifted` : '';
      if (r.asn !== undefined) {
        notify(
          r.networks
            ? `AS${r.asn} allowlisted (${r.networks} networks)${lifted}`
            : `AS${r.asn} allowlisted, but no networks are known for it: the controller needs a GeoIP ASN database`,
          r.networks ? 'ok' : 'error',
        );
      } else {
        const until = r.expires_at ? ` until ${dateTime(r.expires_at)}` : '';
        notify(`${r.net} allowlisted${until}${lifted}`);
      }
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
    Address, network or autonomous system
    <input class="mono" bind:value={net} required placeholder="192.0.2.0/24, 2001:db8:5::/48 or AS64500" />
    <span class="hint">
      {#if isAsn}All its networks in the controller's GeoIP data (updated with it); permanent.
      {:else}At most /8 (IPv4) or /16 (IPv6). Never banned centrally from now on.{/if}
    </span>
  </label>
  <label class="field">
    Comment <span class="hint">who or what this is</span>
    <input bind:value={comment} maxlength="200" placeholder="e.g. monitoring, partner VPN" />
  </label>
  <label class="field" class:hidden={isAsn}>
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
  .hidden { display: none; }
</style>
