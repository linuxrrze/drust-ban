<script lang="ts">
  import { ApiError, get, post } from '../lib/api';
  import { notify } from '../lib/toast.svelte';
  import type { Agent, Decision } from '../lib/types';
  import Dialog from './Dialog.svelte';

  let {
    open = $bindable(false),
    initialTarget = '',
    ondone,
  }: { open: boolean; initialTarget?: string; ondone?: () => void } = $props();

  let target = $state('');
  let duration = $state('24h');
  let customDuration = $state('');
  let scope = $state('global');
  let jail = $state('');
  let reason = $state('');
  let error = $state('');
  let busy = $state(false);
  let groups = $state<string[]>([]);

  $effect(() => {
    if (open) {
      target = initialTarget;
      error = '';
      get<{ agents: Agent[] }>('/agents')
        .then((r) => (groups = [...new Set(r.agents.map((a) => a.group))].sort()))
        .catch(() => (groups = []));
    }
  });

  async function submit() {
    busy = true;
    error = '';
    try {
      const d = duration === 'custom' ? customDuration.trim() : duration;
      const r = await post<{ decision: Decision | null; message?: string }>('/bans', {
        target: target.trim(),
        duration: d === 'permanent' ? null : d,
        scope,
        jail: jail.trim() || null,
        reason: reason.trim() || null,
      });
      notify(r.decision ? `Banned ${r.decision.target}` : (r.message ?? 'Already banned'));
      open = false;
      ondone?.();
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open title="Ban address or prefix" onsubmit={submit}>
  <label class="field">
    Address or prefix
    <input bind:value={target} required placeholder="203.0.113.7 or 2001:db8::/64" class="mono" />
    <span class="hint">At most /8 (IPv4) or /16 (IPv6). Allowlisted networks are refused.</span>
  </label>
  <div class="two">
    <label class="field">
      Duration
      <select bind:value={duration}>
        <option value="1h">1 hour</option>
        <option value="24h">24 hours</option>
        <option value="7d">7 days</option>
        <option value="30d">30 days</option>
        <option value="permanent">permanent</option>
        <option value="custom">other…</option>
      </select>
    </label>
    <label class="field">
      Applies to
      <select bind:value={scope}>
        <option value="global">all agents</option>
        {#each groups as g (g)}
          <option value="group:{g}">group {g}</option>
        {/each}
      </select>
    </label>
  </div>
  {#if duration === 'custom'}
    <label class="field">
      Custom duration
      <input bind:value={customDuration} required placeholder="e.g. 90m, 3d 12h" />
    </label>
  {/if}
  <div class="two">
    <label class="field">
      Jail <span class="hint">optional</span>
      <input bind:value={jail} placeholder="sshd" />
    </label>
    <label class="field">
      Reason
      <input bind:value={reason} placeholder="manual" />
    </label>
  </div>
  {#if error}<div class="error-box">{error}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" class="primary" disabled={busy}>{busy ? 'Banning…' : 'Ban'}</button>
  </div>
</Dialog>

<style>
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
</style>
