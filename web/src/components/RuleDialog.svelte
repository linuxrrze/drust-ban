<script lang="ts">
  import { ApiError, api } from '../lib/api';
  import { notify } from '../lib/toast.svelte';
  import type { CorrelationRule } from '../lib/types';
  import Dialog from './Dialog.svelte';

  let {
    open = $bindable(false),
    rule,
    jails,
    groups,
    ondone,
  }: { open: boolean; rule: CorrelationRule | null; jails: string[]; groups: string[]; ondone?: () => void } = $props();

  let name = $state('');
  let kind = $state<'threshold' | 'quorum'>('threshold');
  let jail = $state('');
  let group = $state('');
  let minAgents = $state('3');
  let minFailures = $state('10');
  let window_ = $state('10m');
  let bantime = $state('1h');
  let mode = $state<'enforce' | 'monitor' | 'off'>('monitor');
  let error = $state('');
  let busy = $state(false);

  $effect(() => {
    if (open) {
      error = '';
      name = rule?.name ?? '';
      kind = rule?.kind ?? 'threshold';
      jail = rule?.jail ?? '';
      group = rule?.group ?? '';
      minAgents = String(rule?.min_agents ?? 3);
      minFailures = String(rule?.min_failures || 10);
      window_ = rule?.window ?? '10m';
      bantime = rule?.bantime ?? '1h';
      // new rules start in monitor mode: see what they would do first
      mode = !rule ? 'monitor' : !rule.enabled ? 'off' : rule.monitor ? 'monitor' : 'enforce';
    }
  });

  async function save() {
    busy = true;
    error = '';
    try {
      await api('PUT', `/correlation/${encodeURIComponent(name.trim())}`, {
        kind,
        jail: jail.trim() || null,
        group: group || null,
        min_agents: Number(minAgents),
        min_failures: kind === 'threshold' ? Number(minFailures) : 0,
        window: window_.trim(),
        bantime: bantime.trim(),
        enabled: mode !== 'off',
        monitor: mode === 'monitor',
      });
      notify(`Rule ${name.trim()} saved`);
      open = false;
      ondone?.();
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open title={rule ? `Rule ${rule.name}` : 'New correlation rule'} onsubmit={save}>
  {#if !rule}
    <label class="field">
      Name <input bind:value={name} required pattern="[A-Za-z0-9._\-]+" maxlength="64" placeholder="e.g. distributed-ssh" />
    </label>
  {/if}
  <div class="kinds" role="radiogroup" aria-label="Kind">
    <label class="kind" class:selected={kind === 'threshold'}>
      <input type="radio" bind:group={kind} value="threshold" />
      <span><strong>Distributed failures</strong><br /><span class="muted small">Many failures spread over several hosts, each below its own limit.</span></span>
    </label>
    <label class="kind" class:selected={kind === 'quorum'}>
      <input type="radio" bind:group={kind} value="quorum" />
      <span><strong>Quorum</strong><br /><span class="muted small">Ban only when several hosts banned the address themselves.</span></span>
    </label>
  </div>
  <div class="grid">
    {#if kind === 'threshold'}
      <label class="field">At least <input bind:value={minFailures} required inputmode="numeric" /><span class="hint">failures in total</span></label>
    {/if}
    <label class="field">from at least <input bind:value={minAgents} required inputmode="numeric" /><span class="hint">different agents</span></label>
    <label class="field">within <input bind:value={window_} required /><span class="hint">1m to 24h</span></label>
    <label class="field">ban for <input bind:value={bantime} required /></label>
  </div>
  <div class="grid">
    <label class="field">
      Jail <input bind:value={jail} list="rule-jails" placeholder="all jails" />
      <datalist id="rule-jails">{#each jails as j (j)}<option value={j}></option>{/each}</datalist>
    </label>
    <label class="field">
      Agents
      <select bind:value={group}>
        <option value="">all (ban everywhere)</option>
        {#each groups as g (g)}<option value={g}>group {g} (ban there)</option>{/each}
      </select>
    </label>
    <label class="field">
      Mode
      <select bind:value={mode}>
        <option value="monitor">monitor (only record)</option>
        <option value="enforce">ban</option>
        <option value="off">off</option>
      </select>
    </label>
  </div>
  {#if kind === 'quorum'}
    <p class="faint small">
      To protect against a compromised agent, set ban propagation to "Only locally": then single
      agents cannot ban anything on other hosts, and this rule decides.
    </p>
  {/if}
  {#if error}<div class="error-box">{error}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" class="primary" disabled={busy}>Save</button>
  </div>
</Dialog>

<style>
  .kinds { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .kind { display: flex; gap: 8px; align-items: flex-start; padding: 8px 10px; border: 1px solid var(--border); border-radius: 10px; cursor: pointer; }
  .kind.selected { border-color: var(--accent); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; }
  p { margin: 0; }
</style>
