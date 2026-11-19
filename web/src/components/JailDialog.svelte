<script lang="ts">
  import { ApiError, api } from '../lib/api';
  import { notify } from '../lib/toast.svelte';
  import type { JailInfo, JailOverride } from '../lib/types';
  import Dialog from './Dialog.svelte';

  let {
    open = $bindable(false),
    jail,
    groups,
    ondone,
  }: { open: boolean; jail: JailInfo | null; groups: string[]; ondone?: () => void } = $props();

  type Field = 'enabled' | 'maxretry' | 'findtime' | 'bantime' | 'bantime_factor' | 'max_bantime';
  const fields: { id: Field; label: string; hint: string }[] = [
    { id: 'enabled', label: 'Enabled', hint: 'off: no failures are counted, active bans run out' },
    { id: 'maxretry', label: 'Failures until a ban', hint: '1–1000' },
    { id: 'findtime', label: 'Within', hint: 'e.g. 10m (at most 7 days)' },
    { id: 'bantime', label: 'First ban', hint: 'e.g. 1h' },
    { id: 'bantime_factor', label: 'Escalation factor', hint: 'each repeat offense: × this (1–10)' },
    { id: 'max_bantime', label: 'Longest ban', hint: 'e.g. 30d' },
  ];

  let name = $state('');
  let scope = $state(''); // '' = all agents
  let newGroup = $state('');
  let on = $state<Record<Field, boolean>>({} as Record<Field, boolean>);
  let values = $state<Record<Field, string>>({} as Record<Field, string>);
  let enabled = $state(true);
  let error = $state('');
  let busy = $state(false);

  const group = $derived(scope === '+' ? newGroup.trim() : scope);
  const existing = $derived(jail?.overrides.find((o) => (o.group ?? '') === group) ?? null);

  function load(o: JailOverride | null) {
    for (const f of fields) {
      const v = o?.[f.id];
      on[f.id] = v !== undefined && v !== null;
      values[f.id] = v === undefined || v === null || f.id === 'enabled' ? '' : String(v);
    }
    enabled = o?.enabled ?? true;
  }

  $effect(() => {
    if (open) {
      name = jail?.name ?? '';
      scope = '';
      newGroup = '';
      error = '';
      load(jail?.overrides.find((o) => o.group === null) ?? null);
    }
  });

  // switching the scope shows that scope's settings
  let lastScope = '';
  $effect(() => {
    if (open && group !== lastScope) {
      lastScope = group;
      load(existing);
    }
  });

  async function save(remove = false) {
    busy = true;
    error = '';
    const jailName = name.trim();
    try {
      if (remove) {
        const q = group ? `?group=${encodeURIComponent(group)}` : '';
        await api('DELETE', `/jails/${encodeURIComponent(jailName)}/policy${q}`);
        notify(`Central settings for ${jailName} (${group || 'all agents'}) removed`);
      } else {
        const body: Record<string, unknown> = { group: group || null };
        for (const f of fields) {
          if (!on[f.id]) continue;
          if (f.id === 'enabled') body.enabled = enabled;
          else if (f.id === 'maxretry') body.maxretry = Number(values.maxretry);
          else if (f.id === 'bantime_factor') body.bantime_factor = Number(values.bantime_factor);
          else body[f.id] = values[f.id].trim();
        }
        await api('PUT', `/jails/${encodeURIComponent(jailName)}/policy`, body);
        notify(`Settings for ${jailName} (${group || 'all agents'}) saved; agents apply them at once`);
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

<Dialog bind:open title={jail ? `Settings for ${jail.name}` : 'Configure a jail'} onsubmit={() => save()}>
  {#if !jail}
    <label class="field">
      Jail name
      <input bind:value={name} required pattern="[A-Za-z0-9._\-]+" maxlength="64" placeholder="as in the agents' configuration" />
    </label>
  {/if}
  <label class="field">
    For
    <select bind:value={scope}>
      <option value="">all agents</option>
      {#each groups as g (g)}<option value={g}>group {g}</option>{/each}
      <option value="+">another group…</option>
    </select>
  </label>
  {#if scope === '+'}
    <label class="field">
      Group
      <input bind:value={newGroup} required pattern="[A-Za-z0-9._\-]+" maxlength="64" />
    </label>
  {/if}
  <p class="muted confirm-text">
    Tick what to set centrally; everything else keeps {group ? 'the settings for all agents, then ' : ''}each
    agent's own configuration.{#if group} Settings for group {group} win over those for all agents.{/if}
  </p>
  <div class="grid-fields">
    {#each fields as f (f.id)}
      <label class="check">
        <input type="checkbox" bind:checked={on[f.id]} />
        {f.label}
      </label>
      {#if f.id === 'enabled'}
        <select bind:value={enabled} disabled={!on.enabled} aria-label={f.label}>
          <option value={true}>on</option>
          <option value={false}>off</option>
        </select>
      {:else}
        <input bind:value={values[f.id]} disabled={!on[f.id]} required={on[f.id]} aria-label={f.label} placeholder={f.hint}
          inputmode={f.id === 'maxretry' || f.id === 'bantime_factor' ? 'decimal' : 'text'} />
      {/if}
    {/each}
  </div>
  {#if error}<div class="error-box">{error}</div>{/if}
  <div class="actions">
    {#if existing}
      <button type="button" class="danger" disabled={busy} onclick={() => save(true)}>Remove these settings</button>
      <span class="spacer"></span>
    {/if}
    <button type="button" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" class="primary" disabled={busy || !name.trim()}>Save</button>
  </div>
</Dialog>

<style>
  p { margin: 0; }
  .grid-fields { display: grid; grid-template-columns: auto 1fr; gap: 8px 14px; align-items: center; }
  .check { display: flex; gap: 8px; align-items: center; font-size: 13px; font-weight: 550; }
  .spacer { flex: 1; }
  input:disabled, select:disabled { opacity: 0.5; }
</style>
