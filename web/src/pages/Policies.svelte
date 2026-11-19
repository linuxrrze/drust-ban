<script lang="ts">
  import { ApiError, api, get } from '../lib/api';
  import { duration } from '../lib/format';
  import { href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import { notify } from '../lib/toast.svelte';
  import type { JailInfo, JailOverride, JailView, Policies, Propagate } from '../lib/types';
  import JailDialog from '../components/JailDialog.svelte';

  let data = $state<Policies | null>(null);
  let error = $state('');
  let propagate = $state<Propagate>('global');
  let saving = $state(false);
  let dialogOpen = $state(false);
  let editing = $state<JailInfo | null>(null);

  const modes: { id: Propagate; title: string; text: string }[] = [
    { id: 'global', title: 'Everywhere', text: 'A ban on one host is applied on all agents.' },
    { id: 'group', title: 'Within the group', text: "A ban on one host is applied on the agents of that host's group." },
    { id: 'off', title: 'Only locally', text: 'Each agent bans for itself; the controller only distributes manual bans.' },
  ];

  async function load() {
    try {
      data = await get<Policies>('/policies');
      propagate = data.propagate;
      error = '';
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  });

  async function savePropagate() {
    saving = true;
    try {
      await api('PUT', '/policies/propagate', { propagate });
      notify('Ban propagation changed');
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : String(e), 'error');
    } finally {
      saving = false;
    }
  }

  /** "3" or "3–5" over the agents that have the jail. */
  function range(values: number[], fmt: (n: number) => string = String): string {
    if (!values.length) return '–';
    const lo = Math.min(...values);
    const hi = Math.max(...values);
    return lo === hi ? fmt(lo) : `${fmt(lo)}–${fmt(hi)}`;
  }

  function effective(j: JailInfo) {
    const v = j.agents.map((a) => a.jail);
    const pick = (f: (x: JailView) => number) => v.map(f);
    return {
      maxretry: range(pick((x) => x.maxretry)),
      findtime: range(pick((x) => x.findtime_secs), duration),
      bantime: range(pick((x) => x.bantime_secs), duration),
      factor: range(pick((x) => x.bantime_factor), (n) => `×${n}`),
      off: v.filter((x) => !x.enabled).length,
      bans: v.reduce((s, x) => s + x.active_bans, 0),
    };
  }

  function summary(o: JailOverride): string {
    const parts: string[] = [];
    if (o.enabled !== undefined && o.enabled !== null) parts.push(o.enabled ? 'enabled' : 'disabled');
    if (o.maxretry) parts.push(`${o.maxretry} failures`);
    if (o.findtime) parts.push(`within ${o.findtime}`);
    if (o.bantime) parts.push(`ban ${o.bantime}`);
    if (o.bantime_factor) parts.push(`×${o.bantime_factor}`);
    if (o.max_bantime) parts.push(`max ${o.max_bantime}`);
    return parts.join(', ');
  }

  function edit(j: JailInfo | null) {
    editing = j;
    dialogOpen = true;
  }
</script>

<div class="page-head"><h1>Policies</h1></div>

{#if error}<div class="error-box">{error}</div>{/if}

{#if data}
  <div class="card section">
    <h2>Ban propagation</h2>
    <p class="muted">What happens when an agent bans an address because of its own logs.</p>
    <div class="modes" role="radiogroup" aria-label="Ban propagation">
      {#each modes as m (m.id)}
        <label class="mode" class:selected={propagate === m.id}>
          <input type="radio" name="propagate" value={m.id} bind:group={propagate} disabled={!can('admin')} />
          <span><strong>{m.title}</strong><br /><span class="muted small">{m.text}</span></span>
        </label>
      {/each}
    </div>
    {#if can('admin') && propagate !== data.propagate}
      <div class="row">
        <button class="primary" onclick={savePropagate} disabled={saving}>Save</button>
        <button onclick={() => (propagate = data!.propagate)}>Cancel</button>
      </div>
    {/if}
  </div>

  <div class="card section">
    <div class="row head">
      <h2>Jails</h2>
      <span class="spacer"></span>
      {#if can('admin')}<button onclick={() => edit(null)}>Configure another jail…</button>{/if}
    </div>
    <p class="muted">
      Jails are defined in each agent's configuration (log sources and filter). Their limits can be set
      here for all agents or per group; agents apply them within seconds and keep them while the
      controller is unreachable.
    </p>
    {#if data.jails.length === 0}
      <div class="empty">No agent has reported a jail yet.</div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Jail</th><th>Agents</th><th class="num">Failures</th><th>Within</th><th>First ban</th>
              <th>Escalation</th><th class="num">Active bans</th><th>Central settings</th>{#if can('admin')}<th></th>{/if}
            </tr>
          </thead>
          <tbody>
            {#each data.jails as j (j.name)}
              {@const e = effective(j)}
              <tr>
                <td>
                  <strong>{j.name}</strong>
                  {#if j.filters.length}<div class="faint small">filter {j.filters.join(', ')}</div>{/if}
                </td>
                <td>
                  {#if j.agents.length}
                    <a href={href('agents')}>{j.agents.length}</a>
                    {#if e.off}<span class="pill warn">{e.off} disabled</span>{/if}
                  {:else}<span class="faint">none yet</span>{/if}
                </td>
                <td class="num">{e.maxretry}</td>
                <td>{e.findtime}</td>
                <td>{e.bantime}</td>
                <td>{e.factor}</td>
                <td class="num">{e.bans}</td>
                <td>
                  {#each j.overrides as o (o.group ?? '*')}
                    <div class="small"><span class="faint">{o.group ? `group ${o.group}` : 'all agents'}:</span> {summary(o)}</div>
                  {:else}<span class="faint small">from the agents' configuration</span>{/each}
                </td>
                {#if can('admin')}<td><button class="link" onclick={() => edit(j)}>Edit…</button></td>{/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="faint small">
        Values are those the agents report (a range when they differ); agents report every 10 seconds.
      </p>
    {/if}
  </div>
{/if}

<JailDialog bind:open={dialogOpen} jail={editing} groups={data?.groups ?? []} ondone={load} />

<style>
  .section { margin-bottom: 16px; display: grid; gap: 12px; }
  .section h2 { margin: 0; }
  p { margin: 0; }
  .modes { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 10px; }
  .mode {
    display: flex; gap: 10px; align-items: flex-start; padding: 10px 12px;
    border: 1px solid var(--border); border-radius: 10px; cursor: pointer;
  }
  .mode.selected { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 6%, transparent); }
  .head { align-items: center; }
  .spacer { flex: 1; }
  td .pill { margin-left: 6px; }
</style>
