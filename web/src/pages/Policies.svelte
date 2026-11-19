<script lang="ts">
  import { ApiError, api, get } from '../lib/api';
  import { duration } from '../lib/format';
  import { href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import { notify } from '../lib/toast.svelte';
  import type { CentralFilter, JailDefinition, JailInfo, JailOverride, JailView, Policies, Propagate } from '../lib/types';
  import Dialog from '../components/Dialog.svelte';
  import FilterDialog from '../components/FilterDialog.svelte';
  import JailDefDialog from '../components/JailDefDialog.svelte';
  import JailDialog from '../components/JailDialog.svelte';

  let data = $state<Policies | null>(null);
  let error = $state('');
  let propagate = $state<Propagate>('global');
  let saving = $state(false);
  let dialogOpen = $state(false);
  let editing = $state<JailInfo | null>(null);
  let defs = $state<JailDefinition[]>([]);
  let filters = $state<CentralFilter[]>([]);
  let defOpen = $state(false);
  let editingDef = $state<JailDefinition | null>(null);
  let filterOpen = $state(false);
  let editingFilter = $state<CentralFilter | null>(null);
  let confirmOpen = $state(false);
  let confirm = $state<{ title: string; text: string; run: () => Promise<void> } | null>(null);

  const modes: { id: Propagate; title: string; text: string }[] = [
    { id: 'global', title: 'Everywhere', text: 'A ban on one host is applied on all agents.' },
    { id: 'group', title: 'Within the group', text: "A ban on one host is applied on the agents of that host's group." },
    { id: 'off', title: 'Only locally', text: 'Each agent bans for itself; the controller only distributes manual bans.' },
  ];

  async function load() {
    try {
      const [p, d, f] = await Promise.all([
        get<Policies>('/policies'),
        get<{ definitions: JailDefinition[] }>('/jail-definitions'),
        get<{ filters: CentralFilter[] }>('/filters'),
      ]);
      data = p;
      defs = d.definitions;
      filters = f.filters;
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

  function ask(title: string, text: string, run: () => Promise<void>) {
    confirm = { title, text, run };
    confirmOpen = true;
  }

  async function runConfirm() {
    if (!confirm) return;
    try {
      await confirm.run();
      confirmOpen = false;
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : String(e), 'error');
    }
  }

  function removeDef(d: JailDefinition) {
    const scope = d.group ? `group ${d.group}` : 'all agents';
    ask(`Remove jail ${d.name} (${scope})?`, 'The agents stop this jail within seconds; its active bans run out.', async () => {
      const q = d.group ? `?group=${encodeURIComponent(d.group)}` : '';
      await api('DELETE', `/jail-definitions/${encodeURIComponent(d.name)}${q}`);
      notify(`Jail ${d.name} removed`);
    });
  }

  function removeFilter(f: CentralFilter) {
    ask(`Delete filter ${f.name}?`, 'Agents keep jails that use their own filter file of this name.', async () => {
      await api('DELETE', `/filters/${encodeURIComponent(f.name)}`);
      notify(`Filter ${f.name} deleted`);
    });
  }

  function sourcesText(d: JailDefinition): string {
    return d.sources
      .map((s) => (s.type === 'file' ? s.paths.join(', ') : `journal ${s.matches.join(' ') || '(all)'}`))
      .join('; ');
  }

  function problems(j: JailInfo) {
    return j.agents.filter((a) => a.jail.error);
  }

  function effective(j: JailInfo) {
    const v = j.agents.map((a) => a.jail).filter((x) => !x.error);
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
                  {#if j.agents.some((a) => a.jail.origin === 'central')}<span class="pill plain">central</span>{/if}
                  {#if j.filters.length}<div class="faint small">filter {j.filters.join(', ')}</div>{/if}
                  {#each problems(j) as p (p.agent)}
                    <div class="problem small" title={p.jail.error}>⚠ {p.agent}: {p.jail.error}</div>
                  {/each}
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

{#if data}
  <div class="card section">
    <div class="row head">
      <h2>Jail definitions</h2>
      <span class="spacer"></span>
      {#if can('admin')}<button onclick={() => { editingDef = null; defOpen = true; }}>Define a jail…</button>{/if}
    </div>
    <p class="muted">
      Jails defined here are created on the agents (for all of them or one group), with their log
      sources and filter. Agents accept them unless their configuration says otherwise
      (<code>central_jails</code>, <code>central_paths</code>, <code>central_journald</code>); a local
      jail with the same name wins. Problems show in the table above.
    </p>
    {#if defs.length === 0}
      <div class="empty">No jails defined centrally.</div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Jail</th><th>For</th><th>Filter</th><th>Sources</th><th>Limits</th>{#if can('admin')}<th></th>{/if}</tr></thead>
          <tbody>
            {#each defs as d (d.name + '|' + (d.group ?? ''))}
              <tr>
                <td><strong>{d.name}</strong>{#if !d.enabled} <span class="pill warn">disabled</span>{/if}</td>
                <td>{d.group ? `group ${d.group}` : 'all agents'}</td>
                <td>{d.filter} <span class="faint small">{d.filter_is_central ? 'central' : "agents' own"}</span></td>
                <td class="mono small sources">{sourcesText(d)}</td>
                <td class="small">{d.maxretry} in {d.findtime} → {d.bantime}{d.bantime_factor > 1 ? ` ×${d.bantime_factor}` : ''}{d.max_bantime ? `, max ${d.max_bantime}` : ''}</td>
                {#if can('admin')}
                  <td class="nowrap">
                    <button class="link" onclick={() => { editingDef = d; defOpen = true; }}>Edit…</button>
                    · <button class="link danger-link" onclick={() => removeDef(d)}>Remove</button>
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>

  <div class="card section">
    <div class="row head">
      <h2>Filters</h2>
      <span class="spacer"></span>
      {#if can('admin')}<button onclick={() => { editingFilter = null; filterOpen = true; }}>New filter…</button>{/if}
    </div>
    <p class="muted">Sent to the agents together with the jails that use them.</p>
    {#if filters.length === 0}
      <div class="empty">No central filters. Jail definitions can also use filters the agents have.</div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Filter</th><th>Used by</th><th>Changed</th>{#if can('admin')}<th></th>{/if}</tr></thead>
          <tbody>
            {#each filters as f (f.name)}
              <tr>
                <td><strong>{f.name}</strong></td>
                <td>{f.used_by.join(', ') || '–'}</td>
                <td class="muted small">by {f.updated_by}</td>
                {#if can('admin')}
                  <td class="nowrap">
                    <button class="link" onclick={() => { editingFilter = f; filterOpen = true; }}>Edit…</button>
                    {#if !f.used_by.length}· <button class="link danger-link" onclick={() => removeFilter(f)}>Delete</button>{/if}
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
{/if}

<JailDialog bind:open={dialogOpen} jail={editing} groups={data?.groups ?? []} ondone={load} />
<JailDefDialog bind:open={defOpen} def={editingDef} groups={data?.groups ?? []} filters={filters.map((f) => f.name)} ondone={load} />
<FilterDialog bind:open={filterOpen} filter={editingFilter} ondone={load} />
<Dialog bind:open={confirmOpen} title={confirm?.title ?? ''} onsubmit={runConfirm}>
  <p class="muted confirm-text">{confirm?.text}</p>
  <div class="actions">
    <button type="button" onclick={() => (confirmOpen = false)}>Cancel</button>
    <button type="submit" class="danger solid">Remove</button>
  </div>
</Dialog>

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
  .problem { color: var(--warn); max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sources { max-width: 280px; overflow-wrap: anywhere; }
  .nowrap { white-space: nowrap; }
  .danger-link { color: var(--bad); }
  p.confirm-text { margin: 0; }
</style>
