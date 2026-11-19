<script lang="ts">
  import { get } from '../lib/api';
  import { dateTime, geoLong, geoMatches, geoShort, origin, relative, remaining, scope, target } from '../lib/format';
  import { onChange } from '../lib/live.svelte';
  import { href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import type { Decision, GeoInfo } from '../lib/types';
  import BanDialog from '../components/BanDialog.svelte';
  import UnbanDialog from '../components/UnbanDialog.svelte';

  // a search preset from the URL (#/bans/as:64500, from the overview)
  let { filter = '' }: { filter?: string } = $props();

  let decisions = $state<Decision[]>([]);
  let geo = $state<Record<string, GeoInfo>>({});
  let loaded = $state(false);
  let error = $state('');
  let now = $state(Date.now());
  // svelte-ignore state_referenced_locally
  let query = $state(filter);
  let jail = $state('');
  let family = $state('');
  let sort = $state<'new' | 'expires' | 'target'>('new');
  let selected = $state<Set<string>>(new Set());
  let banOpen = $state(false);
  let unbanOpen = $state(false);
  let unbanTargets = $state<string[]>([]);
  let limit = $state(200);

  async function load() {
    try {
      const r = await get<{ decisions: Decision[]; geo?: Record<string, GeoInfo> }>('/decisions');
      decisions = r.decisions;
      geo = r.geo ?? {};
      error = '';
      now = Date.now();
      // forget selections that are gone
      const ids = new Set(decisions.map((d) => d.id));
      selected = new Set([...selected].filter((id) => ids.has(id)));
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loaded = true;
    }
  }

  $effect(() => {
    load();
    const off = onChange(load);
    const t = setInterval(() => (now = Date.now()), 30_000);
    return () => {
      off();
      clearInterval(t);
    };
  });

  const jails = $derived([...new Set(decisions.map((d) => d.jail ?? ''))].sort());
  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const out = decisions.filter(
      (d) =>
        (!jail || (d.jail ?? '') === jail) &&
        (!family || (family === '6') === d.target.includes(':')) &&
        (!q ||
          d.target.includes(q) ||
          (d.jail ?? 'manual').toLowerCase().includes(q) ||
          origin(d.origin).toLowerCase().includes(q) ||
          d.reason.toLowerCase().includes(q) ||
          scope(d.scope).toLowerCase().includes(q) ||
          geoShort(geo[d.target]).toLowerCase().includes(q) ||
          geoMatches(geo[d.target], q)),
    );
    const exp = (d: Decision) => (d.expires_at ? Date.parse(d.expires_at) : Infinity);
    if (sort === 'new') out.sort((a, b) => b.seq - a.seq);
    if (sort === 'expires') out.sort((a, b) => exp(a) - exp(b));
    if (sort === 'target') out.sort((a, b) => a.target.localeCompare(b.target, undefined, { numeric: true }));
    return out;
  });
  const page = $derived(filtered.slice(0, limit));
  const hasGeo = $derived(Object.keys(geo).length > 0);
  const allSelected = $derived(page.length > 0 && page.every((d) => selected.has(d.id)));

  function toggle(id: string) {
    const s = new Set(selected);
    if (s.has(id)) s.delete(id);
    else s.add(id);
    selected = s;
  }

  function toggleAll() {
    selected = allSelected ? new Set() : new Set(page.map((d) => d.id));
  }

  function unban(targets: string[]) {
    unbanTargets = [...new Set(targets)];
    unbanOpen = true;
  }
</script>

<div class="page-head">
  <h1>Bans</h1>
  <span class="faint">{decisions.length.toLocaleString()} active</span>
  <span class="spacer"></span>
  {#if can('operator')}
    {#if selected.size > 0}
      <button class="danger" onclick={() => unban(decisions.filter((d) => selected.has(d.id)).map((d) => d.target))}>
        Unban {selected.size} selected
      </button>
    {/if}
    <button class="primary" onclick={() => (banOpen = true)}>Ban…</button>
  {/if}
</div>

<div class="card">
  <div class="filters row">
    <input type="search" class="grow" placeholder={hasGeo ? 'Search address, jail, origin, reason, AS (as:64500), country (country:de)' : 'Search address, jail, origin, reason'} bind:value={query} aria-label="Search bans" />
    <select bind:value={jail} aria-label="Jail">
      <option value="">all jails</option>
      {#each jails as j (j)}<option value={j}>{j || 'manual'}</option>{/each}
    </select>
    <select bind:value={family} aria-label="Address family">
      <option value="">IPv4 + IPv6</option>
      <option value="4">IPv4</option>
      <option value="6">IPv6</option>
    </select>
    <select bind:value={sort} aria-label="Sort">
      <option value="new">newest first</option>
      <option value="expires">expiring first</option>
      <option value="target">by address</option>
    </select>
  </div>

  {#if error}<div class="error-box">{error}</div>{/if}

  {#if loaded && filtered.length === 0}
    <div class="empty">{decisions.length === 0 ? 'No active bans.' : 'No bans match the filter.'}</div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            {#if can('operator')}
              <th class="check"><input type="checkbox" checked={allSelected} onchange={toggleAll} aria-label="Select all shown" /></th>
            {/if}
            <th>Target</th>{#if hasGeo}<th>Network</th>{/if}<th>Jail</th><th>Scope</th><th>Origin</th><th>Reason</th><th>Banned</th><th>Expires</th>
            {#if can('operator')}<th></th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each page as d (d.id)}
            <tr class:selected={selected.has(d.id)}>
              {#if can('operator')}
                <td class="check"><input type="checkbox" checked={selected.has(d.id)} onchange={() => toggle(d.id)} aria-label="Select {d.target}" /></td>
              {/if}
              <td class="mono"><a href={href('ip', d.target)}>{target(d.target)}</a></td>
              {#if hasGeo}<td class="muted nowrap" title={geoLong(geo[d.target])}>{geoShort(geo[d.target])}</td>{/if}
              <td>{d.jail ?? 'manual'}</td>
              <td>{scope(d.scope)}</td>
              <td class="muted">{origin(d.origin)}</td>
              <td class="muted reason">{d.reason}</td>
              <td class="muted" title={dateTime(d.created_at)}>{relative(d.created_at, now)}</td>
              <td title={dateTime(d.expires_at)}>{remaining(d.expires_at, now)}</td>
              {#if can('operator')}
                <td><button class="link" onclick={() => unban([d.target])}>Unban</button></td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if filtered.length > limit}
      <div class="more">
        Showing {limit.toLocaleString()} of {filtered.length.toLocaleString()}.
        <button class="link" onclick={() => (limit += 500)}>Show more</button>
      </div>
    {/if}
  {/if}
</div>

<BanDialog bind:open={banOpen} ondone={load} />
<UnbanDialog bind:open={unbanOpen} targets={unbanTargets} ondone={() => { selected = new Set(); load(); }} />

<style>
  .filters { margin-bottom: 12px; }
  .grow { flex: 1 1 240px; }
  .check { width: 1%; }
  .nowrap { white-space: nowrap; }
  .reason { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .more { padding: 12px 0 0; color: var(--text-2); }
</style>
