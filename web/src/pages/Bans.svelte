<script lang="ts">
  import { get } from '../lib/api';
  import { dateTime, geoLong, geoShort, origin, relative, remaining, scope, target } from '../lib/format';
  import { onChange } from '../lib/live.svelte';
  import { href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import type { Decision, GeoInfo } from '../lib/types';
  import BanDialog from '../components/BanDialog.svelte';
  import UnbanDialog from '../components/UnbanDialog.svelte';

  // a search preset from the URL (#/bans/as:64500, from the overview)
  let { filter = '' }: { filter?: string } = $props();

  interface Page {
    decisions: Decision[];
    geo?: Record<string, GeoInfo>;
    total: number;
    active: number;
    jails: (string | null)[];
  }

  // the server filters, sorts and pages (there may be 100 000 bans)
  let decisions = $state<Decision[]>([]);
  let total = $state(0);
  let active = $state(0);
  let jails = $state<(string | null)[]>([]);
  let geo = $state<Record<string, GeoInfo>>({});
  let loaded = $state(false);
  let error = $state('');
  let now = $state(Date.now());
  // svelte-ignore state_referenced_locally
  let query = $state(filter);
  let jail = $state('');
  let family = $state('');
  let sort = $state<'new' | 'expires' | 'target'>('new');
  // selected bans: id -> target (also those scrolled out of the page)
  let selected = $state<Map<string, string>>(new Map());
  let banOpen = $state(false);
  let unbanOpen = $state(false);
  let unbanTargets = $state<string[]>([]);
  let limit = $state(200);
  // the newest request wins (typing sends one per pause)
  let generation = 0;

  async function load() {
    const mine = ++generation;
    const p = new URLSearchParams({ sort, limit: String(limit) });
    if (query.trim()) p.set('q', query.trim());
    if (jail) p.set('jail', jail);
    if (family) p.set('family', family);
    try {
      const r = await get<Page>(`/decisions?${p}`);
      if (mine !== generation) return;
      decisions = r.decisions;
      geo = r.geo ?? {};
      total = r.total;
      active = r.active;
      jails = r.jails;
      error = '';
      now = Date.now();
    } catch (e) {
      if (mine !== generation) return;
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loaded = true;
    }
  }

  // filters: reload (search after a short pause); back to the first page
  let first = true;
  $effect(() => {
    void [query, jail, family, sort];
    if (first) {
      first = false;
      return;
    }
    limit = 200;
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
  });

  $effect(() => {
    load();
    const off = onChange(load);
    const t = setInterval(() => (now = Date.now()), 30_000);
    return () => {
      off();
      clearInterval(t);
    };
  });

  // the server sends at most 10 000 at a time
  const MAX_PAGE = 10_000;

  function more() {
    limit = Math.min(limit + 500, MAX_PAGE);
    load();
  }

  const hasGeo = $derived(Object.keys(geo).length > 0);
  const allSelected = $derived(decisions.length > 0 && decisions.every((d) => selected.has(d.id)));

  function toggle(d: Decision) {
    const s = new Map(selected);
    if (s.has(d.id)) s.delete(d.id);
    else s.set(d.id, d.target);
    selected = s;
  }

  function toggleAll() {
    selected = allSelected ? new Map() : new Map(decisions.map((d) => [d.id, d.target]));
  }

  function unban(targets: string[]) {
    unbanTargets = [...new Set(targets)];
    unbanOpen = true;
  }
</script>

<div class="page-head">
  <h1>Bans</h1>
  <span class="faint">{active.toLocaleString()} active</span>
  <span class="spacer"></span>
  {#if can('operator')}
    {#if selected.size > 0}
      <button class="danger" onclick={() => unban([...selected.values()])}>
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
      {#each jails as j (j)}<option value={j ?? '-'}>{j ?? 'manual'}</option>{/each}
    </select>
    <select bind:value={family} aria-label="Address family">
      <option value="">IPv4 + IPv6</option>
      <option value="4">IPv4</option>
      <option value="6">IPv6</option>
    </select>
    <select bind:value={sort} aria-label="Sort">
      <option value="new">newest first</option>
      <option value="old">oldest first</option>
      <option value="expires">expiring first</option>
      <option value="target">by address</option>
    </select>
  </div>

  {#if error}<div class="error-box">{error}</div>{/if}

  {#if loaded && total === 0}
    <div class="empty">{active === 0 ? 'No active bans.' : 'No bans match the filter.'}</div>
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
          {#each decisions as d (d.id)}
            <tr class:selected={selected.has(d.id)}>
              {#if can('operator')}
                <td class="check"><input type="checkbox" checked={selected.has(d.id)} onchange={() => toggle(d)} aria-label="Select {d.target}" /></td>
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
    {#if total > decisions.length}
      <div class="more">
        Showing {decisions.length.toLocaleString()} of {total.toLocaleString()}.
        {#if limit < MAX_PAGE}<button class="link" onclick={more}>Show more</button>{:else}Narrow the search to see the rest.{/if}
      </div>
    {/if}
  {/if}
</div>

<BanDialog bind:open={banOpen} ondone={load} />
<UnbanDialog bind:open={unbanOpen} targets={unbanTargets} ondone={() => { selected = new Map(); load(); }} />

<style>
  .filters { margin-bottom: 12px; }
  .grow { flex: 1 1 240px; }
  .check { width: 1%; }
  .nowrap { white-space: nowrap; }
  .reason { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .more { padding: 12px 0 0; color: var(--text-2); }
</style>
